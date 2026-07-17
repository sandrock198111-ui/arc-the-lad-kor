#!/usr/bin/env python3
"""Audit residual Japanese text in non-story Arc the Lad resources."""

from __future__ import annotations

import csv
import struct
import sys
from collections import Counter
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from audit_psx_ui_tables import decode_string  # noqa: E402
from build_ui_full_v26 import PSX_LOAD_BASE, TABLES  # noqa: E402
from build_ui_safe_v33 import (  # noqa: E402
    BATTLE_MANIFEST,
    OUTPUT,
    RELOCATED_TEXTS,
    SYSTEM_TEXTS,
    WORLD_TABLE,
    WORLD_TEXTS,
)
from build_ui_safe_v30 import TARGETS as TUTORIAL_FILES  # noqa: E402
from build_ui_safe_v31 import BATTLE_FILES  # noqa: E402
from extract_story_corpus import build_glyph_map  # noqa: E402


ORIGINAL = ROOT / "01_work" / "PSX.EXE"
CORE_FILES = (
    ROOT / "01_work" / "COMM.DAT",
    ROOT / "01_work" / "S000.DAT",
)
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_safe_v33"
POINTER_REPORT = ANALYSIS / "nonstory_psx_pointer_audit.csv"
DIRECT_REPORT = ANALYSIS / "nonstory_core_direct_scan.csv"
SUMMARY = ANALYSIS / "nonstory_japanese_summary.txt"
CONFIRMED_REPORT = ANALYSIS / "nonstory_confirmed_residuals.csv"
FILE_REPORT = ANALYSIS / "nonstory_file_inventory.csv"
MANIFEST = ROOT / "05_docs" / "ui_safe_v33.csv"

# Binary bytes can decode as Japanese under this game's low-byte table. Only
# these already verified executable text pools are high-confidence scan scope.
CONFIRMED_TEXT_RANGES = (
    (0x7809C, 0x78220),
    (0x80224, 0x82348),
    (0x82A88, 0x82AC0),
)


def csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, object]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def raw_string(data: bytes, offset: int, limit: int = 128) -> bytes | None:
    end = data.find(b"\x00", offset, min(len(data), offset + limit + 1))
    if end < 0 or end == offset:
        return None
    return data[offset:end]


def japanese_score(text: str) -> int:
    return sum(
        "\u3040" <= char <= "\u30ff" or "\u3400" <= char <= "\u9fff"
        for char in text
    )


def table_pointer_labels() -> dict[int, str]:
    labels: dict[int, str] = {}
    for key, (count, _segment, pointer_table) in TABLES.items():
        for index in range(count):
            labels[pointer_table + index * 4] = f"{key}[{index}]"
    return labels


def pointer_audit(original: bytes, patched: bytes) -> list[dict[str, object]]:
    glyph_map, _ambiguity, nearest, _glyph_rows = build_glyph_map()
    table_labels = table_pointer_labels()
    system_pointers = {pointer for pointer, _source, _text in RELOCATED_TEXTS}
    world_pointers = {
        pointer: f"world_name[{index}]"
        for index, (pointer, _source, _jp, _ko, _missing) in enumerate(WORLD_TABLE)
    }
    rows: list[dict[str, object]] = []
    seen: set[tuple[int, int]] = set()

    for pointer in range(0, len(original) - 3, 4):
        word = struct.unpack_from("<I", original, pointer)[0]
        target = word - PSX_LOAD_BASE
        if not 0 <= target < len(original):
            continue
        key = (pointer, target)
        if key in seen:
            continue
        seen.add(key)
        raw = raw_string(original, target)
        if raw is None or len(raw) < 3:
            continue
        try:
            decoded, _length = decode_string(original, target, glyph_map, nearest)
        except (KeyError, ValueError, IndexError):
            continue
        score = japanese_score(decoded)
        if score < 2 or decoded.count("<CTRL:") > 3:
            continue

        patched_word = struct.unpack_from("<I", patched, pointer)[0]
        patched_target = patched_word - PSX_LOAD_BASE
        patched_raw = (
            raw_string(patched, patched_target)
            if 0 <= patched_target < len(patched)
            else None
        )
        residual = patched_word == word and patched_raw == raw
        if pointer in table_labels:
            category = "confirmed_ui_table"
            label = table_labels[pointer]
        elif pointer in world_pointers:
            category = "confirmed_world_table"
            label = world_pointers[pointer]
        elif pointer in system_pointers:
            category = "confirmed_system"
            label = "system"
        else:
            category = "unclassified_pointer"
            label = ""
        rows.append(
            {
                "pointer_offset": f"0x{pointer:X}",
                "source_offset": f"0x{target:X}",
                "category": category,
                "label": label,
                "japanese": decoded,
                "encoded_bytes": len(raw),
                "patched_pointer_changed": patched_word != word,
                "patched_payload_changed": patched_raw != raw,
                "residual_japanese": residual,
                "raw_hex": raw.hex(" ").upper(),
                "confirmed_text_pool": any(
                    start <= target < end for start, end in CONFIRMED_TEXT_RANGES
                ),
            }
        )
    return rows


def direct_scan(path: Path) -> list[dict[str, object]]:
    data = path.read_bytes()
    glyph_map, _ambiguity, nearest, _glyph_rows = build_glyph_map()
    rows: list[dict[str, object]] = []
    offset = 0
    while offset < len(data):
        if data[offset] == 0 or (offset and data[offset - 1] != 0):
            offset += 1
            continue
        raw = raw_string(data, offset, 80)
        if raw is None or len(raw) < 4:
            offset += 1
            continue
        try:
            decoded, _length = decode_string(data, offset, glyph_map, nearest)
        except (KeyError, ValueError, IndexError):
            offset += 1
            continue
        score = japanese_score(decoded)
        controls = decoded.count("<CTRL:")
        if score >= 4 and controls <= 1 and score * 2 >= len(decoded.replace(" ", "")):
            rows.append(
                {
                    "file": path.name,
                    "offset": f"0x{offset:X}",
                    "japanese": decoded,
                    "encoded_bytes": len(raw),
                    "raw_hex": raw.hex(" ").upper(),
                    "classification": "unverified_direct_candidate",
                }
            )
            offset += len(raw) + 1
        else:
            offset += 1
    return rows


def file_inventory() -> list[dict[str, object]]:
    battle_files = set(BATTLE_FILES)
    tutorial_files = set(TUTORIAL_FILES)
    rows: list[dict[str, object]] = []
    with ZipFile(OUTPUT) as archive:
        for info in archive.infolist():
            name = info.filename
            if name == "PSX.EXE":
                scope = "nonstory_text"
                method = "503 UI + 33 system + 7 world-name pointer tables"
                result = "audited"
            elif name == "COMM.IMG":
                scope = "shared_font_and_graphics"
                method = "declared LV bitplane delta and texture-preservation audit"
                result = "audited_binary"
            elif name in battle_files:
                scope = "battle_choice_ui"
                method = "63-record battle-choice manifest readback"
                result = "audited"
            elif name in tutorial_files:
                scope = "battle_tutorial_ui"
                method = "24-row tutorial E2/E6 control-preservation readback"
                result = "audited"
            else:
                scope = "story_or_event_script"
                method = "excluded by non-story audit request"
                result = "excluded"
            rows.append(
                {
                    "source": "v33_patch_zip",
                    "file": name,
                    "bytes": info.file_size,
                    "scope": scope,
                    "method": method,
                    "result": result,
                }
            )

    core = (
        ("COMM.DAT", "common_binary_data", "direct decoder scan; no confirmed text table", "unverified_candidates_only"),
        ("S000.DAT", "system_scene_binary", "direct decoder scan; no confirmed text table", "unverified_candidates_only"),
        ("COMM.SND", "pBAV_audio_bank", "binary signature classification", "not_text"),
        ("S000.IMG", "pBAV_audio_bank", "binary signature classification", "not_text"),
    )
    for name, scope, method, result in core:
        path = ROOT / "01_work" / name
        rows.append(
            {
                "source": "original_core_resource",
                "file": name,
                "bytes": path.stat().st_size,
                "scope": scope,
                "method": method,
                "result": result,
            }
        )
    return rows


def main() -> None:
    original = ORIGINAL.read_bytes()
    with ZipFile(OUTPUT) as archive:
        patched = archive.read("PSX.EXE")

    pointer_rows = pointer_audit(original, patched)
    direct_rows = [row for path in CORE_FILES for row in direct_scan(path)]
    file_rows = file_inventory()
    write_csv(
        POINTER_REPORT,
        pointer_rows,
        [
            "pointer_offset",
            "source_offset",
            "category",
            "label",
            "japanese",
            "encoded_bytes",
            "patched_pointer_changed",
            "patched_payload_changed",
            "residual_japanese",
            "raw_hex",
            "confirmed_text_pool",
        ],
    )
    write_csv(
        DIRECT_REPORT,
        direct_rows,
        ["file", "offset", "japanese", "encoded_bytes", "raw_hex", "classification"],
    )
    write_csv(
        FILE_REPORT,
        file_rows,
        ["source", "file", "bytes", "scope", "method", "result"],
    )

    manifest = csv_rows(MANIFEST)
    preserved = [row for row in manifest if row["status"] == "preserved_v25_missing_glyph"]
    residual = [row for row in pointer_rows if row["residual_japanese"]]
    counts = Counter(row["category"] for row in residual)
    high_confidence_unclassified = [
        row
        for row in residual
        if row["category"] == "unclassified_pointer" and row["confirmed_text_pool"]
    ]
    world_preserved = [row for row in WORLD_TABLE if row[4]]

    confirmed_rows: list[dict[str, object]] = []
    for row in preserved:
        confirmed_rows.append(
            {
                "source": "ui_manifest",
                "table_key": row["table_key"],
                "index": row["index"],
                "pointer_offset": row["pointer_offset"],
                "japanese": row["japanese"],
                "korean_target": row["korean_target"],
                "missing_glyphs": row["missing_glyphs"],
                "reason": "verified_glyph_missing",
            }
        )
    for index, (pointer, _source, japanese, korean, missing) in enumerate(WORLD_TABLE):
        if not missing:
            continue
        confirmed_rows.append(
            {
                "source": "world_name_table",
                "table_key": "world_name",
                "index": index,
                "pointer_offset": f"0x{pointer:X}",
                "japanese": japanese,
                "korean_target": korean,
                "missing_glyphs": missing,
                "reason": "verified_glyph_missing",
            }
        )
    write_csv(
        CONFIRMED_REPORT,
        confirmed_rows,
        [
            "source",
            "table_key",
            "index",
            "pointer_offset",
            "japanese",
            "korean_target",
            "missing_glyphs",
            "reason",
        ],
    )
    lines = [
        "Non-story Japanese audit v0.33",
        f"confirmed_ui_records={len(manifest)}",
        f"confirmed_ui_korean={len(manifest) - len(preserved)}",
        f"confirmed_ui_preserved_japanese={len(preserved)}",
        f"confirmed_system_records={len(SYSTEM_TEXTS)}",
        f"confirmed_system_korean={len(SYSTEM_TEXTS)}",
        f"confirmed_world_name_records={len(WORLD_TABLE)}",
        f"confirmed_world_name_korean={len(WORLD_TEXTS)}",
        f"confirmed_world_name_preserved_japanese={len(world_preserved)}",
        f"confirmed_residual_entries={len(confirmed_rows)}",
        f"psx_pointer_candidates={len(pointer_rows)}",
        f"psx_residual_pointer_candidates={len(residual)}",
        f"psx_residual_confirmed_ui={counts['confirmed_ui_table']}",
        f"psx_residual_confirmed_system={counts['confirmed_system']}",
        f"psx_residual_confirmed_world={counts['confirmed_world_table']}",
        f"psx_residual_unclassified={counts['unclassified_pointer']}",
        f"psx_high_confidence_unclassified_residual={len(high_confidence_unclassified)}",
        f"comm_dat_direct_candidates={sum(row['file'] == 'COMM.DAT' for row in direct_rows)}",
        f"s000_dat_direct_candidates={sum(row['file'] == 'S000.DAT' for row in direct_rows)}",
        "comm_img_classification=graphics_and_font_no_direct_text_scan",
        "comm_snd_classification=audio_no_direct_text_scan",
        "broad_pointer_and_direct_counts=unverified_binary_decoder_candidates_not_confirmed_text",
        f"file_inventory_records={len(file_rows)}",
        f"file_inventory_audited={sum(row['result'].startswith('audited') for row in file_rows)}",
        f"file_inventory_story_excluded={sum(row['result'] == 'excluded' for row in file_rows)}",
        f"battle_choice_manifest_records={len(csv_rows(BATTLE_MANIFEST))}",
        "battle_tutorial_manifest_records=24",
    ]
    SUMMARY.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
