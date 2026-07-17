#!/usr/bin/env python3
"""Build the expanded safe UI batch with guide-reviewed skill wording."""

from __future__ import annotations

import csv
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from build_ui_full_v26 import (  # noqa: E402
    BASE,
    BASE_HASH,
    FONT_TARGET,
    PSX_LOAD_BASE,
    PSX_TARGET,
    TABLES,
    allocate_pool,
    digest,
    pointer_target,
    raw_string,
    verify_executable_changes,
)
from build_ui_safe_v27 import encode, load_mapping, missing_chars  # noqa: E402
from ui_full_v26_data import TRANSLATIONS  # noqa: E402
from ui_safe_v28_overrides import OVERRIDES  # noqa: E402


OUTPUT = ROOT / "03_output" / "ui_safe_v28_cumulative_patch_only.zip"
MANIFEST = ROOT / "05_docs" / "ui_safe_v28.csv"
SKILL_REFERENCE = ROOT / "05_docs" / "ui_skill_guide_reference_v28.csv"
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_safe_v28"
REPORT = ANALYSIS / "build_report.txt"
READBACK = ANALYSIS / "readback.csv"
SOURCE_AUDIT = ROOT / "01_work" / "analysis" / "ui_tables_v24" / "psx_ui_tables.csv"


def guide_page(index: int) -> str:
    if 1 <= index <= 5:
        return "Game Magazine p.92 (아크)"
    if 6 <= index <= 12:
        return "Game Magazine p.93 (쿠쿠루)"
    if 13 <= index <= 16:
        return "Game Magazine p.94 (토슈)"
    if 17 <= index <= 24:
        return "Game Magazine p.92 (포코)"
    if 25 <= index <= 31:
        return "Game Magazine p.93 (고겐)"
    if 32 <= index <= 37:
        return "Game Magazine p.95 (이가)"
    if 38 <= index <= 45:
        return "Game Magazine p.95 (총가라 소환수)"
    return "PSX.EXE 일본어 원문"


def load_japanese() -> dict[tuple[str, int], str]:
    with SOURCE_AUDIT.open(encoding="utf-8-sig", newline="") as handle:
        return {
            (row["table_key"], int(row["index"])): row["japanese"]
            for row in csv.DictReader(handle)
        }


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("v0.25 cumulative base ZIP hash differs")
    mapping = load_mapping()
    japanese = load_japanese()

    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        files = {info.filename: archive.read(info.filename) for info in infos}
    before_files = dict(files)
    executable = bytearray(files[PSX_TARGET])

    base_payloads: dict[tuple[str, int], bytes] = {}
    for key, (count, _, pointer_table) in TABLES.items():
        for index in range(count):
            target = pointer_target(executable, pointer_table, index)
            base_payloads[(key, index)] = raw_string(executable, target)

    records: list[dict[str, object]] = []
    payloads: list[bytes] = []
    for key, (count, _, _) in TABLES.items():
        for index in range(count):
            record_key = (key, index)
            korean = OVERRIDES.get(record_key, TRANSLATIONS[key][index])
            missing = missing_chars(korean, mapping)
            if not missing:
                payload = encode(korean, mapping)
                status = (
                    "guide_safe_override"
                    if record_key in OVERRIDES
                    else "translated_existing_bank"
                )
            else:
                payload = base_payloads[record_key]
                status = "preserved_v25_missing_glyph"
            payloads.append(payload)
            records.append(
                {
                    "table_key": key,
                    "index": index,
                    "japanese": japanese[record_key],
                    "status": status,
                    "korean_target": korean,
                    "missing_glyphs": missing,
                    "encoded_bytes": len(payload),
                    "encoded_hex": payload.hex(" ").upper(),
                }
            )

    locations, cursors = allocate_pool(executable, payloads)
    cursor = 0
    for key, (count, _, pointer_table) in TABLES.items():
        for index in range(count):
            payload = payloads[cursor]
            target = locations[payload]
            struct.pack_into("<I", executable, pointer_table + index * 4, PSX_LOAD_BASE + target)
            records[cursor]["pointer_offset"] = f"0x{pointer_table + index * 4:X}"
            records[cursor]["string_offset"] = f"0x{target:X}"
            cursor += 1

    cursor = 0
    for key, (count, _, pointer_table) in TABLES.items():
        for index in range(count):
            target = pointer_target(executable, pointer_table, index)
            if raw_string(executable, target) != payloads[cursor]:
                raise SystemExit(f"safe pointer readback failed: {key}[{index}]")
            cursor += 1

    changed_exe = verify_executable_changes(before_files[PSX_TARGET], executable)
    files[PSX_TARGET] = bytes(executable)
    changed_members = [name for name in files if files[name] != before_files[name]]
    if changed_members != [PSX_TARGET]:
        raise SystemExit(f"safe patch changed unexpected members: {changed_members}")
    if files[FONT_TARGET] != before_files[FONT_TARGET]:
        raise SystemExit("safe patch changed COMM.IMG")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w", ZIP_DEFLATED, compresslevel=9) as archive:
        for info in infos:
            archive.writestr(info, files[info.filename])
    with ZipFile(OUTPUT) as archive:
        for name, expected in files.items():
            if archive.read(name) != expected:
                raise SystemExit(f"output readback differs: {name}")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    fieldnames = list(records[0])
    for path in (MANIFEST, READBACK):
        with path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(records)

    skill_rows = [
        {
            "index": row["index"],
            "record_type": row["table_key"],
            "japanese": row["japanese"],
            "korean": row["korean_target"],
            "reference": guide_page(int(row["index"])),
            "basis": (
                "공략본의 한국어 명칭/효과와 PSX.EXE 원문을 함께 반영"
                if 1 <= int(row["index"]) <= 45
                else "공략본에 없는 적 전용 기술로 PSX.EXE 원문 효과를 반영"
            ),
        }
        for row in records
        if row["table_key"] in {"skill_name", "skill_description"}
    ]
    with SKILL_REFERENCE.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(skill_rows[0]))
        writer.writeheader()
        writer.writerows(skill_rows)

    translated = sum(row["status"] != "preserved_v25_missing_glyph" for row in records)
    guide_overrides = sum(row["status"] == "guide_safe_override" for row in records)
    preserved = len(records) - translated
    segments = [block for _, block, _ in TABLES.values()]
    free_bytes = sum(end - position for (_, end), position in zip(segments, cursors))
    report = [
        "UI safe v0.28 cumulative guide-reviewed batch",
        f"base_zip_sha256={BASE_HASH}",
        f"output_zip_sha256={digest(OUTPUT.read_bytes())}",
        f"translated_existing_bank={translated}",
        f"guide_safe_overrides={guide_overrides}",
        f"preserved_v25_missing_glyph={preserved}",
        f"total_records={len(records)}",
        f"deduplicated_strings={len(locations)}",
        f"global_pool_free_bytes={free_bytes}",
        f"psx_exe_changed_bytes={changed_exe}",
        "skill_reference_pages=92,93,94,95",
        "comm_img_byte_identical_to_v25=true",
        "battle_cursor_and_sprite_texture_source_preserved=true",
        "e1_e8_ui_codes_added=false",
        "unrelated_zip_members_preserved=true",
        f"changed_members={','.join(changed_members)}",
    ]
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
