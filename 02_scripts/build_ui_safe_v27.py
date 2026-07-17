#!/usr/bin/env python3
"""Build a playable UI patch using only the already accepted DD-E0 glyph bank."""

from __future__ import annotations

import csv
import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from build_ui_full_v26 import (  # noqa: E402
    BASE,
    BASE_HASH,
    FILLER,
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
from ui_full_v26_data import TRANSLATIONS  # noqa: E402


OUTPUT = ROOT / "03_output" / "ui_safe_v27_cumulative_patch_only.zip"
MANIFEST = ROOT / "05_docs" / "ui_safe_v27.csv"
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_safe_v27"
REPORT = ANALYSIS / "build_report.txt"
READBACK = ANALYSIS / "readback.csv"
CHARMAPS = (
    ROOT / "05_docs" / "korean_charmap.csv",
    ROOT / "05_docs" / "korean_charmap_extended.csv",
)


def csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def load_mapping() -> dict[str, bytes]:
    mapping: dict[str, bytes] = {}
    for path in CHARMAPS:
        for row in csv_rows(path):
            if row["char"]:
                code = bytes.fromhex(row["code_hex"])
                if len(code) == 2 and not 0xDD <= code[0] <= 0xE0:
                    raise SystemExit(f"unsafe existing glyph code for {row['char']!r}: {code.hex()}")
                mapping[row["char"]] = code
    return mapping


def missing_chars(text: str, mapping: dict[str, bytes]) -> str:
    return "".join(
        sorted(
            {
                char
                for char in text
                if char != " "
                and not (char.isascii() and char.isdigit())
                and (char not in mapping or 0x00 in mapping[char])
            }
        )
    )


def encode(text: str, mapping: dict[str, bytes]) -> bytes:
    output = bytearray()
    for char in text:
        if char == " ":
            output.append(FILLER)
        elif char.isascii() and char.isdigit():
            output.append(0x11 + int(char))
        else:
            output.extend(mapping[char])
    return bytes(output)


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("v0.25 cumulative base ZIP hash differs")
    mapping = load_mapping()

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
            korean = TRANSLATIONS[key][index]
            missing = missing_chars(korean, mapping)
            if not missing:
                payload = encode(korean, mapping)
                status = "translated_existing_bank"
            else:
                payload = base_payloads[(key, index)]
                status = "preserved_v25_missing_glyph"
            payloads.append(payload)
            records.append(
                {
                    "table_key": key,
                    "index": index,
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
    with MANIFEST.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)
    with READBACK.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    translated = sum(row["status"] == "translated_existing_bank" for row in records)
    preserved = len(records) - translated
    segments = [block for _, block, _ in TABLES.values()]
    free_bytes = sum(end - position for (_, end), position in zip(segments, cursors))
    report = [
        "UI safe v0.27 cumulative hotfix",
        f"base_zip_sha256={BASE_HASH}",
        f"output_zip_sha256={digest(OUTPUT.read_bytes())}",
        f"translated_existing_bank={translated}",
        f"preserved_v25_missing_glyph={preserved}",
        f"total_records={len(records)}",
        f"deduplicated_strings={len(locations)}",
        f"global_pool_free_bytes={free_bytes}",
        f"psx_exe_changed_bytes={changed_exe}",
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
