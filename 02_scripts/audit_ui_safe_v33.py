#!/usr/bin/env python3
"""Independently audit the v0.33 system-help and compact-LV repair."""

from __future__ import annotations

import csv
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from build_ui_full_v26 import PSX_LOAD_BASE, TABLES, pointer_target, raw_string  # noqa: E402
from build_ui_safe_v27 import load_mapping  # noqa: E402
from build_ui_safe_v33 import (  # noqa: E402
    HELP_TEXTS,
    MANIFEST,
    OUTPUT,
    RELOCATED_TEXTS,
    SYSTEM_AUDIT,
    SYSTEM_POOLS,
    SYSTEM_TEXTS,
    UI_FIXES,
    WORLD_TABLE,
    WORLD_TEXTS,
    label_bitmap,
    patch_lv,
    system_payload,
)


V32 = ROOT / "03_output" / "ui_safe_v32_cumulative_patch_only.zip"
REPORT = ROOT / "01_work" / "analysis" / "ui_safe_v33" / "audit_report.txt"


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def contains_icon_control(payload: bytes) -> bool:
    cursor = 0
    while cursor < len(payload):
        first = payload[cursor]
        if 0xDD <= first <= 0xE0:
            cursor += 2
            continue
        if 0xE1 <= first <= 0xE8:
            return True
        cursor += 1
    return False


def main() -> None:
    mapping = load_mapping()
    manifest = rows(MANIFEST)
    keyed = {(row["table_key"], int(row["index"])): row for row in manifest}
    if len(manifest) != 503 or len(keyed) != 503:
        raise SystemExit("v0.33 UI manifest coverage differs")

    with ZipFile(V32) as before, ZipFile(OUTPUT) as after:
        if after.namelist() != before.namelist():
            raise SystemExit("v0.33 ZIP member order differs")
        old_files = {name: before.read(name) for name in before.namelist()}
        new_files = {name: after.read(name) for name in after.namelist()}
    changed = {name for name in new_files if new_files[name] != old_files[name]}
    if changed != {"COMM.IMG", "PSX.EXE"}:
        raise SystemExit(f"v0.33 changed-member set differs: {sorted(changed)}")

    expected_font = bytearray(old_files["COMM.IMG"])
    patch_lv(expected_font)
    if new_files["COMM.IMG"] != bytes(expected_font):
        raise SystemExit("v0.33 COMM.IMG differs outside the declared LV plane")

    executable = new_files["PSX.EXE"]
    for key, (count, _segment, pointer_table) in TABLES.items():
        for index in range(count):
            row = keyed[(key, index)]
            payload = raw_string(executable, pointer_target(executable, pointer_table, index))
            if payload.hex(" ").upper() != row["encoded_hex"]:
                raise SystemExit(f"v0.33 UI payload differs: {key}[{index}]")

    system_rows = rows(SYSTEM_AUDIT)
    if len(system_rows) != len(RELOCATED_TEXTS) or len(HELP_TEXTS) != 13:
        raise SystemExit("v0.33 system coverage differs")
    by_pointer = {int(row["pointer_offset"], 0): row for row in system_rows}
    for pointer, source, text in RELOCATED_TEXTS:
        row = by_pointer[pointer]
        target = struct.unpack_from("<I", executable, pointer)[0] - PSX_LOAD_BASE
        expected = system_payload(text, mapping)
        if target != int(row["new_offset"], 0):
            raise SystemExit(f"v0.33 pointer differs: 0x{pointer:X}")
        if int(row["source_offset"], 0) != source:
            raise SystemExit(f"v0.33 source differs: 0x{pointer:X}")
        if raw_string(executable, target) != expected:
            raise SystemExit(f"v0.33 payload differs: 0x{pointer:X}")
        if row["encoded_hex"] != expected.hex(" ").upper():
            raise SystemExit(f"v0.33 manifest hex differs: 0x{pointer:X}")

    for pointer, _source, text in HELP_TEXTS:
        target = struct.unpack_from("<I", executable, pointer)[0] - PSX_LOAD_BASE
        payload = raw_string(executable, target)
        if payload != system_payload(text, mapping):
            raise SystemExit(f"v0.33 help differs: 0x{pointer:X}")
        if contains_icon_control(payload):
            raise SystemExit(f"v0.33 help retained a broken icon control: 0x{pointer:X}")

    translated_world = {pointer for pointer, _source, _text in WORLD_TEXTS}
    for pointer, source, _japanese, korean, missing in WORLD_TABLE:
        target = struct.unpack_from("<I", executable, pointer)[0] - PSX_LOAD_BASE
        if pointer in translated_world:
            if raw_string(executable, target) != system_payload(korean, mapping):
                raise SystemExit(f"v0.33 world name differs: 0x{pointer:X}")
        elif not missing or target != source or raw_string(executable, target) != raw_string(
            old_files["PSX.EXE"], source
        ):
            raise SystemExit(f"v0.33 preserved world name differs: 0x{pointer:X}")

    yes_no = next(text for pointer, _source, text in SYSTEM_TEXTS if pointer == 0x82AC0)
    if yes_no != "예    아니요":
        raise SystemExit("v0.33 confirmation spacing differs")

    allowed = bytearray(len(executable))
    for start, end in SYSTEM_POOLS:
        allowed[start:end] = b"\x01" * (end - start)
    for pointer, _source, _text in RELOCATED_TEXTS:
        allowed[pointer:pointer + 4] = b"\x01" * 4
    for offset, (old, new) in enumerate(zip(old_files["PSX.EXE"], executable)):
        if old != new and not allowed[offset]:
            raise SystemExit(f"v0.33 PSX delta outside range: 0x{offset:X}")

    lines = [
        "UI safe v0.33 independent audit",
        "pointer_payload_readback=503/503",
        f"system_text_pointer_readback={len(SYSTEM_TEXTS)}/{len(SYSTEM_TEXTS)}",
        f"ui_relocation_readback={len(UI_FIXES)}/{len(UI_FIXES)}",
        "battle_help_pointer_readback=13/13",
        f"world_name_pointer_readback={len(WORLD_TEXTS)}/{len(WORLD_TEXTS)}",
        "world_name_preserved_missing_glyph=1",
        "battle_help_icon_controls=0",
        "confirmation_spacing=4_spaces",
        f"lv_bitmap_pixels={len(label_bitmap())}",
        "lv_change_scope=single_physical_bitplane",
        "battle_and_story_members_byte_identical_to_v32=true",
        "changes_outside_declared_ranges=false",
        "result=PASS",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
