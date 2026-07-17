#!/usr/bin/env python3
"""Independently audit the v0.32 button-help, target-help, and LV repair."""

from __future__ import annotations

import csv
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from build_ui_full_v26 import PSX_LOAD_BASE, TABLES, pointer_target, raw_string  # noqa: E402
from build_ui_safe_v32 import (  # noqa: E402
    ICON_TOKENS,
    MANIFEST,
    OUTPUT,
    SYSTEM_AUDIT,
    SYSTEM_POOLS,
    SYSTEM_TEXTS,
    label_bitmap,
    patch_lv,
    system_payload,
)
from build_ui_safe_v27 import load_mapping  # noqa: E402


V31 = ROOT / "03_output" / "ui_safe_v31_cumulative_patch_only.zip"
REPORT = ROOT / "01_work" / "analysis" / "ui_safe_v32" / "audit_report.txt"


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def main() -> None:
    mapping = load_mapping()
    manifest = rows(MANIFEST)
    keyed = {(row["table_key"], int(row["index"])): row for row in manifest}
    if len(manifest) != 503 or len(keyed) != 503:
        raise SystemExit("v0.32 UI manifest coverage differs")

    with ZipFile(V31) as before, ZipFile(OUTPUT) as after:
        if after.namelist() != before.namelist():
            raise SystemExit("v0.32 ZIP member order differs")
        old_files = {name: before.read(name) for name in before.namelist()}
        new_files = {name: after.read(name) for name in after.namelist()}
    changed = {name for name in new_files if new_files[name] != old_files[name]}
    if changed != {"COMM.IMG", "PSX.EXE"}:
        raise SystemExit(f"v0.32 changed-member set differs: {sorted(changed)}")

    expected_font = bytearray(old_files["COMM.IMG"])
    patch_lv(expected_font)
    if new_files["COMM.IMG"] != bytes(expected_font):
        raise SystemExit("v0.32 COMM.IMG differs outside the new LV plane")

    executable = new_files["PSX.EXE"]
    for key, (count, _segment, pointer_table) in TABLES.items():
        for index in range(count):
            row = keyed[(key, index)]
            payload = raw_string(executable, pointer_target(executable, pointer_table, index))
            if payload.hex(" ").upper() != row["encoded_hex"]:
                raise SystemExit(f"v0.32 UI payload differs: {key}[{index}]")

    system_rows = rows(SYSTEM_AUDIT)
    if len(system_rows) != 22 or len(SYSTEM_TEXTS) != 22:
        raise SystemExit("v0.32 system coverage differs")
    by_pointer = {int(row["pointer_offset"], 0): row for row in system_rows}
    for pointer_offset, source_offset, text in SYSTEM_TEXTS:
        row = by_pointer[pointer_offset]
        target = struct.unpack_from("<I", executable, pointer_offset)[0] - PSX_LOAD_BASE
        expected = system_payload(text, mapping)
        if target != int(row["new_offset"], 0):
            raise SystemExit(f"v0.32 pointer differs: 0x{pointer_offset:X}")
        if int(row["source_offset"], 0) != source_offset:
            raise SystemExit(f"v0.32 source differs: 0x{pointer_offset:X}")
        if raw_string(executable, target) != expected:
            raise SystemExit(f"v0.32 payload differs: 0x{pointer_offset:X}")
        if row["encoded_hex"] != expected.hex(" ").upper():
            raise SystemExit(f"v0.32 manifest hex differs: 0x{pointer_offset:X}")

    button_target = struct.unpack_from("<I", executable, 0x8235C)[0] - PSX_LOAD_BASE
    button_payload = raw_string(executable, button_target)
    if button_payload.count(ICON_TOKENS["{결정버튼}"]) != 1:
        raise SystemExit("decision button icon differs")
    if button_payload.count(ICON_TOKENS["{상태버튼}"]) != 1:
        raise SystemExit("status button icon differs")
    target_help = struct.unpack_from("<I", executable, 0x82360)[0] - PSX_LOAD_BASE
    if raw_string(executable, target_help) != system_payload("다음 대상을 선택합니다", mapping):
        raise SystemExit("target-selection help differs")

    allowed = bytearray(len(executable))
    for start, end in SYSTEM_POOLS:
        allowed[start:end] = b"\x01" * (end - start)
    for pointer_offset, _source_offset, _text in SYSTEM_TEXTS:
        allowed[pointer_offset:pointer_offset + 4] = b"\x01" * 4
    for offset, (old, new) in enumerate(zip(old_files["PSX.EXE"], executable)):
        if old != new and not allowed[offset]:
            raise SystemExit(f"v0.32 PSX delta outside range: 0x{offset:X}")

    for name in new_files:
        if name not in {"COMM.IMG", "PSX.EXE"} and new_files[name] != old_files[name]:
            raise SystemExit(f"v0.32 changed an unrelated member: {name}")

    lines = [
        "UI safe v0.32 independent audit",
        "pointer_payload_readback=503/503",
        "system_text_pointer_readback=22/22",
        "decision_status_button_icons=2/2",
        "target_selection_help=translated",
        f"lv_bitmap_pixels={len(label_bitmap())}",
        "lv_change_scope=single_physical_bitplane",
        "battle_and_story_members_byte_identical_to_v31=true",
        "changes_outside_declared_ranges=false",
        "result=PASS",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
