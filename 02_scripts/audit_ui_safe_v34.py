#!/usr/bin/env python3
"""Independently audit the v0.34 presentation-only UI repair."""

from __future__ import annotations

import csv
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_ui_safe_v34 as build  # noqa: E402
from build_ui_full_v26 import PSX_LOAD_BASE, TABLES, pointer_target, raw_string  # noqa: E402
from build_ui_safe_v27 import load_mapping  # noqa: E402


BEFORE = ROOT / "03_output" / "ui_safe_v33_cumulative_patch_only.zip"
REPORT = build.ANALYSIS / "audit_report.txt"


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def main() -> None:
    mapping = load_mapping()
    with ZipFile(BEFORE) as before, ZipFile(build.OUTPUT) as after:
        if after.namelist() != before.namelist():
            raise SystemExit("v0.34 ZIP member order differs")
        old_files = {name: before.read(name) for name in before.namelist()}
        new_files = {name: after.read(name) for name in after.namelist()}

    changed = {name for name in new_files if new_files[name] != old_files[name]}
    if changed != {"COMM.IMG", "PSX.EXE"}:
        raise SystemExit(f"v0.34 changed-member set differs: {sorted(changed)}")

    build.configure_base()
    expected_font = bytearray(old_files["COMM.IMG"])
    build.base.patch_lv(expected_font)
    if new_files["COMM.IMG"] != bytes(expected_font):
        raise SystemExit("v0.34 COMM.IMG differs outside the declared LV plane")

    executable = new_files["PSX.EXE"]
    manifest = rows(build.MANIFEST)
    keyed = {(row["table_key"], int(row["index"])): row for row in manifest}
    if len(manifest) != 503 or len(keyed) != 503:
        raise SystemExit("v0.34 UI manifest coverage differs")
    for key, (count, _segment, pointer_table) in TABLES.items():
        for index in range(count):
            payload = raw_string(executable, pointer_target(executable, pointer_table, index))
            if payload.hex(" ").upper() != keyed[(key, index)]["encoded_hex"]:
                raise SystemExit(f"v0.34 UI payload differs: {key}[{index}]")

    system_rows = rows(build.SYSTEM_AUDIT)
    by_pointer = {int(row["pointer_offset"], 0): row for row in system_rows}
    if len(system_rows) != len(build.RELOCATED_TEXTS):
        raise SystemExit("v0.34 system coverage differs")
    for pointer, source, text in build.RELOCATED_TEXTS:
        target = struct.unpack_from("<I", executable, pointer)[0] - PSX_LOAD_BASE
        expected = build.base.system_payload(text, mapping)
        row = by_pointer[pointer]
        if int(row["source_offset"], 0) != source or int(row["new_offset"], 0) != target:
            raise SystemExit(f"v0.34 pointer audit differs: 0x{pointer:X}")
        if raw_string(executable, target) != expected:
            raise SystemExit(f"v0.34 payload differs: 0x{pointer:X}")

    bottom = next(text for pointer, _source, text in build.HELP_TEXTS if pointer == 0x8235C)
    yes_no = next(text for pointer, _source, text in build.SYSTEM_TEXTS if pointer == 0x82AC0)
    if bottom != "결정 : 돌아가기" or yes_no != "예      아니요":
        raise SystemExit("v0.34 presentation strings differ")
    bottom_target = struct.unpack_from("<I", executable, 0x8235C)[0] - PSX_LOAD_BASE
    if b"\xE7" in raw_string(executable, bottom_target):
        raise SystemExit("v0.34 reintroduced unsafe E7 icon controls")

    allowed = bytearray(len(executable))
    for start, end in build.base.SYSTEM_POOLS:
        allowed[start:end] = b"\x01" * (end - start)
    for pointer, _source, _text in build.RELOCATED_TEXTS:
        allowed[pointer:pointer + 4] = b"\x01" * 4
    for offset, (old, new) in enumerate(zip(old_files["PSX.EXE"], executable)):
        if old != new and not allowed[offset]:
            raise SystemExit(f"v0.34 PSX delta outside range: 0x{offset:X}")

    lines = [
        "UI safe v0.34 independent audit",
        "pointer_payload_readback=503/503",
        f"system_text_pointer_readback={len(build.SYSTEM_TEXTS)}/{len(build.SYSTEM_TEXTS)}",
        "battle_help_pointer_readback=13/13",
        "bottom_help=결정 : 돌아가기",
        "button_icon_controls=0",
        "confirmation_spacing=6_spaces",
        f"lv_bitmap_pixels={len(build.label_bitmap())}",
        "lv_change_scope=single_physical_bitplane",
        "other_zip_members_byte_identical_to_v33=true",
        "changes_outside_declared_ranges=false",
        "result=PASS",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
