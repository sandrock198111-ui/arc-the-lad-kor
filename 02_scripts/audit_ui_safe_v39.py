#!/usr/bin/env python3
"""Independently audit the narrowly scoped v0.39 icon and battle-HUD repair."""

from __future__ import annotations

import csv
import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output" / "ui_safe_v38_cumulative_patch_only.zip"
V37 = ROOT / "03_output" / "ui_safe_v37_cumulative_patch_only.zip"
OUTPUT = ROOT / "03_output" / "ui_safe_v39_cumulative_patch_only.zip"
REPORT = ROOT / "01_work" / "analysis" / "ui_safe_v39" / "independent_audit.txt"

BASE_HASH = "D66E6F4F780E3096B604C7699E3E7EB00392EE7C0C4FA457AEDE3F61EEFD45D9"
PSX_LOAD_BASE = 0x8011A800
ROW_BYTES = 0x380

PSX_TARGET = "PSX.EXE"
FONT_TARGET = "COMM.IMG"
ICON_U_OFFSET = 0x80214
ICON_RESTORE = (0, 130)
ICON_X = (12, 130)
ICON_CIRCLE = (24, 130)
ICON_CIRCLE_SOURCE = (114, 354)
ICON_WIDTH = 12
ICON_HEIGHT = 12

HUD_POINTERS = (0x823AC, 0x823B0, 0x823B4, 0x823B8, 0x823BC)
HUD_SOURCES = (0x820A8, 0x820AC, 0x820B0, 0x820B4, 0x820B8)
HUD_PAYLOADS = (
    bytes.fromhex("6C 00 00 00"),
    bytes.fromhex("00 00 00 00"),
    bytes.fromhex("DD B2 00 00"),
    bytes.fromhex("01 DE 4F 00"),
    bytes.fromhex("DD 90 00 00"),
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def pixel(data: bytes, x: int, y: int) -> int:
    value = data[y * ROW_BYTES + x // 2]
    return value & 0x0F if x % 2 == 0 else value >> 4


def rectangle(data: bytes, x: int, y: int) -> tuple[int, ...]:
    return tuple(
        pixel(data, x + dx, y + dy)
        for dy in range(ICON_HEIGHT)
        for dx in range(ICON_WIDTH)
    )


def rectangle_byte_offsets(x: int, y: int) -> set[int]:
    return {
        (y + dy) * ROW_BYTES + (x + dx) // 2
        for dy in range(ICON_HEIGHT)
        for dx in range(ICON_WIDTH)
    }


def glyph_index(code: bytes) -> int:
    if len(code) == 1:
        return code[0] - 1
    return 0xDB + (code[0] - 0xDD) * 255 + code[1]


def plane(data: bytes, code: bytes) -> bytes:
    index = glyph_index(code)
    row, remainder = divmod(index, 84)
    column, bitplane = divmod(remainder, 4)
    bit = 1 << bitplane
    return bytes(
        1 if pixel(data, column * 12 + x, row * 12 + y) & bit else 0
        for y in range(12)
        for x in range(12)
    )


def raw_string(executable: bytes, pointer_offset: int) -> tuple[int, bytes]:
    target = struct.unpack_from("<I", executable, pointer_offset)[0] - PSX_LOAD_BASE
    end = executable.index(0, target)
    return target, executable[target:end]


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("v0.38 base ZIP hash differs")

    with ZipFile(BASE) as archive:
        before_names = archive.namelist()
        before = {name: archive.read(name) for name in before_names}
    with ZipFile(V37) as archive:
        v37_font = archive.read(FONT_TARGET)
    with ZipFile(OUTPUT) as archive:
        after_names = archive.namelist()
        after = {name: archive.read(name) for name in after_names}

    if after_names != before_names:
        raise SystemExit("ZIP member order differs")
    changed = [name for name in before_names if before[name] != after[name]]
    if changed != [FONT_TARGET, PSX_TARGET]:
        raise SystemExit(f"unexpected changed members: {changed}")

    old_exe = before[PSX_TARGET]
    new_exe = after[PSX_TARGET]
    old_font = before[FONT_TARGET]
    new_font = after[FONT_TARGET]

    if new_exe[ICON_U_OFFSET] != 0x18 or new_exe[0x80216] != 0x0C:
        raise SystemExit("E7 icon U table differs")
    if rectangle(new_font, *ICON_CIRCLE) != rectangle(new_font, *ICON_CIRCLE_SOURCE):
        raise SystemExit("relocated circle differs from verified duplicate")
    if rectangle(new_font, *ICON_X) != rectangle(old_font, *ICON_X):
        raise SystemExit("working X icon regressed")
    if rectangle(new_font, *ICON_RESTORE) != rectangle(v37_font, *ICON_RESTORE):
        raise SystemExit("failed U=0 destination was not restored")

    for pointer, source, payload in zip(HUD_POINTERS, HUD_SOURCES, HUD_PAYLOADS):
        if struct.unpack_from("<I", new_exe, pointer)[0] != PSX_LOAD_BASE + source:
            raise SystemExit(f"HUD pointer differs at 0x{pointer:X}")
        if new_exe[source:source + 4] != payload:
            raise SystemExit(f"HUD payload differs at 0x{source:X}")

    for code in (bytes.fromhex("6C"), bytes.fromhex("DDB2"), bytes.fromhex("DE4F"), bytes.fromhex("DD90")):
        if plane(new_font, code) != plane(old_font, code):
            raise SystemExit(f"required HUD glyph plane regressed: {code.hex().upper()}")

    expected_help = bytes.fromhex("E7 02 DF 86 E0 EB 9C E7 03 E0 D5 E0 9C E0 C0 E0 AC")
    help_target, help_payload = raw_string(new_exe, 0x8235C)
    if help_target != 0x82094 or help_payload != expected_help:
        raise SystemExit("field-help icon payload regressed")
    if raw_string(new_exe, 0x82360) != raw_string(old_exe, 0x82360):
        raise SystemExit("target-selection help regressed")

    allowed_psx = {ICON_U_OFFSET}
    allowed_psx.update(range(0x820A8, 0x820BC))
    for pointer in HUD_POINTERS:
        allowed_psx.update(range(pointer, pointer + 4))
    psx_diffs = [index for index, (old, new) in enumerate(zip(old_exe, new_exe)) if old != new]
    outside_psx = [offset for offset in psx_diffs if offset not in allowed_psx]
    if outside_psx:
        raise SystemExit(f"PSX delta outside declared ranges: 0x{outside_psx[0]:X}")

    allowed_font = rectangle_byte_offsets(*ICON_RESTORE) | rectangle_byte_offsets(*ICON_CIRCLE)
    font_diffs = [index for index, (old, new) in enumerate(zip(old_font, new_font)) if old != new]
    outside_font = [offset for offset in font_diffs if offset not in allowed_font]
    if outside_font:
        raise SystemExit(f"COMM delta outside icon rectangles: 0x{outside_font[0]:X}")

    manifest = ROOT / "05_docs" / "ui_nonstory_system_v39.csv"
    with manifest.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    repaired = [row for row in rows if row.get("status") == "battle_hud_pointer_repaired"]
    if len(repaired) != 5:
        raise SystemExit("v0.39 HUD manifest rows differ")

    lines = [
        "UI safe v0.39 independent audit",
        f"zip_sha256={digest(OUTPUT.read_bytes())}",
        f"psx_sha256={digest(new_exe)}",
        f"comm_sha256={digest(new_font)}",
        "changed_members=COMM.IMG,PSX.EXE",
        f"psx_changed_bytes={len(psx_diffs)}",
        f"comm_changed_bytes={len(font_diffs)}",
        "circle_icon=verified_duplicate_relocated_to_u_0x18",
        "cross_icon=preserved",
        "battle_hud_pointers=5/5_safe_pool",
        "battle_hud_labels=LV_empty_aux_M_P",
        "item_lv_plane=preserved",
        "field_help_payload=preserved",
        "target_help=preserved",
        "changes_outside_declared_ranges=false",
        "result=PASS",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
