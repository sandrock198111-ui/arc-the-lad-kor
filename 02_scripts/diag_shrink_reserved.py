"""Give the game back part of the RAM the resident block takes, and see if it heals.

The entry point at 0x801757BC copies 5,356 bytes from the executable tail to
0x801FE3C4 and then moves the game's own structure up to 0x801FF8B0 to get out of the
way.  The original structure sits at 0x801FE3C4 and has 0x801FFFF0 above it, so this
patch cut it from 7,212 bytes to 1,856.

Reverting the patch is not a test: the 276-byte helper it copies is code that other
patches call at 0x801FE3C4, so without the copy the game executes its own data and
dies at boot.  Both attempts to revert it did exactly that.

What can be done is take less.  The copied block ends with strip C (936 bytes) and
1,064 bytes that v145 already emptied, and cutting the copy short there costs only
strip C's 52 glyphs -- which Japanese text never asks for, and this disc carries the
original .DAT files.

    copy 5,356 -> 2,788    structure base 0x801FF8B0 -> 0x801FEEA8
    game keeps 1,856 -> 4,424 bytes

If the monster heals, the reserved block is the cause and the fix is to stop keeping
the strips resident at all.  If it does not, the game needs more than 4,424 and the
answer is the same, only more urgent.
"""
from __future__ import annotations

import hashlib
import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE_ZIP = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
R2F = 0x8011A800
LEN_AT, BASE_AT = 0x801757CC - R2F, 0x80175810 - R2F
DST = 0x801FE3C4
NEW_LEN = 0x801A91D0 - 0x801A86EC          # helper, strips A and B, classifier, both tables


def addiu(rt: int, rs: int, imm: int) -> int:
    return (0x09 << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def main() -> None:
    with zipfile.ZipFile(BASE_ZIP) as z:
        info = z.getinfo("PSX.EXE")
        exe = bytearray(z.read("PSX.EXE"))

    old_len = struct.unpack_from("<I", exe, LEN_AT)[0] & 0xFFFF
    old_base = 0x80200000 + (((struct.unpack_from("<I", exe, BASE_AT)[0] & 0xFFFF) ^ 0x8000) - 0x8000)
    if old_len != 5356 or old_base != 0x801FF8B0:
        raise SystemExit(f"unexpected boot patch: len={old_len} base=0x{old_base:08X}")

    new_base = DST + NEW_LEN
    struct.pack_into("<I", exe, LEN_AT, addiu(6, 0, NEW_LEN))
    struct.pack_into("<I", exe, BASE_AT, addiu(4, 4, new_base - 0x80200000))

    out = ROOT / "03_output/DIAG_exe_shrink_reserved.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as w:
        ni = zipfile.ZipInfo("PSX.EXE", info.date_time)
        for attr in ("compress_type", "external_attr", "create_system"):
            setattr(ni, attr, getattr(info, attr))
        w.writestr(ni, bytes(exe))

    print("진단용 빌드 (배포 금지 -- strip C 글자 52자가 안 나온다)")
    print(f"  복사 길이   {old_len} -> {NEW_LEN} 바이트  (strip C와 빈 꼬리를 안 옮긴다)")
    print(f"  구조체 시작 0x{old_base:08X} -> 0x{new_base:08X}")
    print(f"  게임이 쓰는 공간 {0x801FFFF0-old_base} -> {0x801FFFF0-new_base} 바이트"
          f"  (원본은 {0x801FFFF0-DST})")
    print(f"  sha256      {hashlib.sha256(out.read_bytes()).hexdigest().upper()}")
    print(f"  output      {out.name}")


if __name__ == "__main__":
    main()
