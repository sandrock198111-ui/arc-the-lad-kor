"""Take the kernel-reserved register out of the frame routine.

The frame routine runs on the DrawOT path, once per frame, alongside the V-blank
interrupt.  It parks a value in k0:

    801FF700  andi k0, s0, 15
    801FF704  srl  s0, s0, 4
    801FF708  beq  k0, zero, 0x801FF7D4

k0 and k1 belong to the exception handler.  The PS1 BIOS clobbers them on every
interrupt, so any value held across two instructions there can vanish -- and here
the branch that reads it decides which path the routine takes.  The window is two
instructions wide, which is exactly why this would show up as an intermittent
fault rather than a clean one.

v0 is untouched between those instructions, so the swap is mechanical: two
instructions, same encoding, different register field.  Nothing else moves.

This is not a claim about the v218 boot failure.  Codex traced that to a false
cache marker and unhandled FFFF owners, and this build does not address either.
It removes a separate hazard that has been in the selector path since v214.
"""
from __future__ import annotations

import glob
import hashlib
import struct
import sys
import zipfile
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = Path(sorted(glob.glob(str(ROOT / "03_output/arc1_v218_*.zip")))[-1])
OUT = ROOT / "03_output/arc1_v218k_CLAUDE_no_kernel_regs_TEST_ONLY.zip"

R2F, DST, SRC = 0x8011A800, 0x801FE3C4, 0x801A86EC
K0, V0 = 26, 2
PATCH = ((0x801FF700, 0x321A000F, 0x3202000F),   # andi k0,s0,15 -> andi v0,s0,15
         (0x801FF708, 0x13400032, 0x10400032))   # beq  k0,zero  -> beq  v0,zero


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system",
                 "create_version", "extract_version", "flag_bits", "volume",
                 "internal_attr", "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def at(ram: int) -> int:
    return (SRC + (ram - DST)) - R2F


def main() -> None:
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}
    exe = bytearray(members["PSX.EXE"])

    for ram, was, now in PATCH:
        here = struct.unpack_from("<I", exe, at(ram))[0]
        if here != was:
            raise SystemExit(f"0x{ram:08X} 가 {was:08X} 가 아니다: {here:08X}")
        struct.pack_into("<I", exe, at(ram), now)

    # v0 must stay untouched across the window, or the swap changes behaviour
    for ram in range(PATCH[0][0], PATCH[1][0], 4):
        word = struct.unpack_from("<I", exe, at(ram))[0]
        if ram in (p[0] for p in PATCH):
            continue
        op, rs, rt, rd = word >> 26, (word >> 21) & 31, (word >> 16) & 31, (word >> 11) & 31
        regs = {rs, rt, rd} if op == 0 else ({rt} if op == 0x0F else {rs, rt})
        if V0 in regs:
            raise SystemExit(f"0x{ram:08X} 가 v0 를 건드린다. 교체하면 안 된다")

    # and no k0/k1 may remain in the frame routine
    left = []
    for i in range(584 // 4):
        ram = 0x801FF668 + i * 4
        word = struct.unpack_from("<I", exe, at(ram))[0]
        op, rs, rt, rd = word >> 26, (word >> 21) & 31, (word >> 16) & 31, (word >> 11) & 31
        regs = {rs, rt, rd} if op == 0 else ({rt} if op == 0x0F else {rs, rt})
        if regs & {26, 27}:
            left.append(ram)
    if left:
        raise SystemExit(f"frame 에 k0/k1 이 {len(left)}곳 남았다: {[hex(x) for x in left]}")

    changed = sum(1 for a, b in zip(exe, members["PSX.EXE"]) if a != b)
    if changed != 2 or len(exe) != len(members["PSX.EXE"]):
        raise SystemExit(f"{changed}바이트가 변했다. 2여야 한다")
    members["PSX.EXE"] = bytes(exe)

    with ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])

    print("v218k  frame routine 에서 커널 예약 레지스터 제거")
    print(f"  base    {BASE.name}")
    for ram, was, now in PATCH:
        print(f"    0x{ram:08X}  {was:08X} -> {now:08X}   k0 -> v0")
    print(f"\n  frame routine 에 남은 k0/k1  0곳")
    print(f"  바뀐 바이트  {changed}개")
    print(f"  output  {OUT.name}")
    print(f"  sha256  {hashlib.sha256(OUT.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
