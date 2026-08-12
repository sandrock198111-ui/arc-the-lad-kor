"""Put the E7 icon stub back where v171 wrote a string over it.

The button icons stopped appearing and the game froze when they should have been
drawn.  The pictures were not the problem: rows 19 columns 15..19 are byte-identical
to v151 in v172, and so are the E7 V hook at 0x8016B6C8, the dispatcher at
0x8019C934 and the icon U table.

What is gone is the landing point.  0x8016B6C8 jumps to 0x8019C934, which jumps to
0x8019D000, and in v172 that address holds string bytes.  The CPU executes them.
v170 still has the real stub there:

    8019D000  addiu t0, v1, -2      icon id 2 ?
    8019D004  beq   t0, zero, +0x38
    8019D00C  addiu t0, v1, -4      id 4 ?
    8019D018  addiu t0, v1, -8      id 8 ?
    8019D024  addiu t0, v1, -14     id 14 ?
    8019D02C  ori   v0, zero, 130   not an icon: V = 130
    8019D038  ori   v0, zero, 228   icon: V = 228, the row-19 bank
    8019D03C  sb    v0, 41(s0)
    8019D040  j     0x8016B6D0      back to the caller

v171 repacked the executable string pool and treated that range as free space.

Only those 72 bytes are restored, from v170, which is the last build where the stub
was intact.  Nothing else is touched -- not the strings v171 placed elsewhere, not
COMM.IMG, not the cache, not the .DAT files.  If the freeze and the missing icons
share this cause, both go away; if they do not, the change is small enough to read.
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

BASE = Path(sorted(glob.glob(str(ROOT / "03_output/*v172*.zip")))[-1])
DONOR = ROOT / "03_output/arc1_v170_restore_blank_space_filler_F8A67A67.zip"
OUT = ROOT / "03_output/arc1_v173_restore_e7_icon_stub.zip"

R2F = 0x8011A800
STUB, STUB_LEN = 0x8019D000, 72
E7_HOOK, DISPATCH = 0x8016B6C8, 0x8019C934
POOL_LO, POOL_HI = 0x78000, 0x83000
RAM_LO, RAM_HI = 0x80000000, 0x80200000


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system",
                 "create_version", "extract_version", "flag_bits", "volume",
                 "internal_attr", "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def main() -> None:
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}
    with ZipFile(DONOR) as archive:
        donor = archive.read("PSX.EXE")
    with ZipFile(ROOT / "00_original/arc.zip") as archive:
        stock = archive.read("PSX.EXE")

    exe = bytearray(members["PSX.EXE"])
    at = STUB - R2F

    # The donor must actually hold the stub, and the target must be the string
    # bytes we are replacing -- otherwise the address moved and this is wrong.
    if struct.unpack_from("<I", donor, at)[0] != 0x2468FFFE:      # addiu t0, v1, -2
        raise SystemExit("v170에 E7 스텁이 없다. 주소가 바뀌었다")
    if struct.unpack_from("<I", donor, at + 0x38)[0] != 0x340200E4:  # ori v0, zero, 228
        raise SystemExit("v170 스텁의 V=228 명령이 기대 위치에 없다")
    if struct.unpack_from("<I", exe, at)[0] == 0x2468FFFE:
        raise SystemExit("v172에 이미 스텁이 있다. 되돌릴 것이 없다")

    was = bytes(exe[at:at + STUB_LEN])
    exe[at:at + STUB_LEN] = donor[at:at + STUB_LEN]

    # the two jumps that reach it must still be intact
    for name, addr, expect in (("E7 V 훅", E7_HOOK, DISPATCH),
                               ("분배기", DISPATCH, STUB)):
        w = struct.unpack_from("<I", exe, addr - R2F)[0]
        target = (addr & 0xF0000000) | ((w & 0x3FFFFFF) << 2)
        if (w >> 26) != 2 or target != expect:
            raise SystemExit(f"{name} 0x{addr:08X} 가 0x{expect:08X} 로 안 간다")

    if len(exe) != len(members["PSX.EXE"]):
        raise SystemExit("PSX.EXE 크기가 변했다")
    members["PSX.EXE"] = bytes(exe)

    broken = [i for i in range(POOL_LO, POOL_HI, 4)
              if RAM_LO <= struct.unpack_from("<I", stock, i)[0] < RAM_HI
              and not (RAM_LO <= struct.unpack_from("<I", exe, i)[0] < RAM_HI)]
    if broken:
        raise SystemExit(f"문자열 풀 포인터 {len(broken)}개가 RAM 밖을 가리킨다")

    with ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])

    print("v173  E7 아이콘 스텁 복구")
    print(f"  base    {BASE.name}")
    print(f"  donor   {DONOR.name}")
    print(f"  복구    0x{STUB:08X} ~ 0x{STUB+STUB_LEN:08X}  {STUB_LEN}바이트")
    print(f"    v172  {was[:16].hex(' ')} ...")
    print(f"    v173  {bytes(exe[at:at+16]).hex(' ')} ...")
    print(f"  경로    0x{E7_HOOK:08X} -> 0x{DISPATCH:08X} -> 0x{STUB:08X}  확인됨")
    print(f"  바뀐 멤버  PSX.EXE 하나, {STUB_LEN}바이트")
    print(f"  포인터 무결성  이상 0개")
    print(f"  output  {OUT.name}")
    print(f"  sha256  {hashlib.sha256(OUT.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
