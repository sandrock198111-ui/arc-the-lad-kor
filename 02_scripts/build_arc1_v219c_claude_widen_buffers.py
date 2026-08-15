"""Widen the gap between the two scratch buffers in the frame routine.

Codex traced the v219b corruption to the decompressed glyph and the 12x12 upload
sharing one scratch area: writing the first row overwrites rows not yet read.

The stack offsets say the overlap is real but older than v219b:

    v218    s3 = sp+72   a1 = sp+128    gap 56B   ← a 72-byte glyph overruns it
    v219b   s3 = sp+0    a1 = sp+72     gap 72B   ← exactly touching

A 12x12 4bpp glyph is 72 bytes, so v218 overran by 16 and v219b lands flush
against the next buffer -- one byte of slack anywhere and it corrupts.  Neither
build leaves room.

This moves a1 from sp+72 to sp+96, giving 96 bytes to a 72-byte glyph and 24
bytes of margin.  The frame is 624 bytes and the upload buffer needs 504
(21 halfwords x 12 rows x 2), so sp+96+504 = 600 still fits with room to spare.

Two instructions.  If the corruption is the overlap, this alone
clears it; if it is not, the result rules the overlap out cleanly.
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

BASE = Path(sorted(glob.glob(str(ROOT / "03_output/arc1_v219b_*.zip")))[-1])
OUT = ROOT / "03_output/arc1_v219c_CLAUDE_widen_buffers_TEST_ONLY.zip"

R2F, DST, SRC = 0x8011A800, 0x801FE3C4, 0x801A86EC
FRAME, GLYPH, UPLOAD = 624, 72, 504
OLD_A1, NEW_A1 = 72, 96
SITES = (0x801FF6D4, 0x801FF880)


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

    want = (0x09 << 26) | (29 << 21) | (5 << 16) | OLD_A1        # addiu a1, sp, 72
    fresh = (0x09 << 26) | (29 << 21) | (5 << 16) | NEW_A1       # addiu a1, sp, 96
    for ram in SITES:
        here = struct.unpack_from("<I", exe, at(ram))[0]
        if here != want:
            raise SystemExit(f"0x{ram:08X} 가 addiu a1,sp,{OLD_A1} 가 아니다: {here:08X}")
        struct.pack_into("<I", exe, at(ram), fresh)

    # the frame must still hold both buffers
    if NEW_A1 + UPLOAD > FRAME:
        raise SystemExit(f"sp+{NEW_A1}+{UPLOAD} 가 프레임 {FRAME}B 를 넘는다")
    if NEW_A1 < GLYPH:
        raise SystemExit(f"간격 {NEW_A1}B 가 글리프 {GLYPH}B 보다 작다")

    # nothing else may move, and the frame size itself stays put
    head = struct.unpack_from("<I", exe, at(0x801FF668))[0]
    if head != (0x09 << 26) | (29 << 21) | (29 << 16) | ((-FRAME) & 0xFFFF):
        raise SystemExit("프레임 크기 명령이 예상과 다르다")
    changed = sum(1 for a, b in zip(exe, members["PSX.EXE"]) if a != b)
    expect = sum(1 for a, b in zip(struct.pack("<I", want), struct.pack("<I", fresh)) if a != b) * len(SITES)
    if changed != expect or len(exe) != len(members["PSX.EXE"]):
        raise SystemExit(f"{changed}바이트가 변했다. {expect} 여야 한다")
    members["PSX.EXE"] = bytes(exe)

    with ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])

    print("v219c  CLAUDE  두 임시 버퍼 간격을 벌림")
    print(f"  base    {BASE.name}")
    print(f"    s3 = sp+0   글리프 {GLYPH}B")
    for ram in SITES:
        print(f"    0x{ram:08X}  addiu a1, sp, {OLD_A1}  ->  addiu a1, sp, {NEW_A1}")
    print(f"\n    간격 {OLD_A1}B -> {NEW_A1}B   글리프 {GLYPH}B 에 여유 {NEW_A1-GLYPH}B")
    print(f"    올림 버퍼 sp+{NEW_A1}~{NEW_A1+UPLOAD}  <=  프레임 {FRAME}B")
    print(f"  바뀐 바이트  {changed}개,  프레임 크기 그대로")
    print(f"  output  {OUT.name}")
    print(f"  sha256  {hashlib.sha256(OUT.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
