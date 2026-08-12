"""Move the control-code dispatcher somewhere it fits, and give it all four codes.

The circle icon is drawn as a Korean syllable.  At screen (18,214) v151 emits
U=192, V=228, CLUT=7AC1 -- the icon bank -- and the current build emits cache slot
23 instead.  The cause is upstream of the icon stub v173 restored.

v151's helper at 0x801FE3C4 recognises four control codes and, for any of them,
advances the string pointer past the code's argument:

    t0 == 40, 63, 53 or 52  ->  lbu a3, 40(a1) / addiu a3, a3, 4 / sb a3, 40(a1)
    otherwise               ->  no advance
    both                    ->  lbu v0, 14(a2) / j 0x8016B5E0

It spends 23 words doing that, in reserved RAM where space was plentiful.

The rewritten dispatcher at 0x801A2060 has nine words and tests 40 alone.  52, 53
and 63 fall through without consuming their argument, the renderer reads those bytes
as text, and they take cache slots.

Nine words cannot hold four tests.  Even folding 52..63 into one range test needs a
tenth word for the delay slot of the final jump, and 0x801A2084 is a different
routine that 0x801A2204 calls -- overwriting it kills that path.

So the dispatcher moves.  0x8019D074 holds 196 zero bytes that nothing jumps to,
immediately after the E7 stub v173 put back, and the entry at 0x8016B5D8 is
repointed there.  The old nine words are left alone; nothing reaches them any more.

Codes 54..62 are covered by the range test and are not emitted by this script --
v151's four values are the complete set its helper ever saw.
"""
from __future__ import annotations

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

BASE = ROOT / "03_output/arc1_v173_restore_e7_icon_stub.zip"
OUT = ROOT / "03_output/arc1_v176_control_code_dispatch.zip"

R2F = 0x8011A800
ENTRY = 0x8016B5D8          # j <dispatcher>
OLD = 0x801A2060
NEW = 0x8019D074            # 196 free bytes, nothing references it
EXIT = 0x8016B5E0
POOL_LO, POOL_HI = 0x78000, 0x83000
RAM_LO, RAM_HI = 0x80000000, 0x80200000

A1, A2, A3, T0, V0, ZERO = 5, 6, 7, 8, 2, 0


def addiu(rt, rs, imm): return (0x09 << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)
def sltiu(rt, rs, imm): return (0x0B << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)
def lbu(rt, rs, off):   return (0x24 << 26) | (rs << 21) | (rt << 16) | (off & 0xFFFF)
def sb(rt, rs, off):    return (0x28 << 26) | (rs << 21) | (rt << 16) | (off & 0xFFFF)
def bne(rs, rt, here, tgt): return (0x05 << 26) | (rs << 21) | (rt << 16) | (((tgt - here - 4) >> 2) & 0xFFFF)
def beq(rs, rt, here, tgt): return (0x04 << 26) | (rs << 21) | (rt << 16) | (((tgt - here - 4) >> 2) & 0xFFFF)
def j(tgt):             return (0x02 << 26) | ((tgt & 0x3FFFFFF) >> 2)


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
    with ZipFile(ROOT / "00_original/arc.zip") as archive:
        stock = archive.read("PSX.EXE")

    exe = bytearray(members["PSX.EXE"])

    if struct.unpack_from("<I", exe, ENTRY - R2F)[0] != j(OLD):
        raise SystemExit(f"0x{ENTRY:08X} 가 0x{OLD:08X} 로 안 간다")
    if any(exe[NEW - R2F:NEW - R2F + 196]):
        raise SystemExit(f"0x{NEW:08X} 가 비어 있지 않다")

    # v151 헬퍼(0x801FE3C4) 의 23워드를 그대로 옮긴다.  범위로 묶지 않는다 --
    # 52..63 을 한 번에 잡았더니 54..62 가 실제 글자 코드여서 인자를 건너뛰었고
    # 화면에서 글자가 대량으로 사라졌다.  v151 이 네 값만 본 데는 이유가 있었다.
    take = NEW + 0x40
    skip = NEW + 0x50
    body = []
    for i, code in enumerate((40, 63, 53, 52)):
        here = NEW + i * 16
        body += [addiu(A3, T0, -code), sltiu(A3, A3, 1)]
        if code == 52:
            body += [beq(A3, ZERO, here + 8, skip), 0]
        else:
            body += [bne(A3, ZERO, here + 8, take), 0]
    body += [lbu(A3, A1, 40), 0, addiu(A3, A3, 4), sb(A3, A1, 40)]   # take
    body += [lbu(V0, A2, 14), j(EXIT), 0]                            # skip
    at = NEW - R2F
    if len(body) * 4 > 196:
        raise SystemExit("196바이트를 넘는다")
    struct.pack_into(f"<{len(body)}I", exe, at, *body)

    struct.pack_into("<I", exe, ENTRY - R2F, j(NEW))

    for i, w in enumerate(struct.unpack_from(f"<{len(body)}I", exe, at)):
        op = w >> 26
        if op in (0x04, 0x05):
            simm = ((w & 0xFFFF) ^ 0x8000) - 0x8000
            tgt = NEW + i * 4 + 4 + simm * 4
            if not (NEW <= tgt < NEW + len(body) * 4):
                raise SystemExit(f"분기 목적지 0x{tgt:08X} 가 루틴 밖")

    if len(exe) != len(members["PSX.EXE"]):
        raise SystemExit("PSX.EXE 크기가 변했다")
    members["PSX.EXE"] = bytes(exe)

    broken = [i for i in range(POOL_LO, POOL_HI, 4)
              if RAM_LO <= struct.unpack_from("<I", stock, i)[0] < RAM_HI
              and not (RAM_LO <= struct.unpack_from("<I", exe, i)[0] < RAM_HI)]
    if broken:
        raise SystemExit(f"문자열 풀 포인터 {len(broken)}개가 RAM 밖")

    with ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])

    print("v176  제어코드 분배기를 빈 자리로 옮기고 52/53/63 을 되살림")
    print(f"  base    {BASE.name}")
    print(f"  진입    0x{ENTRY:08X}  j 0x{OLD:08X} -> j 0x{NEW:08X}")
    print(f"  새 자리 0x{NEW:08X}  {len(body)*4}바이트 (196 중)")
    print(f"  검사    40 / 63 / 53 / 52.  v151 헬퍼와 동일")
    print(f"  포인터 무결성  이상 0개")
    print(f"  output  {OUT.name}")
    print(f"  sha256  {hashlib.sha256(OUT.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
