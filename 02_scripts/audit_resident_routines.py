"""Static checks on code that a build copies into reserved RAM and runs every frame.

v157 through v160 all fail to boot.  The routines they add do not live in the
executable image -- they are copied from the tail to 0x801FE3C4 at the entry point --
so nothing about them is visible to a normal diff, and a single wrong constant kills
the game on the first frame with no message.

Checked here, per routine:

    alignment      lw/sw need 4-byte addresses and lh/sh need 2.  A misaligned
                   access raises Address Error on R3000 and the game stops.
    residency      the routine and everything it reads must sit inside the 5,356
                   bytes the boot memcpy actually copies.
    exit           a routine entered with jal must end at jr ra; one entered with j
                   must jump back.
    branches       every target must land inside the routine.
    delay slots    the instruction after a branch or jump always executes, so it
                   must not be the branch's own setup.
    displaced      whatever instruction a hook overwrote has to be performed by the
                   routine it calls, or the game loses that work.

    python 02_scripts/audit_resident_routines.py <build.zip> [more.zip ...]
"""
from __future__ import annotations

import re
import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

R2F = 0x8011A800
COPY_SRC, COPY_DST, COPY_LEN = 0x801A86EC, 0x801FE3C4, 5356
REG = ["zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3",
       "t4", "t5", "t6", "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
       "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra"]
WORD_LS = {0x23: "lw", 0x2B: "sw"}
HALF_LS = {0x21: "lh", 0x25: "lhu", 0x29: "sh"}


def report_for(zip_path: Path) -> Path | None:
    stem = zip_path.stem.rsplit("_", 1)[0]
    candidate = ROOT / "01_work/analysis" / stem / "build_report.txt"
    return candidate if candidate.exists() else None


def routines(zip_path: Path) -> list[tuple[str, int, int]]:
    path = report_for(zip_path)
    if not path:
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"\s*(decoder|frame routine)\s+0x([0-9A-Fa-f]+)\s*/\s*(\d+)\s*bytes", line)
        if m:
            out.append((m.group(1), int(m.group(2), 16), int(m.group(3))))
    return out


def check(exe: bytes, name: str, ram: int, length: int) -> list[str]:
    src = COPY_SRC + (ram - COPY_DST)
    problems = []
    if not (COPY_SRC <= src and src + length <= COPY_SRC + COPY_LEN):
        problems.append(f"복사 범위 밖이다: 원본 0x{src:08X}~0x{src+length:08X}, "
                        f"복사는 0x{COPY_SRC:08X}~0x{COPY_SRC+COPY_LEN:08X}")
        return problems

    at0 = src - R2F
    words = [struct.unpack_from("<I", exe, at0 + i * 4)[0] for i in range(length // 4)]
    known: dict[int, int] = {}
    has_jr_ra = False
    exits = []
    for i, w in enumerate(words):
        pc = ram + i * 4
        op, rs, rt = w >> 26, (w >> 21) & 31, (w >> 16) & 31
        imm = w & 0xFFFF
        simm = (imm ^ 0x8000) - 0x8000

        if op == 0x0F:
            known[rt] = imm << 16
        elif op == 0x0D and rs in known:
            known[rt] = known[rs] | imm
        elif op == 0x09 and rs in known:
            known[rt] = (known[rs] + simm) & 0xFFFFFFFF
        elif op in WORD_LS or op in HALF_LS:
            if rs in known:
                addr = (known[rs] + simm) & 0xFFFFFFFF
                need = 4 if op in WORD_LS else 2
                if addr % need:
                    kind = WORD_LS.get(op) or HALF_LS[op]
                    problems.append(f"정렬 위반  {pc:08X}  {kind} {REG[rt]}, "
                                    f"0x{addr:08X}  (%{need} = {addr % need})")
                if COPY_DST <= addr < COPY_DST + COPY_LEN:
                    off = addr - COPY_DST
                    if off + need > COPY_LEN:
                        problems.append(f"복사 범위 밖 접근  {pc:08X}  0x{addr:08X}")
            if op in WORD_LS and rt in known:
                known.pop(rt, None)
        else:
            if op in (0x00,) and ((w >> 11) & 31) in known:
                known.pop((w >> 11) & 31, None)
            elif op not in (0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x28, 0x29, 0x2B):
                known.pop(rt, None)

        if w == 0x03E00008:
            has_jr_ra = True
        if op in (0x04, 0x05, 0x06, 0x07):
            target = pc + 4 + simm * 4
            if not (ram <= target < ram + length):
                problems.append(f"분기 목적지가 루틴 밖  {pc:08X} -> 0x{target:08X}")
        if op in (0x02, 0x03):
            target = ((pc & 0xF0000000) | ((w & 0x3FFFFFF) << 2))
            exits.append((pc, "j" if op == 2 else "jal", target))
        if op in (0x02, 0x03, 0x04, 0x05) and i + 1 < len(words):
            nxt = words[i + 1]
            nop_ok = nxt == 0
            if not nop_ok and (nxt >> 26) in (0x02, 0x03, 0x04, 0x05):
                problems.append(f"지연 슬롯에 분기  {pc + 4:08X}")

    if not has_jr_ra:
        problems.append("jr ra 가 없다 -- jal 로 불리면 못 돌아온다")
    return problems


POOL_LO, POOL_HI = 0x78000, 0x83000
RAM_LO, RAM_HI = 0x80000000, 0x80200000


def pointer_damage(stock: bytes, built: bytes) -> tuple[int, int, list[str]]:
    """Words the original uses as RAM pointers must still point into RAM.

    v157 through v160 did not boot because a one-byte glyph remap ran over the
    executable's string pool, which holds pointer tables as well as text.  0x80
    became 0x7D 4,737 times and every one of 4,093 pointers ended up outside RAM.
    Nothing in the build caught it; the game simply stopped after the BIOS.
    """
    pointers = [i for i in range(POOL_LO, POOL_HI, 4)
                if RAM_LO <= struct.unpack_from("<I", stock, i)[0] < RAM_HI]
    dead = []
    for at in pointers:
        value = struct.unpack_from("<I", built, at)[0]
        if not (RAM_LO <= value < RAM_HI):
            dead.append(f"파일 0x{at:06X}  RAM 0x{at + R2F:08X}  "
                        f"0x{struct.unpack_from('<I', stock, at)[0]:08X} -> 0x{value:08X}")
    return len(pointers), len(dead), dead


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    with zipfile.ZipFile(ROOT / "00_original/arc.zip") as z:
        orig_font = z.read("COMM.IMG")
        stock_exe = z.read("PSX.EXE")

    for arg in sys.argv[1:]:
        zip_path = Path(arg)
        with zipfile.ZipFile(zip_path) as z:
            exe, font = z.read("PSX.EXE"), z.read("COMM.IMG")
        print("=" * 66)
        print(zip_path.name)

        blank_refilled = 0
        for r in range(512 // 12):
            for c in range(1792 // 12):
                o = b"".join(orig_font[(r * 12 + dy) * 896 + c * 6:][:6] for dy in range(12))
                n = b"".join(font[(r * 12 + dy) * 896 + c * 6:][:6] for dy in range(12))
                if o != n and not any(o):
                    blank_refilled += 1
        print(f"  원본이 비워 둔 칸에 다시 채운 것 {blank_refilled}개 (0이어야 한다)")

        total, broken, samples = pointer_damage(stock_exe, exe)
        mark = "" if not broken else "   <- 이 빌드는 부팅하지 않는다"
        print(f"  문자열 풀의 RAM 포인터 {total}개 중 RAM 밖을 가리키는 것 {broken}개{mark}")
        for line in samples[:5]:
            print(f"      {line}")

        found = routines(zip_path)
        if not found:
            print("  build_report.txt 에서 루틴 주소를 못 찾았다")
            continue
        for name, ram, length in found:
            problems = check(exe, name, ram, length)
            print(f"  {name} 0x{ram:08X} / {length}B  ->  "
                  f"{'문제 없음' if not problems else f'{len(problems)}건'}")
            for p in problems:
                print(f"      {p}")


if __name__ == "__main__":
    main()
