"""Is texture page 15,1 actually free where the resident strips are uploaded?

The rows were chosen from 99 save states that contained no battle.  These two do, and
they come from a build whose strips were blanked, so the strips uploaded zeros --
anything non-zero in those rectangles is the game's own graphics, sitting exactly
where the strips land every frame.

    python 02_scripts/audit_strip_rows_in_battle.py <state.vram.bin> [...]
"""
from __future__ import annotations

import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

W = 1024
STRIP_X, STRIP_HW = 961, 39          # 156 px at 4bpp = 39 halfwords
STRIPS = {"A": 480, "B": 500, "C": 380}
PAGE_X0, PAGE_X1 = 960, 1024


def used(vram: bytes, x0: int, x1: int, y: int) -> int:
    at = (y * W + x0) * 2
    return sum(1 for i in range(0, (x1 - x0) * 2, 2)
               if vram[at + i] or vram[at + i + 1])


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    for arg in sys.argv[1:]:
        vram = Path(arg).read_bytes()
        print(Path(arg).name)
        for name, y0 in sorted(STRIPS.items(), key=lambda kv: kv[1]):
            total = sum(used(vram, STRIP_X, STRIP_X + STRIP_HW, y0 + dy) for dy in range(12))
            print(f"  strip {name}  y {y0}~{y0+11}  x {STRIP_X}~{STRIP_X+STRIP_HW-1}   "
                  f"게임이 쓴 halfword {total}/{STRIP_HW*12}")
        print("  페이지 15,1 전체 점유 (y 256~511, x 960~1023)")
        runs = []
        for y in range(256, 512):
            n = used(vram, PAGE_X0, PAGE_X1, y)
            runs.append((y, n))
        busy = [y for y, n in runs if n]
        if busy:
            start, prev = busy[0], busy[0]
            out = []
            for y in busy[1:]:
                if y != prev + 1:
                    out.append((start, prev))
                    start = y
                prev = y
            out.append((start, prev))
            print("    쓰이는 줄: " + ", ".join(f"y {a}~{b}" for a, b in out))
        else:
            print("    비어 있음")
        free = [y for y, n in runs if n == 0]
        print(f"    빈 줄 {len(free)}/256")
        print()


if __name__ == "__main__":
    main()
