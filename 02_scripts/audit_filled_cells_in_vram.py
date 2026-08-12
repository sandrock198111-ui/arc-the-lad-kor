"""Which cells this project filled are still our pixels in VRAM during the battle.

COMM.IMG is uploaded whole to 16-bit VRAM x 320..767, y 0..511, and the game then
writes its own graphics over most of that area -- 502 of 512 rows differ from the
file in a battle save state.  Wherever our pixels survive, they are in VRAM while the
battle draws, and a sprite whose quad covers them will show them.

So the dangerous set is not "cells the original left blank".  It is the intersection:
cells we changed, that the game does not overwrite, and that lie outside the glyph
columns the renderer actually reads from.

    python 02_scripts/audit_filled_cells_in_vram.py <state.vram.bin>
"""
from __future__ import annotations

import sys
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

CELL = 12
IMG_W, IMG_H = 1792, 512
IMG_ROW = IMG_W // 2
VRAM_ROW = 1024 * 2
COMM_VRAM_X_BYTES = 320 * 2
COLS, ROWS = IMG_W // CELL, IMG_H // CELL


def cell_bytes(buf: bytes, row: int, col: int, stride: int) -> bytes:
    out = bytearray()
    for dy in range(CELL):
        at = (row * CELL + dy) * stride + (col * CELL) // 2
        out += buf[at:at + CELL // 2]
    return bytes(out)


def vram_cell_bytes(vram: bytes, row: int, col: int) -> bytes:
    """Read one COMM.IMG cell at its real x=320 placement in raw VRAM."""
    out = bytearray()
    for dy in range(CELL):
        at = ((row * CELL + dy) * VRAM_ROW + COMM_VRAM_X_BYTES
              + (col * CELL) // 2)
        out += vram[at:at + CELL // 2]
    return bytes(out)


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    vram = Path(sys.argv[1]).read_bytes()
    if len(vram) != 1024 * 512 * 2:
        raise SystemExit("input must be an exact marker-based 1024x512x16-bit VRAM dump")
    with zipfile.ZipFile(ROOT / "00_original/arc.zip") as z:
        original = z.read("COMM.IMG")
    staged = ROOT / "01_work/package_test/files/COMM.IMG"
    if staged.exists():
        ours = staged.read_bytes()
    else:
        with zipfile.ZipFile(ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip") as z:
            ours = z.read("COMM.IMG")

    changed, live, blank_before = [], [], []
    for row in range(ROWS):
        for col in range(COLS):
            mine = cell_bytes(ours, row, col, IMG_ROW)
            orig = cell_bytes(original, row, col, IMG_ROW)
            if mine == orig:
                continue
            changed.append((row, col))
            if not any(orig):
                blank_before.append((row, col))
            if vram_cell_bytes(vram, row, col) == mine:
                live.append((row, col))

    print(f"원본과 다른 칸 {len(changed)}개  (그중 원본이 완전히 비어 있던 칸 {len(blank_before)}개)")
    print(f"이 세이브스테이트의 VRAM에 우리 픽셀 그대로 살아 있는 칸 {len(live)}개")
    print()
    by_col = Counter(col for _, col in live)
    print("살아 있는 칸의 열 분포")
    for col in sorted(by_col):
        print(f"   열 {col:3}  {by_col[col]}칸")
    print()

    live_set = set(live)
    runs = []
    for row in range(ROWS):
        run = []
        for col in range(COLS):
            if (row, col) in live_set:
                run.append(col)
            elif run:
                runs.append((row, run[0], run[-1]))
                run = []
        if run:
            runs.append((row, run[0], run[-1]))
    wide = [r for r in runs if r[2] - r[1] + 1 >= 3]
    print(f"가로로 3칸 이상 이어진 곳 {len(wide)}개  (화면의 블록은 36픽셀 = 3칸이다)")
    for row, a, b in wide[:40]:
        print(f"   행 {row:2} 열 {a}~{b}   x {a*CELL}~{b*CELL+CELL-1}  y {row*CELL}~{row*CELL+CELL-1}")


if __name__ == "__main__":
    main()
