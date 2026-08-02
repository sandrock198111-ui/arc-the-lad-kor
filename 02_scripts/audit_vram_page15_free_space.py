"""Where is there room for more glyph strips inside texture page 15,1?

The renderer emits one DR_TPAGE per text object but writes U and V per glyph, so a
strip anywhere inside the page the objects already select is nearly free -- the
helper and the classifier each learn one more row, and the frame routine one more
LoadImage.  A strip outside that page is not: every glyph on it would need its own
tpage primitive.  So the question worth measuring is narrow: which rectangles inside
page 15,1 does the game leave alone?

Page 15,1 is halfword x 960..1023, y 256..511.  A glyph column is 12 pixels at 4bpp,
which is 3 halfwords, and a strip is 12 rows tall.  V comes from the glyph row as
(12 * row) & 0xFF and the page's y offset is 256, so a strip's y must be 256 plus a
multiple of 4 -- that is the granularity used here.

"Free" means every captured state has zeroes there.  That is evidence, not proof:
a scene nobody saved could still draw into it.  The count of states is reported so
the strength of the claim stays visible.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from extract_savestate_vram import VRAM_W, load  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "01_work/analysis/vram_page15_free_space.txt"

PAGE_X0, PAGE_X1 = 960, 1024          # halfwords
PAGE_Y0, PAGE_Y1 = 256, 512
CELL_ROWS, HW_PER_COL = 12, 3         # a 12x12 glyph cell at 4bpp
STEP = 4                              # V granularity: (12*row)&0xFF is a multiple of 4

STRIPS = {"A": (961, 480), "B": (961, 500)}


def used_map(vrams: list[bytes]) -> list[list[bool]]:
    """used[y - PAGE_Y0][x - PAGE_X0] -- true if any state has a non-zero halfword."""
    used = [[False] * (PAGE_X1 - PAGE_X0) for _ in range(PAGE_Y1 - PAGE_Y0)]
    for vram in vrams:
        for y in range(PAGE_Y0, PAGE_Y1):
            row = vram[(y * VRAM_W + PAGE_X0) * 2:(y * VRAM_W + PAGE_X1) * 2]
            for i in range(PAGE_X1 - PAGE_X0):
                if row[i * 2] or row[i * 2 + 1]:
                    used[y - PAGE_Y0][i] = True
    return used


def blank_strips(used: list[list[bool]]) -> None:
    """The strips are ours, not the game's; do not count them as occupied."""
    for x, y in STRIPS.values():
        for dy in range(CELL_ROWS):
            for dx in range(13 * HW_PER_COL):
                used[y + dy - PAGE_Y0][x + dx - PAGE_X0] = False


def free_runs(used: list[list[bool]], y: int) -> list[tuple[int, int]]:
    """Maximal runs of halfword columns free across all 12 rows of a band at y."""
    band = [not any(used[y + dy - PAGE_Y0][i] for dy in range(CELL_ROWS))
            for i in range(PAGE_X1 - PAGE_X0)]
    runs, start = [], None
    for i, ok in enumerate(band + [False]):
        if ok and start is None:
            start = i
        elif not ok and start is not None:
            runs.append((PAGE_X0 + start, i - start))
            start = None
    return runs


def main() -> None:
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else \
        Path.home() / "AppData/Local/DuckStation/savestates"
    files = sorted(src.glob("HASH-340476B50F5F94CD_*.sav")) if src.is_dir() else [src]
    if not files:
        raise SystemExit("no save states found")
    vrams = [load(f)[1] for f in files]

    used = used_map(vrams)
    occupied_before = sum(r.count(True) for r in used)
    blank_strips(used)

    lines = [
        "free space inside texture page 15,1 (halfword x 960..1023, y 256..511)",
        "",
        f"states surveyed: {len(files)}",
        *(f"  {f.name}" for f in files),
        "",
        "A halfword counts as used if ANY state has it non-zero. The two resident strips",
        "are excluded -- they are ours. Everything else here is the game's.",
        "",
        f"halfwords in the page   {(PAGE_X1 - PAGE_X0) * (PAGE_Y1 - PAGE_Y0)}",
        f"used by the game        {sum(r.count(True) for r in used)}",
        f"  (with our strips)     {occupied_before}",
        "",
        "candidate strip positions -- a band 12 rows tall, y = 256 + a multiple of 4,",
        "listing runs of free halfwords at least one glyph column (3 halfwords) wide:",
        "",
    ]

    best: list[tuple[int, int, int]] = []
    for y in range(PAGE_Y0, PAGE_Y1 - CELL_ROWS + 1, STEP):
        runs = [(x, n) for x, n in free_runs(used, y) if n >= HW_PER_COL]
        if not runs:
            continue
        parts = "  ".join(f"x {x}..{x + n - 1} ({n // HW_PER_COL} col"
                          f"{'s' if n // HW_PER_COL != 1 else ''})" for x, n in runs)
        lines.append(f"  y {y:>3}  V={y - PAGE_Y0:>3}   {parts}")
        for x, n in runs:
            best.append((n // HW_PER_COL, x, y))

    lines += ["", "widest single positions, most columns first:"]
    seen: set[tuple[int, int]] = set()
    for cols, x, y in sorted(best, reverse=True)[:12]:
        if (x, y) in seen:
            continue
        seen.add((x, y))
        lines.append(f"  {cols:>2} columns = {cols * 4:>3} glyphs   x {x}  y {y}  "
                     f"V={y - PAGE_Y0}")

    lines += [
        "",
        "Overlapping bands are listed separately; picking one at y removes the bands",
        "from y-8 to y+8 as options. Choose non-overlapping y values.",
        "",
        "Caveat worth keeping: this is what these states show, not what the game can do.",
        "A rectangle free here can still be drawn into by a scene nobody captured.",
    ]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\n-> {OUT}")


if __name__ == "__main__":
    main()
