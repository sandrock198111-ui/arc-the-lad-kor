"""Find every place the patch wrote over artwork the original game already had.

The battle range overlay broke because the Hangul font replacement filled glyph cells
that were not empty: the original COMM.IMG held a UI tile there. Any other cell with
the same property is another instance of the same fault, waiting for whatever draws it
to appear on screen.

The test is exact and needs no emulator. A byte the patch changed is safe only if the
original byte was zero -- that is empty space the patch is entitled to use. A byte the
patch changed that was non-zero in the original is destroyed game artwork.

Results are grouped into 12x12 glyph cells, since that is the unit the font uses, and
each cell is reported with the VRAM coordinates the game would sample it at.

    python 02_scripts/audit_overwritten_game_art.py [patch.zip]
"""
from __future__ import annotations

import struct
import sys
import zipfile
from pathlib import Path

ORIG_ISO = Path(r"E:\arc\원본\arc1.bin")
OUT = Path(__file__).resolve().parents[1] / "03_output"
DEFAULT = "ui_hud_e7_v109_restore_range_overlay_patch_only.zip"
RAW, COMM_LBA, COMM_SIZE = 2352, 667, 458752
STRIP_ROW, X0 = 896, 320                # COMM.IMG uploads at 16-bit x 320
CELL, COLS, PLANES = 12, 21, 4
IPR = COLS * PLANES
LOOKUP, LOOKUP_N, RAM_TO_FILE = 0x801A7520, 409, 0x8011A800
P6_X4 = 2856                            # where the expanded strip lives


def read_original() -> bytes:
    with ORIG_ISO.open("rb") as raw:
        def sector(l):
            raw.seek(l * RAW)
            s = raw.read(RAW)
            return s[24:24 + 2048] if s[15] == 2 else s[16:16 + 2048]
        return b"".join(sector(COMM_LBA + i) for i in range(COMM_SIZE // 2048))


def main() -> None:
    name = sys.argv[1] if len(sys.argv) > 1 else DEFAULT
    path = Path(name)
    if not path.exists():
        path = OUT / name
    if not path.exists():
        raise SystemExit(f"no such archive: {name}")
    with zipfile.ZipFile(path) as z:
        new, exe = z.read("COMM.IMG"), z.read("PSX.EXE")
    orig = read_original()
    if len(orig) != len(new):
        raise SystemExit("COMM.IMG sizes differ")
    print(f"comparing {path.name} against the original disc\n")

    changed = [i for i in range(len(orig)) if orig[i] != new[i]]
    destroyed = [i for i in changed if orig[i] != 0]
    print(f"bytes the patch changed        : {len(changed)}")
    print(f"  of those, originally zero    : {len(changed) - len(destroyed)}  "
          f"(empty space, safe to use)")
    print(f"  of those, originally non-zero: {len(destroyed)}  "
          f"(artwork the patch destroyed)")

    if not destroyed:
        print("\nnothing the game had drawn has been overwritten.")
        return

    # group by 12x12 cell, and note whether a glyph is actually placed there
    lut = struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP - RAM_TO_FILE)
    used_cells = {(v // IPR, (v % IPR) // PLANES) for v in lut}
    cells = {}
    for i in destroyed:
        y, bx = divmod(i, STRIP_ROW)
        x4 = X0 * 4 + bx * 2
        if x4 >= P6_X4:                 # the expanded strip, blank in the original
            row, col = y // CELL, (x4 - P6_X4) // CELL
        else:
            row, col = y // CELL, (x4 - X0 * 4) // CELL
        cells.setdefault((row, col, x4 >= P6_X4), []).append(i)

    print(f"\ncells affected: {len(cells)}")
    print(f"{'row':>4} {'col':>4} {'bytes':>6}  {'VRAM 16-bit':>18}  "
          f"{'texture page':>13}  glyph placed?")
    risky = 0
    for (row, col, is_p6), items in sorted(cells.items()):
        x0 = (P6_X4 if is_p6 else X0 * 4) + col * CELL
        vx, vy = x0 // 4, row * CELL
        placed = (row, col) in used_cells
        if not placed:
            risky += 1
        print(f"{row:>4} {col:>4} {len(items):>6}  "
              f"x {vx:>4}..{vx + 2}, y {vy:>3}..{vy + 11}  "
              f"page {vx // 64:>2},{vy // 256}      "
              f"{'yes' if placed else 'NO  <-- pure loss'}")

    print(f"\n{risky} of those cells have no glyph on them at all: the artwork was")
    print("overwritten for nothing and can be restored with no other change.")
    print("The cells that do carry a glyph need that glyph moved first, the way")
    print("v109 moved the two on the range overlay.")


if __name__ == "__main__":
    main()
