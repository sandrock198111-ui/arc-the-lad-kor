"""v160: keep the 20-slot completed-glyph cache in a persistent RAM shadow.

v158/v159 copied each 12x12 physical cell from VRAM with StoreImage, changed one
bitplane, then uploaded it again.  StoreImage returns while the DMA tail of this
72-byte rectangle is still running, so the CPU and LoadImage can race that transfer.

This build starts each of the five cache cells from the final COMM.IMG bytes already
known at build time.  The resident frame routine edits that persistent 360-byte RAM
shadow and uses only the previously runtime-proven LoadImage path.
"""
from __future__ import annotations

from pathlib import Path

import build_arc1_v159_dynamic_cache as base


ROOT = Path(__file__).resolve().parents[1]
ANALYSIS = ROOT / "01_work/analysis/arc1_v160_dynamic_cache_ram_shadow"
ROW_STRIDE = 0x380
CELL_ROW_BYTES = base.CELL // 2
CELL_BYTES = CELL_ROW_BYTES * base.CELL
CACHE_CELLS = base.CACHE_N // base.PLANES


def make_cache_state(font: bytes | bytearray,
                     cache_rows: list[dict[str, str]]) -> bytes:
    """Extract five contiguous 12x12 4bpp cells from the final COMM.IMG."""
    if len(cache_rows) != base.CACHE_N or base.CACHE_N % base.PLANES:
        raise SystemExit("cache plan does not contain complete physical cells")

    state = bytearray()
    for first in range(0, base.CACHE_N, base.PLANES):
        group = cache_rows[first:first + base.PLANES]
        if [int(row["cache_slot"]) for row in group] != \
                list(range(first, first + base.PLANES)):
            raise SystemExit(f"cache slot order differs at {first}")
        rows = {int(row["row"]) for row in group}
        columns = {int(row["column"]) for row in group}
        planes = [int(row["plane"]) for row in group]
        if len(rows) != 1 or len(columns) != 1 or planes != list(range(base.PLANES)):
            raise SystemExit(f"cache slots {first}..{first + 3} do not share one cell")

        row, column = rows.pop(), columns.pop()
        pixel_x = column * base.CELL
        if pixel_x & 1:
            raise SystemExit("cache cell is not byte-aligned")
        for y in range(base.CELL):
            at = (row * base.CELL + y) * ROW_STRIDE + pixel_x // 2
            cell_row = font[at:at + CELL_ROW_BYTES]
            if len(cell_row) != CELL_ROW_BYTES:
                raise SystemExit("cache cell escapes COMM.IMG")
            state += cell_row

    if len(state) != CACHE_CELLS * CELL_BYTES:
        raise SystemExit("RAM shadow size differs")
    return bytes(state)


# Reuse the verified v159 build graph while changing only the cache-state backing and
# the frame routine's transfer mode.  The defaults in the v159 module still reproduce
# the frozen v159 archive byte-for-byte.
base.OUT_STEM = "arc1_v160_dynamic_cache_ram_shadow"
base.ANALYSIS = ANALYSIS
base.REPORT = ANALYSIS / "build_report.txt"
base.DISASSEMBLY = ANALYSIS / "mips_disassembly.txt"
base.BUILD_TITLE = "v160 on-demand 20-slot cache with persistent RAM cell shadow"
base.USE_VRAM_READBACK = False
base.make_cache_state = make_cache_state


if __name__ == "__main__":
    base.main()
