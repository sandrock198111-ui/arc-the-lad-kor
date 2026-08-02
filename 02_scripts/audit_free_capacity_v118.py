"""How many glyph slots are actually free for v118?

Two corrections over the earlier estimate.

The 132-slot figure double counted: it added all 104 resident two-strip slots to
28 blank atlas cells, but 52 + 5 of those strip slots already hold existing
E9/EA characters -- supply, not free space.

The other correction is the safety test.  What must stay untouched is *original
game art*: a cell that the original COMM.IMG draws into shares its nibbles with
the art, so setting a bitplane there changes the art's colours (this is what
v109 and v111 broke).  A cell that was blank in the original and now holds one
of our own glyphs is fine -- its other three bitplanes are ours to use.  The
earlier pass required the cell to be blank *now* as well and so threw away every
partly-filled cell.

Addressability comes from v106's measurement: only rows 0..23 produce a V byte
the base font page answers to.  Rows below that reach VRAM only through the
classifier and a per-frame upload, i.e. only through a resident strip.  Rows 11
to 13, columns 0 to 2, are reserved for the battle range cursor.
"""
from __future__ import annotations

import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from build_story_sf0b1_return_full import ROW_BYTES, get_pixel  # noqa: E402

BASE_ZIP = ROOT / "03_output/ui_hud_e7_v116_direct_stateless_renderer_patch_only.zip"
ORIG_ISO = Path(r"E:\arc\원본\arc1.bin")
REPORT = ROOT / "01_work/analysis/free_capacity_v118.txt"

RAW, COMM_LBA, COMM_SIZE = 2352, 667, 458752
RAM_TO_FILE = 0x8011A800
LOOKUP, LOOKUP_N = 0x801A7520, 409
GA_SRC, GB_SRC = 0x801A8800, 0x801A8BA8
STRIP_BYTES, STRIP_ROW_BYTES, STRIP_COLS = 936, 78, 13

COLS, PLANES = 21, 4
GLYPHS_PER_ROW = COLS * PLANES
BASE_ROWS = 24                      # rows the font page itself answers for
CURSOR_CELLS = {(r, c) for r in (11, 12, 13) for c in (0, 1, 2)}
STRIP_A_BASE, STRIP_B_BASE = 40 * GLYPHS_PER_ROW, 63 * GLYPHS_PER_ROW
STRIP_SLOTS = STRIP_COLS * PLANES


def read_original() -> bytes:
    with ORIG_ISO.open("rb") as raw:
        def sector(lba: int) -> bytes:
            raw.seek(lba * RAW)
            data = raw.read(RAW)
            return data[24:24 + 2048] if data[15] == 2 else data[16:16 + 2048]
        return b"".join(sector(COMM_LBA + i) for i in range(COMM_SIZE // 2048))


def cell_is_blank(font: bytes, row: int, column: int) -> bool:
    return all(
        get_pixel(font, column * 12 + x, row * 12 + y) == 0
        for y in range(12)
        for x in range(12)
    )


def plane_is_blank(font: bytes, row: int, column: int, plane: int) -> bool:
    bit = 1 << plane
    return all(
        not get_pixel(font, column * 12 + x, row * 12 + y) & bit
        for y in range(12)
        for x in range(12)
    )


def strip_plane_is_blank(strip: bytes, slot: int) -> bool:
    column, plane = divmod(slot, PLANES)
    bit = 1 << plane
    for y in range(12):
        for x in range(12):
            px = column * 12 + x
            byte = strip[y * STRIP_ROW_BYTES + px // 2]
            value = byte & 0x0F if px % 2 == 0 else byte >> 4
            if value & bit:
                return False
    return True


def main() -> None:
    with zipfile.ZipFile(BASE_ZIP) as archive:
        exe = archive.read("PSX.EXE")
        font = archive.read("COMM.IMG")
    lut = struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP - RAM_TO_FILE)
    strip_a = exe[GA_SRC - RAM_TO_FILE:GA_SRC - RAM_TO_FILE + STRIP_BYTES]
    strip_b = exe[GB_SRC - RAM_TO_FILE:GB_SRC - RAM_TO_FILE + STRIP_BYTES]
    original = read_original()

    # indices some byte sequence already resolves to
    physical: set[int] = {code - 1 for code in range(0x01, 0x100)}
    for lead in range(0xDD, 0xE9):
        for trail in range(0x01, 0xFF):
            physical.add((lead - 0xDD) * 255 + trail + 0xDB)
    virtual = set(lut)

    free_direct: list[tuple[int, int, int]] = []   # usable with a physical code today
    free_needs_code: list[tuple[int, int, int]] = []  # blank+safe but no code reaches it
    art = occupied = cursor = 0

    for row in range(BASE_ROWS):
        for column in range(COLS):
            safe = cell_is_blank(original, row, column)
            for plane in range(PLANES):
                index = row * GLYPHS_PER_ROW + column * PLANES + plane
                if not plane_is_blank(font, row, column, plane):
                    occupied += 1
                elif (row, column) in CURSOR_CELLS:
                    cursor += 1
                elif not safe:
                    art += 1
                elif index in physical or index in virtual:
                    free_direct.append((row, column, plane))
                else:
                    free_needs_code.append((row, column, plane))

    free_a = [s for s in range(STRIP_SLOTS) if strip_plane_is_blank(strip_a, s)]
    free_b = [s for s in range(STRIP_SLOTS) if strip_plane_is_blank(strip_b, s)]

    by_cell: dict[tuple[int, int], list[int]] = {}
    for row, column, plane in free_direct:
        by_cell.setdefault((row, column), []).append(plane)

    total = len(free_direct) + len(free_a) + len(free_b)
    lines = [
        f"base                            : {BASE_ZIP.name}",
        "",
        f"rows 0..{BASE_ROWS - 1} of the font page:",
        f"  planes holding a glyph        : {occupied}",
        f"  blank, but original game art  : {art}",
        f"  blank, but cursor reservation : {cursor}",
        f"  blank and safe, code reaches  : {len(free_direct)}  ({len(by_cell)} cells)",
        f"  blank and safe, no code yet   : {len(free_needs_code)}",
        "",
        f"resident strip A free slots     : {len(free_a)} / {STRIP_SLOTS}",
        f"resident strip B free slots     : {len(free_b)} / {STRIP_SLOTS}",
        "",
        f"TOTAL FREE, USABLE TODAY        : {total}",
        "",
        "free planes in safe font-page cells:",
    ]
    for (row, column), planes in sorted(by_cell.items()):
        base = row * GLYPHS_PER_ROW + column * PLANES
        lines.append(
            f"  row {row:>2} col {column:>2}  V={(row * 12) & 0xFF:>3}  "
            f"planes {planes}  indices {[base + p for p in planes]}"
        )

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
