"""Can the whole font live in cells the original disc drew glyphs into?

Two things have to leave where they are.  The 140 cells the original left blank are
what put a block over the slime, and the three resident strips are what the game
overwrites in battle -- both are proven by build, not argued.  Everything they hold
has to move somewhere that is font and only font.

The one property that has survived every test today is this: a cell the original disc
drew pixels into has never once been implicated.  277 such cells are patched in v151
and two separate bisections over them produced nothing.  So they are the pool.

Counted here:

    need    glyphs the text actually draws out of the 140 blank cells and the strips
    pool    glyph planes inside originally-drawn cells that no code reads today
    verdict whether the move fits without a runtime cache

A cell holds four glyphs, one per bitplane, so the unit is a plane and not a cell.
Nothing is written; this only counts.
"""
from __future__ import annotations

import csv
import struct
import sys
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from plan_bulk_insertion import tokens  # noqa: E402

BUILD = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
ORIGINAL = ROOT / "00_original/arc.zip"
ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"

IPR, PLANES, CELL, COLS = 84, 4, 12, 21
IMG_ROW = 896
RAM_TO_FILE = 0x8011A800
LOOKUP_SRC, LOOKUP_N = 0x801A8FD4, 508
STRIP_ROWS = (40, 53, 63)
SLOT_BASE, SLOT_COUNT, SLOT_SIZE = 0x47800, 79, 0x80
POOL = (0x78000, 0x83000)


def cell_has_pixels(font: bytes, row: int, col: int) -> bool:
    for dy in range(CELL):
        at = (row * CELL + dy) * IMG_ROW + (col * CELL) // 2
        if any(font[at:at + CELL // 2]):
            return True
    return False


def index_of(token: bytes, lut: tuple[int, ...]) -> int | None:
    """The glyph a token draws, for the three spellings this project uses."""
    if len(token) == 1:
        return token[0] if token[0] >= 0x20 else None
    if token[0] in (0xE9, 0xEA):
        slot = (token[0] - 0xE9) * 254 + token[1] - 1
        return lut[slot] if 0 <= slot < len(lut) else None
    if 0xDD <= token[0] <= 0xDF:
        return (token[0] - 0xDD) * 254 + token[1] - 1 + 256
    return None


def text_regions(members: dict[str, bytes], original: dict[str, bytes]):
    """Body lines, the external slot bank, and only the executable text we wrote."""
    with ORIGINAL_CSV.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
        rows = [(r["source file"], int(r[key], 0),
                 len(bytes.fromhex(r["raw bytes as hex"].replace(" ", "")))) for r in reader]

    for name, offset, size in rows:
        if name in members and offset + size <= len(members[name]):
            yield members[name][offset:offset + size]

    for name in {n for n, _, _ in rows}:
        data = members.get(name)
        if not data or len(data) < SLOT_BASE + SLOT_COUNT * SLOT_SIZE:
            continue
        for slot in range(SLOT_COUNT):
            block = data[SLOT_BASE + slot * SLOT_SIZE:][:SLOT_SIZE]
            if not block or not block[0] or 0 not in block:
                continue
            yield block[:block.index(0)]

    # Only the runs this project actually rewrote.  Reading the whole pool as text is
    # what put 0x7D over 4,093 pointers in v159 and stopped the game booting.
    ours, stock = members["PSX.EXE"], original["PSX.EXE"]
    lo, hi = POOL
    run = bytearray()
    for i in range(lo, hi):
        if ours[i] != stock[i] and ours[i]:
            run.append(ours[i])
        else:
            if len(run) > 1:
                yield bytes(run)
            run.clear()
    if len(run) > 1:
        yield bytes(run)


def main() -> None:
    with zipfile.ZipFile(BUILD) as z:
        members = {n: z.read(n) for n in z.namelist()}
    with zipfile.ZipFile(ORIGINAL) as z:
        original = {"PSX.EXE": z.read("PSX.EXE"), "COMM.IMG": z.read("COMM.IMG")}

    exe, font, stock_font = members["PSX.EXE"], members["COMM.IMG"], original["COMM.IMG"]
    lut = struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP_SRC - RAM_TO_FILE)

    used = Counter()
    for payload in text_regions(members, original):
        for token in tokens(payload):
            index = index_of(token, lut)
            if index is not None:
                used[index] += 1
    print(f"텍스트가 실제로 그리는 글리프 자리 {len(used)}개")

    blank_cells = {(r, c) for r in range(512 // CELL) for c in range(COLS)
                   if not cell_has_pixels(stock_font, r, c) and cell_has_pixels(font, r, c)}
    print(f"원본이 비워 둔 칸에 우리가 채운 것 {len(blank_cells)}칸")

    def where(index: int) -> tuple[int, int, int]:
        row, rest = divmod(index, IPR)
        col, plane = divmod(rest, PLANES)
        return row, col, plane

    need_blank = {i for i in used if where(i)[0] < 512 // CELL
                  and (where(i)[0], where(i)[1]) in blank_cells}
    need_strip = {i for i in used if where(i)[0] in STRIP_ROWS}
    print()
    print(f"옮겨야 할 글자")
    print(f"  비워 둔 칸 안에서 쓰이는 것   {len(need_blank)}자")
    print(f"  스트립 안에서 쓰이는 것       {len(need_strip)}자")
    print(f"  합계                          {len(need_blank | need_strip)}자")

    pool = []
    for row in range(512 // CELL):
        for col in range(COLS):
            if not cell_has_pixels(stock_font, row, col):
                continue
            for plane in range(PLANES):
                index = row * IPR + col * PLANES + plane
                if index not in used:
                    pool.append(index)
    print()
    print(f"이전 후보 (원본에 픽셀이 있던 칸 안에서 아무도 안 읽는 자리) {len(pool)}자")
    print(f"  칸으로는 {len({(i // IPR, (i % IPR) // PLANES) for i in pool})}칸")

    need = len(need_blank | need_strip)
    print()
    if need <= len(pool):
        print(f"판정: 들어간다.  필요 {need}자 <= 후보 {len(pool)}자  (여유 {len(pool)-need}자)")
        print("      동적 캐시 없이 정적 재배치만으로 끝난다.")
    else:
        print(f"판정: 부족하다.  필요 {need}자 > 후보 {len(pool)}자  ({need-len(pool)}자 모자람)")


if __name__ == "__main__":
    main()
