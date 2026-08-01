"""How much room is really left in the glyph atlas?

Every estimate so far rested on the belief that the base atlas was full, which is why
the P6 expansion and then the dynamic-cache idea existed at all. That belief came from
counting occupancy with the lookup table, and the lookup table only covers characters
whose lead byte is 0xE9 or 0xEA. Counting all three index paths gives a different
picture, so measure it properly before designing anything else.

A cell is available only if all three hold:
  no character maps to it, by any of the three paths
  it is entirely blank in the ORIGINAL COMM.IMG, so the game draws nothing from it
  its row produces a V byte the renderer can address
"""
from __future__ import annotations

import csv
import struct
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "03_output/ui_hud_e7_v103_heap_reserved_glyphs_patch_only.zip"
ORIG_ISO = Path(r"E:\arc\원본\arc1.bin")
MAPS = ("korean_charmap.csv", "korean_charmap_extended.csv")
RAW, COMM_LBA, COMM_SIZE = 2352, 667, 458752
STRIP_ROW, X0 = 896, 320
CELL, COLS, PLANES, ROWS = 12, 21, 4, 24
IPR = COLS * PLANES
LOOKUP, LOOKUP_N, RAM_TO_FILE = 0x801A7520, 409, 0x8011A800
BASE_X4, P6_X4, P6_ROW = X0 * 4, 2856, 24


def read_original() -> bytes:
    with ORIG_ISO.open("rb") as raw:
        def sector(l):
            raw.seek(l * RAW)
            s = raw.read(RAW)
            return s[24:24 + 2048] if s[15] == 2 else s[16:16 + 2048]
        return b"".join(sector(COMM_LBA + i) for i in range(COMM_SIZE // 2048))


def cell_bytes(row, col):
    x4 = (P6_X4 if row == P6_ROW else BASE_X4) + col * CELL
    lo = (x4 - BASE_X4) // 2
    return [(row * CELL + dy) * STRIP_ROW + lo + k
            for dy in range(CELL) for k in range(CELL // 2)]


def main() -> None:
    with zipfile.ZipFile(PATCH) as z:
        exe = z.read("PSX.EXE")
    lut = struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP - RAM_TO_FILE)
    orig = read_original()

    chars = {}
    for name in MAPS:
        with (ROOT / "05_docs" / name).open(encoding="utf-8") as f:
            for row in csv.DictReader(f):
                code = (row.get("code_hex") or "").strip()
                if code:
                    chars[row["char"]] = int(code, 16)

    def index_of(code):
        if code <= 0xFF:
            return code - 1
        lead, trail = code >> 8, code & 0xFF
        if lead in (0xE9, 0xEA):
            s = (lead - 0xE9) * 254 + trail - 1
            return lut[s] if 0 <= s < LOOKUP_N else None
        if lead >= 0xDD:
            return (lead - 221) * 255 + trail + 219
        return None

    used_slots = set()
    for code in chars.values():
        i = index_of(code)
        if i is not None:
            used_slots.add(i)
    used_slots |= set(lut)
    used_cells = {(i // IPR, (i % IPR) // PLANES) for i in used_slots}

    print(f"characters mapped        : {len(chars)}")
    print(f"glyph slots in use       : {len(used_slots)}")
    print(f"cells touched by them    : {len(used_cells)}")
    print(f"cells the lookup table alone would report: "
          f"{len({(v // IPR, (v % IPR) // PLANES) for v in lut})}\n")

    # V is stored as a byte, so a row is addressable when its V is unique
    seen_v, ok_rows = {}, []
    for r in range(64):
        v = (r * 12) & 0xFF
        if v in seen_v:
            continue
        seen_v[v] = r
        ok_rows.append(r)

    free_blank, free_but_drawn, occupied = [], [], []
    for r in range(ROWS):
        for c in range(COLS):
            if (r, c) in used_cells:
                occupied.append((r, c))
            elif all(orig[i] == 0 for i in cell_bytes(r, c)):
                free_blank.append((r, c))
            else:
                free_but_drawn.append((r, c))

    print(f"{'':22}{'cells':>7}{'slots':>8}")
    print(f"{'occupied by a glyph':22}{len(occupied):>7}{len(occupied)*PLANES:>8}")
    print(f"{'free and blank in orig':22}{len(free_blank):>7}"
          f"{len(free_blank)*PLANES:>8}   <== usable")
    print(f"{'free but has game art':22}{len(free_but_drawn):>7}"
          f"{len(free_but_drawn)*PLANES:>8}   off limits")
    print(f"{'total':22}{ROWS*COLS:>7}{ROWS*COLS*PLANES:>8}")

    per_row = {}
    for r, c in free_blank:
        per_row.setdefault(r, []).append(c)
    print("\nusable cells by row (all rows below produce a distinct V byte):")
    for r in sorted(per_row):
        print(f"  row {r:>2}  V={(r*12) & 0xFF:>3}  {len(per_row[r]):>2} cells "
              f"({len(per_row[r])*PLANES:>3} slots)  columns {per_row[r]}")

    need = 947
    have = len(free_blank) * PLANES
    print(f"\nfull script needs about {need} distinct syllables (Heaps' law projection)")
    print(f"currently placed        : {len(used_slots)}")
    print(f"usable slots remaining  : {have}")
    print(f"still short by          : {max(0, need - len(used_slots) - have)}")
    if len(used_slots) + have >= need:
        print("\nthe whole script fits in the existing atlas; no cache is needed.")


if __name__ == "__main__":
    main()
