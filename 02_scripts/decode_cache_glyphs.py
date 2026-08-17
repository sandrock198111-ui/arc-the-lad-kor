"""Decode the compressed cache glyphs, reproducing the routine at 0x801FF580.

The resident block holds a canonical Huffman stream.  Reading the disassembly:

    a3 = 0x801FE3C4              symbol table, 2 bytes per entry
    v0 = a3 + 0x156              bit stream
    a2 = v0 + 0xdb6              count of symbols per code length, 1 byte each
    t0 = halfword at 0x801A7760 + (glyph >> 4) * 2      start bit of the group
    t1 = (glyph & 0xf) * 11      symbols to discard before this glyph
    t2 = 11                      rows emitted, plus a final zero row = 12

The inner loop walks at most 13 bit lengths, accumulating `code`, `first` and
`index` the usual canonical way, and a symbol resolves to symbols[index + code -
first].  Each symbol is one 16-bit row of a 12x12 glyph.

Output: 01_work/analysis/cache_glyphs/glyphs.pkl  {glyph number: [12 rows]}
"""
from __future__ import annotations
import pickle
import struct
import sys
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

OUT = ROOT / "03_output"
ANALYSIS = ROOT / "01_work/analysis/cache_glyphs"
R2F = 0x8011A800
RES_SRC, RES_BASE, RES_N = 0x801A86EC, 0x801FE3C4, 5356
GROUP_TABLE = 0x801A7760
SYM_OFF, STREAM_OFF = 0x0, 0x156
COUNT_OFF = STREAM_OFF + 0xDB6
MAX_LEN, ROWS = 13, 11


def decode(res: bytes, exe: bytes, glyph: int) -> list[int] | None:
    grp, within = glyph >> 4, glyph & 0xF
    at = GROUP_TABLE - R2F + grp * 2
    if at + 2 > len(exe):
        return None
    bit = struct.unpack_from("<H", exe, at)[0]
    skip = within * ROWS
    out = []
    while len(out) < ROWS:
        code = first = index = 0
        found = None
        for _ in range(MAX_LEN):
            byte_at = STREAM_OFF + (bit >> 3)
            if byte_at >= len(res):
                return None
            b = (res[byte_at] >> ((bit & 7) ^ 7)) & 1
            bit += 1
            code = (code << 1) | b
            cnt_at = COUNT_OFF + (_)
            if cnt_at >= len(res):
                return None
            n = res[cnt_at]
            if code - first < n:
                found = index + code - first
                break
            index += n
            first = (first + n) << 1
        row = 0
        if found is not None:
            s = SYM_OFF + found * 2
            if s + 2 > len(res):
                return None
            row = struct.unpack_from("<H", res, s)[0]
        if skip:
            skip -= 1
            continue
        out.append(row)
    return out + [0]


def main() -> None:
    base = sorted(OUT.glob("arc1_v235_cache_row36_TEST_ONLY_*.zip"))[-1]
    with ZipFile(base) as z:
        exe = z.read("PSX.EXE")
    res = exe[RES_SRC - R2F:RES_SRC - R2F + RES_N]

    TABLE, SLOTS, STATIC_MAX = 0x801A7520, 0x19D, 0x600

    def tget(slot: int) -> int:
        b = slot * 11
        byt, off = divmod(b, 8)
        a = TABLE - R2F + byt
        return ((exe[a] | (exe[a + 1] << 8) | (exe[a + 2] << 16)) >> off) & 0x7FF

    wanted = {}
    for s in range(SLOTS):
        v = tget(s)
        if v >= STATIC_MAX:
            wanted[s] = v - STATIC_MAX

    got, blank, fail = {}, 0, 0
    for slot, g in sorted(wanted.items()):
        rows = decode(res, exe, g)
        if rows is None:
            fail += 1
        elif not any(rows):
            blank += 1
        else:
            got[slot] = rows

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    pickle.dump(got, open(ANALYSIS / "glyphs.pkl", "wb"))
    print(f"cache entries={len(wanted)}   decoded with ink={len(got)}   "
          f"blank={blank}   failed={fail}")
    if got:
        k = sorted(got)[:6]
        print("\nfirst few, drawn as 12x12:")
        for s in k:
            print(f"  slot {s}")
            for r in got[s][:12]:
                print("    " + "".join("#" if (r >> (11 - x)) & 1 else "." for x in range(12)))
    print(f"\nsaved {ANALYSIS / 'glyphs.pkl'}")


if __name__ == "__main__":
    main()
