"""Build v307: move cached glyphs into the atlas so the world map stops erasing them.

v197 still relies on the dynamic cache: 309 of the 413 lookup entries point above
0x600, so the runtime decompresses those glyphs into a small VRAM rectangle that
the world map later overwrites.  Their pixels are recoverable -- decode_cache_glyphs
reproduces the resident Huffman stream -- and the lookup table decides statically:

    0x801A7520   11-bit packed table,  entry = glyph index or cache request
    value < 0x600  ->  drawn straight from the atlas, cache never touched

Only cells blank in BOTH the original and v197 are used.  Icons are sampled by UV
rather than by glyph code, so "no dialogue references it" never excludes them;
blank-in-both is the only safe test.  238 such cells exist, so the 238 most-used
cache entries become static and 71 keep using the cache.
"""
from __future__ import annotations
import collections
import csv
import hashlib
import pickle
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = sorted((ROOT / "03_output").glob("arc1_v306_v197_johab_TEST_ONLY_*.zip"))[-1]
ORIG = ROOT / "00_original/arc.zip"
PIX = ROOT / "01_work/analysis/cache_glyphs/glyphs.pkl"
OUT = ROOT / "03_output"
STEM = "arc1_v307_cache_static_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v307_cache_static"
PSX, COMM = "PSX.EXE", "COMM.IMG"
R2F = 0x8011A800
TABLE, SLOTS, CACHE_MARK = 0x801A7520, 0x19D, 0x600
ROW, CELL, COLS, PL = 896, 12, 21, 4
N = COLS * 42 * PL


def clone(i: ZipInfo) -> ZipInfo:
    o = ZipInfo(i.filename, i.date_time)
    for a in ("compress_type", "comment", "extra", "create_system", "create_version",
              "extract_version", "flag_bits", "volume", "internal_attr", "external_attr"):
        setattr(o, a, getattr(i, a))
    return o


def main() -> None:
    with ZipFile(BASE) as z:
        infos = z.infolist()
        mem = {i.filename: z.read(i.filename) for i in infos}
    with ZipFile(ORIG) as z:
        of = z.read(COMM)
    exe = bytearray(mem[PSX])
    font = bytearray(mem[COMM])
    pix = pickle.load(open(PIX, "rb"))

    def tget(s):
        b = s * 11
        byt, off = divmod(b, 8)
        a = TABLE - R2F + byt
        return ((exe[a] | (exe[a + 1] << 8) | (exe[a + 2] << 16)) >> off) & 0x7FF

    def tset(s, val):
        b = s * 11
        byt, off = divmod(b, 8)
        a = TABLE - R2F + byt
        v = exe[a] | (exe[a + 1] << 8) | (exe[a + 2] << 16)
        v = (v & ~(0x7FF << off)) | (val << off)
        exe[a], exe[a + 1], exe[a + 2] = v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF

    def cell(f, i):
        c, pl = divmod(i, PL)
        col, row = c % COLS, c // COLS
        if (row + 1) * CELL > 504:
            return None
        out = []
        for y in range(CELL):
            b = (row * CELL + y) * ROW + col * (CELL // 2)
            v = 0
            for x in range(CELL):
                if (f[b + x // 2] >> (0 if x % 2 == 0 else 4)) & 0x0F & (1 << pl):
                    v |= 1 << (CELL - 1 - x)
            out.append(v)
        return out

    def put(i, rows):
        c, pl = divmod(i, PL)
        col, row = c % COLS, c // COLS
        bit = 1 << pl
        for y in range(CELL):
            base = (row * CELL + y) * ROW + col * (CELL // 2)
            src = rows[y] if y < len(rows) else 0
            for x in range(CELL):
                at = base + x // 2
                sh = 0 if x % 2 == 0 else 4
                nib = (font[at] >> sh) & 0x0F
                nib = (nib | bit) if (src >> (CELL - 1 - x)) & 1 else (nib & ~bit & 0x0F)
                font[at] = (font[at] & (0xF0 if sh == 0 else 0x0F)) | (nib << sh)

    def encodable(i):
        if i < 220:
            return True
        rel = i - 0xDB
        lead, trail = divmod(rel, 255)
        return 0 <= lead <= 3 and 1 <= trail <= 254

    # how often each lookup slot is actually asked for
    uses = collections.Counter()
    with (ROOT / "05_docs/script_original_full.csv").open(encoding="utf-8-sig", newline="") as fh:
        for r in csv.DictReader(fh):
            b = bytes.fromhex(r["raw bytes as hex"].replace(" ", ""))
            i = 0
            while i < len(b):
                x = b[i]
                if x == 0:
                    break
                if x >= 0xE1:
                    if x in (0xE9, 0xEA) and i + 1 < len(b):
                        s = (x - 0xE9) * 254 + b[i + 1] - 1
                        if 0 <= s < SLOTS:
                            uses[s] += 1
                    i += 2
                    continue
                i += 1 if x < 0xDD else 2

    taken = {tget(s) for s in range(SLOTS) if tget(s) < CACHE_MARK}
    free = [i for i in range(CACHE_MARK)
            if encodable(i) and i not in taken
            and not any(cell(of, i) or [1]) and not any(cell(font, i) or [1])]
    cached = [s for s in range(SLOTS) if tget(s) >= CACHE_MARK]
    cached.sort(key=lambda s: -uses[s])

    moved = skipped = 0
    for s in cached:
        rows = pix.get(s)
        if not rows or not any(rows[:CELL]) or not free:
            skipped += 1
            continue
        dest = free.pop(0)
        put(dest, list(rows[:CELL]))
        tset(s, dest)
        moved += 1

    mem[PSX] = bytes(exe)
    mem[COMM] = bytes(font)
    left = sum(1 for s in range(SLOTS) if tget(s) >= CACHE_MARK)

    tmp = OUT / f"{STEM}_building.zip"
    if tmp.exists():
        tmp.unlink()
    with ZipFile(tmp, "w", ZIP_DEFLATED, compresslevel=1) as z:
        for i in infos:
            z.writestr(clone(i), mem[i.filename])
    st = hashlib.sha256(tmp.read_bytes()).hexdigest().upper()
    out = OUT / f"{STEM}_{st[:8]}.zip"
    tmp.replace(out)

    rep = [
        "v307 TEST ONLY - cached glyphs made resident, cache pressure cut",
        f"base={BASE.name}", f"output={out.name}", f"sha256={st}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        f"cache entries at start=309   moved to atlas={moved}   still cached={left}",
        f"skipped (no pixels or no cell)={skipped}",
        "cells used were blank in BOTH the original and v197 -- icons untouched",
        "runtime=PENDING user cold boot",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(rep) + "\n", encoding="utf-8")
    print("\n".join(rep))


if __name__ == "__main__":
    main()
