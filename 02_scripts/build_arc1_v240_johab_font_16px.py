"""Build v240: 16px Hangul composed from johab pieces, replacing the whole atlas.

This is the build the johab work has been heading for.  The pieces are composed
offline into finished 16x16 syllables and written as a new atlas, so the game
needs no composition code at run time -- and no dynamic cache, which is what
made the world map destroy text for the last two days.

    script Hangul        632 kinds  -> composed from 8-bul pieces
    ASCII / punctuation   31 kinds  -> taken from the same BDF (8x16, left aligned)
    everything else                 -> blank; these are untranslated Japanese

    663 glyphs / 4 planes = 166 cells, 15 per row = 12 rows
    240x192 px inside the 252x504 glyph area, about 21 KB against 62 KB today

Three things change together and none of them works alone:

    COMM.IMG   new atlas: cell = index/4, plane = index%4, 15 columns
    PSX.EXE    0x8016B530 `ori v0,zero,84` -> 60   (row stride = 15 cols x 4)
    DAT files  every glyph code rewritten to its new index

The re-encode keeps each token's width: codes that were one byte stay one byte
(new index below 220) and two-byte codes stay two-byte.  Body lengths, pointers
and file sizes are therefore untouched.  Codes whose character could not be
established from the script/original cross-reference are pointed at a blank
cell rather than guessed at -- v231 guessed and 52 glyphs came out wrong.

Pieces: Hanme_8x4x4.bdf (github.com/iolo/8x4x4-fonts, MIT / OFL-1.1).
"""
from __future__ import annotations

import collections
import hashlib
import pickle
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from plan_bulk_insertion import LOOKUP_N, LOOKUP_SRC, RAM_TO_FILE  # noqa: E402
from audit_dynamic_cache_requirements import glyph_index  # noqa: E402
from build_arc1_v231_static_promotion_restored162 import text_regions, PSX  # noqa: E402

ART = ROOT / "01_work/analysis/hangul_johab_16px"
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v244_johab_font_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v244_johab_font"

COMM = "COMM.IMG"
ROW_BYTES = 896
CELL = 16
COLS = 15
PLANES = 4
STRIDE_AT = 0x8016B530          # ori v0, zero, 84
OLD_STRIDE, NEW_STRIDE = 84, COLS * PLANES
R2F = 0x8011A800
ONE_BYTE_MAX = 220


def digest(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for a in ("compress_type", "comment", "extra", "create_system", "create_version",
              "extract_version", "flag_bits", "volume", "internal_attr", "external_attr"):
        setattr(out, a, getattr(info, a))
    return out


def encode(index: int) -> bytes | None:
    """Canonical code for a physical index, or None where the code space has a hole."""
    if 0 <= index < ONE_BYTE_MAX:
        return bytes((index + 1,))
    rel = index - 0xDB
    lead, trail = divmod(rel, 255)
    if not (0 <= lead <= 3 and 1 <= trail <= 254):
        return None
    return bytes((0xDD + lead, trail))


def put(font: bytearray, index: int, rows: list[int]) -> None:
    cell, plane = divmod(index, PLANES)
    col, row = cell % COLS, cell // COLS
    bit = 1 << plane
    for y in range(CELL):
        base = (row * CELL + y) * ROW_BYTES + col * (CELL // 2)
        src = rows[y] if y < len(rows) else 0
        for x in range(CELL):
            at = base + x // 2
            shift = 0 if x % 2 == 0 else 4
            nib = (font[at] >> shift) & 0x0F
            nib = (nib | bit) if (src >> (CELL - 1 - x)) & 1 else (nib & ~bit & 0x0F)
            font[at] = (font[at] & (0xF0 if shift == 0 else 0x0F)) | (nib << shift)


def main() -> None:
    base_path = sorted(OUT_DIR.glob("arc1_v238_glyph_16px_TEST_ONLY_*.zip"))
    if not base_path:
        raise SystemExit("v238 base not found")
    base_path = base_path[-1]
    with ZipFile(base_path) as z:
        infos = z.infolist()
        before = {i.filename: z.read(i.filename) for i in infos}
    members = dict(before)
    exe = bytearray(members[PSX])
    lut = struct.unpack_from(f"<{LOOKUP_N}H", bytes(exe), LOOKUP_SRC - RAM_TO_FILE)

    composed = pickle.load(open(ART / "composed_16px.pkl", "rb"))   # old idx -> 16 rows
    ascii_g = pickle.load(open(ART / "ascii_16px.pkl", "rb"))       # char -> 16 rows
    code2ch = pickle.load(open(ART / "code_to_char.pkl", "rb"))

    # how each old index is referenced, and how often
    width = {}
    uses = collections.Counter()
    for name, s, e in text_regions(before):
        d = before[name]
        i = s
        while i < e:
            b = d[i]
            if b == 0xE2 or 0xE3 <= b <= 0xE8:
                i += 2
                continue
            w = 1 if b < 0xDD else 2
            if i + w > e:
                break
            gi = glyph_index(bytes(d[i:i + w]), lut)
            if gi is not None:
                uses[gi] += 1
                width.setdefault(gi, set()).add(w)
            i += w

    drawable = {}
    for gi in uses:
        if gi in composed:
            drawable[gi] = composed[gi]
        else:
            ch = code2ch.get(gi)
            if ch in ascii_g:
                drawable[gi] = ascii_g[ch]

    # width must be stable.  An index below 220 has no two-byte code, so a glyph
    # referenced both ways needs two cells holding the same picture.
    one = [g for g in drawable if 1 in width.get(g, set())]
    two = [g for g in drawable if 2 in width.get(g, set())]
    one.sort(key=lambda g: -uses[g])
    two.sort(key=lambda g: -uses[g])
    if len(one) > ONE_BYTE_MAX - 1:
        raise SystemExit(f"{len(one)} one-byte glyphs exceed the {ONE_BYTE_MAX - 1} slots")

    assign1, assign2 = {}, {}
    for n, g in enumerate(one):
        assign1[g] = n
    blank_one = len(one)                       # blank cell for unknown one-byte codes
    # trail 0 is not a legal code, so index 474, 729, ... are holes to skip
    nxt = ONE_BYTE_MAX
    for g in two:
        while encode(nxt) is None:
            nxt += 1
        assign2[g] = nxt
        nxt += 1
    while encode(nxt) is None:
        nxt += 1
    blank_two = nxt
    total = nxt + 1
    cells = -(-total // PLANES)
    rows_needed = -(-cells // COLS)
    if COLS * CELL > 252 or rows_needed * CELL > 504:
        raise SystemExit("atlas layout leaves the glyph area")

    font = bytearray(len(members[COMM]))
    font[:] = members[COMM]
    for y in range(rows_needed * CELL):
        b = y * ROW_BYTES
        font[b:b + COLS * (CELL // 2)] = bytes(COLS * (CELL // 2))
    for tbl in (assign1, assign2):
        for g, new in tbl.items():
            put(font, new, drawable[g])

    remap = {}
    for g in uses:
        for w in width.get(g, set()):
            tbl = assign1 if w == 1 else assign2
            idx = tbl.get(g, blank_one if w == 1 else blank_two)
            code = encode(idx)
            if code is None or len(code) != w:
                raise SystemExit(f"no {w}-byte code for glyph {g}")
            remap[(g, w)] = code

    scratch = {n: bytearray(v) for n, v in before.items()}
    replaced = 0
    for name, s, e in text_regions(before):
        buf = scratch[name]
        i = s
        while i < e:
            b = buf[i]
            if b == 0xE2 or 0xE3 <= b <= 0xE8:
                i += 2
                continue
            w = 1 if b < 0xDD else 2
            if i + w > e:
                break
            gi = glyph_index(bytes(buf[i:i + w]), lut)
            if gi is not None and (gi, w) in remap:
                new = remap[(gi, w)]
                if len(new) != w:
                    raise SystemExit(f"width change at {name} 0x{i:X}: idx {gi}")
                buf[i:i + w] = new
                replaced += 1
            i += w

    w0 = struct.unpack_from("<I", exe, STRIDE_AT - R2F)[0]
    if (w0 >> 26) != 0x0D or (w0 & 0xFFFF) != OLD_STRIDE:
        raise SystemExit(f"stride site is {w0:08X}, not `ori v0,zero,84`")
    struct.pack_into("<I", exe, STRIDE_AT - R2F, (w0 & ~0xFFFF) | NEW_STRIDE)

    members[PSX] = bytes(exe)
    members[COMM] = bytes(font)
    for n, v in scratch.items():
        if n not in (PSX, COMM):
            members[n] = bytes(v)
    for n in members:
        if len(members[n]) != len(before[n]):
            raise SystemExit(f"{n} size changed")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tmp = OUT_DIR / f"{OUT_STEM}_building.zip"
    if tmp.exists():
        raise SystemExit(f"refusing to overwrite: {tmp}")
    with ZipFile(tmp, "w", ZIP_DEFLATED) as z:
        for info in infos:
            z.writestr(clone(info), members[info.filename])
    stamp = digest(tmp.read_bytes())
    out = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    if out.exists():
        raise SystemExit(f"refusing to overwrite: {out}")
    tmp.replace(out)

    changed = [n for n in members if members[n] != before[n]]
    report = [
        "v240 TEST ONLY - 16px johab-composed atlas, cache-free",
        f"base={base_path.name}", f"output={out.name}", f"sha256={stamp}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        f"glyphs={len(assign1)+len(assign2)} cells  (one-byte {len(assign1)}, two-byte {len(assign2)})",
        f"one_byte={len(one)}  two_byte={len(two)}  blanks=2",
        f"atlas={cells} cells, {COLS} cols x {rows_needed} rows, "
        f"{COLS * CELL}x{rows_needed * CELL} px",
        f"row_stride {OLD_STRIDE} -> {NEW_STRIDE} at 0x{STRIDE_AT:08X}",
        f"script codes rewritten={replaced}",
        f"unknown codes pointed at blank={sum(1 for g in uses if g not in drawable)}",
        f"changed members={len(changed)}",
        "widths preserved: one-byte stays one-byte, pointers and sizes unchanged",
        "pieces=Hanme_8x4x4.bdf (iolo/8x4x4-fonts, MIT / OFL-1.1)",
        "runtime=PENDING user cold boot",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
