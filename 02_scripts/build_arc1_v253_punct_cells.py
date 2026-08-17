"""Build v249: re-encode the script from the translation source, not from old codes.

Every attempt so far tried to work out what the existing glyph codes meant, so
the johab atlas could be pointed at the right pieces.  That failed repeatedly --
the codes have been rebased across many generations and no trustworthy record of
them survives, which is why `불꽃` came out as `부쫑`.

The Korean text is already in 05_docs/script_translated_full.csv.  Encoding it
fresh removes the whole problem: the atlas is built from the characters the
translation actually uses, and each line is written out in the new codes.  No
character table, no guessing.

    translation uses      673 kinds  (646 Hangul)
    top 219 by frequency -> one-byte codes, the rest two-byte
    each glyph composed offline from the 8-bul pieces, 16x16

Lines are written in place: the body keeps its original length, padded with
spaces, so pointers and file sizes never move.  A line whose translation does
not fit is left at whatever length fits and the remainder dropped, which is the
same trade the project has made before when tightening text.

Pieces: Hanme_8x4x4.bdf (github.com/iolo/8x4x4-fonts, MIT / OFL-1.1).
"""
from __future__ import annotations

import collections
import csv
import functools
import hashlib
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

import build_arc1_v186_runtime_text_choice_fixes as v186  # noqa: E402

ART = ROOT / "01_work/analysis/hangul_johab_16px"
OUT_DIR = ROOT / "03_output"
STEM = "arc1_v253_punct_cells_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v253_punct_cells"
CSV = ROOT / "05_docs/script_translated_full.csv"

PSX, COMM = "PSX.EXE", "COMM.IMG"
ROW_BYTES, CELL, COLS, PLANES = 896, 16, 15, 4
ONE_BYTE_MAX = 220
SPACE = 0x9C
STRIDE_AT, OLD_STRIDE, NEW_STRIDE = 0x8016B530, 84, COLS * PLANES
R2F = 0x8011A800
SB, SS, SC = v186.SLOT_BASE, v186.SLOT_SIZE, v186.SLOT_COUNT
PUNCT = {" ": SPACE, ",": 0x0D, "!": 0x02, ".": 0x0F, "?": 0x3C}

A = {0, 1, 2, 3, 4, 5, 6, 7, 20}
B = {8, 12, 18}
C = {13, 17}


def grp(j: int) -> int:
    return 0 if j in A else 1 if j in B else 2 if j in C else 3


def digest(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest().upper()


def clone(i: ZipInfo) -> ZipInfo:
    o = ZipInfo(i.filename, i.date_time)
    for a in ("compress_type", "comment", "extra", "create_system", "create_version",
              "extract_version", "flag_bits", "volume", "internal_attr", "external_attr"):
        setattr(o, a, getattr(i, a))
    return o


def encode(index: int) -> bytes | None:
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
    base = sorted(OUT_DIR.glob("arc1_v238_glyph_16px_TEST_ONLY_*.zip"))[-1]
    with ZipFile(base) as z:
        infos = z.infolist()
        before = {i.filename: z.read(i.filename) for i in infos}
    members = dict(before)

    raw = (ART / "pieces_1bpp.bin").read_bytes()
    piece = lambda i: [struct.unpack_from(">H", raw, (i * 16 + y) * 2)[0] for y in range(16)]
    ascii_g = __import__("pickle").load(open(ART / "ascii_16px.pkl", "rb"))
    OR = lambda *g: [functools.reduce(lambda a, b: a | b, (x[y] for x in g)) for y in range(16)]

    def compose(ch: str) -> list[int] | None:
        if "가" <= ch <= "힣":
            x = ord(ch) - 0xAC00
            cho, r = divmod(x, 588)
            jung, jong = divmod(r, 28)
            p = [piece((grp(jung) + (4 if jong else 0)) * 20 + cho + 1),
                 piece(160 + ((1 if cho in (0, 15) else 0) + (2 if jong else 0)) * 22 + jung + 1)]
            if jong:
                p.append(piece(248 + grp(jung) * 28 + jong))
            return OR(*p)
        return ascii_g.get(ch)

    rows = list(csv.DictReader(open(CSV, encoding="utf-8-sig")))
    freq = collections.Counter()
    for r in rows:
        kr = (r.get("korean") or "").strip()
        if kr and r["source file"] in members:
            for ch in kr:
                if ch not in PUNCT:
                    freq[ch] += 1
    drawable = [ch for ch, _ in freq.most_common() if compose(ch) is not None]
    skipped = [ch for ch, _ in freq.most_common() if compose(ch) is None]

    # PUNCT keeps its historical byte, so the cell that byte points at belongs
    # to that punctuation mark and nothing else may be assigned there.
    reserved = {v - 1: k for k, v in PUNCT.items()}
    assign, nxt = {}, 0
    for ch in drawable:
        while nxt in reserved:
            nxt += 1
        if nxt >= ONE_BYTE_MAX - 1:
            break
        assign[ch] = nxt
        nxt += 1
    one_n = len(assign)
    while nxt in reserved:
        nxt += 1
    blank = nxt
    nxt = ONE_BYTE_MAX
    for ch in drawable[one_n:]:
        while encode(nxt) is None:
            nxt += 1
        assign[ch] = nxt
        nxt += 1
    total = nxt
    cells = -(-total // PLANES)
    rows_needed = -(-cells // COLS)
    if COLS * CELL > 252 or rows_needed * CELL > 504:
        raise SystemExit("atlas leaves the glyph area")

    font = bytearray(members[COMM])
    for y in range(rows_needed * CELL):
        b = y * ROW_BYTES
        font[b:b + COLS * (CELL // 2)] = bytes(COLS * (CELL // 2))
    for ch, idx in assign.items():
        put(font, idx, compose(ch))
    for idx, ch in reserved.items():          # punctuation lives in its own cell
        g = ascii_g.get(ch)
        if g:
            put(font, idx, g)

    def code(ch: str) -> bytes:
        if ch in PUNCT:
            return bytes((PUNCT[ch],))
        idx = assign.get(ch)
        return encode(idx) if idx is not None else bytes((SPACE,))

    scratch = {n: bytearray(v) for n, v in before.items()}
    did = lambda s: s + 0x81 if s < 40 else s + 0x82
    wrote = truncated = 0
    for r in rows:
        kr = (r.get("korean") or "").strip()
        n = r["source file"]
        if not kr or n not in scratch:
            continue
        try:
            off = int(r["offset"], 0)
        except Exception:
            continue
        buf = scratch[n]
        e = off
        while e < len(buf) and buf[e]:
            e += 1
        start, cap = off, e - off
        if cap >= 2 and buf[off] == 0xE2:
            for s in range(SC):
                if did(s) == buf[off + 1]:
                    blk = SB + s * SS
                    end = blk
                    while end < blk + SS and buf[end]:
                        end += 1
                    start, cap = blk, SS - 1
                    break
        # keep every control code where it is; only glyph slots are rewritten
        body = bytes(buf[start:start + cap])
        spans, i = [], 0
        while i < cap:
            b = body[i]
            if b == 0xE2 or 0xE3 <= b <= 0xE8:
                i += 2
                continue
            j = i
            while j < cap:
                b2 = body[j]
                if b2 == 0xE2 or 0xE3 <= b2 <= 0xE8:
                    break
                j += 1 if b2 < 0xDD else 2
            spans.append((i, min(j, cap)))
            i = j
        room = sum(b - a for a, b in spans)
        out = bytearray()
        for ch in kr:
            c = code(ch)
            if len(out) + len(c) > room:
                truncated += 1
                break
            out += c
        out += bytes((SPACE,)) * (room - len(out))
        pos = 0
        for a, b in spans:
            n = b - a
            buf[start + a:start + b] = out[pos:pos + n]
            pos += n
        wrote += 1

    exe = bytearray(members[PSX])
    w0 = struct.unpack_from("<I", exe, STRIDE_AT - R2F)[0]
    if (w0 >> 26) != 0x0D or (w0 & 0xFFFF) != OLD_STRIDE:
        raise SystemExit(f"stride site is {w0:08X}")
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
    tmp = OUT_DIR / f"{STEM}_building.zip"
    if tmp.exists():
        raise SystemExit("temp exists")
    with ZipFile(tmp, "w", ZIP_DEFLATED) as z:
        for i in infos:
            z.writestr(clone(i), members[i.filename])
    stamp = digest(tmp.read_bytes())
    out = OUT_DIR / f"{STEM}_{stamp[:8]}.zip"
    tmp.replace(out)

    report = [
        "v253 TEST ONLY - control codes preserved, punctuation cells reserved",
        f"base={base.name}", f"output={out.name}", f"sha256={stamp}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        f"glyphs={len(assign)}  (one-byte {one_n}, two-byte {len(assign)-one_n}, "
        f"punct cells reserved {len(reserved)})",
        f"atlas={cells} cells, {COLS}x{rows_needed}, {COLS*CELL}x{rows_needed*CELL} px",
        f"lines written={wrote}   truncated={truncated}",
        f"characters with no glyph={len(skipped)} (drawn as space)",
        f"row_stride {OLD_STRIDE} -> {NEW_STRIDE}",
        "no character table involved; glyphs come straight from the translation",
        "pieces=Hanme_8x4x4.bdf (iolo/8x4x4-fonts, MIT / OFL-1.1)",
        "runtime=PENDING user cold boot",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
