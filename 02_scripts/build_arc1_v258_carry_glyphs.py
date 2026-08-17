"""Build v258: carry the existing glyph pictures into a compact 16px atlas.

Every previous attempt tried to work out *what character* each old code meant so
the johab pieces could be composed for it.  That decoding is unnecessary: 1044 of
the 1813 codes still have their picture sitting in the old atlas, covering 79% of
all script glyphs.  Copying the picture is exact -- there is nothing to get wrong.

    code has a picture            -> copy the old 12x12 into the new cell
    code is blank but decodable   -> compose it from johab pieces at 16px
    neither                       -> blank cell

The script text is untouched apart from the code bytes, and widths are kept
(one-byte codes stay one-byte), so pointers, body lengths and file sizes hold.

The point of the exercise is the atlas size: ~300 cells at 15 columns is about
320px tall against the old 504px, and every glyph the script uses is resident.
The dynamic cache -- the thing the world map has been destroying since v197 --
is no longer needed at all.
"""
from __future__ import annotations
import collections
import functools
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
from build_arc1_v231_static_promotion_restored162 import text_regions  # noqa: E402
from plan_bulk_insertion import LOOKUP_N, LOOKUP_SRC, RAM_TO_FILE      # noqa: E402
from audit_dynamic_cache_requirements import glyph_index               # noqa: E402

ART = ROOT / "01_work/analysis/hangul_johab_16px"
OUT = ROOT / "03_output"
STEM = "arc1_v258_carry_glyphs_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v258_carry_glyphs"
PSX, COMM = "PSX.EXE", "COMM.IMG"
ROW = 896
OLDC, OLDCOLS = 12, 21
NEWC, COLS, PL = 16, 15, 4
ONE_MAX = 220
STRIDE_AT, R2F = 0x8016B530, 0x8011A800
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


def encode(ix: int) -> bytes | None:
    if 0 <= ix < ONE_MAX:
        return bytes((ix + 1,))
    rel = ix - 0xDB
    lead, trail = divmod(rel, 255)
    if not (0 <= lead <= 3 and 1 <= trail <= 254):
        return None
    return bytes((0xDD + lead, trail))


def read_old(font: bytes, idx: int) -> list[int] | None:
    """The 12x12 picture of an old index as 16 rows of 16 bits, top-left aligned."""
    cell, pl = divmod(idx, PL)
    col, row = cell % OLDCOLS, cell // OLDCOLS
    if (row + 1) * OLDC > 504 or (col + 1) * OLDC > 252:
        return None
    out = []
    for y in range(OLDC):
        b = (row * OLDC + y) * ROW + col * (OLDC // 2)
        v = 0
        for x in range(OLDC):
            if (font[b + x // 2] >> (0 if x % 2 == 0 else 4)) & 0x0F & (1 << pl):
                v |= 1 << (15 - x)
        out.append(v)
    return out + [0] * (NEWC - OLDC)


def put(font: bytearray, idx: int, rows: list[int]) -> None:
    cell, pl = divmod(idx, PL)
    col, row = cell % COLS, cell // COLS
    bit = 1 << pl
    for y in range(NEWC):
        base = (row * NEWC + y) * ROW + col * (NEWC // 2)
        src = rows[y] if y < len(rows) else 0
        for x in range(NEWC):
            at = base + x // 2
            sh = 0 if x % 2 == 0 else 4
            nib = (font[at] >> sh) & 0x0F
            nib = (nib | bit) if (src >> (NEWC - 1 - x)) & 1 else (nib & ~bit & 0x0F)
            font[at] = (font[at] & (0xF0 if sh == 0 else 0x0F)) | (nib << sh)


def main() -> None:
    old_zip = sorted(OUT.glob("arc1_v235_cache_row36_TEST_ONLY_*.zip"))[-1]
    with ZipFile(old_zip) as z:
        old = {n: z.read(n) for n in z.namelist()}
    base_zip = sorted(OUT.glob("arc1_v238_glyph_16px_TEST_ONLY_*.zip"))[-1]
    with ZipFile(base_zip) as z:
        infos = z.infolist()
        before = {i.filename: z.read(i.filename) for i in infos}
    members = dict(before)
    lut = struct.unpack_from(f"<{LOOKUP_N}H", old[PSX], LOOKUP_SRC - RAM_TO_FILE)
    oldfont = old[COMM]

    raw = (ART / "pieces_1bpp.bin").read_bytes()

    def piece(i):
        return [struct.unpack_from(">H", raw, (i * 16 + y) * 2)[0] for y in range(16)]

    def OR(*g):
        return [functools.reduce(lambda a, b: a | b, (x[y] for x in g)) for y in range(16)]

    ascii_g = pickle.load(open(ART / "ascii_16px.pkl", "rb"))
    try:
        decoded = pickle.load(open(ART / "code_map_voted.pkl", "rb"))
    except Exception:
        decoded = {}

    def compose(ch):
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

    uses = collections.Counter()
    width = collections.defaultdict(set)
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
            tok = bytes(d[i:i + w])
            uses[tok] += 1
            width[tok].add(w)
            i += w

    art = {}
    from_pic = from_johab = 0
    for tok in uses:
        gi = glyph_index(tok, lut)
        pic = read_old(oldfont, gi) if gi is not None else None
        if pic and any(pic):
            art[tok] = pic
            from_pic += 1
        else:
            ch = decoded.get(tok)
            g = compose(ch) if ch else None
            if g:
                art[tok] = g
                from_johab += 1

    one = sorted((t for t in art if 1 in width[t]), key=lambda t: -uses[t])
    two = sorted((t for t in art if 2 in width[t]), key=lambda t: -uses[t])
    if len(one) > ONE_MAX - 1:
        raise SystemExit(f"{len(one)} one-byte glyphs exceed {ONE_MAX - 1} slots")
    a1 = {t: n for n, t in enumerate(one)}
    blank1 = len(one)
    nxt = ONE_MAX
    a2 = {}
    for t in two:
        while encode(nxt) is None:
            nxt += 1
        a2[t] = nxt
        nxt += 1
    while encode(nxt) is None:
        nxt += 1
    blank2 = nxt
    total = nxt + 1
    cells = -(-total // PL)
    need = -(-cells // COLS)
    if COLS * NEWC > 252 or need * NEWC > 504:
        raise SystemExit(f"atlas {COLS * NEWC}x{need * NEWC} leaves the glyph area")

    font = bytearray(members[COMM])
    for y in range(need * NEWC):
        b = y * ROW
        font[b:b + COLS * (NEWC // 2)] = bytes(COLS * (NEWC // 2))
    for tbl in (a1, a2):
        for t, ix in tbl.items():
            put(font, ix, art[t])

    remap = {}
    for t in uses:
        for w in width[t]:
            tbl = a1 if w == 1 else a2
            ix = tbl.get(t, blank1 if w == 1 else blank2)
            c = encode(ix)
            if c is None or len(c) != w:
                raise SystemExit(f"no {w}-byte code for index {ix}")
            remap[(t, w)] = c

    scratch = {n: bytearray(v) for n, v in before.items()}
    done = 0
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
            key = (bytes(buf[i:i + w]), w)
            if key in remap:
                buf[i:i + w] = remap[key]
                done += 1
            i += w

    exe = bytearray(members[PSX])
    w0 = struct.unpack_from("<I", exe, STRIDE_AT - R2F)[0]
    if (w0 >> 26) != 0x0D or (w0 & 0xFFFF) != 84:
        raise SystemExit(f"stride site is {w0:08X}")
    struct.pack_into("<I", exe, STRIDE_AT - R2F, (w0 & ~0xFFFF) | (COLS * PL))
    members[PSX] = bytes(exe)
    members[COMM] = bytes(font)
    for n, v in scratch.items():
        if n not in (PSX, COMM):
            members[n] = bytes(v)
    for n in members:
        if len(members[n]) != len(before[n]):
            raise SystemExit(f"{n} size changed")

    OUT.mkdir(parents=True, exist_ok=True)
    tmp = OUT / f"{STEM}_building.zip"
    if tmp.exists():
        raise SystemExit("temp exists")
    with ZipFile(tmp, "w", ZIP_DEFLATED) as z:
        for i in infos:
            z.writestr(clone(i), members[i.filename])
    st = digest(tmp.read_bytes())
    out = OUT / f"{STEM}_{st[:8]}.zip"
    tmp.replace(out)

    covered = sum(uses[t] for t in art)
    tot = sum(uses.values())
    rep = [
        "v258 TEST ONLY - old glyph pictures carried into a compact 16px atlas",
        f"base={base_zip.name}   pictures_from={old_zip.name}",
        f"output={out.name}", f"sha256={st}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        f"codes in script={len(uses)}   drawn={len(art)}  "
        f"(from picture {from_pic}, composed {from_johab})",
        f"script glyphs covered={covered:,}/{tot:,}  ({covered * 100 // tot}%)",
        f"atlas={cells} cells, {COLS}x{need}, {COLS * NEWC}x{need * NEWC} px  (limit 252x504)",
        f"one-byte {len(a1)}   two-byte {len(a2)}   codes rewritten={done:,}",
        "script text unchanged; only the code numbers were reassigned",
        "runtime=PENDING user cold boot",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(rep) + "\n", encoding="utf-8")
    print("\n".join(rep))


if __name__ == "__main__":
    main()
