"""Build v270: 16px johab for Korean, carried pixels for everything else.

What finally made this possible was realising the "undecoded" codes are not
Korean at all -- the top 40 by frequency draw as の い に は た て し で が な る
か を れ ま す, i.e. untranslated Japanese.  They never needed decoding; they
need translating, which is a separate job.  So:

    code is Korean (643 decoded)   -> compose it from the 8-bul pieces at 16px
    anything else                  -> copy its existing 12x12 picture
    no room / no picture           -> blank cell

Sites come from two lists, both exact:

    dialogue_sites_full.csv   39,457 dialogue slots, read off the file layout
    ui_full_v42.csv              503 UI strings with their offsets in PSX.EXE

v269 tried to find the UI strings by scanning 0x78000..0x83000 for null-
terminated runs and rewrote executable code as if it were text, which is why it
would not boot.  This build only touches the offsets the table names.

Two-byte codes reach index 1238, so the atlas cannot hold every picture; the
least-used ones fall back to blank.  Korean is placed first so translated text
never loses a glyph to an untranslated one.
"""
from __future__ import annotations
import collections
import csv
import functools
import hashlib
import pickle
import struct
import sys
import time
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

OUT = ROOT / "03_output"
ART = ROOT / "01_work/analysis/hangul_johab_16px"
SITES = ROOT / "05_docs/dialogue_sites_full.csv"
UI = ROOT / "05_docs/ui_full_v42.csv"
CACHE_PIX = ROOT / "01_work/analysis/cache_glyphs/glyphs.pkl"
MAP = ART / "code_map_voted.pkl"
STEM = "arc1_v270_johab_final_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v270_johab_final"
PSX, COMM = "PSX.EXE", "COMM.IMG"
R2F = 0x8011A800
ROW = 896
OLDC, OLDCOLS = 12, 21
NEWC, COLS, PL = 16, 15, 4
ONE_MAX = 220
LAST = 0xDB + 3 * 255 + 254
STRIDE_AT, OLD_STRIDE = 0x8016B530, 84
TABLE, SLOTS, CACHE_MARK = 0x801A7520, 0x19D, 0x600
A = {0, 1, 2, 3, 4, 5, 6, 7, 20}
B = {8, 12, 18}
C = {13, 17}


def step(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


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


def tget(exe: bytes, slot: int) -> int:
    b = slot * 11
    byt, off = divmod(b, 8)
    a = TABLE - R2F + byt
    return ((exe[a] | (exe[a + 1] << 8) | (exe[a + 2] << 16)) >> off) & 0x7FF


def index_of(tok: bytes, exe: bytes) -> tuple[int | None, int | None]:
    if len(tok) == 1:
        return (tok[0] - 1, None) if 0x01 <= tok[0] <= 0xDC else (None, None)
    lead, trail = tok
    if lead in (0xE9, 0xEA):
        s = (lead - 0xE9) * 254 + trail - 1
        if not 0 <= s < SLOTS:
            return None, None
        v = tget(exe, s)
        return (v, None) if v < CACHE_MARK else (None, s)
    if 0xDD <= lead <= 0xE8 and 0x01 <= trail <= 0xFE:
        return (lead - 0xDD) * 255 + trail + 0xDB, None
    return None, None


def read_old(font: bytes, idx: int) -> list[int] | None:
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
                v |= 1 << (NEWC - 1 - x)
        out.append(v)
    return out + [0] * (NEWC - OLDC)


def put(font: bytearray, idx: int, rows) -> None:
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


def load_sites(exe_len: int) -> dict[str, list[tuple[int, int]]]:
    out = collections.defaultdict(list)
    with SITES.open(encoding="utf-8-sig", newline="") as fh:
        for r in csv.DictReader(fh):
            out[r["file"]].append((int(r["offset"], 16), int(r["bytes"])))
    with UI.open(encoding="utf-8-sig", newline="") as fh:
        for r in csv.DictReader(fh):
            try:
                off = int(r["string_offset"], 0)
                ln = len(bytes.fromhex(r["encoded_hex"].replace(" ", "")))
            except Exception:
                continue
            if 0 < ln and 0 <= off < exe_len - ln:
                out[PSX].append((off, ln))
    return out


def main() -> None:
    step("base 열기")
    base_path = sorted(OUT.glob("arc1_v238_glyph_16px_TEST_ONLY_*.zip"))[-1]
    with ZipFile(base_path) as z:
        infos = z.infolist()
        before = {i.filename: z.read(i.filename) for i in infos}
    members = dict(before)
    exe0 = bytes(members[PSX])
    oldfont = members[COMM]
    cache_pix = pickle.load(open(CACHE_PIX, "rb"))
    kmap = pickle.load(open(MAP, "rb"))
    site_map = load_sites(len(exe0))
    step(f"사이트 {sum(len(v) for v in site_map.values()):,}곳  "
         f"(UI {len(site_map.get(PSX, []))}곳 포함)")

    raw = (ART / "pieces_1bpp.bin").read_bytes()
    piece = lambda i: [struct.unpack_from(">H", raw, (i * 16 + y) * 2)[0] for y in range(16)]
    ascii_g = pickle.load(open(ART / "ascii_16px.pkl", "rb"))
    OR = lambda *g: [functools.reduce(lambda a, b: a | b, (x[y] for x in g)) for y in range(16)]

    def compose(ch: str):
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
    for name, spans in site_map.items():
        if name not in before:
            continue
        d = before[name]
        for off, ln in spans:
            i, end = off, min(off + ln, len(d))
            while i < end:
                b = d[i]
                if b == 0xE2 or 0xE3 <= b <= 0xE8:
                    i += 2
                    continue
                w = 1 if b < 0xDD else 2
                if i + w > end:
                    break
                tok = bytes(d[i:i + w])
                uses[tok] += 1
                width[tok].add(w)
                i += w
    step(f"토큰 {len(uses)}종")

    art = {}
    korean = set()
    n_johab = n_carry = 0
    for tok in uses:
        ch = kmap.get(tok)
        g = compose(ch) if ch else None
        if g and any(g):
            art[tok] = g
            korean.add(tok)
            n_johab += 1
            continue
        gi, cs = index_of(tok, exe0)
        pic = None
        if gi is not None:
            pic = read_old(oldfont, gi)
            pic = pic if pic and any(pic) else None
        elif cs is not None and cs in cache_pix:
            rows = cache_pix[cs]
            pic = [(r << 4) & 0xFFFF for r in rows][:NEWC] + [0] * max(0, NEWC - len(rows))
            pic = pic if any(pic) else None
        if pic:
            art[tok] = pic
            n_carry += 1
    step(f"그림 {len(art)}종  (조합형 {n_johab}, 옛 그림 {n_carry})")

    # fold identical pictures, Korean first so translated text keeps its glyphs
    shape = {t: tuple(art[t]) for t in art}
    pu = collections.Counter()
    for t in art:
        pu[shape[t]] += uses[t] + (10 ** 6 if t in korean else 0)
    pics1 = sorted({shape[t] for t in art if 1 in width[t]}, key=lambda p: -pu[p])
    pics2 = sorted({shape[t] for t in art if 2 in width[t]}, key=lambda p: -pu[p])
    if len(pics1) > ONE_MAX - 1:
        pics1 = pics1[:ONE_MAX - 1]
    p1 = {p: n for n, p in enumerate(pics1)}
    blank1 = len(pics1)
    nxt = ONE_MAX
    p2 = {}
    overflow = 0
    for p in pics2:
        while nxt <= LAST and encode(nxt) is None:
            nxt += 1
        if nxt > LAST - 1:
            overflow += 1
            continue
        p2[p] = nxt
        nxt += 1
    blank2 = min(nxt, LAST)
    cells = -(-(blank2 + 1) // PL)
    need = -(-cells // COLS)
    if COLS * NEWC > 252 or need * NEWC > 504:
        raise SystemExit(f"atlas {COLS * NEWC}x{need * NEWC} leaves the glyph area")
    step(f"고유 그림 {len(p1) + len(p2)}종, 넘침 {overflow}, 배치 시작")

    font = bytearray(members[COMM])
    for y in range(need * NEWC):
        b = y * ROW
        font[b:b + COLS * (NEWC // 2)] = bytes(COLS * (NEWC // 2))
    for pic, ix in list(p1.items()) + list(p2.items()):
        put(font, ix, list(pic))

    remap = {}
    for t in uses:
        for w in width[t]:
            tbl = p1 if w == 1 else p2
            ix = tbl.get(shape.get(t), blank1 if w == 1 else blank2)
            c = encode(ix)
            if c is None or len(c) != w:
                ix = blank1 if w == 1 else blank2
                c = encode(ix)
            remap[(t, w)] = c
    step("대본 재인코딩")

    scratch = {n: bytearray(v) for n, v in before.items()}
    done = 0
    for name, spans in site_map.items():
        if name not in scratch:
            continue
        buf = scratch[name]
        for off, ln in spans:
            i, end = off, min(off + ln, len(buf))
            while i < end:
                b = buf[i]
                if b == 0xE2 or 0xE3 <= b <= 0xE8:
                    i += 2
                    continue
                w = 1 if b < 0xDD else 2
                if i + w > end:
                    break
                key = (bytes(buf[i:i + w]), w)
                if key in remap:
                    buf[i:i + w] = remap[key]
                    done += 1
                i += w

    exe = bytearray(scratch[PSX])
    w0 = struct.unpack_from("<I", exe, STRIDE_AT - R2F)[0]
    if (w0 >> 26) != 0x0D or (w0 & 0xFFFF) != OLD_STRIDE:
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

    step("zip 압축")
    OUT.mkdir(parents=True, exist_ok=True)
    tmp = OUT / f"{STEM}_building.zip"
    if tmp.exists():
        tmp.unlink()
    with ZipFile(tmp, "w", ZIP_DEFLATED, compresslevel=1) as z:
        for i in infos:
            z.writestr(clone(i), members[i.filename])
    st = digest(tmp.read_bytes())
    out = OUT / f"{STEM}_{st[:8]}.zip"
    tmp.replace(out)

    kr_uses = sum(uses[t] for t in korean)
    tot = sum(uses.values())
    rep = [
        "v270 TEST ONLY - Korean drawn from johab pieces at 16px, rest carried",
        f"base={base_path.name}", f"output={out.name}", f"sha256={st}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        f"sites={sum(len(v) for v in site_map.values()):,}"
        f"  (dialogue {sum(len(v) for k, v in site_map.items() if k != PSX):,},"
        f" UI strings {len(site_map.get(PSX, []))})",
        f"tokens={len(uses)}   johab-composed={n_johab}   carried pictures={n_carry}",
        f"Korean glyph uses={kr_uses:,}/{tot:,}  ({kr_uses * 100 // max(tot,1)}%)",
        f"atlas={cells} cells, {COLS}x{need}, {COLS * NEWC}x{need * NEWC} px",
        f"one-byte {len(p1)}   two-byte {len(p2)}   overflow to blank={overflow}",
        f"codes rewritten={done:,}",
        "UI strings taken from ui_full_v42.csv offsets, not by scanning for nulls",
        "widths preserved; pointers and file sizes unchanged",
        "runtime=PENDING user cold boot",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(rep) + "\n", encoding="utf-8")
    print("\n".join(rep))


if __name__ == "__main__":
    main()
