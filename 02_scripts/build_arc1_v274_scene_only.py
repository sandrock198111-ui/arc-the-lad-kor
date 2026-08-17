"""Build v271: start over from the original disc, 16px, first scene in Korean.

Every build since v250 was based on v235, which carries several generations of
glyph renumbering.  That lineage had 2634 distinct codes -- more than two-byte
codes can address -- and no surviving record of what each one meant, which is
why decoding stalled at 54%.

The original disc has none of that:

    codes in use      1041      (v235 lineage: 2634)
    two-byte needed    821      (limit 1019)
    atlas at 15 cols   288px    (limit 504)

So the 16px layout fits with room to spare and nothing has to be decoded -- the
original pictures are all present and simply move to their new cell.

Scope of this build is deliberately small: the opening scene in 1/S1011.DAT is
re-encoded into Korean composed from johab pieces; everything else keeps its
original Japanese glyph, carried to the new layout so it still renders.

Pieces: Pilgi_8x4x4 rendered at 16px (github.com/iolo/8x4x4-fonts, MIT/OFL-1.1).
"""
from __future__ import annotations
import collections
import csv
import functools
import hashlib
import io
import struct
import sys
import time
import zipfile
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
from PIL import Image, ImageFont, ImageDraw  # noqa: E402

ORIG = ROOT / "00_original/arc.zip"
FONTZIP = Path("C:/Users/Administrator/Downloads/8x4x4-fonts-all.zip")
FONT_NAME = "Pilgi_8x4x4.ttf"
TRANS = ROOT / "05_docs/script_translated_full.csv"
OUT = ROOT / "03_output"
STEM = "arc1_v274_scene_only_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v274_scene_only"
SCENE = "1/S1011.DAT"
PSX, COMM = "PSX.EXE", "COMM.IMG"
R2F = 0x8011A800
ROW = 896
OLDC, OLDCOLS = 12, 21
NEWC, COLS, PL = 16, 15, 4
ONE_MAX = 220
LAST = 0xDB + 3 * 255 + 254
BASE_OFF = 0x45000
STRIDE_AT, OLD_STRIDE = 0x8016B530, 84
SHIFT_SITES = (0x8016B58C, 0x8016B59C)
LITERAL_SITES = (0x8016B160, 0x8016B6E0, 0x8016B348, 0x8016B394, 0x8016B398)
A = {0, 1, 2, 3, 4, 5, 6, 7, 20}
B = {8, 12, 18}
C = {13, 17}


def step(m: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


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


def old_index(tok: bytes) -> int | None:
    if len(tok) == 1:
        return tok[0] - 1 if 0x01 <= tok[0] <= 0xDC else None
    lead, trail = tok
    if 0xDD <= lead <= 0xE8 and 0x01 <= trail <= 0xFE:
        return (lead - 0xDD) * 255 + trail + 0xDB
    return None


def read_old(font: bytes, idx: int):
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


def scan(d: bytes):
    res = []
    i, L = BASE_OFF, len(d)
    while i < L:
        if d[i] == 0:
            i += 1
            continue
        j = i
        while j < L and d[j]:
            j += 1
        seg = d[i:j]
        ok, k, nt = True, 0, 0
        while k < len(seg):
            b = seg[k]
            if b == 0xE2 or 0xE3 <= b <= 0xE8:
                if k + 1 >= len(seg):
                    ok = False
                    break
                k += 2
                continue
            if 0x01 <= b <= 0xDC:
                k += 1
                nt += 1
                continue
            if 0xDD <= b <= 0xEA and k + 1 < len(seg) and 0x01 <= seg[k + 1] <= 0xFE:
                k += 2
                nt += 1
                continue
            ok = False
            break
        if ok and nt >= 2:
            res.append((i, j - i))
        i = j
    return res


def main() -> None:
    step("원본 열기")
    with ZipFile(ORIG) as z:
        infos = z.infolist()
        before = {i.filename: z.read(i.filename) for i in infos if not i.filename.endswith("/")}
    members = dict(before)
    oldfont = members[COMM]

    step("조각 렌더")
    fz = zipfile.ZipFile(FONTZIP)
    ft = ImageFont.truetype(io.BytesIO(fz.read(FONT_NAME)), NEWC)
    pieces = []
    for i in range(360):
        im = Image.new("L", (NEWC, NEWC), 0)
        ImageDraw.Draw(im).text((0, 0), chr(0xF600 + i), font=ft, fill=255)
        px = im.load()
        r = []
        for y in range(NEWC):
            v = 0
            for x in range(NEWC):
                if px[x, y] > 96:
                    v |= 1 << (NEWC - 1 - x)
            r.append(v)
        pieces.append(r)

    def compose(ch: str):
        if not ("가" <= ch <= "힣"):
            return None
        x = ord(ch) - 0xAC00
        cho, r = divmod(x, 588)
        jung, jong = divmod(r, 28)
        p = [pieces[(grp(jung) + (4 if jong else 0)) * 20 + cho + 1],
             pieces[160 + ((1 if cho in (0, 15) else 0) + (2 if jong else 0)) * 22 + jung + 1]]
        if jong:
            p.append(pieces[248 + grp(jung) * 28 + jong])
        return [functools.reduce(lambda a, b: a | b, (q[y] for q in p)) for y in range(NEWC)]

    # Only the 2878 sites verified against the original script.  v271 scanned for
    # "runs that look like text" and found 54,212 -- most of them game data, and
    # rewriting those is what produced the black screen.
    step("대사 자리 = 원본 대사표만")
    sites = collections.defaultdict(list)
    with (ROOT / "05_docs/script_original_full.csv").open(encoding="utf-8-sig", newline="") as fh:
        for r in csv.DictReader(fh):
            n = r["source file"]
            if n not in before:
                continue
            try:
                off = int(r["byte offset"], 0)
                ln = len(bytes.fromhex(r["raw bytes as hex"].replace(" ", "")))
            except Exception:
                continue
            if 0 <= off and off + ln <= len(before[n]):
                sites[n].append((off, ln))
    sites = dict(sites)

    # Korean for the opening scene
    kr = {}
    with TRANS.open(encoding="utf-8-sig", newline="") as fh:
        for r in csv.DictReader(fh):
            if r["source file"] != SCENE:
                continue
            t = (r.get("korean") or "").strip()
            if not t:
                continue
            try:
                kr[int(r["offset"], 0)] = t
            except Exception:
                pass
    step(f"대사 자리 {sum(len(v) for v in sites.values()):,}곳,  장면 번역 {len(kr)}건")

    uses = collections.Counter()
    width = collections.defaultdict(set)
    for n, sp in sites.items():
        d = before[n]
        for off, ln in sp:
            i, e = off, off + ln
            while i < e:
                b = d[i]
                if b == 0xE2 or 0xE3 <= b <= 0xE8:
                    i += 2
                    continue
                w = 1 if b < 0xDD else 2
                if i + w > e:
                    break
                t = bytes(d[i:i + w])
                uses[t] += 1
                width[t].add(w)
                i += w

    art = {}
    for t in uses:
        gi = old_index(t)
        if gi is None:
            continue
        p = read_old(oldfont, gi)
        if p and any(p):
            art[t] = p
    step(f"토큰 {len(uses)}종,  그림 확보 {len(art)}종")

    # Korean characters used by the scene need their own cells
    chars = sorted({c for t in kr.values() for c in t if "가" <= c <= "힣"})
    kpic = {c: compose(c) for c in chars}
    kpic = {c: g for c, g in kpic.items() if g and any(g)}
    step(f"장면 한글 {len(kpic)}자")

    one = sorted((t for t in art if 1 in width[t]), key=lambda t: -uses[t])
    two = sorted((t for t in art if 2 in width[t]), key=lambda t: -uses[t])
    if len(one) > ONE_MAX - 1:
        one = one[:ONE_MAX - 1]
    a1 = {t: n for n, t in enumerate(one)}
    nxt = ONE_MAX
    a2 = {}
    for t in two:
        while nxt <= LAST and encode(nxt) is None:
            nxt += 1
        if nxt > LAST - 1:
            break
        a2[t] = nxt
        nxt += 1
    kslot = {}
    for c in kpic:
        while nxt <= LAST and encode(nxt) is None:
            nxt += 1
        if nxt > LAST - 1:
            raise SystemExit("no room for scene Korean")
        kslot[c] = nxt
        nxt += 1
    blank = min(nxt, LAST)
    cells = -(-(blank + 1) // PL)
    need = -(-cells // COLS)
    if COLS * NEWC > 252 or need * NEWC > 504:
        raise SystemExit(f"atlas {COLS * NEWC}x{need * NEWC} too tall")
    step(f"칸 {cells}개, {COLS}x{need} = {COLS*NEWC}x{need*NEWC}px, 배치")

    font = bytearray(members[COMM])
    for y in range(need * NEWC):
        b = y * ROW
        font[b:b + COLS * (NEWC // 2)] = bytes(COLS * (NEWC // 2))
    for t, ix in list(a1.items()) + list(a2.items()):
        put(font, ix, art[t])
    for c, ix in kslot.items():
        put(font, ix, kpic[c])

    remap = {}
    for t in uses:
        for w in width[t]:
            tbl = a1 if w == 1 else a2
            ix = tbl.get(t, blank)
            c = encode(ix)
            if c is None or len(c) != w:
                c = encode(blank if w == 2 else ONE_MAX - 1)
                if len(c) != w:
                    c = bytes((ONE_MAX - 1,)) if w == 1 else encode(blank)
            remap[(t, w)] = c

    step("재인코딩")
    scratch = {n: bytearray(v) for n, v in before.items()}
    done = 0
    for n, sp in sites.items():
        buf = scratch[n]
        for off, ln in sp:
            i, e = off, off + ln
            while i < e:
                b = buf[i]
                if b == 0xE2 or 0xE3 <= b <= 0xE8:
                    i += 2
                    continue
                w = 1 if b < 0xDD else 2
                if i + w > e:
                    break
                k = (bytes(buf[i:i + w]), w)
                if k in remap:
                    buf[i:i + w] = remap[k]
                    done += 1
                i += w

    # write the opening scene in Korean, in place, keeping control codes
    space = encode(blank)
    wrote = trunc = 0
    buf = scratch[SCENE]
    src = before[SCENE]
    for off, txt in kr.items():
        e = off
        while e < len(src) and src[e]:
            e += 1
        cap = e - off
        out = bytearray()
        for ch in txt:
            g = kslot.get(ch)
            code = encode(g) if g is not None else None
            if code is None:
                code = bytes((0x9C,)) if ch == " " else None
            if code is None:
                continue
            if len(out) + len(code) > cap:
                trunc += 1
                break
            out += code
        out += bytes((0x9C,)) * (cap - len(out))
        buf[off:off + cap] = out
        wrote += 1

    exe = bytearray(scratch[PSX])

    def word(a):
        return struct.unpack_from("<I", exe, a - R2F)[0]

    for a in SHIFT_SITES:
        w0, w1v, w2v = word(a), word(a + 4), word(a + 8)
        rt, rd = (w0 >> 16) & 0x1F, (w0 >> 11) & 0x1F
        struct.pack_into("<I", exe, a - R2F, (rt << 16) | (rd << 11) | (4 << 6))
        struct.pack_into("<I", exe, a + 4 - R2F, 0)
        struct.pack_into("<I", exe, a + 8 - R2F, 0)
    for a in LITERAL_SITES:
        w0 = word(a)
        struct.pack_into("<I", exe, a - R2F, (w0 & ~0xFFFF) | NEWC)
    w0 = word(STRIDE_AT)
    if (w0 & 0xFFFF) != OLD_STRIDE:
        raise SystemExit(f"stride site {w0:08X}")
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
            if i.filename.endswith("/"):
                z.writestr(clone(i), b"")
            else:
                z.writestr(clone(i), members[i.filename])
    st = digest(tmp.read_bytes())
    out = OUT / f"{STEM}_{st[:8]}.zip"
    tmp.replace(out)

    rep = [
        "v274 TEST ONLY - original disc, 16px, verified dialogue sites only, opening scene in Korean",
        f"base={ORIG.name}   font={FONT_NAME} at {NEWC}px",
        f"output={out.name}", f"sha256={st}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        f"dialogue sites={sum(len(v) for v in sites.values()):,}   tokens={len(uses)}",
        f"pictures carried={len(a1)+len(a2)}   scene Korean glyphs={len(kslot)}",
        f"atlas={cells} cells, {COLS}x{need}, {COLS*NEWC}x{need*NEWC} px",
        f"codes rewritten={done:,}   scene lines written={wrote}   truncated={trunc}",
        f"scene={SCENE}",
        "renderer 12px -> 16px (7 sites), row stride 84 -> 60",
        "runtime=PENDING user cold boot",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(rep) + "\n", encoding="utf-8")
    print("\n".join(rep))


if __name__ == "__main__":
    main()
