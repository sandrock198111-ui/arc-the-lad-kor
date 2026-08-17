"""Build v279: the whole translated script at 16px, from the original disc.

v278 proved the pipeline on hardware but kept 12px.  This is the same build with
the renderer raised to 16px, which v273 already showed boots on the original
disc (that build was the renderer patch alone, 22 bytes, and it ran).

Raising the cell to 16px forces 15 columns instead of 21 (U is one byte, so the
atlas cannot exceed 255px wide), and that renumbers every glyph.  So unlike v278
this build must also rewrite the codes -- but only inside the 2878 offsets
verified against the original script.  v271 scanned for text-looking runs, found
54,212, rewrote game data among them and produced a black screen; that mistake
is not repeated here.

    glyphs kept for the 199 untranslated lines   232
    Korean glyphs                                672
    total ~904 -> 226 cells -> 15 x 16 rows = 240x256px, inside 252x504

Pieces: Hanme_8x4x4 rendered at 16px (github.com/iolo/8x4x4-fonts, MIT/OFL-1.1).
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
import pickle
import zipfile
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
from PIL import Image, ImageFont, ImageDraw  # noqa: E402

ORIG = ROOT / "00_original/arc.zip"
FONTZIP = Path("C:/Users/Administrator/Downloads/8x4x4-fonts-all.zip")
FONT_NAME = "Hanme_8x4x4.ttf"
ORIG_CSV = ROOT / "05_docs/script_original_full.csv"
TRANS_CSV = ROOT / "05_docs/script_translated_full.csv"
OUT = ROOT / "03_output"
STEM = "arc1_v287_bounded_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v287_bounded"
PSX, COMM = "PSX.EXE", "COMM.IMG"
R2F = 0x8011A800
ROW = 896
OLDC, OLDCOLS = 12, 21
NEWC, COLS, PL = 16, 15, 4
ONE_MAX = 220
LAST = 0xDB + 3 * 255 + 254
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


def tokens(b: bytes):
    out, i = [], 0
    while i < len(b):
        x = b[i]
        if x >= 0xE1:
            i += 2
            continue
        w = 1 if x < 0xDD else 2
        if i + w > len(b):
            break
        out.append(bytes(b[i:i + w]))
        i += w
    return out


def main() -> None:
    step("원본 열기")
    with ZipFile(ORIG) as z:
        infos = z.infolist()
        mem = {i.filename: z.read(i.filename) for i in infos if not i.filename.endswith("/")}
    oldfont = mem[COMM]

    step("번역문 / 대사표")
    trans = {}
    with TRANS_CSV.open(encoding="utf-8-sig", newline="") as fh:
        for r in csv.DictReader(fh):
            t = (r.get("korean") or "").strip()
            if t:
                trans[(r["source file"], int(r["offset"], 0))] = t
    lines = []
    with ORIG_CSV.open(encoding="utf-8-sig", newline="") as fh:
        for r in csv.DictReader(fh):
            n = r["source file"]
            if n not in mem:
                continue
            off = int(r["byte offset"], 0)
            raw = bytes.fromhex(r["raw bytes as hex"].replace(" ", ""))
            lines.append((n, off, len(raw)))
    ptr = ROOT / "01_work/analysis/exe_strings_filtered.pkl"
    n_ui = 0
    if ptr.exists():
        for off, ln in sorted(pickle.load(open(ptr, "rb")).items()):
            if off + ln <= len(mem[PSX]):
                lines.append((PSX, off, ln))
                n_ui += 1
    step(f"EXE 문자열 {n_ui}곳 (포인터 추적)")

    # every token the verified sites use, and which of them survive translation
    uses = collections.Counter()
    width = collections.defaultdict(set)
    for n, off, ln in lines:
        d = mem[n]
        e = off
        while e < len(d) and d[e]:
            e += 1
        # never run past the length the site list gives: for PSX.EXE the null
        # scan walks into executable code that follows the string
        if ln:
            e = min(e, off + ln)
        body = d[off:e]
        keep_this = (n, off) not in trans
        for t in tokens(body):
            width[t].add(len(t))
            if keep_this:
                uses[t] += 1
            else:
                uses.setdefault(t, 0)
    kept = [t for t in uses if uses[t] > 0]
    step(f"대사 {len(lines):,}곳,  번역 {len(trans):,},  미번역이 쓰는 코드 {len(kept)}종")

    step("조각 렌더")
    fz = zipfile.ZipFile(FONTZIP)
    ft = ImageFont.truetype(io.BytesIO(fz.read(FONT_NAME)), NEWC)

    def render(ch: str):
        im = Image.new("L", (NEWC, NEWC), 0)
        ImageDraw.Draw(im).text((0, 0), ch, font=ft, fill=255)
        px = im.load()
        out = []
        for y in range(NEWC):
            v = 0
            for x in range(NEWC):
                if px[x, y] > 96:
                    v |= 1 << (NEWC - 1 - x)
            out.append(v)
        return out

    pieces = [render(chr(0xF600 + i)) for i in range(360)]

    def compose(ch: str):
        if "가" <= ch <= "힣":
            x = ord(ch) - 0xAC00
            cho, r = divmod(x, 588)
            jung, jong = divmod(r, 28)
            p = [pieces[(grp(jung) + (4 if jong else 0)) * 20 + cho + 1],
                 pieces[160 + ((1 if cho in (0, 15) else 0) + (2 if jong else 0)) * 22 + jung + 1]]
            if jong:
                p.append(pieces[248 + grp(jung) * 28 + jong])
            return [functools.reduce(lambda a, b: a | b, (q[y] for q in p)) for y in range(NEWC)]
        g = render(ch)
        return g if any(g) else None

    need = collections.Counter()
    for t in trans.values():
        for ch in t:
            if ch != " ":
                need[ch] += 1
    step(f"한글 등 {len(need)}종 필요")

    # layout: kept Japanese first (they must keep a picture), then Korean
    nxt = 0
    a1, a2 = {}, {}
    for t in sorted(kept, key=lambda t: -uses[t]):
        pic = read_old(oldfont, old_index(t) if old_index(t) is not None else -1)
        if not pic or not any(pic):
            continue
        w = 1 if 1 in width[t] else 2
        if w == 1:
            if nxt >= ONE_MAX - 1:
                continue
            a1[t] = nxt
            nxt += 1
        else:
            a2[t] = None
    nxt = max(nxt, ONE_MAX)
    two_pics = {}
    for t in list(a2):
        pic = read_old(oldfont, old_index(t))
        if not pic or not any(pic):
            del a2[t]
            continue
        while nxt <= LAST and encode(nxt) is None:
            nxt += 1
        if nxt > LAST - 1:
            del a2[t]
            continue
        a2[t] = nxt
        two_pics[nxt] = pic
        nxt += 1
    # The most-used Korean must get one-byte codes: a one-byte glyph takes half
    # the room of a two-byte one, and v279 put every Korean letter in the
    # two-byte range, which is why 2,556 lines were cut.  The 82 one-byte cells
    # the untranslated lines do not need cover 68% of all Korean characters.
    space = None
    slot = {}
    kpic = {}
    one_taken = set(a1.values())
    free_one = [i for i in range(ONE_MAX - 1) if i not in one_taken]
    if not free_one:
        raise SystemExit("no one-byte cell for space")
    space = free_one.pop(0)          # padding must be a one-byte code, or the
                                     # leftover half-code derails the stream
    for ch, _ in need.most_common():
        g = compose(ch)
        if not g or not any(g):
            continue
        if free_one:
            ix = free_one.pop(0)
        else:
            while nxt <= LAST and encode(nxt) is None:
                nxt += 1
            if nxt > LAST - 1:
                break
            ix = nxt
            nxt += 1
        slot[ch] = ix
        kpic[ix] = g
    cells = -(-(max(nxt, space) + 1) // PL)
    need_rows = -(-cells // COLS)
    if COLS * NEWC > 252 or need_rows * NEWC > 504:
        raise SystemExit(f"atlas {COLS*NEWC}x{need_rows*NEWC} too tall")
    step(f"칸 {cells}개 = {COLS}x{need_rows} = {COLS*NEWC}x{need_rows*NEWC}px,  "
         f"일본어 {len(a1)+len(a2)}종,  한글 {len(slot)}자")

    font = bytearray(mem[COMM])
    for y in range(need_rows * NEWC):
        b = y * ROW
        font[b:b + COLS * (NEWC // 2)] = bytes(COLS * (NEWC // 2))
    for t, ix in a1.items():
        put(font, ix, read_old(oldfont, old_index(t)))
    for ix, pic in two_pics.items():
        put(font, ix, pic)
    for ix, g in kpic.items():
        put(font, ix, g)

    remap = {}
    for t in list(a1.items()) + list(a2.items()):
        tok, ix = t
        c = encode(ix)
        if c and len(c) == len(tok):
            remap[tok] = c
    sp = encode(space)

    step("재인코딩")
    scratch = {n: bytearray(v) for n, v in mem.items()}
    wrote = trunc = 0
    for n, off, ln in lines:
        d = mem[n]
        e = off
        while e < len(d) and d[e]:
            e += 1
        # never run past the length the site list gives: for PSX.EXE the null
        # scan walks into executable code that follows the string
        if ln:
            e = min(e, off + ln)
        body = d[off:e]
        spans, i = [], 0
        while i < len(body):
            b = body[i]
            if b >= 0xE1:
                i += 2
                continue
            j = i
            while j < len(body):
                b2 = body[j]
                if b2 >= 0xE1:
                    break
                j += 1 if b2 < 0xDD else 2
            spans.append((i, min(j, len(body))))
            i = j
        room = sum(b - a for a, b in spans)
        txt = trans.get((n, off))
        out = bytearray()
        if txt:
            cut = False
            for ch in txt:
                code = sp if ch == " " else (encode(slot[ch]) if ch in slot else None)
                if code is None:
                    continue
                if len(out) + len(code) > room:
                    cut = True
                    break
                out += code
            if cut:
                trunc += 1
            wrote += 1
        else:
            for tok in tokens(body):
                c = remap.get(tok)
                if c is None:
                    continue
                if len(out) + len(c) > room:
                    break
                out += c
        while len(out) + len(sp) <= room:
            out += sp
        out += bytes((sp[0],)) * (room - len(out))
        buf = scratch[n]
        pos = 0
        for a, b in spans:
            k = b - a
            buf[off + a:off + b] = out[pos:pos + k]
            pos += k

    exe = bytearray(scratch[PSX])

    def word(a):
        return struct.unpack_from("<I", exe, a - R2F)[0]

    for a in SHIFT_SITES:
        w0 = word(a)
        rt, rd = (w0 >> 16) & 0x1F, (w0 >> 11) & 0x1F
        struct.pack_into("<I", exe, a - R2F, (rt << 16) | (rd << 11) | (4 << 6))
        struct.pack_into("<I", exe, a + 4 - R2F, 0)
        struct.pack_into("<I", exe, a + 8 - R2F, 0)
    for a in LITERAL_SITES:
        w0 = word(a)
        if (w0 >> 26) != 0x0D or (w0 & 0xFFFF) != 12:
            raise SystemExit(f"{a:08X} is not ori 12")
        struct.pack_into("<I", exe, a - R2F, (w0 & ~0xFFFF) | NEWC)
    w0 = word(STRIDE_AT)
    if (w0 & 0xFFFF) != OLD_STRIDE:
        raise SystemExit("stride site")
    struct.pack_into("<I", exe, STRIDE_AT - R2F, (w0 & ~0xFFFF) | (COLS * PL))
    scratch[PSX] = exe
    scratch[COMM] = font
    for n in scratch:
        if len(scratch[n]) != len(mem[n]):
            raise SystemExit(f"{n} size changed")

    step("zip 압축")
    OUT.mkdir(parents=True, exist_ok=True)
    tmp = OUT / f"{STEM}_building.zip"
    if tmp.exists():
        tmp.unlink()
    with ZipFile(tmp, "w", ZIP_DEFLATED, compresslevel=1) as z:
        for i in infos:
            z.writestr(clone(i), b"" if i.filename.endswith("/") else bytes(scratch[i.filename]))
    st = hashlib.sha256(tmp.read_bytes()).hexdigest().upper()
    out = OUT / f"{STEM}_{st[:8]}.zip"
    tmp.replace(out)

    rep = [
        "v287 TEST ONLY - 16px, writes bounded to the recorded string length",
        f"base={ORIG.name}   font={FONT_NAME} at {NEWC}px",
        f"output={out.name}", f"sha256={st}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        f"dialogue sites={len(lines):,}   translated written={wrote:,}   truncated={trunc:,}",
        f"Japanese glyphs kept={len(a1)+len(a2)}   Korean glyphs={len(slot)}"
        f"   one-byte Korean={sum(1 for v in slot.values() if v < ONE_MAX-1)}",
        f"atlas={cells} cells, {COLS}x{need_rows}, {COLS*NEWC}x{need_rows*NEWC} px",
        "renderer 12px -> 16px (7 sites), row stride 84 -> 60",
        "only the 2878 verified sites rewritten; control codes preserved",
        "runtime=PENDING user cold boot",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(rep) + "\n", encoding="utf-8")
    print("\n".join(rep))


if __name__ == "__main__":
    main()
