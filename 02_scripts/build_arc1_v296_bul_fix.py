"""Build v278: the whole translated script, from the original disc, 12px johab.

This is v277 (which rendered correctly on hardware) applied to every translated
line instead of just the opening scene.  The rules that made v277 work are kept
exactly:

    base            the original disc, not the v235 lineage
    PSX.EXE         untouched -- no renderer patch, so glyph numbering is intact
    font            original glyphs stay where they are; Korean goes in cells
                    nothing references any more
    control codes   left in place; only glyph slots are rewritten
    sites           only the 2878 offsets verified against the original script

Cell budget, measured rather than assumed:

    codes reachable                     1235
    needed by the 199 untranslated lines 232   -> kept
    free for Korean                     1003   vs 646 needed

Pieces: Hanme_8x4x4 rendered at 12px (github.com/iolo/8x4x4-fonts, MIT/OFL-1.1).
"""
from __future__ import annotations
import collections
import csv
import functools
import hashlib
import io
import sys
import time
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
FONT_NAME = "Sans_8x4x4.ttf"
ORIG_CSV = ROOT / "05_docs/script_original_full.csv"
TRANS_CSV = ROOT / "05_docs/script_translated_full.csv"
OUT = ROOT / "03_output"
STEM = "arc1_v296_bul_fix_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v296_bul_fix"
COMM = "COMM.IMG"
ROW, CELL, COLS, PL = 896, 12, 21, 4
ONE_MAX = 220
LAST = 0xDB + 3 * 255 + 254
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


def indices(b: bytes) -> set[int]:
    out, i = set(), 0
    while i < len(b):
        x = b[i]
        if x >= 0xE1:
            i += 2
            continue
        w = 1 if x < 0xDD else 2
        if i + w > len(b):
            break
        t = b[i:i + w]
        if w == 1 and 0x01 <= t[0] <= 0xDC:
            out.add(t[0] - 1)
        elif w == 2 and 0xDD <= t[0] <= 0xE0 and 0x01 <= t[1] <= 0xFE:
            out.add((t[0] - 0xDD) * 255 + t[1] + 0xDB)
        i += w
    return out


def main() -> None:
    step("원본 열기")
    with ZipFile(ORIG) as z:
        infos = z.infolist()
        mem = {i.filename: z.read(i.filename) for i in infos if not i.filename.endswith("/")}
    font = bytearray(mem[COMM])

    def ink(idx: int):
        cell, pl = divmod(idx, PL)
        col, row = cell % COLS, cell // COLS
        if (row + 1) * CELL > 504 or (col + 1) * CELL > 252:
            return None
        for y in range(CELL):
            b = (row * CELL + y) * ROW + col * (CELL // 2)
            for x in range(CELL):
                if (font[b + x // 2] >> (0 if x % 2 == 0 else 4)) & 0x0F & (1 << pl):
                    return True
        return False

    def put(idx: int, rows) -> None:
        cell, pl = divmod(idx, PL)
        col, row = cell % COLS, cell // COLS
        bit = 1 << pl
        for y in range(CELL):
            base = (row * CELL + y) * ROW + col * (CELL // 2)
            src = rows[y]
            for x in range(CELL):
                at = base + x // 2
                sh = 0 if x % 2 == 0 else 4
                nib = (font[at] >> sh) & 0x0F
                nib = (nib | bit) if (src >> (CELL - 1 - x)) & 1 else (nib & ~bit & 0x0F)
                font[at] = (font[at] & (0xF0 if sh == 0 else 0x0F)) | (nib << sh)

    step("번역문 읽기")
    trans = {}
    with TRANS_CSV.open(encoding="utf-8-sig", newline="") as fh:
        for r in csv.DictReader(fh):
            t = (r.get("korean") or "").strip()
            if t:
                trans[(r["source file"], int(r["offset"], 0))] = t

    step("원본 대사표 읽기 / 남길 글리프 계산")
    lines = []
    keep = set()
    with ORIG_CSV.open(encoding="utf-8-sig", newline="") as fh:
        for r in csv.DictReader(fh):
            n = r["source file"]
            if n not in mem:
                continue
            off = int(r["byte offset"], 0)
            raw = bytes.fromhex(r["raw bytes as hex"].replace(" ", ""))
            lines.append((n, off, len(raw)))
            if (n, off) not in trans:
                keep |= indices(raw)          # untranslated: its glyphs must survive
    step(f"대사 {len(lines):,}곳,  번역 {len(trans):,},  남길 글리프 {len(keep)}종")

    step("조각 렌더")
    fz = zipfile.ZipFile(FONTZIP)
    ft = ImageFont.truetype(io.BytesIO(fz.read(FONT_NAME)), CELL)

    def render(ch: str):
        im = Image.new("L", (CELL, CELL), 0)
        ImageDraw.Draw(im).text((0, 0), ch, font=ft, fill=255)
        px = im.load()
        out = []
        for y in range(CELL):
            v = 0
            for x in range(CELL):
                if px[x, y] > 96:
                    v |= 1 << (CELL - 1 - x)
            out.append(v)
        return out

    pieces = [render(chr(0xF600 + i)) for i in range(360)]

    def compose(ch: str):
        if "가" <= ch <= "힣":
            x = ord(ch) - 0xAC00
            cho, r = divmod(x, 588)
            jung, jong = divmod(r, 28)
            # Measured from the font itself, not the standard 8-bul table: this
            # face puts "horizontal vowel + final" on set 2, not set 5.  Using 5
            # gave a narrow initial shoved to the left, so 을/글/슬 all leaned.
            cb = grp(jung) + (4 if jong else 0)
            if grp(jung) == 1 and jong:
                cb = 2
            p = [pieces[cb * 20 + cho + 1],
                 pieces[160 + ((1 if cho in (0, 15) else 0) + (2 if jong else 0)) * 22 + jung + 1]]
            if jong:
                p.append(pieces[248 + grp(jung) * 28 + jong])
            return [functools.reduce(lambda a, b: a | b, (q[y] for q in p)) for y in range(CELL)]
        g = render(ch)
        return g if any(g) else None

    need = collections.Counter()
    for t in trans.values():
        for ch in t:
            if ch != " ":
                need[ch] += 1
    step(f"번역문이 쓰는 글자 {len(need)}종")

    # bible_current.txt: one-byte codes 0x68..0xD0 plus D4/D8/DC are the verified
    # safe range.  0x08..0x64 are shared with menus, numbers, HP/MP and name
    # windows -- Korean there bleeds into UI and untranslated Japanese.
    SAFE1 = [c - 1 for c in list(range(0x68, 0xD1)) + [0xD4, 0xD8, 0xDC]]
    reach = SAFE1 + [i for i in range(ONE_MAX, LAST) if encode(i) is not None]
    avail = [i for i in reach if i not in keep]
    space = None
    for i in avail:
        if ink(i) is False:
            space = i
            break
    if space is None:
        raise SystemExit("no blank cell for space")
    avail = [i for i in avail if i != space]

    slot = {}
    missing = 0
    for ch, _ in need.most_common():
        g = compose(ch)
        if not g or not any(g):
            missing += 1
            continue
        if not avail:
            missing += 1
            continue
        ix = avail.pop(0)
        put(ix, g)
        slot[ch] = ix
    step(f"글자 {len(slot)}자 배치,  자리 못 얻음 {missing},  공백 칸 {space},  남은 칸 {len(avail)}")

    sp = encode(space)
    scratch = {n: bytearray(v) for n, v in mem.items()}
    wrote = trunc = 0
    for n, off, ln in lines:
        txt = trans.get((n, off))
        if not txt:
            continue
        src = mem[n]
        e = off
        while e < len(src) and src[e]:
            e += 1
        body = src[off:e]
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
        out = bytearray()
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
        while len(out) + len(sp) <= room:
            out += sp
        out += bytes((sp[0],)) * (room - len(out))
        buf = scratch[n]
        pos = 0
        for a, b in spans:
            k = b - a
            buf[off + a:off + b] = out[pos:pos + k]
            pos += k
        wrote += 1

    scratch[COMM] = font
    for n in scratch:
        if len(scratch[n]) != len(mem[n]):
            raise SystemExit(f"{n} size changed")
    if bytes(scratch["PSX.EXE"]) != mem["PSX.EXE"]:
        raise SystemExit("PSX.EXE must stay untouched")

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

    changed = sorted(n for n in scratch if bytes(scratch[n]) != mem[n])
    rep = [
        "v294 TEST ONLY - 12px johab, verified-safe slots, PSX.EXE untouched",
        f"base={ORIG.name}   font={FONT_NAME} at {CELL}px",
        f"output={out.name}", f"sha256={st}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        f"dialogue sites={len(lines):,}   translated={len(trans):,}   written={wrote:,}",
        f"Korean glyphs placed={len(slot)}   no cell={missing}   truncated lines={trunc}",
        f"glyphs kept for untranslated lines={len(keep)}   cells left={len(avail)}",
        "PSX.EXE untouched; control codes preserved; only verified sites rewritten",
        f"changed members={len(changed)}",
        "runtime=PENDING user cold boot",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(rep) + "\n", encoding="utf-8")
    print("\n".join(rep))


if __name__ == "__main__":
    main()
