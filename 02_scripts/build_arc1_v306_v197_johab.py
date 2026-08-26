"""Build v306: take the shipped v197 and swap only its Hangul glyphs to johab.

Rebuilding everything from the original disc kept re-breaking things v197 had
already solved -- dialogue placement, UI strings, battle icons.  v197 is a
finished release: 94% of dialogue, 391 UI strings, icons intact.  The only thing
it does not have is the johab typeface.

So this touches one file and 188 cells:

    base        arc1_v197_prompt_width_off_by_one.zip
    changed     COMM.IMG only -- the 188 cells whose character is known
    untouched   every DAT, PSX.EXE, and the 80 cells whose character is unknown

Cells v197 wrote but we cannot identify keep their original completed-syllable
picture.  Mixed typefaces look uneven but nothing breaks, which is the right
trade while the decode table is incomplete.

Pieces: Sans_8x4x4 rendered at 12px (github.com/iolo/8x4x4-fonts, MIT/OFL-1.1).
"""
from __future__ import annotations
import functools
import hashlib
import io
import pickle
import sys
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

BASE = ROOT / "03_output/arc1_v197_prompt_width_off_by_one.zip"
FONTZIP = Path("C:/Users/Administrator/Downloads/8x4x4-fonts-all.zip")
FONT_NAME = "Sans_8x4x4.ttf"
CELLMAP = ROOT / "01_work/analysis/v197_cell_chars.pkl"
OUT = ROOT / "03_output"
STEM = "arc1_v306_v197_johab_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v306_v197_johab"
COMM = "COMM.IMG"
ROW, CELL, COLS, PL = 896, 12, 21, 4
A = {0, 1, 2, 3, 4, 5, 6, 7, 20}
B = {8, 12, 18}
C = {13, 17}


def grp(j: int) -> int:
    return 0 if j in A else 1 if j in B else 2 if j in C else 3


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
    font = bytearray(mem[COMM])
    cellmap = pickle.load(open(CELLMAP, "rb"))

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
        if not ("가" <= ch <= "힣"):
            return None
        x = ord(ch) - 0xAC00
        cho, r = divmod(x, 588)
        jung, jong = divmod(r, 28)
        cb = grp(jung) + (4 if jong else 0)
        if grp(jung) == 1 and jong:
            cb = 2
        p = [pieces[cb * 20 + cho + 1],
             pieces[160 + ((1 if cho in (0, 15) else 0) + (2 if jong else 0)) * 22 + jung + 1]]
        if jong:
            p.append(pieces[248 + grp(jung) * 28 + jong])
        return [functools.reduce(lambda a, b: a | b, (q[y] for q in p)) for y in range(CELL)]

    def put(idx: int, rows) -> None:
        c, pl = divmod(idx, PL)
        col, row = c % COLS, c // COLS
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

    done = skipped = 0
    for idx, ch in sorted(cellmap.items()):
        g = compose(ch)
        if not g or not any(g):
            skipped += 1
            continue
        put(idx, g)
        done += 1

    mem[COMM] = bytes(font)
    changed = [n for n in mem if n in mem and mem[n] != dict(
        (i.filename, None) for i in infos).get(n, mem[n])]
    OUT.mkdir(parents=True, exist_ok=True)
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
        "v306 TEST ONLY - v197 with Hangul glyphs redrawn as johab",
        f"base={BASE.name}   font={FONT_NAME} at {CELL}px",
        f"output={out.name}", f"sha256={st}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        f"cells redrawn={done}   left as-is={skipped}   (unknown cells keep v197 pictures)",
        "COMM.IMG only; every DAT and PSX.EXE byte-identical to v197",
        "runtime=PENDING user cold boot",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(rep) + "\n", encoding="utf-8")
    print("\n".join(rep))


if __name__ == "__main__":
    main()
