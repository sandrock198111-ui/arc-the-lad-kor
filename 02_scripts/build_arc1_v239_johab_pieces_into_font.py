"""Build v239: write the 16px johab pieces into COMM.IMG.

Step two of the transition.  v238 already proved the renderer survives a 16px
cell; this puts the actual glyph data in place.  The renderer still addresses
the atlas with the old 21-column geometry, so nothing looks right yet -- that
comes in the next build together with the composition logic.  What this build
must get right is the byte layout.

COMM.IMG is a 1792x512 4bpp image and the glyph atlas occupies only the left
252x504 of it (21 columns x 12px, 42 rows x 12px).  Each pixel's four bits
belong to four different glyphs, selected at draw time by CLUT -- so a cell
holds four glyphs stacked in planes.

The 360 pieces reuse that:

    cell  = piece / 4          plane = piece % 4
    90 cells at 15 per row  ->  6 rows
    U = (cell % 15) * 16    ->    0..224
    V = (cell / 15) * 16    ->    0..80      both inside one texture page
    row stride = 15 columns * 4 planes = 60  (was 84)

240x96 pixels, i.e. 9% of the area the completed-syllable atlas used, and one
page instead of two.  Written at the top-left so cell 0 starts at index 0.

The pieces overwrite whatever completed syllables sat in the first six 16px
rows.  That is intended -- the whole atlas becomes obsolete once the script is
re-encoded to johab, and v235 remains the rollback point.

Source data is 01_work/analysis/hangul_johab_16px/pieces_1bpp.bin, extracted
from Hanme_8x4x4.bdf (github.com/iolo/8x4x4-fonts, MIT / OFL-1.1).
"""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = ROOT / "03_output/arc1_v238_glyph_16px_TEST_ONLY_F5F9D9DE.zip"
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v239_johab_pieces_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v239_johab_pieces"
PIECES = ROOT / "01_work/analysis/hangul_johab_16px/pieces_1bpp.bin"

COMM = "COMM.IMG"
ROW_BYTES = 896
NEW_CELL = 16
COLS = 15
PLANES = 4
PIECE_N = 360


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system",
                 "create_version", "extract_version", "flag_bits", "volume",
                 "internal_attr", "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def put_plane(font: bytearray, cell: int, plane: int, rows: list[int]) -> None:
    """Write one 16x16 1bpp piece into `plane` of `cell`."""
    col, row = cell % COLS, cell // COLS
    bit = 1 << plane
    for y in range(NEW_CELL):
        base = (row * NEW_CELL + y) * ROW_BYTES + col * (NEW_CELL // 2)
        src = rows[y]
        for x in range(NEW_CELL):
            at = base + x // 2
            shift = 0 if x % 2 == 0 else 4
            nib = (font[at] >> shift) & 0x0F
            nib = (nib | bit) if (src >> (15 - x)) & 1 else (nib & ~bit & 0x0F)
            font[at] = (font[at] & (0xF0 if shift == 0 else 0x0F)) | (nib << shift)


def get_plane(font: bytes, cell: int, plane: int) -> list[int]:
    col, row = cell % COLS, cell // COLS
    bit = 1 << plane
    out = []
    for y in range(NEW_CELL):
        base = (row * NEW_CELL + y) * ROW_BYTES + col * (NEW_CELL // 2)
        v = 0
        for x in range(NEW_CELL):
            nib = (font[base + x // 2] >> (0 if x % 2 == 0 else 4)) & 0x0F
            if nib & bit:
                v |= 1 << (15 - x)
        out.append(v)
    return out


def main() -> None:
    if not BASE.exists():
        cands = sorted(OUT_DIR.glob("arc1_v238_glyph_16px_TEST_ONLY_*.zip"))
        if not cands:
            raise SystemExit("v238 base archive not found")
        base_path = cands[-1]
    else:
        base_path = BASE
    with ZipFile(base_path) as archive:
        infos = archive.infolist()
        before = {i.filename: archive.read(i.filename) for i in infos}
    members = dict(before)

    raw = PIECES.read_bytes()
    if len(raw) != PIECE_N * NEW_CELL * 2:
        raise SystemExit(f"piece blob is {len(raw)}B, expected {PIECE_N * NEW_CELL * 2}")
    pieces = [[struct.unpack_from(">H", raw, (p * NEW_CELL + y) * 2)[0]
               for y in range(NEW_CELL)] for p in range(PIECE_N)]

    cells = -(-PIECE_N // PLANES)
    rows_needed = -(-cells // COLS)
    if COLS * NEW_CELL > 252 or rows_needed * NEW_CELL > 504:
        raise SystemExit("layout leaves the glyph atlas area")

    font = bytearray(members[COMM])
    for idx, bits in enumerate(pieces):
        put_plane(font, idx // PLANES, idx % PLANES, bits)

    for idx, bits in enumerate(pieces):
        if get_plane(bytes(font), idx // PLANES, idx % PLANES) != bits:
            raise SystemExit(f"readback mismatch at piece {idx}")

    touched = set()
    for cell in range(cells):
        col, row = cell % COLS, cell // COLS
        for y in range(NEW_CELL):
            b0 = (row * NEW_CELL + y) * ROW_BYTES + col * (NEW_CELL // 2)
            touched.update(range(b0, b0 + NEW_CELL // 2))
    diffs = [i for i, (a, b) in enumerate(zip(members[COMM], bytes(font))) if a != b]
    if any(i not in touched for i in diffs):
        raise SystemExit("COMM.IMG changed outside the piece cells")
    if len(font) != len(members[COMM]):
        raise SystemExit("COMM.IMG size changed")

    members[COMM] = bytes(font)
    if [n for n in members if members[n] != before[n]] != [COMM]:
        raise SystemExit("unexpected changed members")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tmp = OUT_DIR / f"{OUT_STEM}_building.zip"
    if tmp.exists():
        raise SystemExit(f"refusing to overwrite: {tmp}")
    with ZipFile(tmp, "w", ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    with ZipFile(tmp) as archive:
        for name, want in members.items():
            if archive.read(name) != want:
                raise SystemExit(f"roundtrip differs: {name}")
    stamp = digest(tmp.read_bytes())
    out = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    if out.exists():
        raise SystemExit(f"refusing to overwrite: {out}")
    tmp.replace(out)

    report = [
        "v239 TEST ONLY - 16px johab pieces written into COMM.IMG",
        f"base={base_path.name}", f"output={out.name}", f"sha256={stamp}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        f"pieces={PIECE_N} in {cells} cells x {PLANES} planes, {COLS} cols x {rows_needed} rows",
        f"atlas_area={COLS * NEW_CELL}x{rows_needed * NEW_CELL} px  (glyph area is 252x504)",
        "U=(cell%15)*16 -> 0..224   V=(cell/15)*16 -> 0..80   one texture page",
        "row_stride=60 (15 cols x 4 planes); renderer still uses 84 -- next build",
        f"COMM_changed_bytes={len(diffs)}",
        "PSX.EXE=byte-identical PASS  all_DAT_members=byte-identical PASS",
        "readback=360/360 pieces verified",
        "source=Hanme_8x4x4.bdf (iolo/8x4x4-fonts, MIT / OFL-1.1)",
        "runtime=data only; nothing renders correctly until the composition build",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
