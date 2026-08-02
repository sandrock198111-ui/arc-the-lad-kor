"""What can the shipping build actually draw, and what does the script still need?

The CSV maps have drifted from the executable: 64 of the 409 lookup entries in
v116 point somewhere other than `ui_glyph_store_v42_map.csv` says, and three
cells that map claims are occupied are blank or hold a different glyph.  So do
not count supply from CSVs.  Count it from the artifacts that ship.

Supply is derived by walking every byte sequence the encoder can emit, resolving
it to a physical glyph index, reading the 12x12 bitplane at that index out of
COMM.IMG or one of the two resident strips, and identifying the bitmap by
comparing it against every Hangul syllable rendered through the project's own
render_glyph().  Demand is every Hangul syllable in the translation corpus.

Writes UTF-8; the Windows console cannot print the character lists.
"""
from __future__ import annotations

import csv
import pickle
import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from build_story_sf0b1_return_full import ROW_BYTES, get_pixel, render_glyph  # noqa: E402

BASE_ZIP = ROOT / "03_output/ui_hud_e7_v116_direct_stateless_renderer_patch_only.zip"
REPORT = ROOT / "01_work/analysis/atlas_ground_truth.txt"
CACHE = Path(
    r"C:\Users\ADMINI~1\AppData\Local\Temp\claude\E--korean"
    r"\328ae25b-6478-4de1-a913-c780c9b01e72\scratchpad\hangul_bitmaps.pkl"
)

RAM_TO_FILE = 0x8011A800
LOOKUP, LOOKUP_N = 0x801A7520, 409
GA_SRC, GB_SRC = 0x801A8800, 0x801A8BA8
STRIP_BYTES, STRIP_ROW_BYTES, STRIP_COLS = 936, 78, 13
ROW_A, ROW_B = 40, 63

GLYPHS_PER_ROW = 84          # 21 columns x 4 bitplanes
COMM_ROWS = 512 // 12        # rows of cells that exist inside COMM.IMG

STRIP_A_BASE = ROW_A * GLYPHS_PER_ROW    # 3360
STRIP_B_BASE = ROW_B * GLYPHS_PER_ROW    # 5292
STRIP_SLOTS = STRIP_COLS * 4             # 52


def csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def hangul_bitmaps() -> dict[tuple[int, ...], str]:
    if CACHE.exists():
        return pickle.loads(CACHE.read_bytes())
    table: dict[tuple[int, ...], str] = {}
    collisions = 0
    for point in range(0xAC00, 0xD7A4):
        char = chr(point)
        glyph = render_glyph(char)
        key = tuple(1 if glyph.getpixel((x, y)) else 0 for y in range(12) for x in range(12))
        if not any(key):
            continue
        if key in table:
            collisions += 1
            continue
        table[key] = char
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_bytes(pickle.dumps(table))
    print(f"rendered {len(table)} distinct syllable bitmaps ({collisions} collisions dropped)")
    return table


def strip_bitmap(strip: bytes, slot: int) -> tuple[int, ...]:
    column, plane = divmod(slot, 4)
    bit = 1 << plane
    out = []
    for y in range(12):
        for x in range(12):
            px = column * 12 + x
            byte = strip[y * STRIP_ROW_BYTES + px // 2]
            value = byte & 0x0F if px % 2 == 0 else byte >> 4
            out.append(1 if value & bit else 0)
    return tuple(out)


def comm_bitmap(font: bytes, index: int) -> tuple[int, ...]:
    row, remainder = divmod(index, GLYPHS_PER_ROW)
    column, plane = divmod(remainder, 4)
    bit = 1 << plane
    return tuple(
        1 if get_pixel(font, column * 12 + x, row * 12 + y) & bit else 0
        for y in range(12)
        for x in range(12)
    )


def main() -> None:
    with zipfile.ZipFile(BASE_ZIP) as archive:
        exe = archive.read("PSX.EXE")
        font = archive.read("COMM.IMG")
    lut = struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP - RAM_TO_FILE)
    strip_a = exe[GA_SRC - RAM_TO_FILE:GA_SRC - RAM_TO_FILE + STRIP_BYTES]
    strip_b = exe[GB_SRC - RAM_TO_FILE:GB_SRC - RAM_TO_FILE + STRIP_BYTES]

    def bitmap(index: int) -> tuple[int, ...] | None:
        if STRIP_A_BASE <= index < STRIP_A_BASE + STRIP_SLOTS:
            return strip_bitmap(strip_a, index - STRIP_A_BASE)
        if STRIP_B_BASE <= index < STRIP_B_BASE + STRIP_SLOTS:
            return strip_bitmap(strip_b, index - STRIP_B_BASE)
        if 0 <= index < COMM_ROWS * GLYPHS_PER_ROW:
            return comm_bitmap(font, index)
        return None

    # every byte sequence the decoder resolves to a glyph index
    codes: dict[int, list[str]] = {}

    def note(index: int, label: str) -> None:
        codes.setdefault(index, []).append(label)

    for code in range(0x01, 0x100):
        note(code - 1, f"{code:02X}")
    for lead in range(0xDD, 0xE9):
        for trail in range(0x01, 0xFF):
            note((lead - 0xDD) * 255 + trail + 0xDB, f"{lead:02X}{trail:02X}")
    for lead in (0xE9, 0xEA):
        for trail in range(0x01, 0xFF):
            slot = (lead - 0xE9) * 254 + trail - 1
            if 0 <= slot < LOOKUP_N:
                note(lut[slot], f"{lead:02X}{trail:02X}")

    table = hangul_bitmaps()

    reachable: dict[str, list[str]] = {}
    unidentified: list[int] = []
    blank_reachable = 0
    for index in sorted(codes):
        bits = bitmap(index)
        if bits is None:
            continue
        if not any(bits):
            blank_reachable += 1
            continue
        char = table.get(bits)
        if char is None:
            unidentified.append(index)
            continue
        reachable.setdefault(char, []).extend(codes[index])

    # demand
    demand: dict[str, int] = {}
    corpus = [ROOT / "05_docs/script_translated_full.csv"]
    for row in csv_rows(corpus[0]):
        for char in row.get("korean", ""):
            if "\uac00" <= char <= "\ud7a3":
                demand[char] = demand.get(char, 0) + 1

    missing = {char: n for char, n in demand.items() if char not in reachable}
    lines = [
        f"base                 : {BASE_ZIP.name}",
        f"syllables drawable   : {len(reachable)}",
        f"reachable-but-blank  : {blank_reachable} index slots",
        f"unidentified bitmaps : {len(unidentified)}",
        "",
        f"corpus               : {corpus[0].name}",
        f"distinct syllables   : {len(demand)}",
        f"already drawable     : {len(demand) - len(missing)}",
        f"MISSING              : {len(missing)}",
        "",
        "missing syllables (by frequency):",
    ]
    for char, count in sorted(missing.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"  {char}  x{count}")
    lines.append("")
    lines.append("drawable syllables:")
    lines.append("  " + "".join(sorted(reachable)))
    if unidentified:
        lines.append("")
        lines.append("indices holding a bitmap that is not a Hangul syllable render:")
        lines.append("  " + ", ".join(str(i) for i in unidentified))

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {REPORT}")
    for line in lines[:12]:
        print(line)


if __name__ == "__main__":
    main()
