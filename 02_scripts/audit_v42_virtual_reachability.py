"""Are the 109 v42-only characters really drawn, and really reachable?

The glyph budget was recomputed on the claim that `ui_glyph_store_v42_map.csv`
contributes 109 characters the two charmaps do not have.  That claim only helps
if, for each of those characters, three things hold in the build we actually
ship:

  1. the 12x12 bitmap in COMM.IMG at the mapped physical index is the character
     (not blank, not some other glyph),
  2. the lookup table at 0x801A7520 sends its E9/EA virtual code to that same
     physical index,
  3. the encoder has some byte sequence that reaches it -- either the virtual
     code, or the physical code when its trail byte is addressable.

v109 and v111 broke glyphs by assuming reachability instead of measuring it, so
measure it.  Report is written as UTF-8; the Windows console cannot print it.
"""
from __future__ import annotations

import csv
import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from build_story_sf0b1_return_full import ROW_BYTES, get_pixel, render_glyph  # noqa: E402

BASE_ZIP = ROOT / "03_output/ui_hud_e7_v116_direct_stateless_renderer_patch_only.zip"
MAP_CSV = ROOT / "05_docs/ui_glyph_store_v42_map.csv"
CHARMAPS = ("korean_charmap.csv", "korean_charmap_extended.csv")
REPORT = ROOT / "01_work/analysis/v42_virtual_reachability.txt"

LOOKUP, LOOKUP_N, RAM_TO_FILE = 0x801A7520, 409, 0x8011A800
GLYPHS_PER_ROW = 84


def csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def position(index: int) -> tuple[int, int, int]:
    row, remainder = divmod(index, GLYPHS_PER_ROW)
    column, plane = divmod(remainder, 4)
    return row, column, plane


def plane_bitmap(font: bytes, index: int) -> tuple[int, ...]:
    row, column, plane = position(index)
    bit = 1 << plane
    return tuple(
        1 if get_pixel(font, column * 12 + x, row * 12 + y) & bit else 0
        for y in range(12)
        for x in range(12)
    )


def rendered_bitmap(char: str) -> tuple[int, ...]:
    glyph = render_glyph(char)
    return tuple(1 if glyph.getpixel((x, y)) else 0 for y in range(12) for x in range(12))


def main() -> None:
    with zipfile.ZipFile(BASE_ZIP) as archive:
        exe = archive.read("PSX.EXE")
        font = archive.read("COMM.IMG")
    lut = struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP - RAM_TO_FILE)

    charmap: dict[str, int] = {}
    for name in CHARMAPS:
        for row in csv_rows(ROOT / "05_docs" / name):
            code = (row.get("code_hex") or "").strip()
            if code:
                charmap[row["char"]] = int(code, 16)

    rows = csv_rows(MAP_CSV)
    lines: list[str] = []
    counts = {
        "drawn_and_correct": 0,
        "drawn_but_mismatched": 0,
        "blank": 0,
        "lut_disagrees": 0,
        "physical_code_addressable": 0,
    }
    detail: list[str] = []

    for position_index, row in enumerate(rows):
        char = row["char"]
        if char in charmap:
            continue  # covered by the charmaps already
        index = int(row["physical_index"])
        virtual = bytes.fromhex(row["virtual_code_hex"])
        physical = bytes.fromhex(row["physical_code_hex"])

        slot = (virtual[0] - 0xE9) * 254 + virtual[1] - 1
        lut_index = lut[slot] if 0 <= slot < LOOKUP_N else None
        lut_ok = lut_index == index
        if not lut_ok:
            counts["lut_disagrees"] += 1

        actual = plane_bitmap(font, index)
        expected = rendered_bitmap(char)
        if not any(actual):
            state = "BLANK"
            counts["blank"] += 1
        elif actual == expected:
            state = "match"
            counts["drawn_and_correct"] += 1
        else:
            state = "MISMATCH"
            counts["drawn_but_mismatched"] += 1

        addressable = physical[1] not in (0x00, 0xFF)
        if addressable:
            counts["physical_code_addressable"] += 1

        r, c, p = position(index)
        detail.append(
            f"{char}  slot={position_index:>3}  virtual={virtual.hex(' ').upper()}  "
            f"physical={physical.hex(' ').upper()}  index={index:>4}  "
            f"row={r:>2} col={c:>2} plane={p}  bitmap={state}  "
            f"lut={'ok' if lut_ok else f'-> {lut_index}'}  "
            f"phys_addressable={'yes' if addressable else 'no'}"
        )

    total = sum(1 for row in rows if row["char"] not in charmap)
    lines.append(f"base            : {BASE_ZIP.name}")
    lines.append(f"v42 rows        : {len(rows)}")
    lines.append(f"charmap chars   : {len(charmap)}")
    lines.append(f"v42-only chars  : {total}")
    lines.append("")
    for key, value in counts.items():
        lines.append(f"  {key:26}{value:>5}")
    lines.append("")
    lines.append("per character:")
    lines.extend("  " + line for line in detail)

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {REPORT}")
    for key, value in counts.items():
        print(f"  {key:26}{value:>5}")
    print(f"  {'v42-only total':26}{total:>5}")


if __name__ == "__main__":
    main()
