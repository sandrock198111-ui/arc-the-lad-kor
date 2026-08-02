"""The v118 glyph budget, measured rather than assumed.

Supply is what the v116 build can actually draw (see audit_atlas_ground_truth).
Free space is what audit_free_capacity_v118 measures.  This script puts demand
against them, for three versions of the script:

  now        the committed corpus, after the two abbreviation passes
  reverted   the corpus as it stood before 04b09a5, i.e. every abbreviation undone
  ui         text already shipping in the UI tables, which must keep its glyphs

and reports how many currently drawn glyphs nothing uses any more, since those
are recyclable slots.

Writes UTF-8; the Windows console cannot print the character lists.
"""
from __future__ import annotations

import csv
import pickle
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from build_story_sf0b1_return_full import get_pixel  # noqa: E402

BASE_ZIP = ROOT / "03_output/ui_hud_e7_v116_direct_stateless_renderer_patch_only.zip"
REPORT = ROOT / "01_work/analysis/glyph_budget_v118.txt"
CACHE = Path(
    r"C:\Users\ADMINI~1\AppData\Local\Temp\claude\E--korean"
    r"\328ae25b-6478-4de1-a913-c780c9b01e72\scratchpad\hangul_bitmaps.pkl"
)

PRE_REDUCTION_COMMIT = "2239a0e"
SCRIPT_CSV = "05_docs/script_translated_full.csv"

# every UI table whose text is already inside the shipping executable
UI_CSVS = (
    "ui_full_v42.csv",
    "ui_items_equipment_skills_v42_review.csv",
    "ui_skill_guide_reference_v42.csv",
    "ui_safe_v39.csv",
    "ui_system_v39.csv",
    "ui_world_name_v39.csv",
    "ui_battle_choice_v39.csv",
    "ui_consumables_v25.csv",
    "ui_v41_to_v42_restored_terms_2026-07-18.csv",
)

RAM_TO_FILE = 0x8011A800
LOOKUP, LOOKUP_N = 0x801A7520, 409
GA_SRC, GB_SRC = 0x801A8800, 0x801A8BA8
STRIP_BYTES, STRIP_ROW_BYTES, STRIP_COLS = 936, 78, 13
GLYPHS_PER_ROW, PLANES = 84, 4
COMM_ROWS = 512 // 12
STRIP_A_BASE, STRIP_B_BASE = 40 * GLYPHS_PER_ROW, 63 * GLYPHS_PER_ROW
STRIP_SLOTS = STRIP_COLS * PLANES


def hangul(text: str) -> set[str]:
    return {c for c in text if "\uac00" <= c <= "\ud7a3"}


def csv_hangul(text: str) -> set[str]:
    found: set[str] = set()
    for row in csv.reader(text.splitlines()):
        for cell in row:
            found |= hangul(cell)
    return found


def strip_bitmap(strip: bytes, slot: int) -> tuple[int, ...]:
    column, plane = divmod(slot, PLANES)
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
    column, plane = divmod(remainder, PLANES)
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

    reachable: set[int] = {code - 1 for code in range(0x01, 0x100)}
    for lead in range(0xDD, 0xE9):
        for trail in range(0x01, 0xFF):
            reachable.add((lead - 0xDD) * 255 + trail + 0xDB)
    reachable |= set(lut)

    table: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    drawable: dict[str, int] = {}
    for index in sorted(reachable):
        bits = bitmap(index)
        if not bits or not any(bits):
            continue
        char = table.get(bits)
        if char is not None:
            drawable.setdefault(char, index)

    now = csv_hangul((ROOT / SCRIPT_CSV).read_text(encoding="utf-8-sig"))
    pre = csv_hangul(subprocess.run(
        ["git", "show", f"{PRE_REDUCTION_COMMIT}:{SCRIPT_CSV}"],
        cwd=ROOT, capture_output=True, check=True,
    ).stdout.decode("utf-8-sig"))
    ui: set[str] = set()
    for name in UI_CSVS:
        path = ROOT / "05_docs" / name
        if path.exists():
            ui |= csv_hangul(path.read_text(encoding="utf-8-sig"))

    supply = set(drawable)
    missing_now = now - supply
    missing_pre = pre - supply
    unused = supply - now - pre - ui

    lines = [
        f"base                              : {BASE_ZIP.name}",
        "",
        f"syllables the build can draw      : {len(supply)}",
        "",
        f"UI text already shipping          : {len(ui)} syllables",
        f"story corpus, as committed        : {len(now)} syllables",
        f"story corpus, abbreviations undone: {len(pre)} syllables",
        "",
        f"MISSING, as committed             : {len(missing_now)}",
        f"MISSING, abbreviations undone     : {len(missing_pre)}",
        "",
        f"drawn but no longer used anywhere : {len(unused)}   <- recyclable slots",
        "",
        "free slots measured in v116        : 48  (47 strip B + 1 font page)",
        "",
        "missing, as committed:",
        "  " + "".join(sorted(missing_now)),
        "",
        "missing, abbreviations undone:",
        "  " + "".join(sorted(missing_pre)),
        "",
        "recyclable (drawn, unused by story or UI):",
        "  " + "".join(sorted(unused)),
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    for line in lines[:17]:
        print(line)
    print(f"\nwrote {REPORT}")


if __name__ == "__main__":
    main()
