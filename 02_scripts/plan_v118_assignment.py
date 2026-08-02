"""Decide which syllable goes into which glyph slot for v118.

v118 adds no renderer code.  It only fills storage that the shipping renderer
already reaches:

  strip B slots 5..51   47  already uploaded every frame, classifier already
                            answers to V=244; five of its slots are in use today
  index 1671             1  row 19 col 18 plane 3, the one blank plane left in a
                            cell that the original COMM.IMG never draws into

Two other sources were measured and rejected.  Eight drawn glyphs are unused by
the corpus and the UI tables, but their two-byte codes occur throughout the DAT
files at rates indistinguishable from chance (a given 2-byte value is expected
about 372 times across 24 MB), so nothing proves the text already inserted does
not use them.  Three blank planes sit in cells whose art this patch already
overwrote, but they fall in the one-byte code range 0x99..0x9C -- 0x9C is the
space filler, blank by design, not free.

Strip B needs lookup entries and all 409 existing ones are taken, so the table
moves to a new sector at the end of PSX.EXE and grows.  The decoder computes
`254 * (lead - 0xE9) + trail - 1` with no bounds check, so slots up to 507 are
already reachable; only storage was missing.

Assignment is by frequency in the committed corpus: the syllables that appear
most often get slots first, so whatever v118 cannot fit is the rarest tail.
"""
from __future__ import annotations

import csv
import pickle
import struct
import sys
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from build_story_sf0b1_return_full import get_pixel  # noqa: E402

BASE_ZIP = ROOT / "03_output/ui_hud_e7_v116_direct_stateless_renderer_patch_only.zip"
ORIG_ISO = Path(r"E:\arc\원본\arc1.bin")
PLAN_CSV = ROOT / "05_docs/v118_slot_assignment.csv"
REPORT = ROOT / "01_work/analysis/v118_assignment.txt"
CACHE = Path(
    r"C:\Users\ADMINI~1\AppData\Local\Temp\claude\E--korean"
    r"\328ae25b-6478-4de1-a913-c780c9b01e72\scratchpad\hangul_bitmaps.pkl"
)

RAW, COMM_LBA, COMM_SIZE = 2352, 667, 458752
RAM_TO_FILE = 0x8011A800
LOOKUP, LOOKUP_N = 0x801A7520, 409
GA_SRC, GB_SRC = 0x801A8800, 0x801A8BA8
STRIP_BYTES, STRIP_ROW_BYTES, STRIP_COLS = 936, 78, 13
GLYPHS_PER_ROW, PLANES, COLS = 84, 4, 21
COMM_ROWS = 512 // 12
STRIP_A_BASE, STRIP_B_BASE = 40 * GLYPHS_PER_ROW, 63 * GLYPHS_PER_ROW
STRIP_SLOTS = STRIP_COLS * PLANES
CURSOR_CELLS = {(r, c) for r in (11, 12, 13) for c in (0, 1, 2)}

UI_CSVS = (
    "ui_full_v42.csv", "ui_items_equipment_skills_v42_review.csv",
    "ui_skill_guide_reference_v42.csv", "ui_safe_v39.csv", "ui_system_v39.csv",
    "ui_world_name_v39.csv", "ui_battle_choice_v39.csv", "ui_consumables_v25.csv",
    "ui_v41_to_v42_restored_terms_2026-07-18.csv",
)


def hangul(text: str) -> set[str]:
    return {c for c in text if "\uac00" <= c <= "\ud7a3"}


def csv_hangul(path: Path) -> set[str]:
    found: set[str] = set()
    with path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.reader(handle):
            for cell in row:
                found |= hangul(cell)
    return found


def read_original() -> bytes:
    with ORIG_ISO.open("rb") as raw:
        def sector(lba: int) -> bytes:
            raw.seek(lba * RAW)
            data = raw.read(RAW)
            return data[24:24 + 2048] if data[15] == 2 else data[16:16 + 2048]
        return b"".join(sector(COMM_LBA + i) for i in range(COMM_SIZE // 2048))


def cell(data: bytes, row: int, column: int) -> list[int]:
    return [get_pixel(data, column * 12 + x, row * 12 + y)
            for y in range(12) for x in range(12)]


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
    return tuple(1 if get_pixel(font, column * 12 + x, row * 12 + y) & bit else 0
                 for y in range(12) for x in range(12))


def virtual_code(slot: int) -> bytes:
    lead, trail = (0xE9, slot + 1) if slot < 254 else (0xEA, slot - 253)
    return bytes((lead, trail))


def physical_codes() -> dict[int, bytes]:
    """Shortest byte sequence that reaches each index without the lookup table."""
    result: dict[int, bytes] = {}
    for lead in range(0xDD, 0xE9):
        for trail in range(0x01, 0xFF):
            result.setdefault((lead - 0xDD) * 255 + trail + 0xDB, bytes((lead, trail)))
    for code in range(0x01, 0x100):
        result[code - 1] = bytes((code,))
    return result


def main() -> None:
    with zipfile.ZipFile(BASE_ZIP) as archive:
        exe = archive.read("PSX.EXE")
        font = archive.read("COMM.IMG")
    lut = struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP - RAM_TO_FILE)
    strip_a = exe[GA_SRC - RAM_TO_FILE:GA_SRC - RAM_TO_FILE + STRIP_BYTES]
    strip_b = exe[GB_SRC - RAM_TO_FILE:GB_SRC - RAM_TO_FILE + STRIP_BYTES]
    original = read_original()
    table: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    direct = physical_codes()

    def bitmap(index: int) -> tuple[int, ...] | None:
        if STRIP_A_BASE <= index < STRIP_A_BASE + STRIP_SLOTS:
            return strip_bitmap(strip_a, index - STRIP_A_BASE)
        if STRIP_B_BASE <= index < STRIP_B_BASE + STRIP_SLOTS:
            return strip_bitmap(strip_b, index - STRIP_B_BASE)
        if 0 <= index < COMM_ROWS * GLYPHS_PER_ROW:
            return comm_bitmap(font, index)
        return None

    # ---- demand ----
    counts: Counter[str] = Counter()
    for row in csv.DictReader(
        (ROOT / "05_docs/script_translated_full.csv").open(encoding="utf-8-sig")
    ):
        for char in row["korean"]:
            if "\uac00" <= char <= "\ud7a3":
                counts[char] += 1
    ui: set[str] = set()
    for name in UI_CSVS:
        path = ROOT / "05_docs" / name
        if path.exists():
            ui |= csv_hangul(path)

    # ---- supply ----
    reachable: set[int] = set(direct) | set(lut)
    drawn: dict[str, int] = {}
    for index in sorted(reachable):
        bits = bitmap(index)
        if bits and any(bits):
            char = table.get(bits)
            if char is not None:
                drawn.setdefault(char, index)

    missing = [c for c in counts if c not in drawn]
    missing.sort(key=lambda c: (-counts[c], c))

    # ---- free storage ----
    slots: list[dict[str, str | int]] = []

    lut_slot = LOOKUP_N
    for slot in range(STRIP_SLOTS):
        if any(strip_bitmap(strip_b, slot)):
            continue
        index = STRIP_B_BASE + slot
        code = virtual_code(lut_slot)
        slots.append({"kind": "strip_b", "index": index, "code": code.hex().upper(),
                      "lookup_slot": lut_slot, "note": f"strip B slot {slot}"})
        lut_slot += 1

    for index in (1671,):
        code = direct[index]
        slots.append({"kind": "font_page", "index": index, "code": code.hex().upper(),
                      "lookup_slot": "", "note": "row 19 col 18 plane 3, cell blank in original"})

    # ---- assign ----
    assigned = []
    for char, slot in zip(missing, slots):
        assigned.append({"char": char, "occurrences": counts[char], **slot})
    leftover = missing[len(slots):]

    with PLAN_CSV.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "char", "occurrences", "kind", "index", "code", "lookup_slot", "note"])
        writer.writeheader()
        writer.writerows(assigned)

    by_kind = Counter(row["kind"] for row in assigned)
    lines = [
        f"base            : {BASE_ZIP.name}",
        f"missing          : {len(missing)} syllables, {sum(counts[c] for c in missing)} occurrences",
        f"slots available  : {len(slots)}",
        f"assigned         : {len(assigned)}",
        f"still missing    : {len(leftover)} syllables, "
        f"{sum(counts[c] for c in leftover)} occurrences",
        "",
        "by storage kind:",
        *(f"  {kind:12}{n:>4}" for kind, n in by_kind.items()),
        "",
        "left for the third strip (rarest tail):",
        "  " + " ".join(f"{c}x{counts[c]}" for c in leftover),
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:10]))
    print(f"\nplan  -> {PLAN_CSV}")


if __name__ == "__main__":
    main()
