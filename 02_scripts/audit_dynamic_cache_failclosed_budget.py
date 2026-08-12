"""Measure cache/RAM cost after removing every sampled non-text static cell.

This does not approve the remaining static cells and does not build a patch.  It
answers whether the agreed fail-closed direction is still technically feasible if
all currently demonstrated conflicts are moved into the dynamic set.
"""
from __future__ import annotations

import csv
import pickle
import sys
import zipfile
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from audit_comm_physical_cell_safety import (  # noqa: E402
    body_units, exe_units, active_slot_units,
)
from audit_dynamic_cache_requirements import bitmap, glyph_index, read_lut, source_ranges  # noqa: E402
from plan_bulk_insertion import CACHE, IPR, PLANES, tokens  # noqa: E402
from plan_dynamic_cache_v153 import row_values  # noqa: E402


BUILD = ROOT / "03_output/arc1_v163_text_clut_classifier_773E3B82.zip"
ASSIGNMENTS = ROOT / "01_work/analysis/dynamic_cache_v153_widthsafe/glyph_assignments.csv"
CELL_MANIFEST = ROOT / "01_work/analysis/comm_physical_cell_safety/cells.csv"
OUT = ROOT / "01_work/analysis/dynamic_cache_failclosed_budget.txt"
ORIGINAL_STRUCTURE_BYTES = 7212
CURRENT_FIXED_CODE_AND_METADATA = 4208 - 2770
CACHE_SLOTS = 20


def main() -> None:
    with zipfile.ZipFile(BUILD) as archive:
        data = {name: archive.read(name) for name in archive.namelist()}
    exe, font = data["PSX.EXE"], data["COMM.IMG"]
    lut = read_lut(exe)
    ranges = source_ranges()

    records = list(csv.DictReader(ASSIGNMENTS.open(encoding="utf-8-sig", newline="")))
    all_chars = {record["char"] for record in records}
    source_chars = {
        int(record["source_id"]): record["char"]
        for record in records if record.get("source_id")
    }
    index_chars = {
        int(record["physical_index"]): record["char"]
        for record in records if record.get("physical_index")
    }
    char_bits: dict[str, tuple[int, ...]] = {}
    for index, char in index_chars.items():
        bits = bitmap(exe, font, index)
        if bits:
            char_bits[char] = bits
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    for source, char in source_chars.items():
        # Existing dynamic sources are in the plan's shape cache even though their
        # current lookup entry has no physical atlas index.
        if char in char_bits:
            continue
        for bits, known in shapes.items():
            if known == char:
                char_bits[char] = bits
                break
    missing_bits = sorted(all_chars - char_bits.keys())
    if missing_bits:
        raise SystemExit(f"missing bitmaps for {len(missing_bits)} chars: {''.join(missing_bits)}")

    rejected_cells: set[tuple[int, int]] = set()
    with CELL_MANIFEST.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            if row["status"] == "rejected_known_nontext":
                rejected_cells.add((int(row["row"]), int(row["col"])))
    rejected_static = {
        char for index, char in index_chars.items()
        if (index // IPR, (index % IPR) // PLANES) in rejected_cells
    }
    existing_dynamic = set(source_chars.values())
    conflict_dynamic = existing_dynamic | rejected_static

    units = (
        list(body_units(data, ranges))
        + list(active_slot_units(data, ranges))
        + list(exe_units(data))
    )
    unit_chars: list[tuple[str, set[str]]] = []
    for label, payload in units:
        chars: set[str] = set()
        for token in tokens(payload):
            value = glyph_index(token, lut)
            if value is None:
                continue
            char = source_chars.get(value & 0x7FFF) if value & 0x8000 else index_chars.get(value)
            if char:
                chars.add(char)
        if chars:
            unit_chars.append((label, chars))

    def scenario(name: str, dynamic: set[str]) -> list[str]:
        rows = {value for char in dynamic for value in row_values(char_bits[char])}
        if len(rows) > 255:
            row_status = "OVERFLOW"
        else:
            row_status = "PASS"
        working = sorted(
            ((len(chars & dynamic), label) for label, chars in unit_chars), reverse=True
        )
        source_bytes = len(rows) * 2 + len(dynamic) * 12
        resident = CURRENT_FIXED_CODE_AND_METADATA + source_bytes
        heap = ORIGINAL_STRUCTURE_BYTES - resident
        return [
            f"[{name}]",
            f"dynamic_chars={len(dynamic)}",
            f"row_dictionary_entries={len(rows)}",
            f"row_dictionary_status={row_status}",
            f"glyph_row_bytes={len(dynamic) * 12}",
            f"source_bytes={source_bytes}",
            f"estimated_resident_bytes={resident}",
            f"estimated_game_heap_bytes={heap}",
            f"max_simultaneous_dynamic={working[0][0] if working else 0}",
            f"cache_capacity={CACHE_SLOTS}",
            f"cache_capacity_status={'PASS' if not working or working[0][0] <= CACHE_SLOTS else 'FAIL'}",
            "top_units=" + " | ".join(f"{count}:{label}" for count, label in working[:10]),
            "",
        ]

    lines = [
        "Fail-closed dynamic-cache budget (analysis only)",
        f"all_hangul_chars={len(all_chars)}",
        f"existing_dynamic_chars={len(existing_dynamic)}",
        f"sampled_nontext_conflict_cells={len(rejected_cells)}",
        f"static_chars_in_conflict_cells={len(rejected_static)}",
        f"fixed_code_and_metadata_bytes={CURRENT_FIXED_CODE_AND_METADATA}",
        "",
        *scenario("remove_sampled_conflicts", conflict_dynamic),
        *scenario("all_hangul_dynamic", all_chars),
        "These are exact bitmap/row and bounded-text working-set counts.",
        "The resident estimate keeps v163's fixed code/metadata constant; a future",
        "builder must recalculate exact addresses and must not reserve from this estimate.",
    ]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
