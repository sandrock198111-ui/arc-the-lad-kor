"""Width-safe v153 assignment: one bitmap, separate 1/2-byte spellings when needed."""
from __future__ import annotations

import csv
import pickle
import struct
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from audit_dynamic_cache_candidate_tiers import direct_code  # noqa: E402
from audit_dynamic_cache_requirements import (  # noqa: E402
    BUILD, BUILD_SHA, CACHE, ORIGINAL, bitmap, glyph_index, original_bitmap,
    read_lut, sha256, source_ranges, text_units,
)
from plan_bulk_insertion import CELL, IPR, LOOKUP_N, PLANES, tokens  # noqa: E402
from plan_dynamic_cache_v153 import row_values, virtual_code  # noqa: E402

OUT = ROOT / "01_work/analysis/dynamic_cache_v153_widthsafe"
ASSIGNMENTS = OUT / "glyph_assignments.csv"
CACHE_SLOTS = OUT / "cache_slots.csv"
PROTECTED_RELOCATIONS = OUT / "protected_virtual_relocations.csv"
LOOKUP = OUT / "lookup_table.bin"
ROW_DICTIONARY = OUT / "row_dictionary.bin"
GLYPH_ROWS = OUT / "dynamic_glyph_rows.bin"
REPORT = OUT / "plan_report.txt"
CACHE_N = 20
RESIDENT_BUDGET = 5356
RUNTIME_LOOKUP_N = 409


def main() -> None:
    if sha256(BUILD.read_bytes()) != BUILD_SHA:
        raise SystemExit("v151 archive hash differs")
    with zipfile.ZipFile(BUILD) as archive:
        current = {info.filename: archive.read(info.filename) for info in archive.infolist()}
    with zipfile.ZipFile(ORIGINAL) as archive:
        pristine = {info.filename: archive.read(info.filename) for info in archive.infolist()}

    exe, original_exe = current["PSX.EXE"], pristine["PSX.EXE"]
    font, original_font = current["COMM.IMG"], pristine["COMM.IMG"]
    lut, original_lut = read_lut(exe), read_lut(original_exe)
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    ranges = source_ranges()

    frequency: Counter[str] = Counter()
    widths: dict[str, set[int]] = defaultdict(set)
    char_indices: dict[str, set[int]] = defaultdict(set)
    char_bits: dict[str, tuple[int, ...]] = {}
    protected_indices: set[int] = set()
    protected_virtual: set[int] = set()
    units: list[tuple[str, set[str]]] = []
    current_slot_char: dict[int, str] = {}

    for label, payload in text_units(current, ranges):
        unit: set[str] = set()
        for token in tokens(payload):
            index = glyph_index(token, lut)
            if index is None:
                continue
            bits = bitmap(exe, font, index)
            char = shapes.get(bits) if bits else None
            is_hangul = bool(char and any("가" <= c <= "힣" for c in char))
            if is_hangul:
                frequency[char] += 1
                widths[char].add(len(token))
                char_indices[char].add(index)
                char_bits.setdefault(char, bits)
                unit.add(char)
                if len(token) == 2 and token[0] in (0xE9, 0xEA):
                    slot = (token[0] - 0xE9) * 254 + token[1] - 1
                    current_slot_char.setdefault(slot, char)
            else:
                protected_indices.add(index)
                if len(token) == 2 and token[0] in (0xE9, 0xEA):
                    protected_virtual.add((token[0] - 0xE9) * 254 + token[1] - 1)
        if unit:
            units.append((label, unit))

    # Name every lookup entry by its actual v151 bitmap, including entries that did not
    # occur in a bounded unit.  This lets all aliases for one Hangul follow its new home.
    for slot, index in enumerate(lut):
        bits = bitmap(exe, font, index)
        char = shapes.get(bits) if bits else None
        if char and any("가" <= c <= "힣" for c in char):
            current_slot_char.setdefault(slot, char)

    original_used: set[int] = set()
    for _, payload in text_units(pristine, ranges):
        for token in tokens(payload):
            index = glyph_index(token, original_lut)
            if index is not None:
                original_used.add(index)

    def safe(index: int) -> bool:
        if index in protected_indices or index >= IPR * (256 // CELL):
            return False
        if direct_code(index) is None:
            return False
        bits = original_bitmap(original_font, index)
        return bool(bits and any(bits))

    safe_pool = {index for index in range(IPR * (256 // CELL)) if safe(index)}
    physical: dict[str, int] = {}
    occupied: set[int] = set()

    # Mandatory one-byte homes.
    one_byte_chars = [char for char in frequency if 1 in widths[char]]
    for char in sorted(one_byte_chars, key=lambda c: (-frequency[c], c)):
        choices = sorted(index for index in char_indices[char]
                         if index < 220 and index in safe_pool and index not in occupied)
        if not choices:
            raise SystemExit(f"no safe one-byte cell for {char!r}")
        physical[char] = choices[0]
        occupied.add(choices[0])

    # Twenty strongest planes become cache slots, packed into few cells.
    strict = [index for index in safe_pool - occupied if index in original_used]
    by_cell: dict[tuple[int, int], list[int]] = defaultdict(list)
    for index in strict:
        row, remainder = divmod(index, IPR)
        by_cell[(row, remainder // PLANES)].append(index)
    cache_indices = []
    for _, indices in sorted(by_cell.items(), key=lambda item: (-len(item[1]), item[0])):
        cache_indices.extend(sorted(indices))
        if len(cache_indices) >= CACHE_N:
            break
    cache_indices = cache_indices[:CACHE_N]
    if len(cache_indices) != CACHE_N:
        raise SystemExit("not enough strict cache planes")
    occupied.update(cache_indices)

    # Keep existing safe homes, then fill remaining safe two-byte planes by frequency.
    for char, _ in frequency.most_common():
        if char in physical:
            continue
        choices = sorted(index for index in char_indices[char]
                         if index in safe_pool and index not in occupied
                         and len(direct_code(index) or b"") == 2)
        if choices:
            physical[char] = choices[0]
            occupied.add(choices[0])
    free_static = sorted(index for index in safe_pool - occupied
                         if len(direct_code(index) or b"") == 2)
    for char, _ in frequency.most_common():
        if char in physical or not free_static:
            continue
        physical[char] = free_static.pop(0)
        occupied.add(physical[char])

    dynamic = [char for char, _ in frequency.most_common() if char not in physical]
    if any(1 in widths[char] for char in dynamic):
        raise SystemExit("a one-byte character fell into the dynamic set")
    source_id = {char: i for i, char in enumerate(dynamic)}

    # Allocate two-byte aliases.  Existing same-character slots win.  All bounded
    # non-Hangul slots are protected, and every remaining Hangul slot is reusable.
    protected_high = sorted(slot for slot in protected_virtual if slot >= RUNTIME_LOOKUP_N)
    if protected_high:
        raise SystemExit(f"non-Hangul text needs lookup slots beyond 408: {protected_high}")

    # Relocate every protected virtual glyph whose v151 bitmap would be lost when the
    # COMM.IMG grid is restored. This covers both former high-page glyphs and custom
    # low-page UI glyphs absent from the untouched disc.
    free_protected = sorted(
        safe_pool - occupied,
        key=lambda index: (len(direct_code(index) or b"") != 2, index),
    )
    protected_relocations = []
    for slot in sorted(protected_virtual):
        source_index = lut[slot]
        bits = bitmap(exe, font, source_index)
        if not bits or not any(bits):
            raise SystemExit(f"protected slot {slot} has no relocatable bitmap")
        if bits == original_bitmap(original_font, source_index):
            continue
        if not free_protected:
            raise SystemExit("no low-page plane remains for protected UI glyphs")
        destination_index = free_protected.pop(0)
        occupied.add(destination_index)
        protected_relocations.append((slot, source_index, destination_index))
    slots_by_char: dict[str, list[int]] = defaultdict(list)
    reusable = []
    for slot, char in sorted(current_slot_char.items()):
        if slot < RUNTIME_LOOKUP_N and slot not in protected_virtual:
            slots_by_char[char].append(slot)
            reusable.append(slot)
    used_slots: set[int] = set()

    def take_slot(char: str) -> int:
        preferred = [slot for slot in slots_by_char[char] if slot not in used_slots]
        available = preferred or [slot for slot in reusable if slot not in used_slots]
        if not available:
            raise SystemExit("not enough E9/EA slots for width-safe aliases")
        slot = available[0]
        used_slots.add(slot)
        return slot

    code_by_width: dict[tuple[str, int], bytes] = {}
    canonical_slot: dict[str, int] = {}
    for char in frequency:
        if 1 in widths[char]:
            code = direct_code(physical[char])
            if len(code or b"") != 1:
                raise SystemExit(f"{char!r} lost its one-byte home")
            code_by_width[(char, 1)] = code
        if 2 in widths[char]:
            if char in physical and len(direct_code(physical[char]) or b"") == 2:
                code_by_width[(char, 2)] = direct_code(physical[char])
            else:
                slot = take_slot(char)
                canonical_slot[char] = slot
                code_by_width[(char, 2)] = virtual_code(slot)

    # Rebuild lookup aliases.  Every known Hangul slot follows the character's new
    # static home or dynamic source.  Protected non-Hangul slots remain byte-identical.
    new_lut = list(lut[:RUNTIME_LOOKUP_N])
    for slot, _, destination_index in protected_relocations:
        new_lut[slot] = destination_index
    for slot, char in current_slot_char.items():
        if slot >= RUNTIME_LOOKUP_N or slot in protected_virtual or char not in frequency:
            continue
        new_lut[slot] = (physical[char] if char in physical else 0x8000 | source_id[char])
    for char, slot in canonical_slot.items():
        new_lut[slot] = (physical[char] if char in physical else 0x8000 | source_id[char])

    rewrites = 0
    for _, payload in text_units(current, ranges):
        for token in tokens(payload):
            index = glyph_index(token, lut)
            if index is None:
                continue
            bits = bitmap(exe, font, index)
            char = shapes.get(bits) if bits else None
            code = code_by_width.get((char, len(token)))
            if code is None:
                continue
            if len(code) != len(token):
                raise SystemExit(f"width changed for {char!r}")
            rewrites += token != code

    # Exact row dictionary.
    row_patterns = sorted({row for char in dynamic for row in row_values(char_bits[char])})
    if len(row_patterns) > 255:
        raise SystemExit(f"row dictionary needs {len(row_patterns)} entries")
    row_id = {value: i for i, value in enumerate(row_patterns)}
    dictionary_blob = b"".join(struct.pack("<H", value) for value in row_patterns)
    glyph_blob = bytes(row_id[row] for char in dynamic for row in row_values(char_bits[char]))
    lookup_blob = struct.pack(f"<{RUNTIME_LOOKUP_N}H", *new_lut)

    dynamic_set = set(dynamic)
    working = sorted(((len(chars & dynamic_set), label) for label, chars in units),
                     reverse=True)
    cache_cells = {(index // IPR, (index % IPR) // PLANES) for index in cache_indices}

    OUT.mkdir(parents=True, exist_ok=True)
    fields = ["char", "kind", "code_1byte", "code_2byte", "physical_index",
              "source_id", "frequency"]
    with ASSIGNMENTS.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for char in sorted(frequency):
            writer.writerow({
                "char": char,
                "kind": "static" if char in physical else "dynamic",
                "code_1byte": code_by_width.get((char, 1), b"").hex(" ").upper(),
                "code_2byte": code_by_width.get((char, 2), b"").hex(" ").upper(),
                "physical_index": physical.get(char, ""),
                "source_id": source_id.get(char, ""),
                "frequency": frequency[char],
            })
    fields = ["cache_slot", "physical_index", "row", "column", "plane"]
    with CACHE_SLOTS.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for slot, index in enumerate(cache_indices):
            row, remainder = divmod(index, IPR)
            column, plane = divmod(remainder, PLANES)
            writer.writerow({"cache_slot": slot, "physical_index": index, "row": row,
                             "column": column, "plane": plane})
    fields = ["virtual_slot", "source_index", "destination_index"]
    with PROTECTED_RELOCATIONS.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for slot, source_index, destination_index in protected_relocations:
            writer.writerow({"virtual_slot": slot, "source_index": source_index,
                             "destination_index": destination_index})
    LOOKUP.write_bytes(lookup_blob)
    ROW_DICTIONARY.write_bytes(dictionary_blob)
    GLYPH_ROWS.write_bytes(glyph_blob)

    # Metadata estimate: owners u16, slot indices u16, active+next, RECT, 72-byte cell.
    data_bytes = len(dictionary_blob) + len(glyph_blob)
    metadata_bytes = CACHE_N * 2 + CACHE_N * 2 + 8 + 8 + 72
    lines = [
        "v153 width-safe dynamic-cache assignment",
        f"unique_hangul_shapes={len(frequency)}",
        f"static_shapes={len(physical)}",
        f"dynamic_shapes={len(dynamic)}",
        f"one_byte_shapes={len(one_byte_chars)}",
        f"mixed_width_shapes={sum(widths[c] == {1, 2} for c in widths)}",
        f"two_byte_aliases={len(canonical_slot)}",
        f"cache_slots={CACHE_N}",
        f"cache_physical_cells={len(cache_cells)}",
        f"max_dynamic_in_one_unit={working[0][0]}",
        f"token_rewrites={rewrites}",
        f"protected_nonhangul_indices={len(protected_indices)}",
        f"protected_nonhangul_virtual_slots={len(protected_virtual)}",
        f"protected_virtual_relocations={len(protected_relocations)}",
        f"safe_direct_pool={len(safe_pool)}",
        f"row_dictionary_entries={len(row_patterns)}",
        f"row_dictionary_bytes={len(dictionary_blob)}",
        f"runtime_lookup_entries={RUNTIME_LOOKUP_N}",
        f"dynamic_glyph_rows_bytes={len(glyph_blob)}",
        f"lookup_bytes={len(lookup_blob)}",
        f"resident_data_bytes_before_code={data_bytes + metadata_bytes}",
        f"resident_budget={RESIDENT_BUDGET}",
        f"resident_bytes_left_for_code={RESIDENT_BUDGET - data_bytes - metadata_bytes}",
        "top_dynamic_working_sets=" + ", ".join(
            f"{count}:{label}" for count, label in working[:10]
        ),
        "",
        "No game member was modified.",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
