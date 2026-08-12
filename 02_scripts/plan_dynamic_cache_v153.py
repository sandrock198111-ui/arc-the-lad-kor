"""Create a deterministic, byte-width-preserving dynamic-cache assignment for v151.

No game member is modified.  The emitted CSV files are the input contract for the
runtime builder that follows.
"""
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

OUT = ROOT / "01_work/analysis/dynamic_cache_v153"
ASSIGNMENTS = OUT / "glyph_assignments.csv"
CACHE_SLOTS = OUT / "cache_slots.csv"
ROW_DICTIONARY = OUT / "row_dictionary.bin"
GLYPH_ROWS = OUT / "dynamic_glyph_rows.bin"
REPORT = OUT / "plan_report.txt"
CACHE_N = 20
RESIDENT_BUDGET = 5356


def row_values(bits: tuple[int, ...]) -> tuple[int, ...]:
    return tuple(sum(bits[y * CELL + x] << (CELL - 1 - x) for x in range(CELL))
                 for y in range(CELL))


def virtual_code(slot: int) -> bytes:
    if not 0 <= slot < LOOKUP_N:
        raise ValueError(slot)
    return (bytes((0xE9, slot + 1)) if slot < 254
            else bytes((0xEA, slot - 254 + 1)))


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
            else:
                protected_indices.add(index)
                if len(token) == 2 and token[0] in (0xE9, 0xEA):
                    protected_virtual.add((token[0] - 0xE9) * 254 + token[1] - 1)
        if unit:
            units.append((label, unit))

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

    assignments: dict[str, dict[str, object]] = {}
    occupied: set[int] = set()

    # A one-byte occurrence must remain one byte.  Prefer the exact safe cell that is
    # already drawing the character so this phase changes neither width nor appearance.
    one_byte_chars = [char for char in frequency if 1 in widths[char]]
    for char in sorted(one_byte_chars, key=lambda c: (-frequency[c], c)):
        choices = sorted(index for index in char_indices[char]
                         if index < 220 and index in safe_pool and index not in occupied)
        if not choices:
            raise SystemExit(f"no safe one-byte cell for {char!r}")
        index = choices[0]
        assignments[char] = {"kind": "static", "index": index,
                             "code": direct_code(index)}
        occupied.add(index)

    # Reserve the cache from the strongest cells: the original script actually used
    # their exact plane as a glyph.  Pack candidates into as few physical cells as
    # possible to reduce StoreImage/LoadImage traffic.
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

    # Keep an existing safe two-byte home where possible, prioritising frequent text.
    remaining_chars = [char for char, _ in frequency.most_common()
                       if char not in assignments]
    for char in list(remaining_chars):
        choices = sorted(index for index in char_indices[char]
                         if index in safe_pool and index not in occupied
                         and len(direct_code(index) or b"") == 2)
        if not choices:
            continue
        index = choices[0]
        assignments[char] = {"kind": "static", "index": index,
                             "code": direct_code(index)}
        occupied.add(index)

    # Spend every remaining safe plane on the most frequent unassigned shape.
    free_static = sorted(index for index in safe_pool - occupied
                         if len(direct_code(index) or b"") == 2)
    for char in [char for char, _ in frequency.most_common() if char not in assignments]:
        if not free_static:
            break
        index = free_static.pop(0)
        code = direct_code(index)
        assignments[char] = {"kind": "static", "index": index, "code": code}
        occupied.add(index)

    dynamic = [char for char, _ in frequency.most_common() if char not in assignments]
    if any(1 in widths[char] for char in dynamic):
        raise SystemExit("a one-byte character fell into the dynamic set")

    # Prefer a virtual slot that already names the same shape, then reuse any Hangul
    # slot.  Slots seen carrying non-Hangul in bounded text are never repurposed.
    slots_by_char: dict[str, list[int]] = defaultdict(list)
    hangul_slots = []
    for slot, index in enumerate(lut):
        bits = bitmap(exe, font, index)
        char = shapes.get(bits) if bits else None
        if char and any("가" <= c <= "힣" for c in char) and slot not in protected_virtual:
            slots_by_char[char].append(slot)
            hangul_slots.append(slot)
    used_virtual: set[int] = set()
    fallback = [slot for slot in hangul_slots]
    for source_id, char in enumerate(dynamic):
        preferred = [slot for slot in slots_by_char[char] if slot not in used_virtual]
        available = preferred or [slot for slot in fallback if slot not in used_virtual]
        if not available:
            raise SystemExit("not enough unprotected E9/EA slots")
        slot = available[0]
        used_virtual.add(slot)
        assignments[char] = {"kind": "dynamic", "index": "",
                             "code": virtual_code(slot), "source_id": source_id,
                             "virtual_slot": slot}

    # Every replacement keeps its token width.  This is checked over the actual v151
    # regions, not inferred from the character inventory.
    rewrites = 0
    for _, payload in text_units(current, ranges):
        for token in tokens(payload):
            index = glyph_index(token, lut)
            if index is None:
                continue
            bits = bitmap(exe, font, index)
            char = shapes.get(bits) if bits else None
            if char not in assignments:
                continue
            code = assignments[char]["code"]
            if len(code) != len(token):
                raise SystemExit(
                    f"width change for {char!r}: {token.hex()} -> {code.hex()}"
                )
            rewrites += token != code

    # Exact 12x12 bitmaps, compressed only by a dictionary of complete 12-bit rows.
    row_patterns = sorted({row for char in dynamic for row in row_values(char_bits[char])})
    if len(row_patterns) > 255:
        raise SystemExit(f"row dictionary needs {len(row_patterns)} entries")
    row_id = {value: i for i, value in enumerate(row_patterns)}
    dictionary_blob = b"".join(struct.pack("<H", value) for value in row_patterns)
    glyph_blob = bytes(row_id[row] for char in dynamic for row in row_values(char_bits[char]))

    working = sorted(
        ((len(chars & set(dynamic)), label) for label, chars in units), reverse=True
    )
    cache_cells = {(index // IPR, (index % IPR) // PLANES) for index in cache_indices}

    OUT.mkdir(parents=True, exist_ok=True)
    with ASSIGNMENTS.open("w", encoding="utf-8-sig", newline="") as handle:
        fields = ["char", "kind", "code_hex", "physical_index", "source_id",
                  "virtual_slot", "frequency"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for char in sorted(assignments):
            item = assignments[char]
            writer.writerow({
                "char": char,
                "kind": item["kind"],
                "code_hex": item["code"].hex(" ").upper(),
                "physical_index": item.get("index", ""),
                "source_id": item.get("source_id", ""),
                "virtual_slot": item.get("virtual_slot", ""),
                "frequency": frequency[char],
            })
    with CACHE_SLOTS.open("w", encoding="utf-8-sig", newline="") as handle:
        fields = ["cache_slot", "physical_index", "row", "column", "plane"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for slot, index in enumerate(cache_indices):
            row, remainder = divmod(index, IPR)
            column, plane = divmod(remainder, PLANES)
            writer.writerow({"cache_slot": slot, "physical_index": index, "row": row,
                             "column": column, "plane": plane})
    ROW_DICTIONARY.write_bytes(dictionary_blob)
    GLYPH_ROWS.write_bytes(glyph_blob)

    data_bytes = LOOKUP_N * 2 + len(dictionary_blob) + len(glyph_blob)
    metadata_bytes = CACHE_N * 4 + CACHE_N * 2 + 4 + 72 + 8
    lines = [
        "v153 dynamic-cache assignment plan",
        f"unique_hangul_shapes={len(assignments)}",
        f"static_shapes={sum(a['kind'] == 'static' for a in assignments.values())}",
        f"dynamic_shapes={len(dynamic)}",
        f"one_byte_shapes={len(one_byte_chars)}",
        f"cache_slots={CACHE_N}",
        f"cache_physical_cells={len(cache_cells)}",
        f"max_dynamic_in_one_unit={working[0][0]}",
        f"token_rewrites={rewrites}",
        f"protected_nonhangul_indices={len(protected_indices)}",
        f"protected_nonhangul_virtual_slots={len(protected_virtual)}",
        f"safe_direct_pool={len(safe_pool)}",
        f"row_dictionary_entries={len(row_patterns)}",
        f"row_dictionary_bytes={len(dictionary_blob)}",
        f"dynamic_glyph_rows_bytes={len(glyph_blob)}",
        f"lookup_bytes={LOOKUP_N * 2}",
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
