"""Plan the v165 fail-closed 24-slot completed-glyph cache.

This script does not modify a game member or create a patch archive.  It turns the
v164 runtime findings into a reproducible input contract for the next builder:

* restore every v164 plane in a physical cell with a sampled non-text consumer;
* serve the 162 displaced Hangul shapes and protected virtual slot 405 dynamically;
* preserve the existing 207 dynamic shapes, for 370 dynamic sources in total;
* keep direct one/two-byte token widths by intercepting 40 bounded index ranges;
* store exact 12x12 bitmaps as canonical-Huffman-coded 12-bit rows;
* use 24 cache slots but rebuild one complete 4-plane cell in a 72-byte scratch
  buffer, avoiding a 432-byte persistent six-cell shadow.

All source pixels are exact v164 bitmaps.  Huffman decode is verified source by
source before any artifact is written.
"""
from __future__ import annotations

import csv
import hashlib
import heapq
import pickle
import struct
import sys
import zipfile
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from audit_comm_physical_cell_safety import (  # noqa: E402
    active_slot_units,
    body_units,
    exe_units,
)
from audit_dynamic_cache_requirements import (  # noqa: E402
    glyph_index,
    source_ranges,
)
from build_arc1_v159_dynamic_cache import plain_bitmap  # noqa: E402
from plan_bulk_insertion import CACHE, CELL, IPR, PLANES, tokens  # noqa: E402
from plan_dynamic_cache_v153 import row_values  # noqa: E402


BASE = ROOT / "03_output/arc1_v164_predrawot_cache_upload_probe_4E714493.zip"
BASE_SHA256 = "4E71449316530FF19F44F9C98E9DE62780EBE079548A12E25E7A30F0E80ED33C"
ASSIGNMENTS = ROOT / "01_work/analysis/dynamic_cache_v153_widthsafe/glyph_assignments.csv"
OLD_ROW_DICTIONARY = ROOT / "01_work/analysis/dynamic_cache_v153_widthsafe/row_dictionary.bin"
OLD_GLYPH_ROWS = ROOT / "01_work/analysis/dynamic_cache_v153_widthsafe/dynamic_glyph_rows.bin"
CELL_MANIFEST = ROOT / "01_work/analysis/comm_physical_cell_safety/cells.csv"
PROTECTED_RELOCATIONS = (
    ROOT / "01_work/analysis/dynamic_cache_v153_widthsafe/protected_virtual_relocations.csv"
)

OUT = ROOT / "01_work/analysis/dynamic_cache_v165_failclosed"
SOURCE_MANIFEST = OUT / "source_manifest.csv"
RESTORE_CELLS = OUT / "restore_cells.csv"
LOOKUP_TABLE = OUT / "lookup_table.bin"
HUFFMAN_ROWS = OUT / "huffman_rows.bin"
HUFFMAN_COUNTS = OUT / "huffman_counts.bin"
SOURCE_CHECKPOINTS = OUT / "source_checkpoints.bin"
SOURCE_BITSTREAM = OUT / "source_bitstream.bin"
CONFLICT_RANGES = OUT / "conflict_ranges.bin"
NIBBLE_EXPAND = OUT / "nibble_expand.bin"
LAYOUT = OUT / "resident_layout.csv"
REPORT = OUT / "plan_report.txt"

LOOKUP_N = 409
RAM_TO_FILE = 0x8011A800
RUNTIME_LOOKUP_RAM = 0x801A7520
PROTECTED_DYNAMIC_SLOT = 405
CACHE_N = 24
CACHE_CELLS = CACHE_N // PLANES
# Four-source checkpoints keep runtime Huffman work bounded to at most 48 rows
# per requested glyph while still fitting the frozen 5,356-byte reservation.
CHECKPOINT_GROUP = 4
RESIDENT_BASE = 0x801FE3C4
RESIDENT_BUDGET = 5356
CELL_BYTES = CELL * (CELL // 2)
DECODED_GLYPH_BYTES = CELL * 2


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def read_runtime_lut(exe: bytes) -> tuple[int, ...]:
    """Read the 409-entry table used by the v159+ runtime decoder.

    ``plan_bulk_insertion.LOOKUP_SRC`` names the older 508-entry static
    insertion table.  Reusing its generic reader here would silently inspect
    the wrong namespace, so the v164 runtime address is deliberately local and
    explicit.
    """
    at = RUNTIME_LOOKUP_RAM - RAM_TO_FILE
    end = at + LOOKUP_N * 2
    if at < 0 or end > len(exe):
        return ()
    return struct.unpack_from(f"<{LOOKUP_N}H", exe, at)


def old_dynamic_bitmaps(
    old_source_chars: dict[int, str],
) -> dict[str, tuple[int, ...]]:
    dictionary_blob = OLD_ROW_DICTIONARY.read_bytes()
    glyph_blob = OLD_GLYPH_ROWS.read_bytes()
    if len(dictionary_blob) % 2 or len(glyph_blob) != len(old_source_chars) * CELL:
        raise SystemExit("old dynamic bitmap artifacts have unexpected sizes")
    dictionary = struct.unpack(f"<{len(dictionary_blob) // 2}H", dictionary_blob)
    result: dict[str, tuple[int, ...]] = {}
    for source_id, char in sorted(old_source_chars.items()):
        ids = glyph_blob[source_id * CELL:(source_id + 1) * CELL]
        rows = [dictionary[index] for index in ids]
        result[char] = tuple(
            1 if rows[y] & (1 << (CELL - 1 - x)) else 0
            for y in range(CELL) for x in range(CELL)
        )
    return result


def contiguous_ranges(indices: list[int]) -> list[tuple[int, int, int]]:
    """Return (start, length, source_base) for sorted physical indices."""
    if indices != sorted(set(indices)) or not indices:
        raise SystemExit("conflict indices are empty, duplicated, or unsorted")
    result: list[tuple[int, int, int]] = []
    start = previous = indices[0]
    source_base = 0
    for index in indices[1:]:
        if index == previous + 1:
            previous = index
            continue
        result.append((start, previous - start + 1, source_base))
        source_base += previous - start + 1
        start = previous = index
    result.append((start, previous - start + 1, source_base))
    if sum(length for _start, length, _base in result) != len(indices):
        raise SystemExit("conflict ranges do not cover every physical index")
    return result


def huffman_lengths(frequency: Counter[int]) -> dict[int, int]:
    """Build deterministic, unconstrained Huffman code lengths."""
    heap: list[tuple[int, int, int, dict[int, int]]] = []
    serial = 0
    for symbol, count in sorted(frequency.items()):
        heapq.heappush(heap, (count, symbol, serial, {symbol: 0}))
        serial += 1
    if len(heap) < 2:
        raise SystemExit("Huffman alphabet unexpectedly has fewer than two rows")
    while len(heap) > 1:
        left = heapq.heappop(heap)
        right = heapq.heappop(heap)
        lengths = {symbol: length + 1 for symbol, length in left[3].items()}
        lengths.update({symbol: length + 1 for symbol, length in right[3].items()})
        heapq.heappush(
            heap,
            (left[0] + right[0], min(left[1], right[1]), serial, lengths),
        )
        serial += 1
    return heap[0][3]


def canonical_codes(lengths: dict[int, int]) -> tuple[list[int], bytes, dict[int, tuple[int, int]]]:
    ordered = sorted(lengths, key=lambda symbol: (lengths[symbol], symbol))
    maximum = max(lengths.values())
    counts = bytes(sum(length == width for length in lengths.values())
                   for width in range(1, maximum + 1))
    if any(count > 255 for count in counts):
        raise SystemExit("one Huffman length count exceeds one byte")
    code = 0
    previous_length = 0
    codes: dict[int, tuple[int, int]] = {}
    for symbol in ordered:
        length = lengths[symbol]
        code <<= length - previous_length
        if code >= 1 << length:
            raise SystemExit("canonical Huffman code overflow")
        codes[symbol] = (code, length)
        code += 1
        previous_length = length
    return ordered, counts, codes


class BitWriter:
    def __init__(self) -> None:
        self.data = bytearray()
        self.bit_length = 0

    def write(self, value: int, width: int) -> None:
        for shift in range(width - 1, -1, -1):
            byte_index, bit_index = divmod(self.bit_length, 8)
            if byte_index == len(self.data):
                self.data.append(0)
            if value >> shift & 1:
                self.data[byte_index] |= 0x80 >> bit_index
            self.bit_length += 1


def decode_symbol(
    bitstream: bytes,
    bit_position: int,
    counts: bytes,
    canonical_rows: list[int],
) -> tuple[int, int]:
    code = first_code = first_symbol = 0
    for length, count in enumerate(counts, 1):
        if bit_position >= len(bitstream) * 8:
            raise SystemExit("Huffman decoder ran beyond the bitstream")
        byte_index, bit_index = divmod(bit_position, 8)
        code = (code << 1) | ((bitstream[byte_index] >> (7 - bit_index)) & 1)
        bit_position += 1
        delta = code - first_code
        if 0 <= delta < count:
            return canonical_rows[first_symbol + delta], bit_position
        first_symbol += count
        first_code = (first_code + count) << 1
    raise SystemExit("Huffman bitstream contains an invalid code")


def main() -> None:
    if digest(BASE) != BASE_SHA256:
        raise SystemExit("v164 archive hash differs")
    for path in (
        ASSIGNMENTS,
        OLD_ROW_DICTIONARY,
        OLD_GLYPH_ROWS,
        CELL_MANIFEST,
        PROTECTED_RELOCATIONS,
    ):
        if not path.exists():
            raise SystemExit(f"missing required analysis input: {path}")

    with zipfile.ZipFile(BASE) as archive:
        members = {info.filename: archive.read(info.filename) for info in archive.infolist()}
    exe, font = members["PSX.EXE"], members["COMM.IMG"]
    old_lut = read_runtime_lut(exe)
    if len(old_lut) < LOOKUP_N:
        raise SystemExit("runtime lookup table is shorter than 409 entries")

    assignments = read_csv(ASSIGNMENTS)
    cells = read_csv(CELL_MANIFEST)
    relocations = read_csv(PROTECTED_RELOCATIONS)
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())

    index_chars = {
        int(row["physical_index"]): row["char"]
        for row in assignments if row["physical_index"]
    }
    old_source_chars = {
        int(row["source_id"]): row["char"]
        for row in assignments if row["source_id"]
    }
    if sorted(old_source_chars) != list(range(207)):
        raise SystemExit("old dynamic source IDs are no longer exactly 0..206")

    rejected_cells = {
        (int(row["row"]), int(row["col"]))
        for row in cells if row["status"] == "rejected_known_nontext"
    }
    conflict_indices = sorted(
        index for index in index_chars
        if (index // IPR, (index % IPR) // PLANES) in rejected_cells
    )
    conflict_cells = sorted({
        (index // IPR, (index % IPR) // PLANES) for index in conflict_indices
    })
    if len(conflict_indices) != 162 or len(conflict_cells) != 50:
        raise SystemExit(
            f"fail-closed conflict set changed: {len(conflict_indices)} planes / "
            f"{len(conflict_cells)} cells"
        )

    protected = [row for row in relocations
                 if int(row["virtual_slot"]) == PROTECTED_DYNAMIC_SLOT]
    if len(protected) != 1:
        raise SystemExit("protected virtual slot 405 is not unique")
    protected_index = int(protected[0]["destination_index"])
    protected_cell = (protected_index // IPR, (protected_index % IPR) // PLANES)
    if protected_cell not in rejected_cells:
        raise SystemExit("protected virtual slot 405 no longer occupies a rejected cell")

    bitmaps: dict[str, tuple[int, ...]] = {
        char: plain_bitmap(font, index) for index, char in index_chars.items()
    }
    bitmaps.update(old_dynamic_bitmaps(old_source_chars))
    protected_name = f"<VIRTUAL:{PROTECTED_DYNAMIC_SLOT}>"
    bitmaps[protected_name] = plain_bitmap(font, protected_index)
    for char, bitmap_bits in bitmaps.items():
        if len(bitmap_bits) != CELL * CELL or not any(bitmap_bits):
            raise SystemExit(f"missing or blank source bitmap for {char!r}")
        known = shapes.get(bitmap_bits)
        if char[0] != "<" and known != char:
            raise SystemExit(f"bitmap identity differs for {char!r}: {known!r}")

    # Source IDs 0..161 are the sorted direct physical indices.  The decoder can
    # therefore map a direct one/two-byte code with a 40-record bounded range table.
    source_rows: list[dict[str, object]] = []
    source_bitmaps: list[tuple[int, ...]] = []
    conflict_source: dict[int, int] = {}
    for source_id, index in enumerate(conflict_indices):
        char = index_chars[index]
        conflict_source[index] = source_id
        source_rows.append({
            "source_id": source_id,
            "char": char,
            "kind": "restored_static_conflict",
            "old_physical_index": index,
            "old_source_id": "",
            "virtual_slot": "",
        })
        source_bitmaps.append(bitmaps[char])
    old_source_to_new: dict[int, int] = {}
    for old_source_id in sorted(old_source_chars):
        source_id = len(source_rows)
        char = old_source_chars[old_source_id]
        old_source_to_new[old_source_id] = source_id
        source_rows.append({
            "source_id": source_id,
            "char": char,
            "kind": "existing_dynamic",
            "old_physical_index": "",
            "old_source_id": old_source_id,
            "virtual_slot": "",
        })
        source_bitmaps.append(bitmaps[char])
    protected_source_id = len(source_rows)
    source_rows.append({
        "source_id": protected_source_id,
        "char": protected_name,
        "kind": "protected_virtual",
        "old_physical_index": protected_index,
        "old_source_id": "",
        "virtual_slot": PROTECTED_DYNAMIC_SLOT,
    })
    source_bitmaps.append(bitmaps[protected_name])
    if len(source_rows) != 370 or protected_source_id != 369:
        raise SystemExit("new dynamic source IDs do not cover exactly 0..369")

    ranges = contiguous_ranges(conflict_indices)
    if len(ranges) != 40:
        raise SystemExit(f"expected 40 direct-index ranges, found {len(ranges)}")
    range_blob = bytearray()
    for start, length, source_base in ranges:
        if not 0 <= start <= 0xFFFF or not 1 <= length <= 0xFF or not 0 <= source_base <= 0xFF:
            raise SystemExit("one direct-index range exceeds its packed fields")
        range_blob += struct.pack("<HBB", start, length, source_base)

    # Keep the existing 409-entry lookup namespace.  Existing dynamic IDs shift by
    # 162; aliases to a restored physical index become dynamic; slot 405 becomes the
    # protected dynamic source.  No text token width changes.
    new_lut = list(old_lut[:LOOKUP_N])
    protected_aliases = [slot for slot, value in enumerate(new_lut) if value == protected_index]
    if protected_aliases != [PROTECTED_DYNAMIC_SLOT]:
        raise SystemExit(f"protected destination aliases changed: {protected_aliases}")
    for slot, value in enumerate(new_lut):
        if slot == PROTECTED_DYNAMIC_SLOT:
            new_lut[slot] = 0x8000 | protected_source_id
        elif value & 0x8000:
            old_source_id = value & 0x7FFF
            if old_source_id not in old_source_to_new:
                raise SystemExit(f"lookup slot {slot} has unknown old source {old_source_id}")
            new_lut[slot] = 0x8000 | old_source_to_new[old_source_id]
        elif value in conflict_source:
            new_lut[slot] = 0x8000 | conflict_source[value]
    lookup_blob = struct.pack(f"<{LOOKUP_N}H", *new_lut)

    all_rows = [row for bitmap_bits in source_bitmaps for row in row_values(bitmap_bits)]
    frequency = Counter(all_rows)
    lengths = huffman_lengths(frequency)
    canonical_rows, counts, codes = canonical_codes(lengths)
    maximum_length = len(counts)
    if maximum_length > 16:
        raise SystemExit(f"Huffman maximum length {maximum_length} exceeds decoder contract")

    writer = BitWriter()
    checkpoints: list[int] = []
    for source_id, bitmap_bits in enumerate(source_bitmaps):
        if source_id % CHECKPOINT_GROUP == 0:
            checkpoints.append(writer.bit_length)
        for row in row_values(bitmap_bits):
            code, width = codes[row]
            writer.write(code, width)
    if max(checkpoints) > 0xFFFF or writer.bit_length > 0xFFFF:
        raise SystemExit("Huffman bit offsets exceed the 16-bit runtime representation")
    checkpoint_blob = struct.pack(f"<{len(checkpoints)}H", *checkpoints)
    canonical_blob = struct.pack(f"<{len(canonical_rows)}H", *canonical_rows)
    # Four left-to-right monochrome pixels become two 4bpp bytes in plane zero.
    # The frame routine shifts this 16-bit value by plane 0..3 and ORs it into
    # the complete-cell scratch buffer.  One 16-entry table serves all planes.
    expand_values = []
    for nibble in range(16):
        low = ((nibble >> 3) & 1) | (((nibble >> 2) & 1) << 4)
        high = ((nibble >> 1) & 1) | ((nibble & 1) << 4)
        expand_values.append(low | (high << 8))
    expand_blob = struct.pack("<16H", *expand_values)

    # Independent decoder: seek from the group checkpoint and reconstruct all 370
    # exact source bitmaps.  This verifies both canonical tables and bit packing.
    for source_id, expected_bitmap in enumerate(source_bitmaps):
        group, within = divmod(source_id, CHECKPOINT_GROUP)
        bit_position = checkpoints[group]
        decoded_rows: list[int] = []
        for ordinal in range((within + 1) * CELL):
            row, bit_position = decode_symbol(
                bytes(writer.data), bit_position, counts, canonical_rows
            )
            if ordinal >= within * CELL:
                decoded_rows.append(row)
        decoded_bitmap = tuple(
            1 if decoded_rows[y] & (1 << (CELL - 1 - x)) else 0
            for y in range(CELL) for x in range(CELL)
        )
        if decoded_bitmap != expected_bitmap:
            raise SystemExit(f"Huffman source readback differs at source {source_id}")

    # Bounded working-set measurement, including the newly dynamic protected glyph.
    dynamic_chars = {str(row["char"]) for row in source_rows}
    index_to_source_char = {
        index: index_chars[index] for index in conflict_indices
    }

    def token_source_char(token: bytes) -> str | None:
        if len(token) == 2 and token[0] in (0xE9, 0xEA):
            slot = (token[0] - 0xE9) * 254 + token[1] - 1
            if not 0 <= slot < LOOKUP_N:
                return None
            if slot == PROTECTED_DYNAMIC_SLOT:
                return protected_name
            value = old_lut[slot]
            if value & 0x8000:
                return old_source_chars.get(value & 0x7FFF)
            return index_to_source_char.get(value)
        value = glyph_index(token, old_lut)
        if value is None:
            return None
        if value & 0x8000:
            return old_source_chars.get(value & 0x7FFF)
        return index_to_source_char.get(value)

    units = (
        list(body_units(members, source_ranges()))
        + list(active_slot_units(members, source_ranges()))
        + list(exe_units(members))
    )
    working_sets: list[tuple[int, str]] = []
    for label, payload in units:
        chars = {
            char for token in tokens(payload)
            if (char := token_source_char(token)) in dynamic_chars
        }
        if chars:
            working_sets.append((len(chars), label))
    working_sets.sort(reverse=True)
    maximum_working_set = working_sets[0][0] if working_sets else 0
    if maximum_working_set > CACHE_N:
        raise SystemExit(
            f"bounded working set {maximum_working_set} exceeds {CACHE_N} cache slots"
        )

    # Exact pre-code resident layout.  The builder must generate real routines and
    # prove they fit in the remaining bytes; this planner never estimates code size.
    offset = 0
    layout_rows: list[tuple[str, int, int, int]] = []

    def place(name: str, size: int, alignment: int = 1) -> int:
        nonlocal offset
        offset = (offset + alignment - 1) & -alignment
        start = offset
        offset += size
        layout_rows.append((name, RESIDENT_BASE + start, size, alignment))
        return start

    place("huffman_rows", len(canonical_blob), 2)
    place("huffman_counts", len(counts))
    place("conflict_ranges", len(range_blob), 4)
    place("source_checkpoints", len(checkpoint_blob), 2)
    place("source_bitstream", len(writer.data))
    place("nibble_expand", len(expand_blob), 2)
    pre_source_padding = offset
    place("owners", CACHE_N * 2, 2)
    place("active_mask", 4, 4)
    place("next_slot", 4, 4)
    place("upload_rect", 8, 2)
    place("cell_scratch", CELL_BYTES, 4)
    place("decoded_glyph_rows", DECODED_GLYPH_BYTES, 2)
    code_start = (offset + 3) & ~3
    bytes_left_for_code = RESIDENT_BUDGET - code_start
    if bytes_left_for_code <= 0:
        raise SystemExit("planned resident data leaves no room for code")

    OUT.mkdir(parents=True, exist_ok=True)
    with SOURCE_MANIFEST.open("w", encoding="utf-8-sig", newline="") as handle:
        fields = [
            "source_id", "char", "kind", "old_physical_index",
            "old_source_id", "virtual_slot",
        ]
        writer_csv = csv.DictWriter(handle, fieldnames=fields)
        writer_csv.writeheader()
        writer_csv.writerows(source_rows)
    with RESTORE_CELLS.open("w", encoding="utf-8-sig", newline="") as handle:
        writer_csv = csv.writer(handle)
        writer_csv.writerow(("row", "col", "changed_planes", "reason"))
        for row, col in conflict_cells:
            changed = [
                index % PLANES for index in conflict_indices
                if index // IPR == row and (index % IPR) // PLANES == col
            ]
            if (row, col) == protected_cell:
                changed.append(protected_index % PLANES)
            writer_csv.writerow((row, col, " ".join(map(str, sorted(changed))),
                                 "sampled_nontext_consumer"))
    with LAYOUT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer_csv = csv.writer(handle)
        writer_csv.writerow(("name", "runtime_address", "size", "alignment"))
        for name, address, size, alignment in layout_rows:
            writer_csv.writerow((name, f"0x{address:08X}", size, alignment))

    LOOKUP_TABLE.write_bytes(lookup_blob)
    HUFFMAN_ROWS.write_bytes(canonical_blob)
    HUFFMAN_COUNTS.write_bytes(counts)
    SOURCE_CHECKPOINTS.write_bytes(checkpoint_blob)
    SOURCE_BITSTREAM.write_bytes(bytes(writer.data))
    CONFLICT_RANGES.write_bytes(bytes(range_blob))
    NIBBLE_EXPAND.write_bytes(expand_blob)

    direct_one_byte = sum(index < 220 for index in conflict_indices)
    protected_occurrences = 0
    protected_token = bytes((0xEA, PROTECTED_DYNAMIC_SLOT - 254 + 1))
    for _label, payload in units:
        protected_occurrences += sum(token == protected_token for token in tokens(payload))
    lines = [
        "v165 fail-closed 24-slot dynamic-cache plan",
        "",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"all_sources={len(source_rows)}",
        f"restored_static_hangul_sources={len(conflict_indices)}",
        f"existing_dynamic_sources={len(old_source_chars)}",
        "protected_dynamic_sources=1",
        f"protected_virtual_slot={PROTECTED_DYNAMIC_SLOT}",
        f"protected_virtual_occurrences={protected_occurrences}",
        f"restored_physical_cells={len(conflict_cells)}",
        f"direct_one_byte_sources={direct_one_byte}",
        f"direct_index_ranges={len(ranges)}",
        f"cache_slots={CACHE_N}",
        f"cache_physical_cells={CACHE_CELLS}",
        f"bounded_max_simultaneous_dynamic={maximum_working_set}",
        "",
        f"huffman_row_symbols={len(canonical_rows)}",
        f"huffman_max_code_bits={maximum_length}",
        f"huffman_encoded_bits={writer.bit_length}",
        f"huffman_bitstream_bytes={len(writer.data)}",
        f"huffman_rows_bytes={len(canonical_blob)}",
        f"huffman_counts_bytes={len(counts)}",
        f"checkpoint_group={CHECKPOINT_GROUP}",
        f"checkpoint_count={len(checkpoints)}",
        f"checkpoint_bytes={len(checkpoint_blob)}",
        f"conflict_range_bytes={len(range_blob)}",
        f"nibble_expand_bytes={len(expand_blob)}",
        f"compressed_source_and_mapping_bytes={pre_source_padding}",
        "huffman_source_readback=370/370 PASS",
        "lookup_entries=409 unchanged",
        "text_token_width_changes=0 by design",
        "",
        f"resident_data_and_state_before_code={code_start}",
        f"resident_budget={RESIDENT_BUDGET}",
        f"bytes_left_for_all_resident_code={bytes_left_for_code}",
        f"cell_backing=one {CELL_BYTES}-byte rebuild scratch, not {CACHE_CELLS} persistent cells",
        f"decoded_glyph_scratch={DECODED_GLYPH_BYTES}",
        "",
        "top_bounded_working_sets=" + " | ".join(
            f"{count}:{label}" for count, label in working_sets[:10]
        ),
        "",
        "analysis_only=PASS",
        "patch_built=NO",
        "next_gate=generate and disassemble decoder/frame/Huffman routines inside remaining bytes",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
