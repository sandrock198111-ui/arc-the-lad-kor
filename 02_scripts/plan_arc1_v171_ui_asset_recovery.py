"""Plan v171's lossless recovery of overwritten native UI assets.

This is analysis only.  It restores no archive and writes no patch.  The plan
extends the proven v165 fail-closed source set with every Hangul plane displaced
when the 26 measured native UI cells are restored in full:

* row 10 markers and punctuation-adjacent UI cells;
* row 11 controller/START/SELECT cells;
* row 17 16x24 battle-damage digits sampled at V=208/220.

The 462 completed glyphs are represented exactly.  The final blank bitmap row
is omitted from the Huffman stream only after proving that it is zero in every
source.  The runtime lookup is packed to 11 bits, and direct conflict ranges
use one 16-bit word (11-bit start plus 5-bit length-1).  Independent Python
decoders verify every emitted artifact before it is written.
"""
from __future__ import annotations

import csv
import hashlib
import struct
import sys
import zipfile
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v165_failclosed_cache as old  # noqa: E402
import plan_dynamic_cache_v165_failclosed as v165_plan  # noqa: E402
from audit_comm_physical_cell_safety import (  # noqa: E402
    active_slot_units,
    body_units,
    exe_units,
)
from audit_dynamic_cache_requirements import glyph_index, source_ranges  # noqa: E402
from plan_bulk_insertion import CACHE, CELL, IPR, PLANES, tokens  # noqa: E402
from plan_dynamic_cache_v153 import row_values  # noqa: E402


BASE = ROOT / "03_output/arc1_v170_restore_blank_space_filler_F8A67A67.zip"
BASE_SHA256 = "F8A67A674A8E17F18C50DB7408FB3DCFD494FD9760C665D429CC11D36D9EF81B"
ORIGINAL = ROOT / "00_original/arc.zip"
ORIGINAL_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"
CONTROL = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
CONTROL_SHA256 = "A4358FEE5FEA4964C9DD376B630894EB5EC133EFEEDD9E5E85BBC5FDD8CA1A46"

ASSIGNMENTS = v165_plan.ASSIGNMENTS
OLD_SOURCE_MANIFEST = v165_plan.SOURCE_MANIFEST
OUT = ROOT / "01_work/analysis/arc1_v171_ui_asset_recovery"
SOURCE_MANIFEST = OUT / "source_manifest.csv"
RESTORE_CELLS = OUT / "restore_ui_cells.csv"
LOOKUP_TABLE = OUT / "lookup_11bit.bin"
HUFFMAN_ROWS = OUT / "huffman_rows.bin"
HUFFMAN_COUNTS = OUT / "huffman_counts.bin"
SOURCE_CHECKPOINTS = OUT / "source_checkpoints.bin"
SOURCE_BITSTREAM = OUT / "source_bitstream.bin"
CONFLICT_RANGES = OUT / "conflict_ranges_16bit.bin"
REPORT = OUT / "plan_report.txt"

LOOKUP_N = 409
OLD_DIRECT_N = 162
OLD_EXISTING_DYNAMIC_N = 207
OLD_PROTECTED_SOURCE = 369
NEW_DIRECT_N = 254
SOURCE_N = 462
CACHE_N = 28
DYNAMIC_TAG = 1536
SPECIAL_STATIC_TAG = 2047
SPECIAL_STATIC_VALUE = 5296
LOOKUP_BITS = 11
CHECKPOINT_GROUP = 16
ENCODED_ROWS = 11

# Complete cells proven to contain native UI art in the untouched atlas.  The
# set is intentionally explicit and is checked against the measured 92 Hangul
# planes before artifacts are emitted.
UI_CELLS = tuple(
    [(10, col) for col in (6, 7, 8, 11, 19, 20)]
    + [(11, col) for col in (7, 8, 11, 12, 18, 19, 20)]
    + [(17, col) for col in range(13)]
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def pack_fixed(values: list[int], width: int) -> bytes:
    """Pack little-endian fixed-width integers into a byte stream."""
    accumulator = bit_count = 0
    output = bytearray()
    mask = (1 << width) - 1
    for value in values:
        if not 0 <= value <= mask:
            raise SystemExit(f"{value} does not fit in {width} bits")
        accumulator |= value << bit_count
        bit_count += width
        while bit_count >= 8:
            output.append(accumulator & 0xFF)
            accumulator >>= 8
            bit_count -= 8
    if bit_count:
        output.append(accumulator & 0xFF)
    return bytes(output)


def unpack_fixed(blob: bytes, count: int, width: int) -> list[int]:
    result: list[int] = []
    mask = (1 << width) - 1
    for ordinal in range(count):
        bit = ordinal * width
        byte, shift = divmod(bit, 8)
        word = int.from_bytes(blob[byte:byte + 3].ljust(3, b"\0"), "little")
        result.append((word >> shift) & mask)
    return result


def bitmap_rows(bitmap: tuple[int, ...]) -> tuple[int, ...]:
    rows = tuple(row_values(bitmap))
    if len(rows) != CELL:
        raise SystemExit("source bitmap does not have twelve rows")
    return rows


def decode_huffman_source(
    source: int,
    rows: tuple[int, ...],
    counts: bytes,
    checkpoints: tuple[int, ...],
    stream: bytes,
) -> tuple[int, ...]:
    group, within = divmod(source, CHECKPOINT_GROUP)
    bit_position = checkpoints[group]
    decoded: list[int] = []
    for ordinal in range((within + 1) * ENCODED_ROWS):
        symbol, bit_position = v165_plan.decode_symbol(
            stream, bit_position, counts, list(rows)
        )
        if ordinal >= within * ENCODED_ROWS:
            decoded.append(symbol)
    decoded.append(0)
    return tuple(decoded)


def main() -> None:
    for path, expected in (
        (BASE, BASE_SHA256), (ORIGINAL, ORIGINAL_SHA256),
        (CONTROL, CONTROL_SHA256),
    ):
        if digest(path) != expected:
            raise SystemExit(f"archive hash differs: {path.name}")

    # Rebuild the old 370-source provenance from its frozen v164 inputs.  This
    # is deliberately done before consuming its artifacts, so stale files can
    # never silently become v171 inputs.
    v165_plan.main()
    old.CHECKPOINT_GROUP = v165_plan.CHECKPOINT_GROUP
    old_rows = old.decode_sources(old.read_layout())
    old_bitmaps = [old.rows_to_bitmap(value) for value in old_rows]
    if len(old_bitmaps) != 370:
        raise SystemExit("v165 source readback is not exactly 370 glyphs")

    with zipfile.ZipFile(BASE) as archive:
        members = {info.filename: archive.read(info.filename) for info in archive.infolist()}
    with zipfile.ZipFile(ORIGINAL) as archive:
        original_font = archive.read("COMM.IMG")
    with zipfile.ZipFile(CONTROL) as archive:
        control_font = archive.read("COMM.IMG")
    exe, font = members["PSX.EXE"], members["COMM.IMG"]
    if {len(font), len(original_font), len(control_font)} != {458752}:
        raise SystemExit("COMM.IMG sizes differ")

    assignments = read_csv(ASSIGNMENTS)
    old_manifest = read_csv(OLD_SOURCE_MANIFEST)
    index_char = {
        int(row["physical_index"]): row["char"]
        for row in assignments if row["physical_index"]
    }
    old_source_row = {int(row["source_id"]): row for row in old_manifest}
    if sorted(old_source_row) != list(range(370)):
        raise SystemExit("v165 source manifest is not exactly 0..369")
    old_direct_index = {
        int(row["old_physical_index"]): source
        for source, row in old_source_row.items()
        if row["kind"] == "restored_static_conflict"
    }
    if len(old_direct_index) != OLD_DIRECT_N:
        raise SystemExit("v165 direct conflict count differs")

    ui_indices = sorted(
        index for index in index_char
        if (index // IPR, (index % IPR) // PLANES) in UI_CELLS
    )
    additional_indices = sorted(set(ui_indices) - set(old_direct_index))
    if len(UI_CELLS) != 26 or len(ui_indices) != 92 or len(additional_indices) != 92:
        raise SystemExit(
            "UI recovery set is not exactly 26 cells / 92 new Hangul planes: "
            f"{len(UI_CELLS)}, {len(ui_indices)}, {len(additional_indices)}"
        )
    conflict_indices = sorted(set(old_direct_index) | set(additional_indices))
    if len(conflict_indices) != NEW_DIRECT_N:
        raise SystemExit(f"combined direct conflict count is {len(conflict_indices)}, not 254")

    source_rows: list[dict[str, object]] = []
    source_bitmaps: list[tuple[int, ...]] = []
    direct_source: dict[int, int] = {}
    for source, index in enumerate(conflict_indices):
        char = index_char[index]
        direct_source[index] = source
        if index in old_direct_index:
            bitmap = old_bitmaps[old_direct_index[index]]
            kind = "existing_restored_static_conflict"
        else:
            bitmap = v165_plan.plain_bitmap(font, index)
            kind = "ui_asset_displaced_static"
        if not any(bitmap):
            raise SystemExit(f"dynamic source is blank: index {index} {char!r}")
        source_rows.append({
            "source_id": source,
            "char": char,
            "kind": kind,
            "old_physical_index": index,
            "old_source_id": "",
        })
        source_bitmaps.append(bitmap)

    old_dynamic_remap: dict[int, int] = {}
    for old_source in range(OLD_DIRECT_N, OLD_PROTECTED_SOURCE):
        source = len(source_rows)
        old_dynamic_remap[old_source] = source
        row = old_source_row[old_source]
        source_rows.append({
            "source_id": source,
            "char": row["char"],
            "kind": "existing_dynamic",
            "old_physical_index": "",
            "old_source_id": old_source,
        })
        source_bitmaps.append(old_bitmaps[old_source])
    protected_source = len(source_rows)
    source_rows.append({
        "source_id": protected_source,
        "char": old_source_row[OLD_PROTECTED_SOURCE]["char"],
        "kind": "protected_virtual",
        "old_physical_index": old_source_row[OLD_PROTECTED_SOURCE]["old_physical_index"],
        "old_source_id": OLD_PROTECTED_SOURCE,
    })
    source_bitmaps.append(old_bitmaps[OLD_PROTECTED_SOURCE])
    if len(source_rows) != SOURCE_N or protected_source != 461:
        raise SystemExit("v171 source IDs are not exactly 0..461")

    shapes = __import__("pickle").loads(CACHE.read_bytes())
    for row, bitmap in zip(source_rows, source_bitmaps):
        char = str(row["char"])
        if not char.startswith("<") and shapes.get(bitmap) != char:
            raise SystemExit(f"source bitmap identity differs for {char!r}")
        rows = bitmap_rows(bitmap)
        if rows[-1] != 0:
            raise SystemExit(f"source {row['source_id']} has a nonblank omitted row 11")

    # Bounded sorted ranges cover all 254 direct physical indices.  The
    # source base is the cumulative prior length, so it need not be stored.
    ranges = v165_plan.contiguous_ranges(conflict_indices)
    if len(ranges) != 48:
        raise SystemExit(f"combined contiguous range count is {len(ranges)}, not 48")
    packed_ranges = bytearray()
    cumulative = 0
    for start, length, source_base in ranges:
        if source_base != cumulative:
            raise SystemExit("range source base is not cumulative")
        if not 0 <= start < 1 << 11 or not (1 <= length <= 31 or length == 39):
            raise SystemExit(f"range does not fit 11+5 bits: {start},{length}")
        length_field = 31 if length == 39 else length - 1
        packed_ranges += struct.pack("<H", start | (length_field << 11))
        cumulative += length
    decoded_ranges: dict[int, int] = {}
    cumulative = 0
    for at in range(0, len(packed_ranges), 2):
        value = struct.unpack_from("<H", packed_ranges, at)[0]
        start, field = value & 0x7FF, value >> 11
        length = 39 if field == 31 else field + 1
        for delta in range(length):
            decoded_ranges[start + delta] = cumulative + delta
        cumulative += length
    if decoded_ranges != direct_source:
        raise SystemExit("packed direct ranges do not reconstruct 254/254 mappings")

    # Remap the current v170 16-bit lookup and then pack it to 11 bits.  Static
    # values remain their physical index; dynamic values use 1536+source_id.
    current_lut = v165_plan.read_runtime_lut(exe)
    if len(current_lut) != LOOKUP_N:
        raise SystemExit("v170 runtime lookup is not exactly 409 entries")
    normalized: list[int] = []
    for slot, value in enumerate(current_lut):
        if value & 0x8000:
            old_source = value & 0x7FFF
            if old_source < OLD_DIRECT_N:
                old_index = int(old_source_row[old_source]["old_physical_index"])
                source = direct_source[old_index]
            elif old_source < OLD_PROTECTED_SOURCE:
                source = old_dynamic_remap[old_source]
            elif old_source == OLD_PROTECTED_SOURCE:
                source = protected_source
            else:
                raise SystemExit(f"lookup slot {slot} has unknown source {old_source}")
            normalized.append(DYNAMIC_TAG + source)
        elif value in direct_source:
            normalized.append(DYNAMIC_TAG + direct_source[value])
        else:
            if value == SPECIAL_STATIC_VALUE:
                normalized.append(SPECIAL_STATIC_TAG)
            else:
                if value >= DYNAMIC_TAG:
                    raise SystemExit(f"static lookup value collides with dynamic tag: {value}")
                normalized.append(value)
    lookup_blob = pack_fixed(normalized, LOOKUP_BITS)
    if len(lookup_blob) != 563 or unpack_fixed(lookup_blob, LOOKUP_N, LOOKUP_BITS) != normalized:
        raise SystemExit("11-bit lookup roundtrip differs")

    # Canonical Huffman over the eleven non-omitted rows.
    all_rows = [row for bitmap in source_bitmaps for row in bitmap_rows(bitmap)[:ENCODED_ROWS]]
    lengths = v165_plan.huffman_lengths(Counter(all_rows))
    canonical_rows, counts, codes = v165_plan.canonical_codes(lengths)
    if len(counts) > 16:
        raise SystemExit("Huffman maximum code length exceeds 16 bits")
    writer = v165_plan.BitWriter()
    checkpoints: list[int] = []
    for source, bitmap in enumerate(source_bitmaps):
        if source % CHECKPOINT_GROUP == 0:
            checkpoints.append(writer.bit_length)
        for row in bitmap_rows(bitmap)[:ENCODED_ROWS]:
            code, width = codes[row]
            writer.write(code, width)
    if max(checkpoints) > 0xFFFF or writer.bit_length > 0xFFFF:
        raise SystemExit("Huffman offsets exceed 16 bits")
    checkpoint_blob = struct.pack(f"<{len(checkpoints)}H", *checkpoints)
    row_blob = struct.pack(f"<{len(canonical_rows)}H", *canonical_rows)
    stream_blob = bytes(writer.data)
    for source, bitmap in enumerate(source_bitmaps):
        decoded = decode_huffman_source(
            source, tuple(canonical_rows), counts, tuple(checkpoints), stream_blob
        )
        if decoded != bitmap_rows(bitmap):
            raise SystemExit(f"Huffman source readback differs at {source}")

    # Bounded corpus measurement is a safety ceiling, not a claim that every
    # game state is represented by the corpus.
    dynamic_chars = {str(row["char"]) for row in source_rows}
    current_index_char = index_char

    def token_char(token: bytes) -> str | None:
        if len(token) == 2 and token[0] in (0xE9, 0xEA):
            slot = (token[0] - 0xE9) * 254 + token[1] - 1
            if not 0 <= slot < LOOKUP_N:
                return None
            value = normalized[slot]
            if value == SPECIAL_STATIC_TAG:
                return current_index_char.get(SPECIAL_STATIC_VALUE)
            if value >= DYNAMIC_TAG:
                return str(source_rows[value - DYNAMIC_TAG]["char"])
            return current_index_char.get(value)
        value = glyph_index(token, current_lut)
        if value is None:
            return None
        if value in direct_source:
            return str(source_rows[direct_source[value]]["char"])
        return current_index_char.get(value)

    units = (
        list(body_units(members, source_ranges()))
        + list(active_slot_units(members, source_ranges()))
        + list(exe_units(members))
    )
    working_sets: list[tuple[int, str]] = []
    for label, payload in units:
        chars = {char for token in tokens(payload)
                 if (char := token_char(token)) in dynamic_chars}
        if chars:
            working_sets.append((len(chars), label))
    working_sets.sort(reverse=True)
    maximum_working_set = working_sets[0][0] if working_sets else 0
    if maximum_working_set > CACHE_N:
        raise SystemExit(f"bounded working set {maximum_working_set} exceeds {CACHE_N}")

    OUT.mkdir(parents=True, exist_ok=True)
    with SOURCE_MANIFEST.open("w", encoding="utf-8-sig", newline="") as handle:
        fields = ["source_id", "char", "kind", "old_physical_index", "old_source_id"]
        writer_csv = csv.DictWriter(handle, fieldnames=fields)
        writer_csv.writeheader()
        writer_csv.writerows(source_rows)
    with RESTORE_CELLS.open("w", encoding="utf-8-sig", newline="") as handle:
        writer_csv = csv.writer(handle)
        writer_csv.writerow(("row", "col", "displaced_hangul_planes", "reason"))
        for row, col in UI_CELLS:
            planes = [index % PLANES for index in additional_indices
                      if index // IPR == row and (index % IPR) // PLANES == col]
            writer_csv.writerow((row, col, " ".join(map(str, planes)), "native_UI_asset"))
    LOOKUP_TABLE.write_bytes(lookup_blob)
    HUFFMAN_ROWS.write_bytes(row_blob)
    HUFFMAN_COUNTS.write_bytes(counts)
    SOURCE_CHECKPOINTS.write_bytes(checkpoint_blob)
    SOURCE_BITSTREAM.write_bytes(stream_blob)
    CONFLICT_RANGES.write_bytes(bytes(packed_ranges))

    lines = [
        "v171 UI-asset recovery and dynamic-source repack plan",
        "",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"native_UI_cells_to_restore={len(UI_CELLS)}",
        f"newly_displaced_Hangul_sources={len(additional_indices)}",
        f"combined_direct_dynamic_sources={len(conflict_indices)}",
        f"existing_dynamic_sources={OLD_EXISTING_DYNAMIC_N}",
        "protected_virtual_sources=1",
        f"dynamic_sources_total={len(source_rows)}",
        f"direct_ranges={len(ranges)}",
        f"direct_range_max_length={max(length for _start, length, _base in ranges)}",
        f"direct_range_bytes={len(packed_ranges)}",
        "direct_range_readback=254/254 PASS",
        "",
        f"lookup_entries={len(normalized)}",
        f"lookup_bits_per_entry={LOOKUP_BITS}",
        f"lookup_bytes={len(lookup_blob)}",
        f"lookup_max_value={max(normalized)}",
        "lookup_roundtrip=409/409 PASS",
        "",
        f"huffman_sources={len(source_bitmaps)}",
        f"huffman_encoded_rows_per_source={ENCODED_ROWS}",
        "omitted_row_11_blank=462/462 PASS",
        f"huffman_row_symbols={len(canonical_rows)}",
        f"huffman_max_code_bits={len(counts)}",
        f"huffman_encoded_bits={writer.bit_length}",
        f"huffman_bitstream_bytes={len(stream_blob)}",
        f"huffman_rows_bytes={len(row_blob)}",
        f"huffman_counts_bytes={len(counts)}",
        f"checkpoint_group={CHECKPOINT_GROUP}",
        f"checkpoint_count={len(checkpoints)}",
        f"checkpoint_bytes={len(checkpoint_blob)}",
        "huffman_source_readback=462/462 PASS",
        "",
        f"bounded_max_simultaneous_dynamic={maximum_working_set}",
        f"cache_slots={CACHE_N}",
        "cache_physical_cells=7",
        "seventh_cell_x979..981_y480..491_nonzero=0/206 stock+v163 states",
        "runtime_observed_max_is_not_used_as_storage_capacity",
        "text_token_width_changes=0 by design",
        "analysis_only=PASS",
        "patch_built=NO",
        "top_bounded_working_sets=" + " | ".join(
            f"{count}:{label}" for count, label in working_sets[:10]
        ),
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
