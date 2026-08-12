"""Simulate cache sizes and exact-bitmap compression for the v151 corpus."""
from __future__ import annotations

import pickle
import sys
import zipfile
import zlib
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from audit_dynamic_cache_candidate_tiers import direct_code  # noqa: E402
from audit_dynamic_cache_requirements import (  # noqa: E402
    BUILD, BUILD_SHA, CACHE, ORIGINAL, bitmap, glyph_index, original_bitmap,
    read_lut, sha256, source_ranges, text_units,
)
from plan_bulk_insertion import CELL, IPR, tokens  # noqa: E402

OUT = ROOT / "01_work/analysis/dynamic_cache_design/cache_capacity.txt"
CACHE_SIZES = (16, 20, 24, 32, 48, 64)


def pack_bitmap(bits: tuple[int, ...]) -> bytes:
    value = 0
    out = bytearray()
    used = 0
    for bit in bits:
        value = (value << 1) | int(bit)
        used += 1
        if used == 8:
            out.append(value)
            value = used = 0
    if used:
        out.append(value << (8 - used))
    if len(out) != 18:
        raise AssertionError(len(out))
    return bytes(out)


def row_values(bits: tuple[int, ...]) -> tuple[int, ...]:
    return tuple(sum(bits[y * CELL + x] << (CELL - 1 - x) for x in range(CELL))
                 for y in range(CELL))


def escaped_row_dictionary_size(rows: list[tuple[int, ...]]) -> tuple[int, int, int]:
    counts = Counter(value for glyph in rows for value in glyph)
    dictionary = {value: i for i, (value, _) in enumerate(counts.most_common(255))}
    escapes = sum(value not in dictionary for glyph in rows for value in glyph)
    # 2 bytes per dictionary row; one byte per token; escaped token adds its raw 2 bytes.
    return len(dictionary) * 2 + len(rows) * CELL + escapes * 2, len(dictionary), escapes


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

    all_current: set[int] = set()
    char_indices: dict[str, set[int]] = defaultdict(set)
    char_bits: dict[str, tuple[int, ...]] = {}
    frequency: Counter[str] = Counter()
    widths: dict[str, set[int]] = defaultdict(set)
    units: list[tuple[str, set[str]]] = []
    for label, payload in text_units(current, ranges):
        unit: set[str] = set()
        for token in tokens(payload):
            index = glyph_index(token, lut)
            if index is None:
                continue
            all_current.add(index)
            bits = bitmap(exe, font, index)
            char = shapes.get(bits) if bits else None
            if not char or not any("가" <= c <= "힣" for c in char):
                continue
            char_indices[char].add(index)
            char_bits.setdefault(char, bits)
            frequency[char] += 1
            widths[char].add(len(token))
            unit.add(char)
        if unit:
            units.append((label, unit))

    original_used: set[int] = set()
    for _, payload in text_units(pristine, ranges):
        for token in tokens(payload):
            index = glyph_index(token, original_lut)
            if index is not None:
                original_used.add(index)

    def tier2(index: int) -> bool:
        if index >= IPR * (256 // CELL) or direct_code(index) is None:
            return False
        bits = original_bitmap(original_font, index)
        return bool(bits and any(bits))

    represented = {
        char for char, indices in char_indices.items() if any(tier2(index) for index in indices)
    }
    spare = [index for index in range(IPR * (256 // CELL))
             if index not in all_current and tier2(index)]

    lines = [
        "v151 dynamic-cache capacity simulation",
        f"unique_hangul_shapes={len(char_indices)}",
        f"tier2_represented={len(represented)}",
        f"tier2_spare_planes={len(spare)}",
        f"text_units={len(units)}",
        "",
    ]
    for cache_size in CACHE_SIZES:
        if cache_size > len(spare):
            continue
        static_extra_n = len(spare) - cache_size
        remaining = [char for char, _ in frequency.most_common() if char not in represented]
        static = represented | set(remaining[:static_extra_n])
        dynamic = set(char_indices) - static
        working = sorted(
            ((len(chars & dynamic), label) for label, chars in units), reverse=True
        )
        one_byte_dynamic = {char for char in dynamic if 1 in widths[char]}
        raws = [pack_bitmap(char_bits[char]) for char in sorted(dynamic)]
        raw = b"".join(raws)
        row_data = [row_values(char_bits[char]) for char in sorted(dynamic)]
        row_size, row_dict_n, escapes = escaped_row_dictionary_size(row_data)
        lines += [
            f"cache_slots={cache_size}",
            f"  static_shapes={len(static)}",
            f"  dynamic_source_shapes={len(dynamic)}",
            f"  dynamic_raw_bytes={len(raw)}",
            f"  max_dynamic_in_one_unit={working[0][0]}",
            f"  one_byte_dynamic_shapes={len(one_byte_dynamic)}",
            f"  row_dictionary_bytes={row_size}",
            f"  row_dictionary_entries={row_dict_n}",
            f"  row_dictionary_escapes={escapes}",
            f"  zlib_reference_bytes={len(zlib.compress(raw, 9))}",
            "  top_dynamic_working_sets=" + ", ".join(
                f"{count}:{label}" for count, label in working[:5]
            ),
            "",
        ]

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
