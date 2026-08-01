"""Audit records containing ``<CTRL:00>`` against the original Arc 1 disc.

This tool is deliberately read-only.  It measures where the candidates occur,
proves that the CSV raw bytes match the source file bytes, and records the
scanner context that admitted each candidate.  It does not reinterpret bytes.
"""
from __future__ import annotations

import csv
from collections import Counter, defaultdict
from pathlib import Path

import measure_full_script_requirements as corpus


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "05_docs" / "script_original_full.csv"


def load_rows() -> list[dict[str, str]]:
    with SOURCE.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def runtime_token_audit(raw: bytes) -> tuple[bool, int | None, int]:
    """Validate measured inline-renderer token widths without decoding meaning."""
    offset = 0
    controls = 0
    while offset < len(raw):
        first = raw[offset]
        if first == 0:
            return False, offset, controls
        if first < 0xDD:
            offset += 1
            continue
        if offset + 1 >= len(raw):
            return False, offset, controls
        if first >= 0xE1:
            controls += 1
        offset += 2
    return True, None, controls


def candidate_context(data: bytes, begin: int) -> dict[str, object]:
    matches: list[tuple[int, int, str, int | None]] = []
    for marker_offset in (begin - 2, begin - 4):
        if marker_offset < 0:
            continue
        marker = int.from_bytes(data[marker_offset : marker_offset + 2], "little")
        if marker not in (0x17, 0x19):
            continue
        header = corpus.find_header(data, marker_offset)
        computed = marker_offset + 2
        prefix = data[computed : computed + 2]
        prefix_kind = "none"
        if prefix in (b"\x01\0", b"\x02\0", b"\x03\0", b"\x04\0", b"\x05\0", b"\x07\0"):
            computed += 2
            prefix_kind = f"control_{prefix.hex()}"
        elif prefix == b"\0\0" and marker == 0x17 and header == marker_offset - 6:
            computed += 2
            prefix_kind = "control_0000"
        if computed == begin:
            matches.append((marker_offset, marker, prefix_kind, header))
    if len(matches) != 1:
        raise ValueError(f"expected one parser context at 0x{begin:X}, got {matches}")
    marker_offset, marker, prefix_kind, header = matches[0]
    return {
        "marker_offset": marker_offset,
        "marker": marker,
        "prefix_kind": prefix_kind,
        "header_offset": header,
    }


def main() -> None:
    rows = load_rows()
    pattern = [row for row in rows if "<CTRL:00>" in row["decoded Japanese"]]
    listing = corpus.iso_files(corpus.BIN)
    by_file_source: dict[str, bytes] = {}
    per_file = Counter(row["source file"] for row in pattern)
    all_per_file = Counter(row["source file"] for row in rows)
    clean_per_file = Counter(
        row["source file"]
        for row in rows
        if "<CTRL:" not in row["decoded Japanese"]
        and "<G:" not in row["decoded Japanese"]
    )

    raw_mismatch: list[tuple[str, str]] = []
    contexts: list[dict[str, object]] = []
    for row in pattern:
        name = row["source file"]
        data = by_file_source.setdefault(name, corpus.read_file(corpus.BIN, listing[name]))
        begin = int(row["byte offset"], 0)
        raw = bytes.fromhex(row["raw bytes as hex"])
        if data[begin : begin + len(raw)] != raw:
            raw_mismatch.append((name, row["byte offset"]))
        context = candidate_context(data, begin)
        zero_positions = [index for index, value in enumerate(raw) if value == 0]
        odd_zeros = sum(index % 2 == 1 for index in zero_positions)
        even_zeros = len(zero_positions) - odd_zeros
        pair_count = len(raw) // 2
        zero_high_words = sum(raw[index + 1] == 0 for index in range(0, len(raw) - 1, 2))
        runtime_valid, first_runtime_zero, runtime_controls = runtime_token_audit(raw)
        contexts.append(
            {
                "source file": name,
                "byte offset": begin,
                "end": begin + len(raw),
                "length": len(raw),
                **context,
                "zero_count": len(zero_positions),
                "zero_at_even_offset": even_zeros,
                "zero_at_odd_offset": odd_zeros,
                "little_endian_words": pair_count,
                "words_with_zero_high_byte": zero_high_words,
                "zero_high_word_ratio": zero_high_words / pair_count if pair_count else 0.0,
                "has_linebreak": corpus.LINEBREAK in raw,
                "has_pagebreak": corpus.PAGEBREAK in raw,
                "runtime_token_valid": runtime_valid,
                "first_runtime_zero": first_runtime_zero,
                "runtime_control_pairs": runtime_controls,
                "raw": raw,
            }
        )

    overlap_rows: set[tuple[str, int]] = set()
    by_file_context: dict[str, list[dict[str, object]]] = defaultdict(list)
    for item in contexts:
        by_file_context[str(item["source file"])].append(item)
    for name, items in by_file_context.items():
        active: list[dict[str, object]] = []
        for item in sorted(items, key=lambda value: int(value["byte offset"])):
            begin = int(item["byte offset"])
            active = [other for other in active if int(other["end"]) > begin]
            if active:
                overlap_rows.add((name, begin))
                overlap_rows.update((name, int(other["byte offset"])) for other in active)
            active.append(item)

    header_count = sum(item["header_offset"] is not None for item in contexts)
    no_break_no_header = sum(
        item["header_offset"] is None
        and not item["has_linebreak"]
        and not item["has_pagebreak"]
        for item in contexts
    )
    mostly_16le = sum(item["zero_high_word_ratio"] >= 0.75 for item in contexts)
    runtime_valid = sum(bool(item["runtime_token_valid"]) for item in contexts)

    print(f"total_rows={len(rows)}")
    print(f"ctrl00_rows={len(pattern)}")
    print(f"source_byte_mismatches={len(raw_mismatch)}")
    print(f"files_with_ctrl00={len(per_file)}")
    print(f"files_also_having_fully_decoded_rows={sum(clean_per_file[name] > 0 for name in per_file)}")
    print(f"rows_with_dialogue_header29={header_count}")
    print(f"rows_without_header_or_confirmed_break={no_break_no_header}")
    print(f"rows_at_least_75pct_zero_high_16le_words={mostly_16le}")
    print(f"rows_valid_under_runtime_token_widths={runtime_valid}")
    print(f"rows_with_standalone_zero_at_token_boundary={len(contexts) - runtime_valid}")
    print(f"rows_overlapping_another_ctrl00_candidate={len(overlap_rows)}")
    print("file_distribution:")
    for name, count in per_file.most_common():
        print(
            f"  {name},{count},all={all_per_file[name]},"
            f"fully_decoded={clean_per_file[name]}"
        )

    print("lowest_zero_high_ratio:")
    for item in sorted(contexts, key=lambda value: float(value["zero_high_word_ratio"]))[:20]:
        print(
            f"  {item['source file']} 0x{int(item['byte offset']):X} "
            f"len={item['length']} header={item['header_offset']} "
            f"break={item['has_linebreak'] or item['has_pagebreak']} "
            f"ratio={float(item['zero_high_word_ratio']):.3f} "
            f"raw={bytes(item['raw']).hex(' ').upper()}"
        )


if __name__ == "__main__":
    main()
