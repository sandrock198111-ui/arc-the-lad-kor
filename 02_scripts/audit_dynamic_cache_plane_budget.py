"""Count individually reusable font planes and the resulting cache repertoire."""
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

from audit_dynamic_cache_requirements import (  # noqa: E402
    BUILD, BUILD_SHA, CACHE, ORIGINAL, bitmap, glyph_index, original_bitmap,
    read_lut, sha256, source_ranges, text_units,
)
from plan_bulk_insertion import CELL, IPR, PLANES, tokens  # noqa: E402

OUT = ROOT / "01_work/analysis/dynamic_cache_design"
CSV_OUT = OUT / "cache_plane_candidates.csv"
REPORT = OUT / "plane_budget.txt"


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
    hangul_frequency: Counter[str] = Counter()
    char_indices: dict[str, set[int]] = defaultdict(set)
    for _, payload in text_units(current, ranges):
        for token in tokens(payload):
            index = glyph_index(token, lut)
            if index is None:
                continue
            all_current.add(index)
            bits = bitmap(exe, font, index)
            char = shapes.get(bits) if bits else None
            if char and any("가" <= c <= "힣" for c in char):
                hangul_frequency[char] += 1
                char_indices[char].add(index)

    original_used: set[int] = set()
    for _, payload in text_units(pristine, ranges):
        for token in tokens(payload):
            index = glyph_index(token, original_lut)
            if index is not None:
                original_used.add(index)

    def original_text_plane(index: int) -> bool:
        bits = original_bitmap(original_font, index)
        return index in original_used and bool(bits and any(bits))

    safe_existing_chars = {
        char for char, indices in char_indices.items()
        if any(index < IPR * (256 // CELL) and original_text_plane(index)
               for index in indices)
    }

    candidates = []
    by_cell: dict[tuple[int, int], list[int]] = defaultdict(list)
    for index in range(IPR * (256 // CELL)):
        if index in all_current or not original_text_plane(index):
            continue
        row, remainder = divmod(index, IPR)
        column, plane = divmod(remainder, PLANES)
        # Every index below the page edge has a direct spelling.  E2-leading spellings
        # remain unusable because E2 is a command in the current text engine.
        if index < 220:
            code = bytes((index + 1,))
        else:
            lead_offset, trail0 = divmod(index - 0xDC, 255)
            lead, trail = 0xDD + lead_offset, trail0 + 1
            if not (0xDD <= lead <= 0xE8 and 1 <= trail <= 0xFE) or lead == 0xE2:
                continue
            code = bytes((lead, trail))
        by_cell[(row, column)].append(plane)
        candidates.append({
            "index": index,
            "row": row,
            "column": column,
            "plane": plane,
            "code_hex": code.hex(" ").upper(),
            "cell_free_planes": 0,
        })

    free_counts = {cell: len(planes) for cell, planes in by_cell.items()}
    for record in candidates:
        record["cell_free_planes"] = free_counts[(record["row"], record["column"])]

    # Best static allocation: keep every shape already present in a strong position,
    # then spend each candidate plane on the most frequent remaining shape.  The rest
    # is the exact source repertoire a dynamic cache would need to retain.
    remaining = [char for char, _ in hangul_frequency.most_common()
                 if char not in safe_existing_chars]
    static_new = set(remaining[:len(candidates)])
    dynamic = set(remaining[len(candidates):])

    OUT.mkdir(parents=True, exist_ok=True)
    fields = ["index", "row", "column", "plane", "code_hex", "cell_free_planes"]
    with CSV_OUT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(candidates)

    hist = Counter(free_counts.values())
    lines = [
        "dynamic-cache individual-plane budget",
        f"unique_hangul_shapes={len(hangul_frequency)}",
        f"strong_existing_shapes={len(safe_existing_chars)}",
        f"reusable_individual_planes={len(candidates)}",
        f"cells_containing_candidates={len(by_cell)}",
        "candidate_planes_per_cell=" + ", ".join(
            f"{planes}:{hist[planes]}cells" for planes in sorted(hist)
        ),
        f"static_new_shapes_if_all_candidates_used={len(static_new)}",
        f"dynamic_source_shapes={len(dynamic)}",
        f"dynamic_source_bytes_1bpp={len(dynamic) * 18}",
        "dynamic_shapes_by_frequency=",
        "  " + " ".join(sorted(dynamic, key=lambda c: (-hangul_frequency[c], c))),
        "",
        "Counts exclude every bounded current text token, not Hangul alone.",
        "Runtime safety of candidate planes is not claimed by this audit.",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
