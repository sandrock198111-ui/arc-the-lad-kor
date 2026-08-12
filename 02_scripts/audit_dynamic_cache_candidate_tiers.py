"""Compare strict and practical font-plane tiers for a dynamic-cache build."""
from __future__ import annotations

import csv
import pickle
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
REPORT = OUT / "candidate_tiers.txt"
CSV_OUT = OUT / "candidate_tiers.csv"


def direct_code(index: int) -> bytes | None:
    if index < 220:
        return bytes((index + 1,))
    lead_offset, trail0 = divmod(index - 0xDC, 255)
    lead, trail = 0xDD + lead_offset, trail0 + 1
    if 0xDD <= lead <= 0xE8 and 1 <= trail <= 0xFE and lead != 0xE2:
        return bytes((lead, trail))
    return None


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
    chars: dict[str, set[int]] = defaultdict(set)
    frequency: Counter[str] = Counter()
    widths: dict[str, set[int]] = defaultdict(set)
    for _, payload in text_units(current, ranges):
        for token in tokens(payload):
            index = glyph_index(token, lut)
            if index is None:
                continue
            all_current.add(index)
            bits = bitmap(exe, font, index)
            char = shapes.get(bits) if bits else None
            if char and any("가" <= c <= "힣" for c in char):
                chars[char].add(index)
                frequency[char] += 1
                widths[char].add(len(token))

    original_used: set[int] = set()
    for _, payload in text_units(pristine, ranges):
        for token in tokens(payload):
            index = glyph_index(token, original_lut)
            if index is not None:
                original_used.add(index)

    def tier(index: int) -> int:
        if index >= IPR * (256 // CELL) or direct_code(index) is None:
            return 0
        bits = original_bitmap(original_font, index)
        if not bits or not any(bits):
            return 0
        return 1 if index in original_used else 2

    represented = {
        level: {char for char, indices in chars.items()
                if any(0 < tier(index) <= level for index in indices)}
        for level in (1, 2)
    }
    spare = {
        level: [index for index in range(IPR * (256 // CELL))
                if index not in all_current and 0 < tier(index) <= level]
        for level in (1, 2)
    }

    rows = []
    for index in sorted(set(spare[2])):
        row, remainder = divmod(index, IPR)
        column, plane = divmod(remainder, PLANES)
        rows.append({
            "index": index,
            "row": row,
            "column": column,
            "plane": plane,
            "tier": tier(index),
            "code_hex": direct_code(index).hex(" ").upper(),
        })
    OUT.mkdir(parents=True, exist_ok=True)
    with CSV_OUT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    lines = [
        "dynamic-cache candidate tiers",
        f"unique_hangul_shapes={len(chars)}",
        f"one_byte_required_shapes={sum(1 for value in widths.values() if 1 in value)}",
    ]
    for level, name in ((1, "original_text_confirmed"), (2, "original_nonblank")):
        capacity = len(represented[level]) + len(spare[level])
        dynamic = max(0, len(chars) - capacity)
        lines += [
            f"tier_{level}_{name}_represented_shapes={len(represented[level])}",
            f"tier_{level}_{name}_spare_planes={len(spare[level])}",
            f"tier_{level}_{name}_max_static_shapes={capacity}",
            f"tier_{level}_{name}_minimum_dynamic_shapes={dynamic}",
            f"tier_{level}_{name}_minimum_dynamic_bytes={dynamic * 18}",
        ]
    lines += [
        f"tier_2_candidate_cells={len({(r['row'], r['column']) for r in rows})}",
        "",
        "Tier 2 reproduces v151's practical destination rule, but still needs runtime proof.",
        "All counts exclude every bounded current token and exclude E2-leading direct codes.",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
