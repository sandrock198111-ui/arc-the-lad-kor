"""Prove that every current one-byte Hangul can remain one byte after repacking."""
from __future__ import annotations

import pickle
import sys
import zipfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from audit_dynamic_cache_candidate_tiers import direct_code  # noqa: E402
from audit_dynamic_cache_requirements import (  # noqa: E402
    BUILD, BUILD_SHA, CACHE, ORIGINAL, bitmap, glyph_index, original_bitmap,
    read_lut, sha256, source_ranges, text_units,
)
from plan_bulk_insertion import tokens  # noqa: E402

OUT = ROOT / "01_work/analysis/dynamic_cache_design/width_budget.txt"


def main() -> None:
    if sha256(BUILD.read_bytes()) != BUILD_SHA:
        raise SystemExit("v151 archive hash differs")
    with zipfile.ZipFile(BUILD) as archive:
        current = {info.filename: archive.read(info.filename) for info in archive.infolist()}
    with zipfile.ZipFile(ORIGINAL) as archive:
        pristine = {info.filename: archive.read(info.filename) for info in archive.infolist()}

    exe = current["PSX.EXE"]
    font, original_font = current["COMM.IMG"], pristine["COMM.IMG"]
    lut = read_lut(exe)
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())

    one_byte_chars: set[str] = set()
    nonhangul_indices: set[int] = set()
    index_hangul: dict[int, set[str]] = defaultdict(set)
    for _, payload in text_units(current, source_ranges()):
        for token in tokens(payload):
            index = glyph_index(token, lut)
            if index is None:
                continue
            bits = bitmap(exe, font, index)
            char = shapes.get(bits) if bits else None
            if char and any("가" <= c <= "힣" for c in char):
                index_hangul[index].add(char)
                if len(token) == 1:
                    one_byte_chars.add(char)
            else:
                nonhangul_indices.add(index)

    pool = []
    for index in range(220):
        bits = original_bitmap(original_font, index)
        if bits and any(bits) and index not in nonhangul_indices:
            pool.append(index)

    existing_safe = {
        char for index, chars in index_hangul.items() if index in pool
        for char in chars
    }
    missing = one_byte_chars - existing_safe
    unused_pool = [index for index in pool if index not in index_hangul]

    lines = [
        "dynamic-cache one-byte width budget",
        f"one_byte_hangul_shapes={len(one_byte_chars)}",
        f"tier2_one_byte_pool={len(pool)}",
        f"one_byte_shapes_already_safe={len(existing_safe & one_byte_chars)}",
        f"one_byte_shapes_needing_move={len(missing)}",
        f"unused_one_byte_pool={len(unused_pool)}",
        f"assignment_possible={int(len(unused_pool) >= len(missing))}",
        f"spare_after_assignment={len(unused_pool) - len(missing)}",
        "",
        "No token is rewritten here; this is a capacity proof only.",
    ]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
