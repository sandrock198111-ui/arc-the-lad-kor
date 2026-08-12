"""Measure the v151 working set before designing a runtime glyph cache.

This is deliberately read-only with respect to the patch archive.  It answers four
questions from the bytes that actually ship in v151:

* how many Hangul glyphs are drawn from ordinary COMM.IMG cells and strips A..D;
* how many patched COMM.IMG glyph planes originally contained no pixels;
* the largest distinct-Hangul set in one body, slot, or executable string;
* how many whole 12x12 cells were demonstrably used as font cells by the original
  script and are no longer referenced by v151.

The last number is only a cache *candidate* count.  Runtime coexistence still has to be
proved; a savestate that happens not to touch a rectangle is not accepted as proof.
"""
from __future__ import annotations

import csv
import hashlib
import pickle
import struct
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from plan_bulk_insertion import (  # noqa: E402
    CACHE, CELL, IPR, LOOKUP_N, LOOKUP_SRC, PLANES, RAM_TO_FILE, REMAP_SRC,
    SLOT_BASE, SLOT_COUNT, SLOT_SIZE, STRIPS, bitmap, remap_slot, tokens,
)

BUILD = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
BUILD_SHA = "A4358FEE5A7856FCD40C920F2B25CD21669C30FD197A70CFAC389E2CC6FA30A8"
ORIGINAL = ROOT / "00_original/arc.zip"
ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"
OUT = ROOT / "01_work/analysis/dynamic_cache_design"
REPORT = OUT / "requirements.txt"
INVENTORY = OUT / "glyph_inventory.csv"
CANDIDATES = OUT / "cache_cell_candidates.csv"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def glyph_index(token: bytes, lut: tuple[int, ...]) -> int | None:
    """Resolve a text token with the game's index arithmetic.

    E2 is excluded.  In the current build every real E2 glyph was replaced by an E9/EA
    spelling, while E2 in a body is the external-slot command.  Treating that command
    as a glyph would contaminate the working-set count.
    """
    if len(token) == 1 and 0x01 <= token[0] <= 0xDC:
        return token[0] - 1
    if len(token) != 2:
        return None
    lead, trail = token
    if lead == 0xE2:
        return None
    if 0xDD <= lead <= 0xE8 and 0x01 <= trail <= 0xFE:
        return (lead - 0xDD) * 255 + trail + 0xDB
    if lead in (0xE9, 0xEA) and 0x01 <= trail <= 0xFE:
        slot = (lead - 0xE9) * 254 + trail - 1
        return lut[slot] if 0 <= slot < len(lut) else None
    return None


def ranges_from_csv() -> tuple[list[tuple[str, int, int]], dict[str, list[tuple[int, int]]]]:
    items: list[tuple[str, int, int]] = []
    by_file: dict[str, list[tuple[int, int]]] = defaultdict(list)
    with ORIGINAL_CSV.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
        for row in reader:
            raw = bytes.fromhex(row["raw bytes as hex"].replace(" ", ""))
            item = (row["source file"], int(row[key], 0), len(raw))
            items.append(item)
            by_file[item[0]].append((item[1], item[2]))
    return items, by_file


def text_units(members: dict[str, bytes], items: list[tuple[str, int, int]]):
    """Yield the same bounded text regions the insertion tools are allowed to touch."""
    for name, offset, size in items:
        if name in members and offset + size <= len(members[name]):
            yield f"body:{name}:0x{offset:X}", members[name][offset:offset + size]

    seen: set[str] = set()
    for name, _, _ in items:
        if name in seen or name not in members:
            continue
        seen.add(name)
        data = members[name]
        if len(data) < SLOT_BASE + SLOT_COUNT * SLOT_SIZE:
            continue
        for slot in range(SLOT_COUNT):
            at = SLOT_BASE + slot * SLOT_SIZE
            block = data[at:at + SLOT_SIZE]
            # Byte 0x7F is metadata, not text.  A valid slot terminates before it.
            if 0 not in block[:SLOT_SIZE - 1]:
                continue
            end = block.index(0)
            if end:
                yield f"slot:{name}:{slot}", block[:end]

    exe = members.get("PSX.EXE", b"")
    pool = exe[0x78000:0x83000]
    start = 0
    for end, value in enumerate(pool):
        if value == 0:
            if end > start:
                yield f"exe:0x{0x78000 + start:X}", pool[start:end]
            start = end + 1


def main() -> None:
    if not BUILD.exists():
        raise SystemExit(f"missing build: {BUILD}")
    actual_sha = sha256(BUILD.read_bytes())
    # The filename already carries the short hash.  Keep the full-hash guard optional
    # until this one-off audit records it, but never accept a mismatched short hash.
    if not actual_sha.startswith(BUILD.stem.rsplit("_", 1)[-1]):
        raise SystemExit(f"v151 archive hash mismatch: {actual_sha}")

    with zipfile.ZipFile(BUILD) as archive:
        current = {i.filename: archive.read(i.filename) for i in archive.infolist()}
    with zipfile.ZipFile(ORIGINAL) as archive:
        pristine = {i.filename: archive.read(i.filename) for i in archive.infolist()}

    exe = current["PSX.EXE"]
    original_exe = pristine["PSX.EXE"]
    font = current["COMM.IMG"]
    original_font = pristine["COMM.IMG"]
    lut = struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP_SRC - RAM_TO_FILE)
    original_lut = struct.unpack_from(
        f"<{LOOKUP_N}H", original_exe, LOOKUP_SRC - RAM_TO_FILE
    )
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    items, _ = ranges_from_csv()

    occurrences: Counter[int] = Counter()
    spellings: dict[int, set[str]] = defaultdict(set)
    unit_sets: list[tuple[int, str, set[int], set[str]]] = []
    for label, payload in text_units(current, items):
        indices: set[int] = set()
        chars: set[str] = set()
        for token in tokens(payload):
            index = glyph_index(token, lut)
            if index is None:
                continue
            bits = bitmap(exe, font, index)
            char = shapes.get(bits) if bits else None
            if not char or not any("가" <= c <= "힣" for c in char):
                continue
            occurrences[index] += 1
            spellings[index].add(token.hex(" ").upper())
            indices.add(index)
            chars.add(char)
        if indices:
            unit_sets.append((len(chars), label, indices, chars))

    original_used: set[int] = set()
    for _, payload in text_units(pristine, items):
        for token in tokens(payload):
            index = glyph_index(token, original_lut)
            if index is not None:
                original_used.add(index)

    def location(index: int) -> str:
        slot = remap_slot(exe, index)
        if slot is not None:
            return "strip_D_remap"
        row = index // IPR
        if row in STRIPS and index - row * IPR < 52:
            return {40: "strip_A", 63: "strip_B", 53: "strip_C", 52: "strip_D"}[row]
        return "COMM.IMG"

    rows = []
    by_location: Counter[str] = Counter()
    blank_origin = 0
    for index in sorted(occurrences):
        bits = bitmap(exe, font, index)
        char = shapes.get(bits, "?") if bits else "?"
        place = location(index)
        by_location[place] += 1
        original_bits = bitmap(original_exe, original_font, index)
        originally_blank = original_bits is not None and not any(original_bits)
        if place == "COMM.IMG" and originally_blank:
            blank_origin += 1
        rows.append({
            "char": char,
            "index": index,
            "row": index // IPR,
            "column": (index % IPR) // PLANES,
            "plane": index % PLANES,
            "location": place,
            "occurrences": occurrences[index],
            "codes": " | ".join(sorted(spellings[index])),
            "original_plane_nonblank": int(bool(original_bits and any(original_bits))),
            "original_text_used": int(index in original_used),
        })

    current_used = set(occurrences)
    candidate_cells = []
    for row in range(256 // CELL):
        for column in range(21):
            indices = [row * IPR + column * PLANES + plane for plane in range(PLANES)]
            if any(index in current_used for index in indices):
                continue
            original_nonblank = [
                bool((bits := bitmap(original_exe, original_font, index)) and any(bits))
                for index in indices
            ]
            original_text = [index in original_used for index in indices]
            if all(original_nonblank) and all(original_text):
                strength = "all_four_original_text_glyphs"
            elif all(original_nonblank) and any(original_text):
                strength = "all_four_nonblank_some_text_use"
            else:
                continue
            candidate_cells.append({
                "row": row,
                "column": column,
                "x": column * CELL,
                "y": row * CELL,
                "indices": " ".join(map(str, indices)),
                "evidence": strength,
                "original_text_planes": sum(original_text),
            })

    OUT.mkdir(parents=True, exist_ok=True)
    with INVENTORY.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    with CANDIDATES.open("w", encoding="utf-8-sig", newline="") as handle:
        fields = ["row", "column", "x", "y", "indices", "evidence", "original_text_planes"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(candidate_cells)

    unit_sets.sort(reverse=True, key=lambda item: item[0])
    all_four = sum(c["evidence"] == "all_four_original_text_glyphs" for c in candidate_cells)
    report = [
        "v151 dynamic-cache requirement audit",
        f"build={BUILD.name}",
        f"build_sha256={actual_sha}",
        f"unique_rendered_hangul_indices={len(current_used)}",
        f"unique_rendered_hangul_shapes={len({r['char'] for r in rows})}",
        *(f"location_{name}={by_location[name]}" for name in sorted(by_location)),
        f"comm_img_indices_blank_on_original={blank_origin}",
        f"text_units_measured={len(unit_sets)}",
        f"max_distinct_hangul_in_one_unit={unit_sets[0][0] if unit_sets else 0}",
        "top_working_sets=",
        *(f"  {count:3d}  {label}" for count, label, _, _ in unit_sets[:20]),
        f"whole_cell_candidates={len(candidate_cells)}",
        f"whole_cell_candidates_all_4_original_text={all_four}",
        f"candidate_glyph_planes={len(candidate_cells) * PLANES}",
        "",
        "Important: candidate means static evidence only; runtime coexistence is pending.",
    ]
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
