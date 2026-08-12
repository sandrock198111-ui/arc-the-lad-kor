"""Measure the v151 working set before designing a runtime glyph cache.

This audit never changes a game member.  It measures the bytes that actually ship in
v151 and records cache-slot candidates separately from proven runtime-safe slots.
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
    CACHE, CELL, IPR, LOOKUP_N, LOOKUP_SRC, PLANES, RAM_TO_FILE,
    SLOT_BASE, SLOT_COUNT, SLOT_SIZE, STRIPS, bitmap, remap_slot, tokens,
)

BUILD = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
BUILD_SHA = "A4358FEE5FEA4964C9DD376B630894EB5EC133EFEEDD9E5E85BBC5FDD8CA1A46"
ORIGINAL = ROOT / "00_original/arc.zip"
ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"
OUT = ROOT / "01_work/analysis/dynamic_cache_design"
REPORT = OUT / "requirements.txt"
INVENTORY = OUT / "glyph_inventory.csv"
CANDIDATES = OUT / "cache_cell_candidates.csv"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def glyph_index(token: bytes, lut: tuple[int, ...]) -> int | None:
    """Resolve a token using the game's index arithmetic, excluding E2 commands."""
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


def source_ranges() -> list[tuple[str, int, int]]:
    result = []
    with ORIGINAL_CSV.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
        for row in reader:
            raw = bytes.fromhex(row["raw bytes as hex"].replace(" ", ""))
            result.append((row["source file"], int(row[key], 0), len(raw)))
    return result


def slot_from_disk_id(value: int) -> int | None:
    if 0x81 <= value <= 0xA8:
        return value - 0x81
    if 0xAA <= value <= 0xD0:
        return value - 0x82
    return None


def active_slots(members: dict[str, bytes], ranges: list[tuple[str, int, int]]) -> dict[str, tuple[int, ...]]:
    """Derive active external slots from the E2 pointers actually present in a build."""
    by_file: dict[str, set[int]] = defaultdict(set)
    for name, offset, _ in ranges:
        if name not in members or offset + 2 > len(members[name]):
            continue
        data = members[name][offset:offset + 2]
        if len(data) < 2 or data[0] != 0xE2:
            continue
        slot = slot_from_disk_id(data[1])
        if slot is None:
            continue
        if slot in by_file[name]:
            raise ValueError(f"duplicate active slot: {name}:{slot}")
        by_file[name].add(slot)
    return {name: tuple(sorted(slots)) for name, slots in by_file.items()}


def text_units(members: dict[str, bytes], ranges: list[tuple[str, int, int]]):
    """Yield bounded regions that the insertion tools already identify as text."""
    for name, offset, size in ranges:
        if name in members and offset + size <= len(members[name]):
            yield f"body:{name}:0x{offset:X}", members[name][offset:offset + size]

    for name, slots in active_slots(members, ranges).items():
        if name not in members:
            raise ValueError(f"assigned-slot file missing: {name}")
        data = members[name]
        if len(data) < SLOT_BASE + SLOT_COUNT * SLOT_SIZE:
            raise ValueError(f"assigned-slot bank missing: {name}")
        for slot in slots:
            at = SLOT_BASE + slot * SLOT_SIZE
            block = data[at:at + SLOT_SIZE]
            if 0 not in block[:SLOT_SIZE - 1]:
                raise ValueError(f"assigned slot has no terminator: {name}:{slot}")
            end = block.index(0)
            if not end:
                raise ValueError(f"assigned slot is empty: {name}:{slot}")
            yield f"slot:{name}:{slot}", block[:end]

    pool = members.get("PSX.EXE", b"")[0x78000:0x83000]
    start = 0
    for end, value in enumerate(pool):
        if value != 0:
            continue
        if end > start:
            yield f"exe:0x{0x78000 + start:X}", pool[start:end]
        start = end + 1


def read_lut(exe: bytes) -> tuple[int, ...]:
    at = LOOKUP_SRC - RAM_TO_FILE
    if at + LOOKUP_N * 2 > len(exe):
        return ()
    return struct.unpack_from(f"<{LOOKUP_N}H", exe, at)


def original_bitmap(font: bytes, index: int) -> tuple[int, ...] | None:
    """Read one plane directly; the untouched EXE has no v127 remap table."""
    row, remainder = divmod(index, IPR)
    if (row + 1) * CELL > 512:
        return None
    column, plane = divmod(remainder, PLANES)
    bit = 1 << plane
    result = []
    for y in range(CELL):
        for x in range(CELL):
            pixel_x = column * CELL + x
            value = font[(row * CELL + y) * 0x380 + pixel_x // 2]
            nibble = value & 0x0F if pixel_x % 2 == 0 else value >> 4
            result.append(1 if nibble & bit else 0)
    return tuple(result)


def main() -> None:
    actual_sha = sha256(BUILD.read_bytes())
    if actual_sha != BUILD_SHA:
        raise SystemExit(f"v151 archive hash mismatch: {actual_sha}")
    with zipfile.ZipFile(BUILD) as archive:
        current = {info.filename: archive.read(info.filename) for info in archive.infolist()}
    with zipfile.ZipFile(ORIGINAL) as archive:
        pristine = {info.filename: archive.read(info.filename) for info in archive.infolist()}

    exe, original_exe = current["PSX.EXE"], pristine["PSX.EXE"]
    font, original_font = current["COMM.IMG"], pristine["COMM.IMG"]
    lut, original_lut = read_lut(exe), read_lut(original_exe)
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    ranges = source_ranges()

    occurrences: Counter[int] = Counter()
    spellings: dict[int, set[str]] = defaultdict(set)
    all_current_indices: set[int] = set()
    unit_sets: list[tuple[int, str]] = []
    for label, payload in text_units(current, ranges):
        chars: set[str] = set()
        for token in tokens(payload):
            index = glyph_index(token, lut)
            if index is None:
                continue
            all_current_indices.add(index)
            bits = bitmap(exe, font, index)
            char = shapes.get(bits) if bits else None
            if not char or not any("가" <= c <= "힣" for c in char):
                continue
            occurrences[index] += 1
            spellings[index].add(token.hex(" ").upper())
            chars.add(char)
        if chars:
            unit_sets.append((len(chars), label))

    original_used: set[int] = set()
    for _, payload in text_units(pristine, ranges):
        for token in tokens(payload):
            index = glyph_index(token, original_lut)
            if index is not None:
                original_used.add(index)

    def location(index: int) -> str:
        if remap_slot(exe, index) is not None:
            return "strip_D_remap"
        row = index // IPR
        if row in STRIPS and index - row * IPR < 52:
            return {40: "strip_A", 63: "strip_B", 53: "strip_C", 52: "strip_D"}[row]
        return "COMM.IMG"

    inventory = []
    by_location: Counter[str] = Counter()
    blank_origin = 0
    for index in sorted(occurrences):
        bits = bitmap(exe, font, index)
        char = shapes.get(bits, "?") if bits else "?"
        place = location(index)
        by_location[place] += 1
        original_bits = original_bitmap(original_font, index)
        originally_blank = original_bits is not None and not any(original_bits)
        if place == "COMM.IMG" and originally_blank:
            blank_origin += 1
        inventory.append({
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
    candidates = []
    for row in range(256 // CELL):
        for column in range(21):
            indices = [row * IPR + column * PLANES + plane for plane in range(PLANES)]
            if any(index in all_current_indices for index in indices):
                continue
            nonblank = []
            text_used = []
            for index in indices:
                bits = original_bitmap(original_font, index)
                nonblank.append(bool(bits and any(bits)))
                text_used.append(index in original_used)
            if all(nonblank) and all(text_used):
                evidence = "all_four_original_text_glyphs"
            elif all(nonblank) and any(text_used):
                evidence = "all_four_nonblank_some_text_use"
            else:
                continue
            candidates.append({
                "row": row,
                "column": column,
                "x": column * CELL,
                "y": row * CELL,
                "indices": " ".join(map(str, indices)),
                "evidence": evidence,
                "original_text_planes": sum(text_used),
            })

    OUT.mkdir(parents=True, exist_ok=True)
    with INVENTORY.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(inventory[0]))
        writer.writeheader()
        writer.writerows(inventory)
    fields = ["row", "column", "x", "y", "indices", "evidence", "original_text_planes"]
    with CANDIDATES.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(candidates)

    unit_sets.sort(reverse=True)
    all_four = sum(c["evidence"] == "all_four_original_text_glyphs" for c in candidates)
    report = [
        "v151 dynamic-cache requirement audit",
        f"build={BUILD.name}",
        f"build_sha256={actual_sha}",
        f"unique_rendered_hangul_indices={len(current_used)}",
        f"all_current_text_indices={len(all_current_indices)}",
        f"unique_rendered_hangul_shapes={len({row['char'] for row in inventory})}",
        *(f"location_{name}={by_location[name]}" for name in sorted(by_location)),
        f"comm_img_indices_blank_on_original={blank_origin}",
        f"text_units_measured={len(unit_sets)}",
        f"max_distinct_hangul_in_one_unit={unit_sets[0][0] if unit_sets else 0}",
        "top_working_sets=",
        *(f"  {count:3d}  {label}" for count, label in unit_sets[:20]),
        f"whole_cell_candidates={len(candidates)}",
        f"whole_cell_candidates_all_4_original_text={all_four}",
        f"candidate_glyph_planes={len(candidates) * PLANES}",
        "",
        "candidate is static evidence only; runtime coexistence remains pending",
    ]
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
