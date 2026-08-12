"""Independent static verifier for the v159 on-demand completed-glyph cache."""
from __future__ import annotations

import csv
import hashlib
import pickle
import struct
import sys
import zipfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from audit_dynamic_cache_requirements import (  # noqa: E402
    CACHE, active_slots, bitmap, glyph_index, read_lut, source_ranges, text_units,
)
from build_arc1_v159_dynamic_cache import (  # noqa: E402
    CACHE_N, CACHE_SLOTS, CELL, COMM, COPY_N, DECODER_ENTRY, FRAME_HOOK,
    FRAMESWAP, GLYPH_PACKET_HOOK, HEAP_BASE, IPR, LOADIMAGE, LOOKUP_N,
    LOOKUP_RAM, PLANES, PLANNED_DICTIONARY, PLANNED_GLYPHS,
    PROTECTED_RELOCATIONS, PSX, REMAP_HOOK, RENDER_HOOK, RESIDENT_BASE,
    SOURCE_BASE, STOREIMAGE, build_decoder, build_frame, file_at, j, jal,
    plain_bitmap, word,
)
from plan_bulk_insertion import SLOT_BASE, SLOT_COUNT, SLOT_SIZE, tokens  # noqa: E402

BASE = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
BUILD = ROOT / "03_output/arc1_v159_dynamic_cache_4E3F2466.zip"
BUILD_SHA = "4E3F246614B46139EBD637AA576E19397493C421338B5F257D628BCF0AF7B4D7"
ORIGINAL = ROOT / "00_original/arc.zip"
ASSIGNMENTS = ROOT / "01_work/analysis/dynamic_cache_v153_widthsafe/glyph_assignments.csv"
REPORT = ROOT / "01_work/analysis/arc1_v159_dynamic_cache/independent_verification.txt"
VERSION_LABEL = "v159"
EXPECTED_FRAME_CALLS = (STOREIMAGE, LOADIMAGE, FRAMESWAP)


def expected_cache_state(font: bytes, cache_rows: list[dict[str, str]]) -> bytes:
    del font, cache_rows
    return bytes(72)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def archive(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as handle:
        return {info.filename: handle.read(info.filename) for info in handle.infolist()}


def is_hangul(text: str | None) -> bool:
    return bool(text and any("가" <= char <= "힣" for char in text))


def jump_target(address: int, instruction: int) -> int:
    return ((address + 4) & 0xF0000000) | ((instruction & 0x03FFFFFF) << 2)


def main() -> None:
    if sha256(BUILD) != BUILD_SHA:
        raise SystemExit(f"{VERSION_LABEL} archive hash differs")
    base, current, pristine = archive(BASE), archive(BUILD), archive(ORIGINAL)
    if list(base) != list(current):
        raise SystemExit("archive member order or names changed")
    if any(len(base[name]) != len(current[name]) for name in base):
        raise SystemExit("a game member changed size")

    base_exe, base_font = base[PSX], base[COMM]
    exe, font = current[PSX], current[COMM]
    original_font = pristine[COMM]
    old_lut = read_lut(base_exe)
    new_lut = struct.unpack_from(f"<{LOOKUP_N}H", exe, file_at(LOOKUP_RAM))
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    bits_by_char = {char: bits for bits, char in shapes.items()}

    dictionary_blob = PLANNED_DICTIONARY.read_bytes()
    glyph_blob = PLANNED_GLYPHS.read_bytes()
    dictionary = struct.unpack(f"<{len(dictionary_blob) // 2}H", dictionary_blob)

    def source_shape(source: int) -> tuple[int, ...]:
        rows = glyph_blob[source * CELL:(source + 1) * CELL]
        if len(rows) != CELL:
            raise AssertionError(f"dynamic source outside table: {source}")
        return tuple(
            1 if dictionary[rows[y]] & (1 << (CELL - 1 - x)) else 0
            for y in range(CELL) for x in range(CELL)
        )

    def decode_new(token: bytes) -> tuple[tuple[int, ...] | None, int | None, int | None]:
        """Return bitmap, physical index, dynamic source id."""
        if len(token) == 1 and 0x01 <= token[0] <= 0xDC:
            index = token[0] - 1
            return plain_bitmap(font, index), index, None
        if len(token) != 2:
            return None, None, None
        lead, trail = token
        if lead in (0xE9, 0xEA):
            slot = (lead - 0xE9) * 254 + trail - 1
            if not 0 <= slot < LOOKUP_N:
                return plain_bitmap(font, 0), 0, None
            entry = new_lut[slot]
            if entry & 0x8000:
                source = entry & 0x7FFF
                return source_shape(source), None, source
            if entry >= 21 * IPR:
                raise AssertionError(f"lookup slot {slot} still points high: {entry}")
            return plain_bitmap(font, entry), entry, None
        index = glyph_index(token, ())
        if index is None or index >= 21 * IPR:
            return None, index, None
        return plain_bitmap(font, index), index, None

    # Every assigned spelling must decode to the exact v151 completed bitmap.
    assignment_checks = 0
    with ASSIGNMENTS.open(encoding="utf-8-sig", newline="") as handle:
        assignment_rows = list(csv.DictReader(handle))
    for row in assignment_rows:
        expected = bits_by_char[row["char"]]
        for field in ("code_1byte", "code_2byte"):
            if not row[field]:
                continue
            actual, _, _ = decode_new(bytes.fromhex(row[field]))
            if actual != expected:
                raise SystemExit(f"assignment mismatch: {row['char']} {row[field]}")
            assignment_checks += 1

    # Preserve the three live non-Hangul high-page UI shapes exactly.
    relocation_checks = 0
    with PROTECTED_RELOCATIONS.open(encoding="utf-8-sig", newline="") as handle:
        relocation_rows = list(csv.DictReader(handle))
    for row in relocation_rows:
        slot = int(row["virtual_slot"])
        source = int(row["source_index"])
        destination = int(row["destination_index"])
        expected = bitmap(base_exe, base_font, source)
        if new_lut[slot] != destination or plain_bitmap(font, destination) != expected:
            raise SystemExit(f"protected UI relocation mismatch at slot {slot}")
        relocation_checks += 1

    ranges = source_ranges()
    old_units = list(text_units(base, ranges))
    new_units = list(text_units(current, ranges))
    if [label for label, _ in old_units] != [label for label, _ in new_units]:
        raise SystemExit("bounded text unit layout changed")

    semantic_checks = 0
    protected_virtual_checks = 0
    control_checks = 0
    max_dynamic = 0
    max_dynamic_label = ""
    for (label, old_payload), (_, new_payload) in zip(old_units, new_units):
        old_tokens, new_tokens = list(tokens(old_payload)), list(tokens(new_payload))
        if len(old_tokens) != len(new_tokens) or any(
                len(left) != len(right) for left, right in zip(old_tokens, new_tokens)):
            raise SystemExit(f"token width changed in {label}")
        unit_sources: set[int] = set()
        for old_token, new_token in zip(old_tokens, new_tokens):
            if len(old_token) == 2 and (
                    old_token[0] == 0xE2 or old_token in {b"\xE5\x01", b"\xE5\x02",
                                                         b"\xE5\x03", b"\xE5\x04",
                                                         b"\xE6\x01"}):
                if old_token != new_token:
                    raise SystemExit(f"control token changed in {label}: {old_token.hex()}")
                control_checks += 1
                continue
            old_index = glyph_index(old_token, old_lut)
            old_bits = bitmap(base_exe, base_font, old_index) if old_index is not None else None
            old_char = shapes.get(old_bits) if old_bits else None
            new_bits, _, source = decode_new(new_token)
            if source is not None:
                unit_sources.add(source)
            if is_hangul(old_char):
                if new_bits != old_bits:
                    raise SystemExit(f"Hangul changed in {label}: {old_char}")
                semantic_checks += 1
            elif len(old_token) == 2 and old_token[0] in (0xE9, 0xEA):
                slot = (old_token[0] - 0xE9) * 254 + old_token[1] - 1
                if 0 <= slot < len(old_lut) and old_bits and new_bits != old_bits:
                    raise SystemExit(f"protected virtual glyph changed in {label}: slot {slot}")
                if 0 <= slot < len(old_lut) and old_bits:
                    protected_virtual_checks += 1
            elif old_token != new_token:
                raise SystemExit(f"non-Hangul token changed in {label}: {old_token.hex()}")
        if len(unit_sources) > max_dynamic:
            max_dynamic, max_dynamic_label = len(unit_sources), label
    if max_dynamic > CACHE_N:
        raise SystemExit(f"one text unit needs {max_dynamic} cache slots")

    # No write may escape the ranges used by this build.
    allowed_by_file: dict[str, set[int]] = defaultdict(set)
    names_with_ranges: set[str] = set()
    for name, offset, size in ranges:
        names_with_ranges.add(name)
        allowed_by_file[name].update(range(offset, offset + size))
    for name, slots in active_slots(base, ranges).items():
        if name in base:
            for slot in slots:
                at = SLOT_BASE + slot * SLOT_SIZE
                allowed_by_file[name].update(range(at, at + SLOT_SIZE))
    changed_data_bytes = 0
    changed_data_members = 0
    for name in base:
        if name in (PSX, COMM) or base[name] == current[name]:
            continue
        changed = {i for i, (left, right) in enumerate(zip(base[name], current[name]))
                   if left != right}
        if not changed <= allowed_by_file[name]:
            raise SystemExit(f"write escaped text ranges in {name}")
        changed_data_bytes += len(changed)
        changed_data_members += 1

    allowed_exe = set(range(0x78000, 0x83000))
    for address, size in ((REMAP_HOOK, 8), (GLYPH_PACKET_HOOK, 8), (RENDER_HOOK, 8),
                          (LOOKUP_RAM, LOOKUP_N * 2), (SOURCE_BASE, COPY_N),
                          (DECODER_ENTRY, 8), (FRAME_HOOK, 4)):
        at = file_at(address)
        allowed_exe.update(range(at, at + size))
    changed_exe = {i for i, (left, right) in enumerate(zip(base_exe, exe)) if left != right}
    if not changed_exe <= allowed_exe:
        raise SystemExit("PSX.EXE write escaped approved regions")
    for y in range(512):
        if font[y * 0x380 + 126:(y + 1) * 0x380] != \
                base_font[y * 0x380 + 126:(y + 1) * 0x380]:
            raise SystemExit(f"COMM.IMG changed outside font grid at row {y}")

    # Rebuild resident addresses, then verify the linked machine-code contract.
    with CACHE_SLOTS.open(encoding="utf-8-sig", newline="") as handle:
        cache_rows = list(csv.DictReader(handle))
    cache_indices = [int(row["physical_index"]) for row in cache_rows]
    row_dictionary = RESIDENT_BASE
    glyph_rows = row_dictionary + len(dictionary_blob)
    cache_index_ram = glyph_rows + len(glyph_blob)
    owners = cache_index_ram + CACHE_N * 2
    active = (owners + CACHE_N * 2 + 3) & ~3
    if active & 3:
        raise SystemExit("active cache mask is not word-aligned")
    next_slot = active + 4
    rect = next_slot + 4
    scratch = rect + 8
    cache_state_blob = expected_cache_state(font, cache_rows)
    if not cache_state_blob or len(cache_state_blob) & 3:
        raise SystemExit("cache state must have a nonzero word-aligned size")
    decoder = (scratch + len(cache_state_blob) + 3) & ~3
    decoder_blob = build_decoder(decoder, owners, active, next_slot, cache_index_ram)
    frame = (decoder + len(decoder_blob) + 3) & ~3
    frame_blob = build_frame(frame, owners, active, cache_index_ram,
                             row_dictionary, glyph_rows, rect, scratch)
    if frame + len(frame_blob) > RESIDENT_BASE + COPY_N:
        raise SystemExit("resident code crosses the frozen heap boundary")
    source = exe[file_at(SOURCE_BASE):file_at(SOURCE_BASE) + COPY_N]
    if source[scratch - RESIDENT_BASE:scratch - RESIDENT_BASE + len(cache_state_blob)] != \
            cache_state_blob:
        raise SystemExit("cache state source bytes differ")
    if source[decoder - RESIDENT_BASE:decoder - RESIDENT_BASE + len(decoder_blob)] != decoder_blob:
        raise SystemExit("decoder source bytes differ")
    if source[frame - RESIDENT_BASE:frame - RESIDENT_BASE + len(frame_blob)] != frame_blob:
        raise SystemExit("frame source bytes differ")
    if jump_target(DECODER_ENTRY, word(exe, DECODER_ENTRY)) != decoder:
        raise SystemExit("decoder hook target differs")
    if jump_target(FRAME_HOOK, word(exe, FRAME_HOOK)) != frame:
        raise SystemExit("frame hook target differs")
    calls = [jump_target(frame + at, struct.unpack_from("<I", frame_blob, at)[0])
             for at in range(0, len(frame_blob), 4)
             if struct.unpack_from("<I", frame_blob, at)[0] >> 26 == 3]
    if calls != list(EXPECTED_FRAME_CALLS):
        raise SystemExit("frame GPU transfer/call order differs")
    if word(exe, 0x80175810) != 0x2484F8B0 or HEAP_BASE != 0x801FF8B0:
        raise SystemExit("v151 heap boundary changed")

    # Simulate the bitplane edit for every source/slot pair.
    cache_plane_checks = 0
    for index in cache_indices:
        row, remainder = divmod(index, IPR)
        column, plane = divmod(remainder, PLANES)
        if row >= 21:
            raise SystemExit(f"cache slot is not in the low page: {index}")
        bit = 1 << plane
        for source_id in range(len(glyph_blob) // CELL):
            bits = source_shape(source_id)
            for y in range(CELL):
                for x in range(CELL):
                    px = column * CELL + x
                    value = original_font[(row * CELL + y) * 0x380 + px // 2]
                    shift = 0 if px % 2 == 0 else 4
                    nibble = (value >> shift) & 0xF
                    changed = (nibble & ~bit) | (bit if bits[y * CELL + x] else 0)
                    if (changed & ~bit) != (nibble & ~bit) or bool(changed & bit) != bool(bits[y * CELL + x]):
                        raise SystemExit("cache bitplane simulation failed")
            cache_plane_checks += 1

    lines = [
        f"{VERSION_LABEL} independent static verification: PASS",
        f"archive_sha256={BUILD_SHA}",
        f"archive_members={len(current)}",
        f"assignment_spellings_checked={assignment_checks}",
        f"Hangul_occurrences_compared={semantic_checks}",
        f"protected_virtual_occurrences_compared={protected_virtual_checks}",
        f"control_tokens_preserved={control_checks}",
        f"protected_UI_relocations_checked={relocation_checks}",
        f"max_dynamic_sources_in_one_unit={max_dynamic}",
        f"max_dynamic_unit={max_dynamic_label}",
        f"cache_plane_source_pairs_simulated={cache_plane_checks}",
        f"changed_text_members={changed_data_members}",
        f"changed_text_bytes={changed_data_bytes}",
        f"changed_EXE_bytes={len(changed_exe)}",
        "runtime_verification=PENDING",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
