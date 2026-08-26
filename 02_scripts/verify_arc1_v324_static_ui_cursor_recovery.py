#!/usr/bin/env python3
"""Independent static verifier for V324.

This intentionally reimplements packed lookup decoding, Hangul composition,
text-region walking, RLE decoding, and branch target checks instead of calling
the V324 builder.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))

from audit_dynamic_cache_requirements import active_slots, source_ranges  # noqa: E402
from capstone import (  # noqa: E402
    CS_ARCH_MIPS,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_MIPS32,
    Cs,
)


BASE = ROOT / "03_output/arc1_v322_e2_skip_restore_TEST_ONLY_480924F9.zip"
BASE_SHA256 = "480924F970C441BA819BC1F2FA003ED430FA76509ED138C8B33F444044057B32"
ORIGINAL = ROOT / "00_original/arc.zip"
ORIGINAL_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"
PIECES = ROOT / "01_work/analysis/hangul_johab_16px/pieces_1bpp.bin"
PIECES_SHA256 = "409ABA72F4BA2282AA5C4E4982A9EEA16FBD14FB0413A40E151537A6653E2904"
ATLAS = ROOT / "01_work/analysis/arc1_v319_pilgi16_integration/atlas_mapping.csv"
ATLAS_SHA256 = "9553E7643621CC80C23355067611EAE7650FEF7CB547DC9115B62157DB0C3122"
ASSIGNMENTS = ROOT / "01_work/analysis/arc1_v320_hanme_static_recovery/character_assignments.csv"
ASSIGNMENTS_SHA256 = "933BDAC4BC4C39D33DB134D2FF836902B5053B93725C96E19DED714CB7DE98A4"
SOURCES = ROOT / "01_work/analysis/arc1_v190_dynamic_owner_repair/source_manifest.csv"
SOURCES_SHA256 = "A629A8C2010C1C34CB40B6667A2279AB5EB5BE78F3AE8750768C3A42E1D68B00"
OUTPUT = ROOT / "01_work/analysis/arc1_v324_static_ui_cursor_recovery"

FINAL_ZIP_SHA256 = "06F7C289B593AB2767BA3D3ABC256ACCFD21781F60DF46A18F1D3FF58D67FD4B"
FINAL_PSX_SHA256 = "DD6EDADA703BAF7294C762ED787978FAA83CAD1B7AA552806265827FD4681900"
EXPECTED_CHANGED_BYTES = 1385

PSX, COMM = "PSX.EXE", "COMM.IMG"
RAM_TO_FILE = 0x8011A800
SOURCE_BASE, RESIDENT_BASE = 0x801A86EC, 0x801FE3C4
COPY_SIZE, HEAP_BASE = 0x14EC, 0x801FF8B0
SOURCE_FILE = SOURCE_BASE - RAM_TO_FILE
HELPER_RAM, HELPER_SIZE = 0x801FF488, 324
HELPER_FILE = SOURCE_FILE + HELPER_RAM - RESIDENT_BASE
RECLAIM_SIZE = HEAP_BASE - HELPER_RAM
RLE_SIZE, DATA_RAM = 652, HELPER_RAM + HELPER_SIZE
BAD_CAVE_FILE, BAD_CAVE_SIZE = 0x8F3D8, 0x428

HOOK_RAM, HOOK_FILE = 0x8011E614, 0x3E14
LOADIMAGE = 0x80177E4C
LOOKUP_RAM, LOOKUP_SLOTS = 0x801A7520, 413
LOOKUP_FILE = LOOKUP_RAM - RAM_TO_FILE
LOOKUP_BYTES = (LOOKUP_SLOTS * 11 + 7) // 8 + 2
STATIC_LIMIT, CACHE_MARK, BLANK = 960, 0x600, 160

DIRECT_BRANCH_RAM = 0x801FF400
OUT_BRANCH_RAM = 0x801FF440
EPILOGUE_RAM = 0x801FF45C
EPILOGUE_WORDS = (
    0x2D8D03C0, 0x15A00002, 0x00000000, 0x340C00A0, 0x01801821,
    0x00B91021, 0xACC20000, 0x0805AD04, 0x00000000, 0x00000000,
    0x00000000,
)

DESCRIPTOR_FILE, UV_FILE = 0x74F40, 0x750F8
BASE_UV = (
    (0, 128, 32, 128, 0, 160, 32, 160),
    (32, 128, 64, 128, 32, 160, 64, 160),
    (32, 160, 32, 128, 64, 160, 64, 128),
    (64, 160, 32, 160, 64, 128, 32, 128),
    (64, 128, 64, 160, 32, 128, 32, 160),
    (96, 128, 96, 160, 64, 128, 64, 160),
    (64, 128, 96, 128, 64, 160, 96, 160),
    (64, 160, 64, 128, 96, 160, 96, 128),
    (96, 160, 64, 160, 96, 128, 64, 128),
)

CELL, COLS, PLANES, ROW_BYTES = 16, 15, 4, 896
CHO_WITHOUT = (0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 3, 1, 2, 4, 4, 4, 2, 1, 3, 0)
CHO_WITH = (5, 5, 5, 5, 5, 5, 5, 5, 6, 7, 7, 7, 6, 6, 7, 7, 7, 6, 6, 7, 5)
JONG_BY_JUNG = (0, 2, 0, 2, 1, 2, 1, 2, 3, 0, 2, 1, 3, 3, 1, 2, 1, 3, 3, 1, 1)
FALLBACK = {210: "\uB611", 224: "\uCCA9", 405: "<VIRTUAL:405>", 409: "R"}
INVALID_STATIC = {77: 1317, 98: 1338}

SLOT_BASE, SLOT_SIZE = 0x45000, 0x80
EXE_POOL = (0x78000, 0x83000)
RAW_SHA256 = "B0005B318220FC61C11C3290837A7DF245646254FFA5CEBE7EA9A11932C7F421"
RLE_SHA256 = "94CED131CFC00C7B4A249009DEA5BE2361ABC6DAF6C244EE9B6D134F621C7133"
CHUNK_HEIGHTS, ROWS, WORDS_PER_ROW = (8, 8, 8, 8, 1), 33, 25


class VerifyError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as handle:
        names = [item.filename for item in handle.infolist() if not item.is_dir()]
        return names, {name: handle.read(name) for name in names}


def source_at(runtime: int) -> int:
    return SOURCE_FILE + runtime - RESIDENT_BASE


def lookup_get(exe: bytes, slot: int) -> int:
    bit = slot * 11
    byte_index, shift = divmod(bit, 8)
    packed = exe[LOOKUP_FILE + byte_index]
    packed |= exe[LOOKUP_FILE + byte_index + 1] << 8
    packed |= exe[LOOKUP_FILE + byte_index + 2] << 16
    return (packed >> shift) & 0x7FF


def is_hangul(ch: str) -> bool:
    return len(ch) == 1 and 0xAC00 <= ord(ch) <= 0xD7A3


def load_pieces(raw: bytes) -> tuple[tuple[int, ...], ...]:
    if len(raw) != 360 * 32:
        raise VerifyError("piece blob size differs")
    return tuple(tuple(struct.unpack_from(">16H", raw, index * 32)) for index in range(360))


def compose(pieces: tuple[tuple[int, ...], ...], ch: str) -> tuple[int, ...]:
    value = ord(ch) - 0xAC00
    cho, remainder = divmod(value, 588)
    jung, jong = divmod(remainder, 28)
    cho_beol = CHO_WITH[jung] if jong else CHO_WITHOUT[jung]
    jung_beol = (0 if cho in (0, 15) else 1) + (2 if jong else 0)
    jong_beol = JONG_BY_JUNG[jung]
    indices = (
        cho_beol * 20 + cho + 1,
        160 + jung_beol * 22 + jung + 1,
        248 + jong_beol * 28 + jong if jong else -1,
    )
    return tuple(
        pieces[indices[0]][y]
        | pieces[indices[1]][y]
        | (pieces[indices[2]][y] if indices[2] >= 0 else 0)
        for y in range(16)
    )


def read_plane(comm: bytes, index: int) -> tuple[int, ...]:
    cell, plane = divmod(index, PLANES)
    col, row = cell % COLS, cell // COLS
    bit = 1 << plane
    rows = []
    for y in range(16):
        value = 0
        base = (row * 16 + y) * ROW_BYTES + col * 8
        for x in range(16):
            shift = 0 if x % 2 == 0 else 4
            if ((comm[base + x // 2] >> shift) & 0x0F) & bit:
                value |= 1 << (15 - x)
        rows.append(value)
    return tuple(rows)


def identities() -> dict[str, set[int]]:
    by_index: dict[int, str] = {}
    by_char: dict[str, set[int]] = defaultdict(set)
    atlas_rows = atlas_hangul = 0
    with ATLAS.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            index = int(row["index"])
            if index != atlas_rows:
                raise VerifyError("atlas row order differs")
            atlas_rows += 1
            ch = row["char"]
            if is_hangul(ch):
                atlas_hangul += 1
                if by_index.setdefault(index, ch) != ch:
                    raise VerifyError("atlas physical identity conflict")
                by_char[ch].add(index)
    assignment_rows = assignment_hangul = 0
    with ASSIGNMENTS.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            assignment_rows += 1
            ch = row["char"]
            if is_hangul(ch):
                assignment_hangul += 1
                index = int(row["physical_index"])
                if by_index.setdefault(index, ch) != ch:
                    raise VerifyError("assignment physical identity conflict")
                by_char[ch].add(index)
    if (atlas_rows, atlas_hangul, assignment_rows, assignment_hangul) != (728, 632, 750, 727):
        raise VerifyError("mapping census differs")
    if (len(by_index), len(by_char)) != (718, 685):
        raise VerifyError("merged physical identity census differs")
    return by_char


def text_regions(members: dict[str, bytes]) -> list[tuple[str, int, int]]:
    regions: list[tuple[str, int, int]] = []
    ranges = list(source_ranges())
    for name, offset, size in ranges:
        if name in members and offset + size <= len(members[name]):
            regions.append((name, offset, offset + size))
    for name, slots in active_slots(members, ranges).items():
        data = members[name]
        for slot in slots:
            start = SLOT_BASE + slot * SLOT_SIZE
            block = data[start : start + SLOT_SIZE]
            end = block.index(0)
            if end:
                regions.append((name, start, start + end))
    exe = members[PSX]
    start = EXE_POOL[0]
    for cursor in range(*EXE_POOL):
        if exe[cursor]:
            continue
        if cursor > start:
            regions.append((PSX, start, cursor))
        start = cursor + 1
    return regions


def virtual_hits(members: dict[str, bytes], regions: list[tuple[str, int, int]]) -> Counter[int]:
    hits: Counter[int] = Counter()
    for name, start, end in regions:
        data = members[name]
        cursor = start
        while cursor < end:
            width = 1 if data[cursor] < 0xDD else 2
            if cursor + width > end:
                break
            if width == 2 and data[cursor] in (0xE9, 0xEA) and 1 <= data[cursor + 1] <= 0xFE:
                slot = (data[cursor] - 0xE9) * 254 + data[cursor + 1] - 1
                if slot < LOOKUP_SLOTS:
                    hits[slot] += 1
            cursor += width
    return hits


def decode_chunk(stream: bytes, offset: int, count: int) -> tuple[list[int], int]:
    out: list[int] = []
    while len(out) < count:
        if offset >= len(stream):
            raise VerifyError("RLE ends before its chunk")
        control = stream[offset]
        offset += 1
        run = (control & 0x3F) + 1
        if not control & 0x80:
            end = offset + run * 2
            if end > len(stream):
                raise VerifyError("RLE literal exceeds stream")
            out.extend(struct.unpack_from(f"<{run}H", stream, offset))
            offset = end
        elif not control & 0x40:
            out.extend([0] * run)
        else:
            if offset + 2 > len(stream):
                raise VerifyError("RLE repeated word missing")
            word = struct.unpack_from("<H", stream, offset)[0]
            offset += 2
            out.extend([word] * run)
        if len(out) > count:
            raise VerifyError("RLE crosses an upload chunk")
    return out, offset


def read_registers(word: int) -> set[int]:
    opcode = word >> 26
    rs, rt = (word >> 21) & 31, (word >> 16) & 31
    if opcode == 0:
        function = word & 0x3F
        if function == 0x08:
            return {rs}
        if function in (0x00, 0x02, 0x03):
            return {rt} - {0}
        return {rs, rt} - {0}
    if opcode in (0x02, 0x03, 0x0F):
        return set()
    if opcode in (0x04, 0x05):
        return {rs, rt} - {0}
    if opcode in (0x01, 0x06, 0x07):
        return {rs} - {0}
    if opcode in (0x28, 0x29, 0x2A, 0x2B, 0x2E):
        return {rs, rt} - {0}
    return {rs} - {0}


def verify_helper(helper: bytes) -> tuple[int, list[str]]:
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    instructions = list(md.disasm(helper, HELPER_RAM))
    if len(instructions) != 81:
        raise VerifyError(f"helper instruction count differs: {len(instructions)}")
    if (instructions[0].mnemonic, instructions[0].op_str) != ("addiu", "$sp, $sp, -0x1d0"):
        raise VerifyError("helper stack prologue differs")
    if instructions[-2].mnemonic != "jr" or instructions[-2].op_str != "$ra":
        raise VerifyError("helper return differs")
    if (instructions[-1].mnemonic, instructions[-1].op_str) != ("addiu", "$sp, $sp, 0x1d0"):
        raise VerifyError("helper stack restoration differs")
    words = struct.unpack("<81I", helper)
    if words[6] != 0x3C10801F or words[7] != 0x3610F5CC:
        raise VerifyError("helper persistent RLE pointer differs")
    calls: list[int] = []
    for index, instruction in enumerate(instructions):
        if instruction.mnemonic == "jal":
            calls.append(int(instruction.op_str, 16))
        if instruction.mnemonic in {"lb", "lbu", "lh", "lhu", "lw", "lwl", "lwr"} and index + 1 < len(words):
            destination = (words[index] >> 16) & 31
            if destination in read_registers(words[index + 1]):
                raise VerifyError(
                    f"R3000 load delay at 0x{instruction.address:08X}"
                )
    if calls != [LOADIMAGE]:
        raise VerifyError(f"helper calls differ: {calls}")
    return len(instructions), [f"0x{target:08X}" for target in calls]


def branch_target(pc: int, word: int) -> int | None:
    opcode = word >> 26
    if opcode not in (0x01, 0x04, 0x05, 0x06, 0x07):
        return None
    immediate = word & 0xFFFF
    if immediate & 0x8000:
        immediate -= 0x10000
    return pc + 4 + immediate * 4


def jump_target(pc: int, word: int) -> int | None:
    opcode = word >> 26
    if opcode not in (0x02, 0x03):
        return None
    return ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("build", type=Path)
    args = parser.parse_args()
    build = args.build.resolve()
    fixed = (
        (BASE, BASE_SHA256), (ORIGINAL, ORIGINAL_SHA256),
        (PIECES, PIECES_SHA256), (ATLAS, ATLAS_SHA256),
        (ASSIGNMENTS, ASSIGNMENTS_SHA256), (SOURCES, SOURCES_SHA256),
    )
    for path, expected in fixed:
        if not path.is_file() or sha256_file(path) != expected:
            raise VerifyError(f"fixed input hash differs: {path}")
    if not build.is_file() or sha256_file(build) != FINAL_ZIP_SHA256:
        raise VerifyError("V324 build hash differs")

    base_names, base = archive(BASE)
    final_names, final = archive(build)
    with ZipFile(ORIGINAL) as handle:
        original_comm = handle.read(COMM)
    if base_names != final_names or len(final_names) != 164:
        raise VerifyError("archive topology differs")
    changed = [name for name in final_names if base[name] != final[name]]
    if changed != [PSX]:
        raise VerifyError(f"changed members differ: {changed}")
    if any(len(base[name]) != len(final[name]) for name in final_names):
        raise VerifyError("member size differs")
    if any(final[name] != base[name] for name in final_names if name != PSX):
        raise VerifyError("non-PSX member differs from V322")

    old, exe = base[PSX], final[PSX]
    if sha256_bytes(exe) != FINAL_PSX_SHA256:
        raise VerifyError("final PSX.EXE hash differs")
    actual = {i for i, (left, right) in enumerate(zip(old, exe, strict=True)) if left != right}
    if len(actual) != EXPECTED_CHANGED_BYTES:
        raise VerifyError(f"changed-byte census differs: {len(actual)}")
    declared = {
        int(row["file_offset"], 16)
        for row in csv.DictReader((OUTPUT / "expected_writes.csv").open(encoding="utf-8-sig"))
    }
    if declared != actual:
        raise VerifyError("expected_writes.csv does not equal the actual PSX diff")

    # Boot-copy persistence and V323 failure-address exclusion.
    if SOURCE_FILE + COPY_SIZE != BAD_CAVE_FILE or HELPER_FILE + RECLAIM_SIZE != BAD_CAVE_FILE:
        raise VerifyError("resident source geometry differs")
    if struct.unpack_from("<I", exe, 0x5AFCC)[0] != 0x240614EC:
        raise VerifyError("boot copy length is not 5,356")
    if struct.unpack_from("<I", exe, 0x5B010)[0] != 0x2484F8B0:
        raise VerifyError("heap boundary instruction differs")
    if any(exe[BAD_CAVE_FILE : BAD_CAVE_FILE + BAD_CAVE_SIZE]):
        raise VerifyError("discarded V323 cave is not zero")
    expected_jal = 0x0C000000 | ((HELPER_RAM >> 2) & 0x03FFFFFF)
    if struct.unpack_from("<2I", exe, HOOK_FILE) != (expected_jal, 0):
        raise VerifyError("range initializer does not call persistent helper")

    # Independent lookup reconstruction and full staticization check.
    old_values = [lookup_get(old, slot) for slot in range(LOOKUP_SLOTS)]
    new_values = [lookup_get(exe, slot) for slot in range(LOOKUP_SLOTS)]
    old_census = (
        sum(v < STATIC_LIMIT for v in old_values),
        sum(STATIC_LIMIT <= v < CACHE_MARK for v in old_values),
        sum(CACHE_MARK <= v < 0x7FF for v in old_values),
        sum(v == 0x7FF for v in old_values),
    )
    if old_census != (213, 2, 198, 0):
        raise VerifyError(f"V322 lookup census differs: {old_census}")
    if not all(0 <= value < STATIC_LIMIT for value in new_values):
        raise VerifyError("V324 lookup still reaches an invalid/dynamic plane")
    changed_slots = [slot for slot, pair in enumerate(zip(old_values, new_values)) if pair[0] != pair[1]]
    if len(changed_slots) != 200:
        raise VerifyError(f"lookup changed-slot count differs: {len(changed_slots)}")
    if {slot: old_values[slot] for slot in INVALID_STATIC} != INVALID_STATIC:
        raise VerifyError("V322 invalid-static slots differ")
    if any(new_values[slot] != BLANK for slot in INVALID_STATIC):
        raise VerifyError("invalid-static slots are not fail-closed")

    source_rows = list(csv.DictReader(SOURCES.open(encoding="utf-8-sig", newline="")))
    source_chars = {int(row["source_id"]): row["char"] for row in source_rows}
    if len(source_rows) != 466 or set(source_chars) != set(range(466)):
        raise VerifyError("source manifest census differs")
    by_char = identities()
    pieces = load_pieces(PIECES.read_bytes())
    if any(read_plane(base[COMM], BLANK)):
        raise VerifyError("physical 160 is not blank")

    regions = text_regions(base)
    if len(regions) != 8448:
        raise VerifyError(f"text region count differs: {len(regions)}")
    hits = virtual_hits(base, regions)
    if (sum(hits.values()), len(hits)) != (2142, 234):
        raise VerifyError(f"virtual occurrence census differs: {sum(hits.values())}/{len(hits)}")
    live_dynamic = 0
    live_slots = 0
    fallback_seen: dict[int, str] = {}
    for slot, old_value in enumerate(old_values):
        if not CACHE_MARK <= old_value < 0x7FF:
            continue
        count = hits[slot]
        live_dynamic += count
        live_slots += int(bool(count))
        ch = source_chars[old_value - CACHE_MARK]
        candidates = by_char.get(ch, set())
        if len(candidates) == 1:
            physical = next(iter(candidates))
            if new_values[slot] != physical:
                raise VerifyError(f"lookup slot {slot} does not target {ch}/{physical}")
            if read_plane(base[COMM], physical) != compose(pieces, ch):
                raise VerifyError(f"lookup slot {slot} target bitmap differs: {ch}/{physical}")
        else:
            fallback_seen[slot] = ch
            if count or new_values[slot] != BLANK:
                raise VerifyError(f"fallback slot {slot} is used or nonblank")
    if (live_slots, live_dynamic) != (50, 84):
        raise VerifyError(f"live dynamic census differs: {live_slots}/{live_dynamic}")
    if fallback_seen != FALLBACK:
        raise VerifyError(f"fallback identity set differs: {fallback_seen}")

    # Decoder control flow must stop before the reclaimed helper.
    if struct.unpack_from("<11I", exe, source_at(EPILOGUE_RAM)) != EPILOGUE_WORDS:
        raise VerifyError("static decoder epilogue differs")
    decoder = exe[source_at(0x801FF348) : source_at(HELPER_RAM)]
    decoder_words = struct.unpack(f"<{len(decoder) // 4}I", decoder)
    decoder_targets = []
    for index, word in enumerate(decoder_words):
        pc = 0x801FF348 + index * 4
        target = branch_target(pc, word)
        if target is None:
            target = jump_target(pc, word)
        if target is not None:
            decoder_targets.append((pc, target))
    bad_targets = [(pc, target) for pc, target in decoder_targets if HELPER_RAM <= target < HEAP_BASE]
    if bad_targets:
        raise VerifyError(f"decoder still enters reclaimed helper/data: {bad_targets}")

    helper = exe[HELPER_FILE : HELPER_FILE + HELPER_SIZE]
    encoded = exe[HELPER_FILE + HELPER_SIZE : HELPER_FILE + HELPER_SIZE + RLE_SIZE]
    if sha256_bytes(encoded) != RLE_SHA256:
        raise VerifyError("embedded cursor RLE hash differs")
    if any(exe[HELPER_FILE + HELPER_SIZE + RLE_SIZE : HELPER_FILE + RECLAIM_SIZE]):
        raise VerifyError("unused resident tail is not zero")
    instruction_count, calls = verify_helper(helper)
    helper_words = struct.unpack("<81I", helper)
    for index, word in enumerate(helper_words):
        pc = HELPER_RAM + index * 4
        target = branch_target(pc, word)
        if target is not None and not HELPER_RAM <= target < HELPER_RAM + HELPER_SIZE:
            raise VerifyError(f"helper branch leaves helper at 0x{pc:08X}->0x{target:08X}")

    decoded = bytearray()
    cursor = 0
    for height in CHUNK_HEIGHTS:
        words, cursor = decode_chunk(encoded, cursor, height * WORDS_PER_ROW)
        decoded.extend(struct.pack(f"<{len(words)}H", *words))
    if cursor != len(encoded):
        raise VerifyError("cursor RLE has trailing bytes")
    original_raw = b"".join(
        original_comm[y * ROW_BYTES : y * ROW_BYTES + WORDS_PER_ROW * 2]
        for y in range(128, 128 + ROWS)
    )
    if sha256_bytes(original_raw) != RAW_SHA256 or bytes(decoded) != original_raw:
        raise VerifyError("cursor RLE does not reproduce original COMM art")

    old_descriptor = struct.unpack_from("<12I", old, DESCRIPTOR_FILE)
    new_descriptor = struct.unpack_from("<12I", exe, DESCRIPTOR_FILE)
    if old_descriptor[4:6] != (320, 0) or new_descriptor[4:6] != (960, 256):
        raise VerifyError("range TPage coordinates differ")
    if old_descriptor[:4] != new_descriptor[:4] or old_descriptor[6:] != new_descriptor[6:]:
        raise VerifyError("range descriptor changed outside TPage X/Y")
    old_uv = tuple(struct.unpack_from("<8H", old, UV_FILE + i * 16) for i in range(9))
    new_uv = tuple(struct.unpack_from("<8H", exe, UV_FILE + i * 16) for i in range(9))
    if old_uv != BASE_UV:
        raise VerifyError("V322 range UV table differs")
    expected_uv = tuple(
        tuple(value + 63 if index & 1 else value for index, value in enumerate(entry))
        for entry in BASE_UV
    )
    if new_uv != expected_uv:
        raise VerifyError("V324 range UV relocation differs")

    result = {
        "result": "PASS",
        "build": str(build),
        "build_sha256": sha256_file(build),
        "psx_sha256": sha256_bytes(exe),
        "changed_members": changed,
        "changed_psx_bytes": len(actual),
        "comm_and_all_dat_v322_identical": True,
        "lookup": {
            "before": [213, 2, 198, 0],
            "after_safe_static": 413,
            "rewritten_slots": len(changed_slots),
            "live_dynamic_before": [live_slots, live_dynamic],
            "live_dynamic_after": [0, 0],
            "fallback_slots": sorted(fallback_seen),
        },
        "resident": {
            "copy_bytes": COPY_SIZE,
            "helper_address": f"0x{HELPER_RAM:08X}",
            "helper_bytes": len(helper),
            "helper_instructions": instruction_count,
            "helper_calls": calls,
            "r3000_load_delay": "PASS",
            "heap_boundary": f"0x{HEAP_BASE:08X}",
            "bad_v323_cave_zero": True,
        },
        "cursor": {
            "raw_sha256": sha256_bytes(original_raw),
            "rle_sha256": sha256_bytes(encoded),
            "roundtrip": "PASS",
            "tpage": "0x05->0x1F",
            "uv_v": "128/160->191/223",
        },
        "runtime": "PENDING user cold boot/load/menu/battle",
    }
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "independent_verification.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "V324 independent static verification: PASS",
        f"build_sha256={result['build_sha256']}",
        f"PSX_sha256={result['psx_sha256']}",
        f"changed_members=PSX.EXE only; changed_bytes={len(actual)}",
        "COMM.IMG/all DAT=V322 byte-identical PASS",
        "lookup=213 safe + 2 invalid + 198 dynamic -> 413/413 safe static PASS",
        "live dynamic=50 slots/84 occurrences -> 0; four unused missing identities fail-closed",
        f"resident copy={COPY_SIZE}B; helper=0x{HELPER_RAM:08X}/{len(helper)}B/{instruction_count} instructions",
        "decoder tail routes=0; R3000 load delay/RA/stack=PASS",
        f"cursor raw/RLE={len(original_raw)}/{len(encoded)}B roundtrip PASS",
        "V323 bad cave 0x801A9BD8 remains zero; heap boundary unchanged",
        "runtime=PENDING user cold boot/load/menu/battle",
    ]
    (OUTPUT / "independent_verification.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    print("\n".join(lines))


if __name__ == "__main__":
    main()
