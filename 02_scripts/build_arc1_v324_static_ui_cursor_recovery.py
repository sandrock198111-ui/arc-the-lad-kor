#!/usr/bin/env python3
"""Build V324: remove the last live dynamic text routes and restore the cursor.

V323 placed the range-cursor upload helper in 0x801A9BD8.  That address is
inside a scene-loader/BSS area and is overwritten before the range object is
first initialized; the two captured black screens both faulted at that exact
address with MIPS Reserved Instruction.  V324 starts again from V322.

The old dynamic-glyph system still reserves and copies 5,356 bytes from
0x801A86EC to persistent RAM 0x801FE3C4 at boot, even though V318 disabled its
upload calls and V320 made all current direct text cache-free.  This build:

* resolves every remaining packed E9/EA lookup to a verified static 16 px
  plane (or blank for four unused identities with no plane),
* replaces the decoder's dynamic tail with a compact static/fail-closed
  epilogue,
* reclaims the now unreachable resident tail 0x801FF488..0x801FF8B0 for the
  cursor uploader and its RLE data, and
* applies V323's descriptor/UV relocation without touching COMM.IMG or DAT.

The frozen heap boundary remains 0x801FF8B0 and the original 5,356-byte boot
copy remains unchanged in size.  This is TEST_ONLY until a user cold boot and
load/menu/battle traversal succeed.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v171_ui_asset_recovery as v171  # noqa: E402
import build_arc1_v320_hanme_static_recovery as v320  # noqa: E402
import build_arc1_v320c_hanme_official_beol as v320c  # noqa: E402
import build_arc1_v323_skill_range_relocation as v323  # noqa: E402


BASE = ROOT / "03_output/arc1_v322_e2_skip_restore_TEST_ONLY_480924F9.zip"
BASE_SHA256 = "480924F970C441BA819BC1F2FA003ED430FA76509ED138C8B33F444044057B32"
ORIGINAL = ROOT / "00_original/arc.zip"
ORIGINAL_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"

OUTPUT_DIR = ROOT / "03_output"
ANALYSIS_DIR = ROOT / "01_work/analysis/arc1_v324_static_ui_cursor_recovery"
OUTPUT_STEM = "arc1_v324_static_ui_cursor_recovery_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v322"

PSX, COMM = "PSX.EXE", "COMM.IMG"
EXPECTED_MEMBERS = 164
RAM_TO_FILE = 0x8011A800
EXPECTED_PSX_SHA256 = "8E295D22D60C2427F4702618108E9836F7615A5D4BF384CB84FD2F10F9A6218E"
EXPECTED_COMM_SHA256 = "C81F48B805F3FF973C08DE14DE232DD2620612483FC0778A79BA2D2DC26E185B"
EXPECTED_ORIGINAL_COMM_SHA256 = "6C7565B6C326A99A29266482868F17A144FF7D15B871D7D8F8B852EC41014A26"

# Persistent boot-copy reservation inherited from v159-v190.
SOURCE_BASE = 0x801A86EC
RESIDENT_BASE = 0x801FE3C4
COPY_SIZE = 0x14EC
HEAP_BASE = 0x801FF8B0
EXPECTED_RESIDENT_SOURCE_SHA256 = (
    "685BBEA16C9A51D609641190A699E55B989938944B6A0466EE591721CFABFA0E"
)
COPY_LENGTH_WORD_RAM = 0x801757CC
HEAP_BOUNDARY_WORD_RAM = 0x80175810
EXPECTED_COPY_LENGTH_WORD = 0x240614EC
EXPECTED_HEAP_BOUNDARY_WORD = 0x2484F8B0

# The static decoder remains through 0x801FF487.  Everything from 0x801FF488
# to the frozen heap boundary is the obsolete cache allocator/Huffman/frame
# tail and becomes the persistent cursor helper cave.
HELPER_RAM = 0x801FF488
HELPER_SIZE = 324
RECLAIM_SIZE = HEAP_BASE - HELPER_RAM
SOURCE_FILE = SOURCE_BASE - RAM_TO_FILE
HELPER_SOURCE_FILE = SOURCE_FILE + (HELPER_RAM - RESIDENT_BASE)
BAD_V323_CAVE_FILE = 0x8F3D8
BAD_V323_CAVE_SIZE = 0x428

# Two still-reachable decoder branches and the old dynamic dispatch epilogue.
DIRECT_DEAD_BRANCH_RAM = 0x801FF400
DIRECT_DEAD_BRANCH_WORD = 0x10000021  # old target 0x801FF488
OUT_OF_RANGE_BRANCH_RAM = 0x801FF440
OUT_OF_RANGE_BRANCH_WORD = 0x11600048  # old target 0x801FF564
STATIC_EPILOGUE_RAM = 0x801FF45C
STATIC_EPILOGUE_OLD = (
    0x118D0007, 0x00000000, 0x2D8D0600, 0x15A00005, 0x00000000,
    0x258CFA00, 0x10000004, 0x00000000, 0x340C14B0, 0x1000003B,
    0x01801821,
)

# 16px low page has 15 columns x 16 rows x four planes = 960 planes.
STATIC_LIMIT = 960
BLANK_PHYSICAL = 160
LOOKUP_RAM = v320.LOOKUP_RAM
LOOKUP_SLOTS = v320.LOOKUP_SLOTS
LOOKUP_BYTES = (LOOKUP_SLOTS * 11 + 7) // 8 + 2
EXPECTED_LOOKUP_BEFORE = {"safe_static": 213, "invalid_static": 2, "dynamic": 198, "missing": 0}
EXPECTED_INVALID_STATIC = {77: 1317, 98: 1338}
EXPECTED_DYNAMIC_OCCURRENCES = 84
EXPECTED_DYNAMIC_USED_SLOTS = 50
EXPECTED_VIRTUAL_OCCURRENCES = 2142
EXPECTED_VIRTUAL_USED_SLOTS = 234
EXPECTED_FALLBACK = {
    210: "\uB611",       # no static plane; unused in all 8,448 regions
    224: "\uCCA9",       # no static plane; unused in all 8,448 regions
    405: "<VIRTUAL:405>",
    409: "R",
}

# Same object-specific cursor relocation proven statically in V323.
INIT_HOOK = v323.INIT_HOOK
INIT_HOOK_WORDS = v323.INIT_HOOK_WORDS
DESCRIPTOR_FILE = v323.DESCRIPTOR_FILE
DESCRIPTOR_SIZE = v323.DESCRIPTOR_SIZE
DESCRIPTOR_SHA256 = v323.DESCRIPTOR_SHA256
UV_FILE = v323.UV_FILE
UV_SIZE = v323.UV_SIZE
UV_SHA256 = v323.UV_SHA256
BASE_UV = v323.BASE_UV


class BuildError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def file_offset(address: int) -> int:
    return address - RAM_TO_FILE


def resident_source_offset(address: int) -> int:
    if not RESIDENT_BASE <= address < HEAP_BASE:
        raise BuildError(f"resident address outside reservation: 0x{address:08X}")
    return SOURCE_FILE + address - RESIDENT_BASE


def i_type(op: int, rs: int, rt: int, immediate: int) -> int:
    return (op << 26) | (rs << 21) | (rt << 16) | (immediate & 0xFFFF)


def r_type(rs: int, rt: int, rd: int, shift: int, function: int) -> int:
    return (rs << 21) | (rt << 16) | (rd << 11) | (shift << 6) | function


def jump(address: int) -> int:
    return 0x08000000 | ((address >> 2) & 0x03FFFFFF)


def branch_word(op: int, rs: int, rt: int, pc: int, target: int) -> int:
    delta = target - (pc + 4)
    if delta % 4 or not -0x20000 <= delta < 0x20000:
        raise BuildError(f"invalid branch 0x{pc:08X}->0x{target:08X}")
    return i_type(op, rs, rt, delta // 4)


def clone_zipinfo(info: ZipInfo) -> ZipInfo:
    clone = ZipInfo(info.filename, info.date_time)
    for attribute in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(clone, attribute, getattr(info, attribute))
    return clone


def read_archive(path: Path) -> tuple[list[ZipInfo], dict[str, bytes]]:
    with ZipFile(path) as archive:
        infos = archive.infolist()
        members = {
            info.filename: archive.read(info.filename)
            for info in infos if not info.is_dir()
        }
    if len(members) != EXPECTED_MEMBERS or len(members) != len(set(members)):
        raise BuildError("archive topology drift")
    return infos, members


def write_archive(
    stem: str,
    infos: list[ZipInfo],
    members: dict[str, bytes],
    selected: set[str] | None,
) -> tuple[Path, str]:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    temporary = OUTPUT_DIR / f".{stem}.{os.getpid()}.building.zip"
    if temporary.exists():
        raise BuildError(f"temporary output exists: {temporary}")
    try:
        with ZipFile(temporary, "w", ZIP_DEFLATED, compresslevel=1) as archive:
            for info in infos:
                if info.is_dir():
                    if selected is None:
                        archive.writestr(clone_zipinfo(info), b"")
                    continue
                if selected is None or info.filename in selected:
                    archive.writestr(clone_zipinfo(info), members[info.filename])
        digest = sha256_file(temporary)
        final = OUTPUT_DIR / f"{stem}_{digest[:8]}.zip"
        if final.exists():
            if sha256_file(final) != digest:
                raise BuildError(f"existing output differs: {final}")
            temporary.unlink()
        else:
            temporary.replace(final)
        return final, digest
    finally:
        if temporary.exists():
            temporary.unlink()


def is_hangul(ch: str) -> bool:
    return len(ch) == 1 and 0xAC00 <= ord(ch) <= 0xD7A3


def lookup_census(exe: bytes | bytearray) -> dict[str, int]:
    values = [v320.lookup_get(exe, slot) for slot in range(LOOKUP_SLOTS)]
    return {
        "safe_static": sum(value < STATIC_LIMIT for value in values),
        "invalid_static": sum(STATIC_LIMIT <= value < v320.CACHE_MARK for value in values),
        "dynamic": sum(v320.CACHE_MARK <= value < 0x7FF for value in values),
        "missing": sum(value == 0x7FF for value in values),
    }


def virtual_occurrences(
    members: dict[str, bytes], regions: list[tuple[str, int, int]]
) -> Counter[int]:
    hits: Counter[int] = Counter()
    for name, start, end in regions:
        data = members[name]
        cursor = start
        while cursor < end:
            width = 1 if data[cursor] < 0xDD else 2
            if cursor + width > end:
                break
            if (
                width == 2
                and data[cursor] in (0xE9, 0xEA)
                and 1 <= data[cursor + 1] <= 0xFE
            ):
                slot = (data[cursor] - 0xE9) * 254 + data[cursor + 1] - 1
                if slot < LOOKUP_SLOTS:
                    hits[slot] += 1
            cursor += width
    return hits


def physical_identities() -> tuple[dict[int, str], dict[str, set[int]]]:
    by_index: dict[int, str] = {}
    by_char: dict[str, set[int]] = defaultdict(set)

    def register(index: int, ch: str) -> None:
        if not is_hangul(ch):
            return
        if not 0 <= index < STATIC_LIMIT:
            raise BuildError(f"Hangul identity outside low page: {index} {ch}")
        previous = by_index.setdefault(index, ch)
        if previous != ch:
            raise BuildError(f"physical identity conflict: {index} {previous}/{ch}")
        by_char[ch].add(index)

    atlas_rows = atlas_hangul = 0
    with v320c.ATLAS_MAPPING.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            index = int(row["index"])
            if index != atlas_rows:
                raise BuildError("atlas mapping order drift")
            atlas_rows += 1
            if is_hangul(row["char"]):
                atlas_hangul += 1
                register(index, row["char"])
    if (atlas_rows, atlas_hangul) != (728, 632):
        raise BuildError(f"atlas census drift: {atlas_rows}/{atlas_hangul}")

    assignment_rows = assignment_hangul = 0
    with v320c.CHAR_ASSIGNMENTS.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            assignment_rows += 1
            if is_hangul(row["char"]):
                assignment_hangul += 1
                register(int(row["physical_index"]), row["char"])
    if (assignment_rows, assignment_hangul) != (750, 727):
        raise BuildError(
            f"assignment census drift: {assignment_rows}/{assignment_hangul}"
        )
    if (len(by_index), len(by_char)) != (718, 685):
        raise BuildError(f"physical identity census drift: {len(by_index)}/{len(by_char)}")
    return by_index, by_char


def region_name(offset: int, payload_end: int) -> str:
    if file_offset(INIT_HOOK) <= offset < file_offset(INIT_HOOK) + 8:
        return "range_initializer_hook"
    if offset in range(
        resident_source_offset(DIRECT_DEAD_BRANCH_RAM),
        resident_source_offset(DIRECT_DEAD_BRANCH_RAM) + 4,
    ):
        return "decoder_dead_direct_branch"
    if offset in range(
        resident_source_offset(OUT_OF_RANGE_BRANCH_RAM),
        resident_source_offset(OUT_OF_RANGE_BRANCH_RAM) + 4,
    ):
        return "decoder_out_of_range_branch"
    if resident_source_offset(STATIC_EPILOGUE_RAM) <= offset < HELPER_SOURCE_FILE:
        return "decoder_static_epilogue"
    if HELPER_SOURCE_FILE <= offset < HELPER_SOURCE_FILE + HELPER_SIZE:
        return "persistent_upload_helper"
    if HELPER_SOURCE_FILE + HELPER_SIZE <= offset < payload_end:
        return "persistent_cursor_rle"
    if payload_end <= offset < HELPER_SOURCE_FILE + RECLAIM_SIZE:
        return "reclaimed_tail_zero"
    lookup_start = file_offset(LOOKUP_RAM)
    if lookup_start <= offset < lookup_start + LOOKUP_BYTES:
        return "packed_e9ea_lookup"
    if DESCRIPTOR_FILE + 0x10 <= offset < DESCRIPTOR_FILE + 0x18:
        return "range_tpage_descriptor"
    if UV_FILE <= offset < UV_FILE + UV_SIZE:
        return "range_uv_table"
    return "UNEXPECTED"


def main() -> None:
    fixed_inputs = (
        (BASE, BASE_SHA256, "V322 base"),
        (ORIGINAL, ORIGINAL_SHA256, "original archive"),
        (v320c.PIECES, v320c.PIECES_SHA256, "Hanme pieces"),
        (v320c.ATLAS_MAPPING, v320c.ATLAS_MAPPING_SHA256, "atlas mapping"),
        (v320c.CHAR_ASSIGNMENTS, v320c.CHAR_ASSIGNMENTS_SHA256, "character assignments"),
        (v320.SOURCE_MANIFEST, v320.SOURCE_MANIFEST_SHA256, "dynamic source manifest"),
    )
    for path, expected, label in fixed_inputs:
        if not path.is_file() or sha256_file(path) != expected:
            raise BuildError(f"{label} hash mismatch: {path}")

    infos, before = read_archive(BASE)
    with ZipFile(ORIGINAL) as archive:
        original_comm = archive.read(COMM)
    if sha256_bytes(before[PSX]) != EXPECTED_PSX_SHA256:
        raise BuildError("V322 PSX.EXE hash drift")
    if sha256_bytes(before[COMM]) != EXPECTED_COMM_SHA256:
        raise BuildError("V322 COMM.IMG hash drift")
    if sha256_bytes(original_comm) != EXPECTED_ORIGINAL_COMM_SHA256:
        raise BuildError("original COMM.IMG hash drift")

    exe = bytearray(before[PSX])
    if len(exe) != 587_776:
        raise BuildError(f"unexpected PSX.EXE size: {len(exe)}")
    resident_source = bytes(exe[SOURCE_FILE : SOURCE_FILE + COPY_SIZE])
    if sha256_bytes(resident_source) != EXPECTED_RESIDENT_SOURCE_SHA256:
        raise BuildError("V322 persistent resident source drift")
    if SOURCE_FILE + COPY_SIZE != BAD_V323_CAVE_FILE:
        raise BuildError("resident source no longer ends at the V323 tail boundary")
    if HELPER_SOURCE_FILE + RECLAIM_SIZE != SOURCE_FILE + COPY_SIZE:
        raise BuildError("reclaimed resident tail arithmetic drift")
    if RECLAIM_SIZE != 0x428:
        raise BuildError(f"reclaimed tail capacity drift: {RECLAIM_SIZE}")
    if any(exe[BAD_V323_CAVE_FILE : BAD_V323_CAVE_FILE + BAD_V323_CAVE_SIZE]):
        raise BuildError("V322 bad V323 scene-loader cave is no longer zero")
    if struct.unpack_from("<I", exe, file_offset(COPY_LENGTH_WORD_RAM))[0] != EXPECTED_COPY_LENGTH_WORD:
        raise BuildError("boot copy length drift")
    if struct.unpack_from("<I", exe, file_offset(HEAP_BOUNDARY_WORD_RAM))[0] != EXPECTED_HEAP_BOUNDARY_WORD:
        raise BuildError("frozen heap boundary drift")

    if struct.unpack_from("<2I", exe, file_offset(INIT_HOOK)) != INIT_HOOK_WORDS:
        raise BuildError("range initializer hook premise drift")
    if sha256_bytes(bytes(exe[DESCRIPTOR_FILE : DESCRIPTOR_FILE + DESCRIPTOR_SIZE])) != DESCRIPTOR_SHA256:
        raise BuildError("range texture descriptor drift")
    if sha256_bytes(bytes(exe[UV_FILE : UV_FILE + UV_SIZE])) != UV_SHA256:
        raise BuildError("range UV table drift")
    old_uv = tuple(struct.unpack_from("<8H", exe, UV_FILE + i * 16) for i in range(9))
    if old_uv != BASE_UV:
        raise BuildError("range UV entries differ from the nine-tile specification")

    # Reconstruct current text usage and all physical Hangul identities.
    regions = list(v320.text_regions(before))
    if len(regions) != v320.REGION_COUNT or v320.region_fingerprint(regions) != v320.REGION_SHA256:
        raise BuildError("8,448-region text catalogue drift")
    occurrences = virtual_occurrences(before, regions)
    if (sum(occurrences.values()), len(occurrences)) != (
        EXPECTED_VIRTUAL_OCCURRENCES, EXPECTED_VIRTUAL_USED_SLOTS,
    ):
        raise BuildError(
            f"E9/EA occurrence census drift: {sum(occurrences.values())}/{len(occurrences)}"
        )
    if lookup_census(exe) != EXPECTED_LOOKUP_BEFORE:
        raise BuildError(f"lookup census drift: {lookup_census(exe)}")
    invalid_static = {
        slot: v320.lookup_get(exe, slot)
        for slot in range(LOOKUP_SLOTS)
        if STATIC_LIMIT <= v320.lookup_get(exe, slot) < v320.CACHE_MARK
    }
    if invalid_static != EXPECTED_INVALID_STATIC:
        raise BuildError(f"invalid static lookup set drift: {invalid_static}")

    source_rows = list(
        csv.DictReader(v320.SOURCE_MANIFEST.open(encoding="utf-8-sig", newline=""))
    )
    source_chars = {int(row["source_id"]): row["char"] for row in source_rows}
    if len(source_rows) != 466 or set(source_chars) != set(range(466)):
        raise BuildError("dynamic source manifest census drift")

    _by_index, by_char = physical_identities()
    pieces = v320c.load_pieces(v320c.PIECES.read_bytes())
    if any(v320c.read_plane(before[COMM], BLANK_PHYSICAL)):
        raise BuildError("fail-closed physical 160 is no longer blank")

    lookup_rows: list[dict[str, object]] = []
    dynamic_used_slots = 0
    dynamic_occurrences = 0
    fallback_seen: dict[int, str] = {}
    for slot in range(LOOKUP_SLOTS):
        old_value = v320.lookup_get(exe, slot)
        count = occurrences[slot]
        if v320.CACHE_MARK <= old_value < 0x7FF:
            source_id = old_value - v320.CACHE_MARK
            if source_id not in source_chars:
                raise BuildError(f"lookup slot {slot} references unknown source {source_id}")
            ch = source_chars[source_id]
            candidates = by_char.get(ch, set())
            if len(candidates) == 1:
                physical = next(iter(candidates))
                if not is_hangul(ch):
                    raise BuildError(f"non-Hangul unexpectedly mapped at slot {slot}: {ch}")
                actual = v320c.read_plane(before[COMM], physical)
                expected = v320c.compose(pieces, ch, official=True)
                if actual != expected:
                    raise BuildError(f"official Hanme plane mismatch: slot {slot} {ch}/{physical}")
                mode = "verified_static_hanme"
            else:
                physical = BLANK_PHYSICAL
                fallback_seen[slot] = ch
                mode = "unused_identity_failclosed_blank"
                if count:
                    raise BuildError(f"used dynamic slot lacks a static plane: {slot} {ch}")
            v320.lookup_set(exe, slot, physical)
            dynamic_used_slots += int(bool(count))
            dynamic_occurrences += count
            lookup_rows.append(
                {
                    "slot": slot,
                    "code_hex": f"{0xE9 + slot // 254:02X} {slot % 254 + 1:02X}",
                    "old_value": old_value,
                    "source_id": source_id,
                    "char": ch,
                    "new_physical": physical,
                    "occurrences": count,
                    "mode": mode,
                }
            )
        elif STATIC_LIMIT <= old_value < v320.CACHE_MARK:
            if count:
                raise BuildError(f"used static lookup is outside 16px page: {slot}/{old_value}")
            v320.lookup_set(exe, slot, BLANK_PHYSICAL)
            lookup_rows.append(
                {
                    "slot": slot,
                    "code_hex": f"{0xE9 + slot // 254:02X} {slot % 254 + 1:02X}",
                    "old_value": old_value,
                    "source_id": "",
                    "char": "<unresolved high physical>",
                    "new_physical": BLANK_PHYSICAL,
                    "occurrences": count,
                    "mode": "unused_invalid_static_failclosed_blank",
                }
            )
    if len(lookup_rows) != 200:
        raise BuildError(f"lookup rewrite count drift: {len(lookup_rows)}")
    if fallback_seen != EXPECTED_FALLBACK:
        raise BuildError(f"fail-closed identity set drift: {fallback_seen}")
    if (dynamic_used_slots, dynamic_occurrences) != (
        EXPECTED_DYNAMIC_USED_SLOTS, EXPECTED_DYNAMIC_OCCURRENCES,
    ):
        raise BuildError(
            f"used dynamic census drift: {dynamic_used_slots}/{dynamic_occurrences}"
        )
    after_values = [v320.lookup_get(exe, slot) for slot in range(LOOKUP_SLOTS)]
    if any(not 0 <= value < STATIC_LIMIT for value in after_values):
        raise BuildError("lookup table is not entirely inside the 16px static page")

    # Remove every decoder route into the reclaimed dynamic tail.  The compact
    # epilogue accepts only <960 physical indices and maps anything unexpected
    # to the verified blank plane 160.
    direct_at = resident_source_offset(DIRECT_DEAD_BRANCH_RAM)
    if struct.unpack_from("<I", exe, direct_at)[0] != DIRECT_DEAD_BRANCH_WORD:
        raise BuildError("dead direct-cache branch premise drift")
    struct.pack_into(
        "<I", exe, direct_at,
        branch_word(0x04, 0, 0, DIRECT_DEAD_BRANCH_RAM, STATIC_EPILOGUE_RAM + 0x0C),
    )
    out_at = resident_source_offset(OUT_OF_RANGE_BRANCH_RAM)
    if struct.unpack_from("<I", exe, out_at)[0] != OUT_OF_RANGE_BRANCH_WORD:
        raise BuildError("E9/EA out-of-range branch premise drift")
    struct.pack_into(
        "<I", exe, out_at,
        branch_word(0x04, 11, 0, OUT_OF_RANGE_BRANCH_RAM, STATIC_EPILOGUE_RAM + 0x0C),
    )
    epilogue_at = resident_source_offset(STATIC_EPILOGUE_RAM)
    if struct.unpack_from("<11I", exe, epilogue_at) != STATIC_EPILOGUE_OLD:
        raise BuildError("old dynamic decoder epilogue drift")
    static_epilogue = (
        i_type(0x0B, 12, 13, STATIC_LIMIT),                     # sltiu t5,t4,960
        branch_word(0x05, 13, 0, STATIC_EPILOGUE_RAM + 4, STATIC_EPILOGUE_RAM + 0x10),
        0,
        i_type(0x0D, 0, 12, BLANK_PHYSICAL),                   # ori t4,zero,160
        r_type(12, 0, 3, 0, 0x21),                             # move v1,t4
        r_type(5, 25, 2, 0, 0x21),                             # addu v0,a1,t9
        i_type(0x2B, 6, 2, 0),                                 # sw v0,0(a2)
        jump(0x8016B410),
        0,
        0,
        0,
    )
    struct.pack_into("<11I", exe, epilogue_at, *static_epilogue)

    # Build V323's exact cursor art but store/execute it in persistent RAM.
    raw, encoded, chunk_heights = v323.cursor_art(original_comm)
    provisional = v323.build_upload_helper(HELPER_RAM, HELPER_RAM)
    if len(provisional) != HELPER_SIZE:
        raise BuildError(f"persistent upload helper size drift: {len(provisional)}")
    data_ram = HELPER_RAM + HELPER_SIZE
    helper = v323.build_upload_helper(HELPER_RAM, data_ram)
    payload = helper + encoded
    if len(helper) != HELPER_SIZE or len(payload) > RECLAIM_SIZE:
        raise BuildError(f"persistent helper overflow: {len(payload)}/{RECLAIM_SIZE}")
    exe[HELPER_SOURCE_FILE : HELPER_SOURCE_FILE + RECLAIM_SIZE] = bytes(RECLAIM_SIZE)
    exe[HELPER_SOURCE_FILE : HELPER_SOURCE_FILE + len(payload)] = payload
    struct.pack_into("<2I", exe, file_offset(INIT_HOOK), v323.jal(HELPER_RAM), 0)

    struct.pack_into("<I", exe, DESCRIPTOR_FILE + 0x10, v323.DEST_TPAGE_X)
    struct.pack_into("<I", exe, DESCRIPTOR_FILE + 0x14, v323.DEST_TPAGE_Y)
    relocated_uv: list[tuple[int, ...]] = []
    for index, entry in enumerate(BASE_UV):
        values = list(entry)
        for item in (1, 3, 5, 7):
            values[item] += v323.UV_V_DELTA
            if not 0 <= values[item] <= 0xFF:
                raise BuildError("relocated UV exceeds its byte field")
        relocated_uv.append(tuple(values))
        struct.pack_into("<8H", exe, UV_FILE + index * 16, *values)

    # Semantic readback.
    if struct.unpack_from("<2I", exe, file_offset(INIT_HOOK)) != (v323.jal(HELPER_RAM), 0):
        raise BuildError("persistent helper hook readback failed")
    if bytes(exe[HELPER_SOURCE_FILE : HELPER_SOURCE_FILE + HELPER_SIZE]) != helper:
        raise BuildError("persistent helper readback failed")
    if bytes(exe[HELPER_SOURCE_FILE + HELPER_SIZE : HELPER_SOURCE_FILE + len(payload)]) != encoded:
        raise BuildError("persistent RLE readback failed")
    if any(exe[HELPER_SOURCE_FILE + len(payload) : HELPER_SOURCE_FILE + RECLAIM_SIZE]):
        raise BuildError("unused persistent tail is not zero")
    if any(exe[BAD_V323_CAVE_FILE : BAD_V323_CAVE_FILE + BAD_V323_CAVE_SIZE]):
        raise BuildError("discarded V323 scene-loader cave changed")
    if struct.unpack_from("<11I", exe, epilogue_at) != static_epilogue:
        raise BuildError("static decoder epilogue readback failed")
    if tuple(struct.unpack_from("<8H", exe, UV_FILE + i * 16) for i in range(9)) != tuple(relocated_uv):
        raise BuildError("UV relocation readback failed")
    descriptor = struct.unpack_from("<12I", exe, DESCRIPTOR_FILE)
    if descriptor[4:6] != (v323.DEST_TPAGE_X, v323.DEST_TPAGE_Y):
        raise BuildError("texture-page descriptor readback failed")

    # The only executed control transfer into the reclaimed range is the new
    # initializer JAL; decoder branches now land in the compact epilogue.
    if struct.unpack_from("<I", exe, direct_at)[0] != branch_word(
        0x04, 0, 0, DIRECT_DEAD_BRANCH_RAM, STATIC_EPILOGUE_RAM + 0x0C
    ):
        raise BuildError("dead direct branch readback failed")
    if struct.unpack_from("<I", exe, out_at)[0] != branch_word(
        0x04, 11, 0, OUT_OF_RANGE_BRANCH_RAM, STATIC_EPILOGUE_RAM + 0x0C
    ):
        raise BuildError("out-of-range branch readback failed")
    old_upload_jal = struct.pack("<I", v323.jal(0x801FF668))
    text_size = struct.unpack_from("<I", exe, 0x1C)[0]
    if bytes(exe[0x800 : 0x800 + text_size]).count(old_upload_jal):
        raise BuildError("old dynamic frame upload call remains")

    final = dict(before)
    final[PSX] = bytes(exe)
    changed_members = [name for name in before if before[name] != final[name]]
    if changed_members != [PSX]:
        raise BuildError(f"changed member set drift: {changed_members}")
    if final[COMM] != before[COMM] or sha256_bytes(final[COMM]) != EXPECTED_COMM_SHA256:
        raise BuildError("COMM.IMG changed")
    if any(len(before[name]) != len(final[name]) for name in before):
        raise BuildError("archive member size changed")

    actual_offsets = {
        offset
        for offset, (old, new) in enumerate(zip(before[PSX], final[PSX], strict=True))
        if old != new
    }
    lookup_start = file_offset(LOOKUP_RAM)
    allowed_offsets = (
        set(range(file_offset(INIT_HOOK), file_offset(INIT_HOOK) + 8))
        | set(range(direct_at, direct_at + 4))
        | set(range(out_at, out_at + 4))
        | set(range(epilogue_at, HELPER_SOURCE_FILE))
        | set(range(HELPER_SOURCE_FILE, HELPER_SOURCE_FILE + RECLAIM_SIZE))
        | set(range(lookup_start, lookup_start + LOOKUP_BYTES))
        | set(range(DESCRIPTOR_FILE + 0x10, DESCRIPTOR_FILE + 0x18))
        | set(range(UV_FILE, UV_FILE + UV_SIZE))
    )
    if not actual_offsets or not actual_offsets <= allowed_offsets:
        unexpected = sorted(actual_offsets - allowed_offsets)
        raise BuildError(f"PSX.EXE Expected-Write violation: {unexpected[:8]}")
    payload_end = HELPER_SOURCE_FILE + len(payload)
    if any(region_name(offset, payload_end) == "UNEXPECTED" for offset in actual_offsets):
        raise BuildError("Expected-Write classifier missed a changed byte")

    output_path, output_hash = write_archive(OUTPUT_STEM, infos, final, None)
    delta_path, delta_hash = write_archive(DELTA_STEM, infos, final, {PSX})
    with ZipFile(output_path) as archive:
        names = [info.filename for info in archive.infolist() if not info.is_dir()]
        if names != [info.filename for info in infos if not info.is_dir()]:
            raise BuildError("output ZIP topology drift")
        if any(archive.read(name) != final[name] for name in final):
            raise BuildError("output ZIP round-trip mismatch")
    with ZipFile(delta_path) as archive:
        if archive.namelist() != [PSX] or archive.read(PSX) != final[PSX]:
            raise BuildError("delta ZIP mismatch")

    ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
    (ANALYSIS_DIR / "cursor_texture_raw.bin").write_bytes(raw)
    (ANALYSIS_DIR / "cursor_texture_rle.bin").write_bytes(encoded)
    with (ANALYSIS_DIR / "lookup_staticization.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        fields = (
            "slot", "code_hex", "old_value", "source_id", "char",
            "new_physical", "occurrences", "mode",
        )
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(lookup_rows)
    with (ANALYSIS_DIR / "expected_writes.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow(("file_offset", "runtime_or_loaded_address", "before", "after", "region"))
        for offset in sorted(actual_offsets):
            if SOURCE_FILE <= offset < SOURCE_FILE + COPY_SIZE:
                address = RESIDENT_BASE + offset - SOURCE_FILE
            else:
                address = RAM_TO_FILE + offset
            writer.writerow(
                (
                    f"0x{offset:X}", f"0x{address:08X}",
                    f"{before[PSX][offset]:02X}", f"{final[PSX][offset]:02X}",
                    region_name(offset, payload_end),
                )
            )

    manifest = {
        "build": "V324 TEST_ONLY static UI lookup + persistent range cursor recovery",
        "base": {"path": str(BASE), "sha256": BASE_SHA256},
        "output": {"path": str(output_path), "sha256": output_hash},
        "delta": {"path": str(delta_path), "sha256": delta_hash},
        "changed_members": changed_members,
        "changed_psx_bytes": len(actual_offsets),
        "lookup": {
            "before": EXPECTED_LOOKUP_BEFORE,
            "rewritten_slots": len(lookup_rows),
            "dynamic_rewritten": 198,
            "invalid_static_rewritten": 2,
            "used_dynamic_slots": dynamic_used_slots,
            "used_dynamic_occurrences": dynamic_occurrences,
            "after": {"safe_static": LOOKUP_SLOTS, "invalid_static": 0, "dynamic": 0, "missing": 0},
            "fallback_blank_slots": sorted(fallback_seen),
        },
        "resident": {
            "source": f"0x{SOURCE_BASE:08X}",
            "destination": f"0x{RESIDENT_BASE:08X}",
            "copy_bytes": COPY_SIZE,
            "helper": f"0x{HELPER_RAM:08X}",
            "helper_bytes": len(helper),
            "rle_data": f"0x{data_ram:08X}",
            "rle_bytes": len(encoded),
            "reclaimed_bytes": RECLAIM_SIZE,
            "used_bytes": len(payload),
            "free_bytes": RECLAIM_SIZE - len(payload),
            "heap_boundary": f"0x{HEAP_BASE:08X}",
        },
        "cursor": {
            "raw_bytes": len(raw),
            "raw_sha256": sha256_bytes(raw),
            "rle_sha256": sha256_bytes(encoded),
            "upload_rectangles": [
                [
                    v323.DEST_X_HALFWORD,
                    v323.DEST_Y + sum(chunk_heights[:index]),
                    v323.UPLOAD_WORDS_PER_ROW,
                    height,
                ]
                for index, height in enumerate(chunk_heights)
            ],
            "tpage": [15, 1],
            "uv_v_range": [191, 223],
        },
        "preserved": "COMM.IMG, all DAT, V322 text/font/E2, 5356-byte reservation and heap boundary",
        "v323_failure_avoided": "0x801A9BD8 remains zero and is never executed",
        "runtime": "PENDING user cold boot, load/menu traversal, and expanded skill-range test",
        "release_status": "DIAGNOSTIC; DO NOT DISTRIBUTE",
    }
    (ANALYSIS_DIR / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V324 TEST ONLY - static UI lookup + persistent range cursor recovery",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output_path.name}",
        f"sha256={output_hash}",
        f"delta={delta_path.name}",
        f"delta_sha256={delta_hash}",
        "changed_members=PSX.EXE only",
        f"PSX_changed_bytes={len(actual_offsets)}",
        "COMM.IMG/all_DAT=byte-identical to V322 PASS",
        "E9EA_lookup=213 safe + 2 invalid + 198 dynamic -> 413/413 safe static",
        f"live_dynamic_usage={dynamic_used_slots} slots/{dynamic_occurrences} occurrences -> 0 dynamic",
        f"fallback_blank_slots={','.join(map(str, sorted(fallback_seen)))}; occurrences=0",
        f"resident_helper=0x{HELPER_RAM:08X}/{len(helper)}B; RLE={len(encoded)}B; used={len(payload)}/{RECLAIM_SIZE}B",
        f"resident_copy={COPY_SIZE}B unchanged; heap=0x{HEAP_BASE:08X} unchanged",
        "V323_bad_cave=0x801A9BD8 remains zero",
        "upload=page15,1 U0..99,V191..223 via five synchronous LoadImage calls",
        "runtime=PENDING user cold boot/load/menu/battle; TEST_ONLY",
    ]
    (ANALYSIS_DIR / "build_report.txt").write_text(
        "\n".join(report) + "\n", encoding="utf-8"
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
