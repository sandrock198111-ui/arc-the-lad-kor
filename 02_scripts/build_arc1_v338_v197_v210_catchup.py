#!/usr/bin/env python3
"""Build V338: catch up the proven V197-V210 fixes on the V337 16px line.

This is a narrow, guarded build from V337.  It fixes only defects demonstrated
by the six V337 DUCCU states supplied on 2026-08-29, plus one wording regression
found by comparing the current data with the approved V197-V210 history:

* space all 30 remaining ``병사1/2/3`` labels without changing body length;
* restore the approved ``재정비`` spelling at all five current ``개정비`` sites;
* move the consumable quantity down one pixel rather than two;
* repair the level-up stat particle/separator/digit/suffix chain;
* translate the missed inline ``4/S4031.DAT`` sentence in its original 17B;
* give both live question-mark planes two pixels of left side bearing.

No dialogue body, terminator, E2 ownership byte, E4/E5/E6 marker, member size,
resident-copy size, or heap boundary moves.  The level-up digit converter is a
leaf helper in the proven persistent free tail 0x801FF858..0x801FF8B0; the
scene-loader/BSS cave at 0x801A9BD8 remains untouched.
"""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import build_arc1_v320_hanme_static_recovery as v320  # noqa: E402
import build_arc1_v324_static_ui_cursor_recovery as v324  # noqa: E402


BASE = ROOT / "03_output/arc1_v337_damage_remap_branch_fix_TEST_ONLY_2AB80515.zip"
BASE_SHA256 = "2AB80515D70E84F34F83A919FC63F16AFDEDA57342FAE4F40180E841DCF3E856"
OUTPUT_STEM = "arc1_v338_v197_v210_catchup_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v337"
ANALYSIS = ROOT / "01_work/analysis/arc1_v338_v197_v210_catchup"

ASSIGNMENTS = ROOT / "01_work/analysis/arc1_v320_hanme_static_recovery/character_assignments.csv"
ASSIGNMENTS_SHA256 = "933BDAC4BC4C39D33DB134D2FF836902B5053B93725C96E19DED714CB7DE98A4"
ATLAS_MAPPING = ROOT / "01_work/analysis/arc1_v319_pilgi16_integration/atlas_mapping.csv"
ATLAS_MAPPING_SHA256 = "9553E7643621CC80C23355067611EAE7650FEF7CB547DC9115B62157DB0C3122"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
RAM_TO_FILE = 0x8011A800
SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT_COUNT = 64
SLOT_META = 0x7F

BASE_MEMBER_SHA256 = {
    PSX: "AE1E4C2A6D72FBA77B6D836E4368E77DAA5D1BE777C0C8723AD57FD86B8CAAAA",
    COMM: "BDDDF442BC43926CF77A1356F9D0986B199A7A2F32745A3D47D5C1B6B654B9C3",
    "21/S2014.DAT": "026FB2EE3E344FBB6681064D6645760F14B9F6FF5709ADD6B6830C9D94ECA173",
    "21/S2022.DAT": "4ED878027132A3C89690900510661D0AF75B1BB8B414312963A0BD3F529CAF9D",
    "4/S4011.DAT": "B08110785B9982B6FD0725B484C40DE115DA7FAED377DC7F0EA3C4FF95A181F1",
    "4/S4021.DAT": "0D30FFA124778C65668C5496D14346955F12FE12BBDE80F9235C927700FBE3EC",
    "4/S4022.DAT": "1175FE26382D70046367FD7B579200DCB5B6A608B088114583BA8159230AB53C",
    "4/S4031.DAT": "D063C956E16C0327E55A19A1B707E07FA56120804C8D47A070A2A082827E708F",
}

EXPECTED_REGION_COUNT = 8595
EXPECTED_REGION_FINGERPRINT = "B5738225DEF9DAB650974520C0424E35CCB53FFC59EB403B498FF0F7E30BC764"
EXPECTED_V338_REGION_FINGERPRINT = "82A58955B8A066A12AE43D4033CB1CEBA12011A2FF55CD3A718080BEAA227BF7"

# Every old prefix is six bytes: 병 사 digit : space.  The replacement is
# 병 사 space digit : and is also six bytes.  The colon glyph lives at x=3..4
# in its 14px cell, so it already leaves nine blank columns before the body.
SOLDIER_CODES = {1: 0x4A, 2: 0x0B, 3: 0x27}
SOLDIER_EXPECTED = {1: 18, 2: 11, 3: 1}
SOLDIER_STEM = bytes.fromhex("82 34")
COLON = bytes.fromhex("DD 02")
SPACE = 0xA1

# Approved V199 wording.  physical556 is already the official Hanme '재'
# plane; its direct spelling is DE 52 and is unused in all V337 text regions.
REFIT_OLD = bytes.fromhex("DD B4 31 DD 06")  # 개정비
REFIT_NEW = bytes.fromhex("DE 52 31 DD 06")  # 재정비
REFIT_EXPECTED = 5
REFIT_PHYSICAL = 556

# Missed inline source: 一体どうしちまったんだ・・？
MISSED_MEMBER = "4/S4031.DAT"
MISSED_AT = 0x478EC
MISSED_ROOM = 17
MISSED_OLD = bytes.fromhex("8E DD 2D 54 26 1E 4B 27 29 1F 2D 35 DF 61 DF 61 3C")
MISSED_TEXT = "대체 무슨 일이야...?"
MISSED_NEW = bytes.fromhex("37 DD 90 A1 5F DD A0 A1 6B DD 01 49 21 21 21 D1 A1")

# V336 moved only this dedicated quantity path by +2.  V338 makes it +1.
QUANTITY_WORD_FILE = 0x80A40
QUANTITY_OLD_WORD = 0x24420002
QUANTITY_NEW_WORD = 0x24420001

# Level-up table: six stat labels still carry the old trailing '이' byte.
LEVEL_STAT_ENDS = (0x81A1E, 0x813E5, 0x815A3, 0x8060B, 0x80785, 0x81613)
LEVEL_STAT_POINTER_SLOTS = (0x8251C, 0x82520, 0x82524, 0x82528, 0x8252C, 0x82530)
LEVEL_PARTICLE = 0x03
LEVEL_PARTICLE_PHYSICAL = LEVEL_PARTICLE - 1
LEVEL_SEPARATOR_FILE = 0x854D4
LEVEL_SEPARATOR_OLD = bytes.fromhex("9C 00")
LEVEL_SEPARATOR_NEW = bytes.fromhex("A1 00")
LEVEL_SUFFIX_POINTER_FILE = 0x82538
LEVEL_SUFFIX_OLD_RAM = 0x8019B0A7
LEVEL_SUFFIX_NEW_FILE = 0x854F0
LEVEL_SUFFIX_NEW_RAM = LEVEL_SUFFIX_NEW_FILE + RAM_TO_FILE
LEVEL_SUFFIX_TARGET_OLD = bytes.fromhex("9C CD 8E 00")
LEVEL_SUFFIX_TARGET_NEW = bytes.fromhex("A1 8B 69 00")  # " 상승"
LEVEL_FORMAT_FILE = 0x8DAB8
LEVEL_FORMAT = b"%d\0"
LEVEL_CONVERTER_CALL_FILE = 0x45C64
LEVEL_CONVERTER_DELAY_FILE = 0x45C68
GLOBAL_CONVERTER_RAM = 0x8015E4C0
GLOBAL_CONVERTER_JAL = 0x0C057930

# V324's boot copy ends at 0x801FF8B0.  Six V337 runtime states independently
# showed this exact 88-byte tail to be all zero after the copy.
HELPER_RAM = 0x801FF858
HELPER_SOURCE_FILE = 0x8F380
HELPER_CAPACITY = 0x58
HELPER_TABLE_RAM = HELPER_RAM + 0x4C
HELPER_TABLE = bytes((0x91, 0x4A, 0x0B, 0x27, 0x57, 0x9E, 0x9F, 0x9A, 0x10, 0x08))
HELPER_ZERO_SHA256 = "10EEF285DEEF7A4B7C82B22AA53589B7833DF29DE3814649C772BBD5C832F365"
FORBIDDEN_V323_FILE = 0x8F3D8
FORBIDDEN_V323_SIZE = 0x428

# Two live spellings of '?'.  Moving ink right changes side bearing, not the
# global 14px advance or any following glyph position.
QUESTION_PLANES = (208, 222)
QUESTION_ROWS = (
    0x0000, 0x0000, 0x7C00, 0xC600, 0xC600, 0x0C00, 0x1800, 0x1800,
    0x1800, 0x0000, 0x1800, 0x1800, 0x0000, 0x0000, 0x0000, 0x0000,
)
QUESTION_SHIFT = 2
QUESTION_TOKEN_COUNTS = {bytes.fromhex("D1"): 277, bytes.fromhex("DD 03"): 507}

EXPECTED_CHANGED_MEMBERS = {
    PSX, COMM, "21/S2014.DAT", "21/S2022.DAT", "4/S4011.DAT",
    "4/S4021.DAT", "4/S4022.DAT", "4/S4031.DAT",
}


class BuildError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def word_at(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def aligned_pointer_refs(data: bytes | bytearray, address: int) -> list[int]:
    return [
        offset for offset in range(0, len(data) - 3, 4)
        if word_at(data, offset) == address
    ]


def i_type(op: int, rs: int, rt: int, immediate: int) -> int:
    return (op << 26) | (rs << 21) | (rt << 16) | (immediate & 0xFFFF)


def r_type(rs: int, rt: int, rd: int, shift: int, function: int) -> int:
    return (rs << 21) | (rt << 16) | (rd << 11) | (shift << 6) | function


def jal(address: int) -> int:
    return 0x0C000000 | ((address >> 2) & 0x03FFFFFF)


@dataclass
class BranchFixup:
    index: int
    op: int
    rs: int
    rt: int
    label: str


class Assembler:
    def __init__(self, address: int) -> None:
        self.address = address
        self.words: list[int] = []
        self.labels: dict[str, int] = {}
        self.fixups: list[BranchFixup] = []

    def emit(self, value: int) -> None:
        self.words.append(value & 0xFFFFFFFF)

    def label(self, name: str) -> None:
        if name in self.labels:
            raise BuildError(f"duplicate assembler label: {name}")
        self.labels[name] = len(self.words)

    def branch(self, op: int, rs: int, rt: int, label: str) -> None:
        self.fixups.append(BranchFixup(len(self.words), op, rs, rt, label))
        self.emit(0)

    def finish(self) -> bytes:
        result = list(self.words)
        for fixup in self.fixups:
            if fixup.label not in self.labels:
                raise BuildError(f"undefined assembler label: {fixup.label}")
            pc = self.address + fixup.index * 4
            target = self.address + self.labels[fixup.label] * 4
            delta = (target - (pc + 4)) // 4
            if not -0x8000 <= delta <= 0x7FFF:
                raise BuildError(f"helper branch out of range: {fixup.label}")
            result[fixup.index] = i_type(fixup.op, fixup.rs, fixup.rt, delta)
        return struct.pack(f"<{len(result)}I", *result)


def build_level_digit_helper() -> tuple[bytes, list[int]]:
    zero, v0, v1, a0, t0, t1, ra = 0, 2, 3, 4, 8, 9, 31
    asm = Assembler(HELPER_RAM)
    asm.label("loop")
    asm.emit(i_type(0x24, a0, v0, 0))                 # lbu v0,0(a0)
    asm.emit(i_type(0x0F, zero, t1, 0x8020))          # load-delay filler
    asm.branch(0x04, v0, zero, "done")               # beqz v0,done
    asm.emit(i_type(0x09, v0, v1, -0x30))             # delay: raw-'0'
    asm.emit(i_type(0x0B, v1, t0, 10))                # sltiu t0,v1,10
    asm.branch(0x04, t0, zero, "fallback")           # beqz t0,fallback
    asm.emit(i_type(0x09, t1, t1, HELPER_TABLE_RAM & 0xFFFF))
    asm.emit(r_type(t1, v1, t1, 0, 0x21))             # addu t1,t1,v1
    asm.emit(i_type(0x24, t1, v0, 0))                 # lbu v0,0(t1)
    asm.emit(0)                                        # R3000 load delay
    asm.label("store")
    asm.emit(i_type(0x28, a0, v0, 0))                 # sb v0,0(a0)
    asm.emit(i_type(0x09, a0, a0, 1))                 # addiu a0,a0,1
    asm.branch(0x04, zero, zero, "loop")
    asm.emit(0)
    asm.label("fallback")
    asm.emit(i_type(0x09, v0, v0, 0xE1))              # stock converter
    asm.branch(0x04, zero, zero, "store")
    asm.emit(0)
    asm.label("done")
    asm.emit(r_type(ra, zero, zero, 0, 0x08))          # jr ra
    asm.emit(0)
    code = asm.finish()
    words = list(struct.unpack(f"<{len(code) // 4}I", code))
    payload = code + HELPER_TABLE
    if len(code) != 0x4C or len(payload) != 0x56:
        raise BuildError(f"level helper size drift: code={len(code)} payload={len(payload)}")
    return payload + bytes(HELPER_CAPACITY - len(payload)), words


def simulate_level_helper(raw: bytes) -> bytes:
    output = bytearray()
    for value in raw:
        if value == 0:
            break
        if 0x30 <= value <= 0x39:
            output.append(HELPER_TABLE[value - 0x30])
        else:
            output.append((value + 0xE1) & 0xFF)
    return bytes(output)


def iter_tokens(data: bytes, start: int, end: int):
    cursor = start
    while cursor < end:
        value = data[cursor]
        if value == 0:
            return
        if 0x01 <= value <= 0xDC:
            token = bytes((value,))
            width = 1
        elif cursor + 1 < end:
            token = data[cursor:cursor + 2]
            width = 2
        else:
            token = bytes((value,))
            width = 1
        yield cursor, token
        cursor += width


def token_counts(members: dict[str, bytes], regions: list[tuple[str, int, int]]) -> Counter[bytes]:
    result: Counter[bytes] = Counter()
    for name, start, end in regions:
        for _offset, token in iter_tokens(members[name], start, end):
            result[token] += 1
    return result


def marker_positions(data: bytes, start: int, end: int) -> tuple[tuple[int, int, int], ...]:
    return tuple(
        (offset - start, token[0], token[1])
        for offset, token in iter_tokens(data, start, end)
        if len(token) == 2 and 0xE1 <= token[0] <= 0xE8
    )


def changed_offsets(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise BuildError("member size changed")
    return {
        offset
        for offset, (old, new) in enumerate(zip(before, after, strict=True))
        if old != new
    }


def read_atlas_row(index: int) -> dict[str, str]:
    with ATLAS_MAPPING.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if index >= len(rows) or int(rows[index]["index"]) != index:
        raise BuildError(f"atlas row {index} missing")
    return rows[index]


def scan_direct_targets(exe: bytes, lo: int, hi: int) -> list[tuple[int, int, str]]:
    text_size = struct.unpack_from("<I", exe, 0x1C)[0]
    result: list[tuple[int, int, str]] = []
    for offset in range(0x800, min(len(exe), 0x800 + text_size), 4):
        instruction = word_at(exe, offset)
        op = instruction >> 26
        pc = offset + RAM_TO_FILE
        target = None
        kind = ""
        if op in (0x02, 0x03):
            target = ((pc + 4) & 0xF0000000) | ((instruction & 0x03FFFFFF) << 2)
            kind = "jal" if op == 0x03 else "j"
        elif op in (0x04, 0x05, 0x06, 0x07):
            immediate = instruction & 0xFFFF
            if immediate & 0x8000:
                immediate -= 0x10000
            target = (pc + 4 + immediate * 4) & 0xFFFFFFFF
            kind = "branch"
        if target is not None and lo <= target < hi:
            result.append((pc, target, kind))
    return result


def assert_base(members: dict[str, bytes]) -> list[tuple[str, int, int]]:
    if len(members) != 164:
        raise BuildError(f"V337 member count drift: {len(members)}")
    for name, expected in BASE_MEMBER_SHA256.items():
        if name not in members or sha256_bytes(members[name]) != expected:
            raise BuildError(f"V337 member hash drift: {name}")
    if sha256_bytes(ASSIGNMENTS.read_bytes()) != ASSIGNMENTS_SHA256:
        raise BuildError("character assignment table hash drift")
    if sha256_bytes(ATLAS_MAPPING.read_bytes()) != ATLAS_MAPPING_SHA256:
        raise BuildError("atlas mapping hash drift")

    regions = list(v320.text_regions(members))
    if len(regions) != EXPECTED_REGION_COUNT:
        raise BuildError(f"V337 region count drift: {len(regions)}")
    if v320.region_fingerprint(regions) != EXPECTED_REGION_FINGERPRINT:
        raise BuildError("V337 region fingerprint drift")

    exe = members[PSX]
    if word_at(exe, QUANTITY_WORD_FILE) != QUANTITY_OLD_WORD:
        raise BuildError("V337 quantity +2 premise drift")
    if word_at(exe, LEVEL_CONVERTER_CALL_FILE) != GLOBAL_CONVERTER_JAL:
        raise BuildError("level-up converter call drift")
    if word_at(exe, LEVEL_CONVERTER_DELAY_FILE) != 0:
        raise BuildError("level-up converter delay slot is not NOP")
    if exe[LEVEL_FORMAT_FILE:LEVEL_FORMAT_FILE + len(LEVEL_FORMAT)] != LEVEL_FORMAT:
        raise BuildError("level-up format string drift")
    if sha256_bytes(exe[HELPER_SOURCE_FILE:HELPER_SOURCE_FILE + HELPER_CAPACITY]) != HELPER_ZERO_SHA256:
        raise BuildError("persistent free-tail source is not the proven 88-byte zero range")
    if any(exe[FORBIDDEN_V323_FILE:FORBIDDEN_V323_FILE + FORBIDDEN_V323_SIZE]):
        raise BuildError("forbidden V323 scene-loader/BSS cave is no longer zero")
    if scan_direct_targets(exe, HELPER_RAM, HELPER_RAM + HELPER_CAPACITY):
        raise BuildError("V337 already has control flow into the proposed resident helper")
    pointer_hits = [
        offset for offset in range(0, len(exe) - 3, 4)
        if HELPER_RAM <= word_at(exe, offset) < HELPER_RAM + HELPER_CAPACITY
    ]
    if pointer_hits:
        raise BuildError(f"V337 already points into resident helper tail: {pointer_hits[:4]}")

    particle_identity = read_atlas_row(LEVEL_PARTICLE_PHYSICAL)
    if particle_identity["unicode"] != "U+C774" or particle_identity["char"] != "이":
        raise BuildError("direct code 03 no longer decodes to the level-up particle 이")
    for slot, offset in zip(LEVEL_STAT_POINTER_SLOTS, LEVEL_STAT_ENDS, strict=True):
        if exe[offset:offset + 2] != bytes((LEVEL_PARTICLE, 0)):
            raise BuildError(f"level stat particle anchor drift at 0x{offset:X}")
        ram = word_at(exe, slot)
        start = ram - RAM_TO_FILE
        if not 0 <= start < offset or exe.index(0, start) != offset + 1:
            raise BuildError(f"level stat pointer/string boundary drift at 0x{slot:X}")
        if aligned_pointer_refs(exe, ram) != [slot]:
            raise BuildError(f"level stat string reference ownership drift at 0x{slot:X}")
    if exe[LEVEL_SEPARATOR_FILE:LEVEL_SEPARATOR_FILE + 2] != LEVEL_SEPARATOR_OLD:
        raise BuildError("level separator anchor drift")
    if struct.unpack_from("<I", exe, LEVEL_SUFFIX_POINTER_FILE)[0] != LEVEL_SUFFIX_OLD_RAM:
        raise BuildError("level suffix pointer drift")
    if aligned_pointer_refs(exe, LEVEL_SUFFIX_OLD_RAM) != [LEVEL_SUFFIX_POINTER_FILE]:
        raise BuildError("old level suffix reference ownership drift")
    if aligned_pointer_refs(exe, LEVEL_SUFFIX_NEW_RAM):
        raise BuildError("new level suffix target was already referenced")
    if exe[LEVEL_SUFFIX_NEW_FILE:LEVEL_SUFFIX_NEW_FILE + 4] != LEVEL_SUFFIX_TARGET_OLD:
        raise BuildError("level suffix target anchor drift")
    if exe[LEVEL_SUFFIX_OLD_RAM - RAM_TO_FILE:LEVEL_SUFFIX_OLD_RAM - RAM_TO_FILE + 3] != bytes.fromhex("8B 69 00"):
        raise BuildError("old level suffix text drift")
    old_calls = [
        offset for offset in range(0x800, len(exe) - 3, 4)
        if word_at(exe, offset) == GLOBAL_CONVERTER_JAL
    ]
    if old_calls != [0x45C64, 0x4EF74, 0x51520]:
        raise BuildError(f"global converter caller census drift: {old_calls}")

    comm = members[COMM]
    for index in QUESTION_PLANES:
        if v320.read_plane(comm, index) != QUESTION_ROWS:
            raise BuildError(f"question plane {index} drift")
    atlas_re = read_atlas_row(REFIT_PHYSICAL)
    if atlas_re["char"] != "재" or atlas_re["unicode"] != "U+C7AC":
        raise BuildError("physical556 no longer owns 재")
    if not any(v320.read_plane(comm, REFIT_PHYSICAL)):
        raise BuildError("physical556 재 plane is blank")

    if members[MISSED_MEMBER][MISSED_AT:MISSED_AT + MISSED_ROOM] != MISSED_OLD:
        raise BuildError("missed S4031 source anchor drift")
    if members[MISSED_MEMBER][MISSED_AT + MISSED_ROOM] != 0:
        raise BuildError("missed S4031 terminator drift")

    counts = token_counts(members, regions)
    if {token: counts[token] for token in QUESTION_TOKEN_COUNTS} != QUESTION_TOKEN_COUNTS:
        raise BuildError("question token census drift")
    if counts[REFIT_NEW[:2]] != 0:
        raise BuildError("DE52 was already used before V338")
    return regions


def patch_soldiers(
    members: dict[str, bytes], regions: list[tuple[str, int, int]]
) -> tuple[list[dict[str, object]], dict[str, set[int]]]:
    mutable: dict[str, bytearray] = {}
    rows: list[dict[str, object]] = []
    expected: dict[str, set[int]] = {}
    seen = Counter()

    for name, start, end in regions:
        body = members[name][start:end]
        for digit, code in SOLDIER_CODES.items():
            old = SOLDIER_STEM + bytes((code,)) + COLON + bytes((SPACE,))
            if old not in body:
                continue
            if body.count(old) != 1 or body.index(old) != 0:
                raise BuildError(f"ambiguous soldier prefix at {name}:0x{start:X}")
            new = SOLDIER_STEM + bytes((SPACE, code)) + COLON
            if len(new) != len(old):
                raise BuildError("soldier prefix length changed")
            data = mutable.setdefault(name, bytearray(members[name]))
            before_meta = None
            if SLOT_BASE <= start < SLOT_BASE + SLOT_COUNT * SLOT_SIZE and (start - SLOT_BASE) % SLOT_SIZE == 0:
                meta_at = start + SLOT_META
                before_meta = data[meta_at]
            for delta, (was, now) in enumerate(zip(old, new, strict=True)):
                if was != now:
                    expected.setdefault(name, set()).add(start + delta)
            data[start:start + len(old)] = new
            if before_meta is not None and data[start + SLOT_META] != before_meta:
                raise BuildError("soldier slot completion metadata changed")
            seen[digit] += 1
            rows.append({
                "member": name,
                "start": f"0x{start:X}",
                "storage": "slot" if before_meta is not None else "inline",
                "digit": digit,
                "before_hex": old.hex(" ").upper(),
                "after_hex": new.hex(" ").upper(),
                "slot_meta": "" if before_meta is None else before_meta,
                "body_length": end - start,
            })
    if dict(seen) != SOLDIER_EXPECTED:
        raise BuildError(f"soldier prefix census drift: {dict(seen)}")
    for name, data in mutable.items():
        members[name] = bytes(data)
    return rows, expected


def patch_refit_wording(
    members: dict[str, bytes], regions: list[tuple[str, int, int]]
) -> tuple[list[dict[str, object]], dict[str, set[int]]]:
    mutable: dict[str, bytearray] = {}
    rows: list[dict[str, object]] = []
    expected: dict[str, set[int]] = {}
    hits = 0
    for name, start, end in regions:
        body = members[name][start:end]
        cursor = 0
        while True:
            relative = body.find(REFIT_OLD, cursor)
            if relative < 0:
                break
            at = start + relative
            data = mutable.setdefault(name, bytearray(members[name]))
            for delta, (was, now) in enumerate(zip(REFIT_OLD, REFIT_NEW, strict=True)):
                if was != now:
                    expected.setdefault(name, set()).add(at + delta)
            data[at:at + len(REFIT_OLD)] = REFIT_NEW
            rows.append({
                "member": name,
                "region_start": f"0x{start:X}",
                "at": f"0x{at:X}",
                "before": "개정비",
                "after": "재정비",
                "bytes": len(REFIT_OLD),
            })
            hits += 1
            cursor = relative + len(REFIT_OLD)
    if hits != REFIT_EXPECTED:
        raise BuildError(f"개정비 occurrence census drift: {hits}")
    for name, data in mutable.items():
        members[name] = bytes(data)
    return rows, expected


def merge_expected(target: dict[str, set[int]], source: dict[str, set[int]]) -> None:
    for name, offsets in source.items():
        target.setdefault(name, set()).update(offsets)


def build_once(before: dict[str, bytes]) -> tuple[dict[str, bytes], dict[str, object]]:
    regions = assert_base(before)
    final = dict(before)
    expected: dict[str, set[int]] = {}

    soldier_rows, soldier_expected = patch_soldiers(final, regions)
    merge_expected(expected, soldier_expected)
    refit_rows, refit_expected = patch_refit_wording(final, regions)
    merge_expected(expected, refit_expected)

    # Fixed-length missed inline translation.
    missed = bytearray(final[MISSED_MEMBER])
    old_markers = marker_positions(bytes(missed), MISSED_AT, MISSED_AT + MISSED_ROOM)
    if len(MISSED_NEW) != MISSED_ROOM or 0 in MISSED_NEW:
        raise BuildError("missed translation no longer fits its fixed room")
    for delta, (was, now) in enumerate(zip(MISSED_OLD, MISSED_NEW, strict=True)):
        if was != now:
            expected.setdefault(MISSED_MEMBER, set()).add(MISSED_AT + delta)
    missed[MISSED_AT:MISSED_AT + MISSED_ROOM] = MISSED_NEW
    if missed[MISSED_AT + MISSED_ROOM] != 0:
        raise BuildError("missed translation moved its terminator")
    if marker_positions(bytes(missed), MISSED_AT, MISSED_AT + MISSED_ROOM) != old_markers:
        raise BuildError("missed translation changed control markers")
    final[MISSED_MEMBER] = bytes(missed)

    # Question side bearing, preserving sibling planes and total ink.
    comm = bytearray(final[COMM])
    if any(row & ((1 << QUESTION_SHIFT) - 1) for row in QUESTION_ROWS):
        raise BuildError("question shift would discard right-edge ink")
    question_after = tuple(row >> QUESTION_SHIFT for row in QUESTION_ROWS)
    if sum(row.bit_count() for row in question_after) != sum(row.bit_count() for row in QUESTION_ROWS):
        raise BuildError("question shift clipped ink")
    before_comm = bytes(comm)
    sibling_before = {
        index: v320.read_plane(comm, index)
        for owner in QUESTION_PLANES
        for index in range((owner // 4) * 4, (owner // 4) * 4 + 4)
        if index not in QUESTION_PLANES
    }
    for index in QUESTION_PLANES:
        v320.put_plane(comm, index, question_after)
    for index, rows in sibling_before.items():
        if v320.read_plane(comm, index) != rows:
            raise BuildError(f"question sibling plane {index} changed")
    final[COMM] = bytes(comm)
    expected[COMM] = changed_offsets(before_comm, final[COMM])

    # Level-up chain and quantity geometry.
    exe = bytearray(final[PSX])
    for offset in LEVEL_STAT_ENDS:
        exe[offset] = 0
    exe[LEVEL_SEPARATOR_FILE:LEVEL_SEPARATOR_FILE + 2] = LEVEL_SEPARATOR_NEW
    exe[LEVEL_SUFFIX_NEW_FILE:LEVEL_SUFFIX_NEW_FILE + 4] = LEVEL_SUFFIX_TARGET_NEW
    struct.pack_into("<I", exe, LEVEL_SUFFIX_POINTER_FILE, LEVEL_SUFFIX_NEW_RAM)
    struct.pack_into("<I", exe, QUANTITY_WORD_FILE, QUANTITY_NEW_WORD)
    helper, helper_words = build_level_digit_helper()
    exe[HELPER_SOURCE_FILE:HELPER_SOURCE_FILE + HELPER_CAPACITY] = helper
    struct.pack_into("<I", exe, LEVEL_CONVERTER_CALL_FILE, jal(HELPER_RAM))
    if word_at(exe, LEVEL_CONVERTER_DELAY_FILE) != 0:
        raise BuildError("level helper call delay slot changed")
    final[PSX] = bytes(exe)

    psx_allowed = (
        set(range(LEVEL_CONVERTER_CALL_FILE, LEVEL_CONVERTER_CALL_FILE + 4))
        | set(range(QUANTITY_WORD_FILE, QUANTITY_WORD_FILE + 4))
        | set(LEVEL_STAT_ENDS)
        | set(range(LEVEL_SEPARATOR_FILE, LEVEL_SEPARATOR_FILE + 2))
        | set(range(LEVEL_SUFFIX_POINTER_FILE, LEVEL_SUFFIX_POINTER_FILE + 4))
        | set(range(LEVEL_SUFFIX_NEW_FILE, LEVEL_SUFFIX_NEW_FILE + 4))
        | set(range(HELPER_SOURCE_FILE, HELPER_SOURCE_FILE + HELPER_CAPACITY))
    )
    expected[PSX] = changed_offsets(before[PSX], final[PSX])
    if not expected[PSX] <= psx_allowed:
        raise BuildError(f"PSX Expected-Write escape: {sorted(expected[PSX] - psx_allowed)[:8]}")

    # Semantic/readback guards.
    after_regions = list(v320.text_regions(final))
    expected_after_regions = [
        (name, start, end - 1 if name == PSX and end - 1 in LEVEL_STAT_ENDS else end)
        for name, start, end in regions
    ]
    if (
        len(after_regions) != EXPECTED_REGION_COUNT
        or after_regions != expected_after_regions
        or v320.region_fingerprint(after_regions) != EXPECTED_V338_REGION_FINGERPRINT
    ):
        raise BuildError("text region topology changed outside the six approved level-stat suffix removals")
    for (bn, bs, be), (an, ass, ae) in zip(regions, after_regions, strict=True):
        if marker_positions(before[bn], bs, be) != marker_positions(final[an], ass, ae):
            raise BuildError(f"control-marker topology changed at {bn}:0x{bs:X}")

    for digit, code in SOLDIER_CODES.items():
        old = SOLDIER_STEM + bytes((code,)) + COLON + bytes((SPACE,))
        new = SOLDIER_STEM + bytes((SPACE, code)) + COLON
        old_count = sum(final[name][start:end].count(old) for name, start, end in after_regions)
        new_count = sum(final[name][start:end].count(new) for name, start, end in after_regions)
        expected_new_count = SOLDIER_EXPECTED[digit] + (1 if digit == 2 else 0)
        if old_count or new_count != expected_new_count:
            raise BuildError(f"soldier {digit} readback mismatch: old={old_count} new={new_count}")
    preserved_spaced_two = SOLDIER_STEM + bytes((SPACE, SOLDIER_CODES[2])) + COLON + bytes((SPACE,))
    if sum(final[name][start:end].count(preserved_spaced_two) for name, start, end in after_regions) != 1:
        raise BuildError("pre-existing 병사 2 slot changed")

    if sum(final[name][start:end].count(REFIT_OLD) for name, start, end in after_regions):
        raise BuildError("개정비 remains after catch-up")
    if sum(final[name][start:end].count(REFIT_NEW) for name, start, end in after_regions) != REFIT_EXPECTED:
        raise BuildError("재정비 readback count mismatch")
    if final[MISSED_MEMBER][MISSED_AT:MISSED_AT + MISSED_ROOM] != MISSED_NEW:
        raise BuildError("missed translation readback mismatch")

    if v320.read_plane(final[COMM], QUESTION_PLANES[0]) != question_after or v320.read_plane(final[COMM], QUESTION_PLANES[1]) != question_after:
        raise BuildError("question plane readback mismatch")
    if word_at(final[PSX], QUANTITY_WORD_FILE) != QUANTITY_NEW_WORD:
        raise BuildError("quantity +1 readback mismatch")
    if word_at(final[PSX], LEVEL_CONVERTER_CALL_FILE) != jal(HELPER_RAM):
        raise BuildError("level helper call readback mismatch")
    if aligned_pointer_refs(final[PSX], LEVEL_SUFFIX_NEW_RAM) != [LEVEL_SUFFIX_POINTER_FILE]:
        raise BuildError("new level suffix reference ownership mismatch")
    if aligned_pointer_refs(final[PSX], LEVEL_SUFFIX_OLD_RAM):
        raise BuildError("old level suffix remains referenced")
    if final[PSX][HELPER_SOURCE_FILE:HELPER_SOURCE_FILE + HELPER_CAPACITY] != helper:
        raise BuildError("level helper payload readback mismatch")
    if any(final[PSX][FORBIDDEN_V323_FILE:FORBIDDEN_V323_FILE + FORBIDDEN_V323_SIZE]):
        raise BuildError("forbidden V323 cave was modified")
    targets = scan_direct_targets(final[PSX], HELPER_RAM, HELPER_RAM + HELPER_CAPACITY)
    if targets != [(LEVEL_CONVERTER_CALL_FILE + RAM_TO_FILE, HELPER_RAM, "jal")]:
        raise BuildError(f"resident helper inbound control-flow mismatch: {targets}")
    if sum(
        word_at(final[PSX], offset) == GLOBAL_CONVERTER_JAL
        for offset in range(0x800, len(final[PSX]) - 3, 4)
    ) != 2:
        raise BuildError("unrelated global converter callers changed")
    for digit in range(10):
        if simulate_level_helper(bytes((0x30 + digit, 0))) != bytes((HELPER_TABLE[digit],)):
            raise BuildError(f"level helper digit simulation failed: {digit}")
    for value in range(1, 256):
        expected_value = HELPER_TABLE[value - 0x30] if 0x30 <= value <= 0x39 else (value + 0xE1) & 0xFF
        if simulate_level_helper(bytes((value, 0))) != bytes((expected_value,)):
            raise BuildError(f"level helper exhaustive simulation failed: 0x{value:02X}")

    actual_by_member = {
        name: changed_offsets(before[name], final[name])
        for name in before if before[name] != final[name]
    }
    if set(actual_by_member) != EXPECTED_CHANGED_MEMBERS:
        raise BuildError(f"changed member set drift: {sorted(actual_by_member)}")
    for name, actual in actual_by_member.items():
        if actual != expected.get(name, set()):
            raise BuildError(
                f"Expected-Write mismatch for {name}: "
                f"actual-only={sorted(actual - expected.get(name, set()))[:8]} "
                f"expected-only={sorted(expected.get(name, set()) - actual)[:8]}"
            )
    if any(len(before[name]) != len(final[name]) for name in before):
        raise BuildError("archive member length changed")

    metadata = {
        "changed_members": [name for name in before if name in actual_by_member],
        "changed_bytes": {name: len(offsets) for name, offsets in actual_by_member.items()},
        "expected_offsets": {name: sorted(offsets) for name, offsets in expected.items()},
        "soldier_rows": soldier_rows,
        "refit_rows": refit_rows,
        "helper_words": helper_words,
        "question_after": list(question_after),
        "level_helper_sha256": sha256_bytes(helper),
        "level_helper_payload_bytes": 0x56,
        "level_helper_capacity": HELPER_CAPACITY,
    }
    return final, metadata


def write_analysis(
    before: dict[str, bytes], final: dict[str, bytes], metadata: dict[str, object],
    output_path: Path, output_hash: str, delta_path: Path, delta_hash: str,
) -> None:
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    expected_offsets = metadata["expected_offsets"]
    with (ANALYSIS / "expected_writes.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("member", "offset", "before", "after", "purpose"))
        for name in before:
            for offset in expected_offsets.get(name, []):
                if name == PSX and HELPER_SOURCE_FILE <= offset < HELPER_SOURCE_FILE + HELPER_CAPACITY:
                    purpose = "resident level-up digit converter"
                elif name == PSX:
                    purpose = "level-up chain or consumable quantity Y"
                elif name == COMM:
                    purpose = "question-mark 2px side bearing"
                elif name == MISSED_MEMBER and MISSED_AT <= offset < MISSED_AT + MISSED_ROOM:
                    purpose = "missed S4031 inline translation"
                else:
                    purpose = "fixed-length soldier/wording catch-up"
                writer.writerow((
                    name, f"0x{offset:X}", f"{before[name][offset]:02X}",
                    f"{final[name][offset]:02X}", purpose,
                ))

    with (ANALYSIS / "soldier_label_repairs.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        fields = ("member", "start", "storage", "digit", "before_hex", "after_hex", "slot_meta", "body_length")
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(metadata["soldier_rows"])
    with (ANALYSIS / "refit_wording_repairs.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        fields = ("member", "region_start", "at", "before", "after", "bytes")
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(metadata["refit_rows"])

    with (ANALYSIS / "levelup_helper_words.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("index", "resident_address", "source_file_offset", "word"))
        for index, value in enumerate(metadata["helper_words"]):
            writer.writerow((index, f"0x{HELPER_RAM + index * 4:08X}", f"0x{HELPER_SOURCE_FILE + index * 4:X}", f"0x{value:08X}"))

    catchup_rows = (
        ("V195-V196", "level-up labels/suffix", "REGRESSED", "V338", "remove six trailing 이; blank separator; dedicated digit converter; leading-space 상승"),
        ("V197", "choice prompt width", "PRESERVED", "none", "V337 bytes/control topology preserved"),
        ("V198", "relocate overlong inline text to E2 slot", "REJECTED", "none", "historical infinite repeat; V338 never relocates a body"),
        ("V199", "jail wording and fixed body topology", "PARTIAL REGRESSION", "V338", "five 개정비 spellings restored to approved 재정비 with equal-width DE52"),
        ("V200", "jail wording", "PRESENT/LATER EQUIVALENT", "none", "approved lines retained; no blind rollback of later wording"),
        ("V201", "팔렌시아 spelling", "PRESENT", "none", "current corpus uses approved spelling"),
        ("V202-V204", "warehouse missed line and split", "PRESENT", "none", "V336 already restored 잠깐, 뭔가 / 이상해 with E6 fixed"),
        ("V203", "두목 / 세상의 미래", "PRESENT", "none", "current text readback matches approved semantics"),
        ("V205-V206", "zeroed structural script bytes", "PRESENT", "none", "1,539 historical restored offsets audited; V337 has zero regressions at those offsets"),
        ("V207", "skill strings moved away from code", "PRESENT", "none", "V337 skill tables/wrappers remain live; forbidden code cave not reused"),
        ("V208-V210", "D/SD031 translation, slots, final controls", "PRESENT", "none", "E2 owners and E4 1F/E4 3D/E6 topology retained"),
        ("new runtime", "4/S4031 missed inline line", "MISSING", "V338", MISSED_TEXT),
    )
    with (ANALYSIS / "v197_v210_catchup_audit.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("version", "item", "v337_status", "v338_action", "evidence"))
        writer.writerows(catchup_rows)

    runtime_rows = (
        (1, "병사2 attached", "space every remaining soldier label"),
        (2, "병사3 attached", "space every remaining soldier label"),
        (3, "quantity Y +2 looks low", "change dedicated helper to +1"),
        (4, "최대 체력이)어상승", "repair particle/separator/digit/suffix chain"),
        (5, "garbled untranslated S4031 line", MISSED_TEXT),
        (6, "question mark too close", "shift both live ? bitmaps right 2px"),
    )
    with (ANALYSIS / "v337_runtime_defect_map.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("state", "observed", "v338_fix"))
        writer.writerows(runtime_rows)

    manifest = {
        "build": "V338 TEST_ONLY V197-V210 catch-up + V337 runtime fixes",
        "base": {"path": str(BASE), "sha256": BASE_SHA256},
        "output": {"path": str(output_path), "sha256": output_hash},
        "delta": {"path": str(delta_path), "sha256": delta_hash},
        "changed_members": metadata["changed_members"],
        "changed_bytes": metadata["changed_bytes"],
        "soldier_labels": {"repaired": 30, "preexisting_spaced_preserved": 1, "terminators_moved": 0},
        "wording": {"개정비_to_재정비": 5, "missed_inline": MISSED_TEXT, "inline_room": MISSED_ROOM},
        "quantity_y": {"v337": 2, "v338": 1, "scope": "dedicated consumable quantity path"},
        "question": {"planes": list(QUESTION_PLANES), "shift_right_px": QUESTION_SHIFT, "advance_changed": False},
        "level_up": {
            "particles_removed": len(LEVEL_STAT_ENDS),
            "separator": "half-width blank",
            "suffix": " leading-space 상승",
            "helper_resident": f"0x{HELPER_RAM:08X}",
            "helper_source_file": f"0x{HELPER_SOURCE_FILE:X}",
            "helper_sha256": metadata["level_helper_sha256"],
            "persistent_free_runtime_evidence": "six V337 states: 88B all zero, SHA256 10EEF285...F365",
            "forbidden_scene_loader_cave": "0x801A9BD8 remains zero and unreachable",
        },
        "preserved": (
            "all member sizes; all text region starts/ends and E2/E4/E5/E6 topology; "
            "V337 renderer/UI/choice/cursor/item/skill/damage fixes; resident copy size and heap boundary"
        ),
        "runtime": "PENDING user cold boot and six-scene replay",
        "release_status": "TEST ONLY; DO NOT DISTRIBUTE",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = (
        "V338 TEST ONLY - V197-V210 catch-up + V337 runtime fixes\n"
        f"base={BASE.name}\noutput={output_path.name}\nsha256={output_hash}\n"
        f"delta={delta_path.name}\ndelta_sha256={delta_hash}\n"
        f"changed_members={','.join(metadata['changed_members'])}\n"
        f"changed_bytes={json.dumps(metadata['changed_bytes'], ensure_ascii=False, sort_keys=True)}\n"
        "soldier_labels=30 fixed length; preexisting 병사 2 preserved; terminators/controls unchanged\n"
        "V199_wording=개정비 5 -> 재정비 5 using existing physical556\n"
        f"S4031={MISSED_TEXT}; 17B fixed room and terminator preserved\n"
        "quantity_y=+2 -> +1 dedicated path\n"
        "question=physical208/222 bitmap right 2px; global advance unchanged\n"
        f"level_helper=0x{HELPER_RAM:08X}, source file 0x{HELPER_SOURCE_FILE:X}, 86/88B\n"
        "runtime=PENDING; TEST_ONLY\n"
    )
    (ANALYSIS / "build_report.txt").write_text(report, encoding="utf-8")
    checklist = (
        "V338 cold-boot checklist\n\n"
        "- Start V338.cue from power-off; do not load an old emulator save state.\n"
        "- Replay the supplied six scenes. Confirm every 병사 1/2/3 label has a gap.\n"
        "- Confirm item quantity is one pixel below the V335/V337 baseline, not two.\n"
        "- Trigger level-up: expect '최대 체력 3 상승' style output, including multi-digit values.\n"
        f"- Confirm the missed line reads '{MISSED_TEXT}'.\n"
        "- Confirm every '?' has visible left side bearing and normal following spacing.\n"
        "- Recheck choices, warehouse, D/SD031 Gogen scene, skill/item names, icons, damage digits, world map.\n"
        "- Report any freeze/repeat immediately; no V338 body or terminator should have moved.\n"
    )
    (ANALYSIS / "runtime_checklist.txt").write_text(checklist, encoding="utf-8")


def main() -> None:
    if not BASE.is_file() or v324.sha256_file(BASE) != BASE_SHA256:
        raise BuildError(f"V337 base hash mismatch: {BASE}")
    infos, before = v324.read_archive(BASE)
    final, metadata = build_once(before)
    rebuilt, rebuilt_metadata = build_once(before)
    if final != rebuilt or metadata != rebuilt_metadata:
        raise BuildError("in-memory deterministic rebuild mismatch")

    output_path, output_hash = v324.write_archive(OUTPUT_STEM, infos, final, None)
    delta_path, delta_hash = v324.write_archive(
        DELTA_STEM, infos, final, set(metadata["changed_members"])
    )
    with ZipFile(output_path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        expected_names = [item.filename for item in infos if not item.is_dir()]
        if names != expected_names or any(archive.read(name) != final[name] for name in final):
            raise BuildError("full ZIP round-trip/topology mismatch")
    with ZipFile(delta_path) as archive:
        expected_delta = [name for name in final if name in set(metadata["changed_members"])]
        if archive.namelist() != expected_delta:
            raise BuildError("delta ZIP topology mismatch")
        if any(archive.read(name) != final[name] for name in expected_delta):
            raise BuildError("delta ZIP payload mismatch")

    write_analysis(before, final, metadata, output_path, output_hash, delta_path, delta_hash)
    print(f"V338 full ZIP: {output_path}")
    print(f"V338 full SHA256: {output_hash}")
    print(f"V338 delta ZIP: {delta_path}")
    print(f"V338 delta SHA256: {delta_hash}")
    print(f"changed members: {metadata['changed_members']}")
    print(f"changed bytes: {metadata['changed_bytes']}")


if __name__ == "__main__":
    main()
