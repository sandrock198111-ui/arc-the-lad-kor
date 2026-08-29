#!/usr/bin/env python3
"""Build V339: center the 16px UI text and size name bars by real width.

V339 is a narrow TEST_ONLY successor to V338.  It changes PSX.EXE and
COMM.IMG only:

* compact the equipment description so the final ``복`` stays on line one;
* restore the concise equipment name ``모조상``;
* replace the shared 12*N+15 name-window formula with the real
  14px-glyph/6px-space width, for equipment, consumables, and skills;
* move those names up one pixel while preserving the already-correct
  equipment quantity Y and the consumable name/quantity one-pixel offset;
* move bottom battle help, item/skill acquisition, and level-up notices up 1px;
* restore the original corner-bracket art on two proven blank 16px planes and
  repoint the item/skill acquisition strings to bracketed payloads;
* restore the accepted battle-help wording ``링 열기`` without flattening E7
  controller-button tokens.

No DAT member, member size, dialogue body, control marker, renderer advance,
or frame geometry changes.  The width helper is a leaf in the proven loaded
zero cave 0x8019D0C8..0x8019D138; the protected pointer word at file 0x82938
and the forbidden scene-loader/BSS cave remain untouched.
"""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import build_arc1_johab_font_poc as old12  # noqa: E402
import build_arc1_v320_hanme_static_recovery as v320  # noqa: E402
import build_arc1_v324_static_ui_cursor_recovery as v324  # noqa: E402


BASE = ROOT / "03_output/arc1_v338_v197_v210_catchup_TEST_ONLY_29CEF6F5.zip"
BASE_SHA256 = "29CEF6F5ADF4461C9263B39586222F7B88EEEE3DF0D6BEDFE5F0C5695509A777"
ORIGINAL = ROOT / "00_original/arc.zip"
ORIGINAL_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"
OUTPUT_STEM = "arc1_v339_ui_banner_geometry_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v338"
ANALYSIS = ROOT / "01_work/analysis/arc1_v339_ui_banner_geometry"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
RAM_TO_FILE = 0x8011A800
BASE_PSX_SHA256 = "B5006203002EBC87B3228E59B0624D5F50E0DD10EAE6823E3137AEA0C4F001FD"
BASE_COMM_SHA256 = "657E6242C1CEA6468C00C1E045B9D054446C82E231CE4A557C2613B0AEC7806C"
ORIGINAL_COMM_SHA256 = "6C7565B6C326A99A29266482868F17A144FF7D15B871D7D8F8B852EC41014A26"
BASE_REGION_COUNT = 8595
BASE_REGION_FINGERPRINT = "82A58955B8A066A12AE43D4033CB1CEBA12011A2FF55CD3A718080BEAA227BF7"

# Shared name-window width function and loaded zero cave.
WIDTH_HOOK_FILE = 0x51C98
WIDTH_HOOK_RAM = WIDTH_HOOK_FILE + RAM_TO_FILE
WIDTH_HOOK_OLD = bytes.fromhex(
    "E8 FF BD 27 10 00 BF AF 33 AD 05 0C 00 00 00 00 "
    "40 18 02 00 21 18 62 00 80 18 03 00 10 00 BF 8F "
    "0F 00 62 24 08 00 E0 03"
)
CAVE_FILE = 0x828C8
CAVE_RAM = CAVE_FILE + RAM_TO_FILE
CAVE_END_FILE = 0x82938
CAVE_SIZE = CAVE_END_FILE - CAVE_FILE
CAVE_ZERO_SHA256 = "B5FDAB78D8947EACC864BFEECB4D2100780E5AFE1CD8EFAFB124887913AC49FA"
PROTECTED_POINTER = bytes.fromhex("3C CE 19 80 DA C2 19 80")

# The 64-byte helper leaves 48 bytes for four bracket strings.
WIDTH_HELPER_SIZE = 0x40
OPEN_FILE = CAVE_FILE + WIDTH_HELPER_SIZE
OPEN_RAM = OPEN_FILE + RAM_TO_FILE
ITEM_CLOSE_FILE = OPEN_FILE + 3
ITEM_CLOSE_RAM = ITEM_CLOSE_FILE + RAM_TO_FILE
SKILL_CLOSE_FILE = ITEM_CLOSE_FILE + 14
SKILL_CLOSE_RAM = SKILL_CLOSE_FILE + RAM_TO_FILE
POSSESSIVE_FILE = SKILL_CLOSE_FILE + 11
POSSESSIVE_RAM = POSSESSIVE_FILE + RAM_TO_FILE
PAYLOAD_END_FILE = POSSESSIVE_FILE + 4

OPEN_POINTERS = (0x82470, 0x82550)
ITEM_CLOSE_POINTER = 0x82474
SKILL_CLOSE_POINTER = 0x82554
POSSESSIVE_POINTER = 0x82558
OLD_POINTERS = {
    0x82470: 0x8019CC64,
    0x82474: 0x8019AA30,
    0x82550: 0x8019D06F,
    0x82554: 0x8019C2BF,
    0x82558: 0x8019D05A,
}
ITEM_SUFFIX = bytes.fromhex("36 A1 85 0E A1 6F 61 2D 07 01 21")
SKILL_SUFFIX = bytes.fromhex("36 A1 DD 93 DE 15 01 21")

# Original 12px physical89=closing bracket, physical90=opening bracket.
ORIGINAL_CLOSE_ROWS = (0x080,) * 10 + (0x780, 0x000)
ORIGINAL_OPEN_ROWS = (0x03C,) + (0x020,) * 10 + (0x000,)
CLOSE_PLANE = 738
OPEN_PLANE = 774
CLOSE_TOKEN = bytes.fromhex("DF 09")
OPEN_TOKEN = bytes.fromhex("DF 2D")
QUOTE_PLANES = (CLOSE_PLANE, OPEN_PLANE)
QUOTE_STATIC_AUDIT = {
    "savestates_total": 757,
    "savestates_read": 629,
    "savestates_failed": 128,
    "close_rect": "U64..79,V192..207",
    "open_rect": "U208..223,V192..207",
    "nontext_overlaps": 0,
}

# Name tables that converge on 0x8016C498.
NAME_TABLES = (
    ("equipment", 0x804A4, 64),
    ("consumable", 0x80C9C, 32),
    ("skill", 0x811C0, 59),
)

# Vertical geometry.  Name Y moves -1 globally; equipment quantity adds +1
# only after that, keeping its original screen Y.  Consumable already calls
# the same +1 helper, so name and quantity both move -1 with their offset kept.
NAME_Y_FILE = 0x51C68
NAME_Y_OLD = 0x00402821                 # move a1,v0
NAME_Y_NEW = 0x2445FFFF                 # addiu a1,v0,-1
EQUIPMENT_QUANTITY_CALL_FILE = 0x49888
EQUIPMENT_QUANTITY_OLD = 0x0C05ACC9     # jal 0x8016B324
QUANTITY_HELPER_RAM = 0x8019B238
CONSUMABLE_QUANTITY_CALL_FILE = 0x4A35C
CONSUMABLE_QUANTITY_CALL = 0x0C066C8E   # jal 0x8019B238
QUANTITY_HELPER_FILE = 0x80A38
QUANTITY_HELPER_BYTES = bytes.fromhex(
    "08 00 A2 94 00 00 00 00 01 00 42 24 C9 AC 05 08 08 00 A2 A4"
)

BATTLE_HELP_Y_FILE = 0x51FB0
BATTLE_HELP_Y_OLD = 0x3406000C
BATTLE_HELP_Y_NEW = 0x3406000B
ACQUISITION_Y_FILE = 0x44F38
ACQUISITION_Y_OLD = 0x3405001E
ACQUISITION_Y_NEW = 0x3405001D
LEVEL_NOTICE_Y_FILE = 0x449C8
LEVEL_NOTICE_Y_OLD = 0x26650016
LEVEL_NOTICE_Y_NEW = 0x26650015

# Fixed-room wording changes.
EQUIPMENT_NAME_FILE = 0x80696
EQUIPMENT_NAME_OLD = bytes.fromhex("0C DE B9 A1 8B 00")   # 가짜 상
EQUIPMENT_NAME_NEW = bytes.fromhex("55 90 8B 00 00 00")   # 모조상
DESCRIPTION_FILE = 0x81DF2
DESCRIPTION_OLD = bytes.fromhex(
    "09 58 A1 DD C9 A1 DD 31 DD 32 A1 DF 0B DE 07 A1 7A DD 9F 00"
)                                                                # 아크 매 행동 MP 회복
DESCRIPTION_NEW = bytes.fromhex(
    "09 58 A1 DD C9 DD 31 DD 32 A1 DF 0B DE 07 7A DD 9F 00 00 00"
)                                                                # 아크 매행동 MP회복
BATTLE_HELP_FILE = 0x80950
BATTLE_HELP_OLD = bytes.fromhex(
    "E7 02 DD 10 DD 0A E7 05 DD AD DD 47 A1 DD 89 24 00"
)                                                                # ○ 공격 / □ 연결 열기
BATTLE_HELP_NEW = bytes.fromhex(
    "E7 02 DD 10 DD 0A E7 05 DE 54 A1 DD 89 24 00 00 00"
)                                                                # ○ 공격 / □ 링 열기

# Keep the known dangerous scene-loader/BSS cave untouched.
FORBIDDEN_FILE = 0x8F3D8
FORBIDDEN_SIZE = 0x428


class BuildError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def word(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def write_word(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value & 0xFFFFFFFF)


def i_type(op: int, rs: int, rt: int, immediate: int) -> int:
    return (op << 26) | (rs << 21) | (rt << 16) | (immediate & 0xFFFF)


def r_type(rs: int, rt: int, rd: int, shift: int, function: int) -> int:
    return (rs << 21) | (rt << 16) | (rd << 11) | (shift << 6) | function


def jump(address: int) -> int:
    return 0x08000000 | ((address >> 2) & 0x03FFFFFF)


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
            raise BuildError(f"duplicate label {name}")
        self.labels[name] = len(self.words)

    def branch(self, op: int, rs: int, rt: int, label: str) -> None:
        self.fixups.append(BranchFixup(len(self.words), op, rs, rt, label))
        self.emit(0)

    def finish(self) -> tuple[bytes, tuple[int, ...]]:
        result = list(self.words)
        for fixup in self.fixups:
            target_index = self.labels.get(fixup.label)
            if target_index is None:
                raise BuildError(f"undefined label {fixup.label}")
            delta = target_index - (fixup.index + 1)
            if not -0x8000 <= delta <= 0x7FFF:
                raise BuildError(f"branch out of range: {fixup.label}")
            result[fixup.index] = i_type(fixup.op, fixup.rs, fixup.rt, delta)
        return struct.pack(f"<{len(result)}I", *result), tuple(result)


def build_width_helper() -> tuple[bytes, tuple[int, ...]]:
    """a0=NUL string -> v0=sum(14 per glyph, 6 per A1 space)+15."""
    zero, v0, v1, a0, t0, ra = 0, 2, 3, 4, 8, 31
    asm = Assembler(CAVE_RAM)
    asm.emit(r_type(zero, zero, v1, 0, 0x21))       # move v1,zero
    asm.label("loop")
    asm.emit(i_type(0x24, a0, v0, 0))               # lbu v0,0(a0)
    asm.emit(i_type(0x09, a0, a0, 1))               # load-delay filler
    asm.branch(0x04, v0, zero, "done")             # beqz v0,done
    asm.emit(i_type(0x0B, v0, t0, 0xDD))            # delay: one-byte?
    asm.emit(i_type(0x0E, t0, t0, 1))               # xori -> skip trail if lead
    asm.emit(r_type(a0, t0, a0, 0, 0x21))           # addu a0,a0,t0
    asm.emit(i_type(0x09, v0, t0, -0xA1))           # token == A1?
    asm.branch(0x04, t0, zero, "space")
    asm.emit(i_type(0x09, v1, v1, 14))              # delay: default +14
    asm.branch(0x04, zero, zero, "loop")
    asm.emit(0)
    asm.label("space")
    asm.branch(0x04, zero, zero, "loop")
    asm.emit(i_type(0x09, v1, v1, -8))              # net space +6
    asm.label("done")
    asm.emit(r_type(ra, zero, zero, 0, 0x08))        # jr ra
    asm.emit(i_type(0x09, v1, v0, 15))              # delay: margin
    code, words = asm.finish()
    if len(code) != WIDTH_HELPER_SIZE:
        raise BuildError(f"width helper size drift: {len(code)}")
    return code, words


def tokens(data: bytes) -> list[bytes]:
    result: list[bytes] = []
    at = 0
    while at < len(data):
        value = data[at]
        if value == 0:
            break
        width = 1 if value < 0xDD else 2
        if at + width > len(data):
            raise BuildError("truncated name token")
        result.append(data[at:at + width])
        at += width
    return result


def actual_name_width(data: bytes) -> int:
    return 15 + sum(6 if token == b"\xA1" else 14 for token in tokens(data))


def simulate_width_helper(data: bytes) -> int:
    total = 0
    at = 0
    while True:
        value = data[at]
        at += 1
        if value == 0:
            return total + 15
        if value >= 0xDD:
            at += 1
        total += 6 if value == 0xA1 else 14


def c_string(data: bytes | bytearray, start: int) -> bytes:
    end = data.index(0, start)
    return bytes(data[start:end + 1])


def aligned_pointer_refs(data: bytes | bytearray, address: int) -> list[int]:
    return [
        at for at in range(0, len(data) - 3, 4)
        if word(data, at) == address
    ]


def direct_targets(data: bytes | bytearray, lo: int, hi: int) -> list[tuple[int, int, str]]:
    text_size = word(data, 0x1C)
    result: list[tuple[int, int, str]] = []
    for at in range(0x800, min(len(data), 0x800 + text_size), 4):
        instruction = word(data, at)
        op = instruction >> 26
        pc = at + RAM_TO_FILE
        target: int | None = None
        kind = ""
        if op in (2, 3):
            target = ((pc + 4) & 0xF0000000) | ((instruction & 0x03FFFFFF) << 2)
            kind = "jal" if op == 3 else "j"
        elif op in (4, 5, 6, 7):
            immediate = instruction & 0xFFFF
            if immediate & 0x8000:
                immediate -= 0x10000
            target = (pc + 4 + immediate * 4) & 0xFFFFFFFF
            kind = "branch"
        if target is not None and lo <= target < hi:
            result.append((pc, target, kind))
    return result


def changed_offsets(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise BuildError("member size changed")
    return {
        at for at, (old, new) in enumerate(zip(before, after, strict=True))
        if old != new
    }


def padded_quote(rows12: tuple[int, ...]) -> tuple[int, ...]:
    if len(rows12) != 12:
        raise BuildError("original quote row count drift")
    return (0, 0) + tuple(row << 2 for row in rows12) + (0, 0)


def assert_base(before: dict[str, bytes], original: dict[str, bytes]) -> list[dict[str, object]]:
    if len(before) != 164:
        raise BuildError(f"V338 member count drift: {len(before)}")
    if sha256_bytes(before[PSX]) != BASE_PSX_SHA256:
        raise BuildError("V338 PSX hash drift")
    if sha256_bytes(before[COMM]) != BASE_COMM_SHA256:
        raise BuildError("V338 COMM hash drift")
    if sha256_bytes(original[COMM]) != ORIGINAL_COMM_SHA256:
        raise BuildError("original COMM hash drift")

    regions = list(v320.text_regions(before))
    if len(regions) != BASE_REGION_COUNT or v320.region_fingerprint(regions) != BASE_REGION_FINGERPRINT:
        raise BuildError("V338 text-region census drift")
    for token in (OPEN_TOKEN, CLOSE_TOKEN):
        uses = sum(before[name][start:end].count(token) for name, start, end in regions)
        if uses:
            raise BuildError(f"quote token already used: {token.hex()} x{uses}")

    exe = before[PSX]
    if exe[WIDTH_HOOK_FILE:WIDTH_HOOK_FILE + len(WIDTH_HOOK_OLD)] != WIDTH_HOOK_OLD:
        raise BuildError("name-width function anchor drift")
    if sha256_bytes(exe[CAVE_FILE:CAVE_END_FILE]) != CAVE_ZERO_SHA256:
        raise BuildError("loaded V339 cave is not the proven 112-byte zero span")
    if exe[CAVE_END_FILE:CAVE_END_FILE + len(PROTECTED_POINTER)] != PROTECTED_POINTER:
        raise BuildError("protected pointer words after cave drift")
    if direct_targets(exe, CAVE_RAM, CAVE_END_FILE + RAM_TO_FILE):
        raise BuildError("V338 already has control flow into V339 cave")
    if any(
        CAVE_RAM <= word(exe, at) < CAVE_END_FILE + RAM_TO_FILE
        for at in range(0, len(exe) - 3, 4)
    ):
        raise BuildError("V338 already has aligned pointers into V339 cave")

    anchors = (
        (NAME_Y_FILE, NAME_Y_OLD, "name Y"),
        (EQUIPMENT_QUANTITY_CALL_FILE, EQUIPMENT_QUANTITY_OLD, "equipment quantity call"),
        (CONSUMABLE_QUANTITY_CALL_FILE, CONSUMABLE_QUANTITY_CALL, "consumable quantity call"),
        (BATTLE_HELP_Y_FILE, BATTLE_HELP_Y_OLD, "battle help Y"),
        (ACQUISITION_Y_FILE, ACQUISITION_Y_OLD, "acquisition Y"),
        (LEVEL_NOTICE_Y_FILE, LEVEL_NOTICE_Y_OLD, "level notice Y"),
    )
    for at, expected, label in anchors:
        if word(exe, at) != expected:
            raise BuildError(f"{label} anchor drift")
    if exe[QUANTITY_HELPER_FILE:QUANTITY_HELPER_FILE + len(QUANTITY_HELPER_BYTES)] != QUANTITY_HELPER_BYTES:
        raise BuildError("existing +1 quantity helper drift")
    if exe[EQUIPMENT_NAME_FILE:EQUIPMENT_NAME_FILE + len(EQUIPMENT_NAME_OLD)] != EQUIPMENT_NAME_OLD:
        raise BuildError("equipment name anchor drift")
    if exe[DESCRIPTION_FILE:DESCRIPTION_FILE + len(DESCRIPTION_OLD)] != DESCRIPTION_OLD:
        raise BuildError("equipment description anchor drift")
    if exe[BATTLE_HELP_FILE:BATTLE_HELP_FILE + len(BATTLE_HELP_OLD)] != BATTLE_HELP_OLD:
        raise BuildError("battle help payload drift")
    for at, expected in OLD_POINTERS.items():
        if word(exe, at) != expected:
            raise BuildError(f"bracket pointer anchor drift at 0x{at:X}")

    if old12.read_plane(original[COMM], 89) != ORIGINAL_CLOSE_ROWS:
        raise BuildError("original closing-bracket bitmap drift")
    if old12.read_plane(original[COMM], 90) != ORIGINAL_OPEN_ROWS:
        raise BuildError("original opening-bracket bitmap drift")
    for index in QUOTE_PLANES:
        if any(v320.read_plane(before[COMM], index)):
            raise BuildError(f"quote destination plane {index} is not blank")

    if any(exe[FORBIDDEN_FILE:FORBIDDEN_FILE + FORBIDDEN_SIZE]):
        raise BuildError("forbidden scene-loader/BSS cave is not zero")

    width_rows: list[dict[str, object]] = []
    for table, table_at, count in NAME_TABLES:
        for index in range(count):
            pointer = word(exe, table_at + index * 4)
            start = pointer - RAM_TO_FILE
            if not 0x78000 <= start < 0x83000:
                raise BuildError(f"{table}[{index}] pointer outside UI pool: 0x{pointer:08X}")
            payload = c_string(exe, start)
            name_tokens = tokens(payload)
            if any(token[0] >= 0xE1 for token in name_tokens):
                raise BuildError(f"{table}[{index}] contains control/virtual token")
            old_width = len(name_tokens) * 12 + 15
            new_width = actual_name_width(payload)
            if simulate_width_helper(payload) != new_width:
                raise BuildError(f"width helper model mismatch: {table}[{index}]")
            width_rows.append({
                "table": table,
                "index": index,
                "pointer": f"0x{pointer:08X}",
                "file": f"0x{start:X}",
                "tokens": len(name_tokens),
                "spaces": sum(token == b"\xA1" for token in name_tokens),
                "old_width": old_width,
                "new_width": new_width,
                "delta": new_width - old_width,
                "hex": payload[:-1].hex(" ").upper(),
            })
    if len(width_rows) != 155:
        raise BuildError("name-width census drift")
    return width_rows


def build_once(before: dict[str, bytes], original: dict[str, bytes]) -> tuple[dict[str, bytes], dict[str, object]]:
    width_rows = assert_base(before, original)
    final = dict(before)
    exe = bytearray(before[PSX])
    comm = bytearray(before[COMM])
    helper, helper_words = build_width_helper()

    # Shared actual-width helper and four bracketed payloads.
    write_word(exe, WIDTH_HOOK_FILE, jump(CAVE_RAM))
    write_word(exe, WIDTH_HOOK_FILE + 4, 0)
    exe[CAVE_FILE:CAVE_FILE + len(helper)] = helper
    open_payload = OPEN_TOKEN + b"\x00"
    item_close_payload = CLOSE_TOKEN + ITEM_SUFFIX + b"\x00"
    skill_close_payload = CLOSE_TOKEN + SKILL_SUFFIX + b"\x00"
    possessive_payload = CLOSE_TOKEN + bytes.fromhex("4D 00")
    payload = open_payload + item_close_payload + skill_close_payload + possessive_payload
    if len(payload) != PAYLOAD_END_FILE - OPEN_FILE:
        raise BuildError(f"bracket payload layout drift: {len(payload)}")
    exe[OPEN_FILE:PAYLOAD_END_FILE] = payload
    if any(exe[PAYLOAD_END_FILE:CAVE_END_FILE]):
        raise BuildError("V339 cave spare tail became nonzero")

    for at in OPEN_POINTERS:
        write_word(exe, at, OPEN_RAM)
    write_word(exe, ITEM_CLOSE_POINTER, ITEM_CLOSE_RAM)
    write_word(exe, SKILL_CLOSE_POINTER, SKILL_CLOSE_RAM)
    write_word(exe, POSSESSIVE_POINTER, POSSESSIVE_RAM)

    # Vertical placement with the user's screen-specific baseline distinction.
    write_word(exe, NAME_Y_FILE, NAME_Y_NEW)
    write_word(exe, EQUIPMENT_QUANTITY_CALL_FILE, jal(QUANTITY_HELPER_RAM))
    write_word(exe, BATTLE_HELP_Y_FILE, BATTLE_HELP_Y_NEW)
    write_word(exe, ACQUISITION_Y_FILE, ACQUISITION_Y_NEW)
    write_word(exe, LEVEL_NOTICE_Y_FILE, LEVEL_NOTICE_Y_NEW)

    exe[EQUIPMENT_NAME_FILE:EQUIPMENT_NAME_FILE + len(EQUIPMENT_NAME_NEW)] = EQUIPMENT_NAME_NEW
    exe[DESCRIPTION_FILE:DESCRIPTION_FILE + len(DESCRIPTION_NEW)] = DESCRIPTION_NEW
    exe[BATTLE_HELP_FILE:BATTLE_HELP_FILE + len(BATTLE_HELP_NEW)] = BATTLE_HELP_NEW

    close_rows = padded_quote(ORIGINAL_CLOSE_ROWS)
    open_rows = padded_quote(ORIGINAL_OPEN_ROWS)
    v320.put_plane(comm, CLOSE_PLANE, close_rows)
    v320.put_plane(comm, OPEN_PLANE, open_rows)

    final[PSX] = bytes(exe)
    final[COMM] = bytes(comm)

    # Readback and scope guards.
    if word(exe, WIDTH_HOOK_FILE) != jump(CAVE_RAM) or word(exe, WIDTH_HOOK_FILE + 4) != 0:
        raise BuildError("width hook readback mismatch")
    if exe[CAVE_FILE:CAVE_FILE + WIDTH_HELPER_SIZE] != helper:
        raise BuildError("width helper readback mismatch")
    if exe[CAVE_END_FILE:CAVE_END_FILE + len(PROTECTED_POINTER)] != PROTECTED_POINTER:
        raise BuildError("protected pointer word changed")
    if exe[FORBIDDEN_FILE:FORBIDDEN_FILE + FORBIDDEN_SIZE] != before[PSX][FORBIDDEN_FILE:FORBIDDEN_FILE + FORBIDDEN_SIZE]:
        raise BuildError("forbidden cave changed")
    if direct_targets(exe, CAVE_RAM, CAVE_END_FILE + RAM_TO_FILE)[0] != (WIDTH_HOOK_RAM, CAVE_RAM, "j"):
        raise BuildError("width helper external inbound flow mismatch")

    expected_refs = {
        OPEN_RAM: list(OPEN_POINTERS),
        ITEM_CLOSE_RAM: [ITEM_CLOSE_POINTER],
        SKILL_CLOSE_RAM: [SKILL_CLOSE_POINTER],
        POSSESSIVE_RAM: [POSSESSIVE_POINTER],
    }
    for address, refs in expected_refs.items():
        if aligned_pointer_refs(exe, address) != refs:
            raise BuildError(f"bracket pointer ownership mismatch: 0x{address:08X}")
    if any(aligned_pointer_refs(exe, old) for old in OLD_POINTERS.values()):
        # Old strings can have other owners; only reject the exact five old
        # table slots below, not all global references.
        pass
    for at, old in OLD_POINTERS.items():
        if word(exe, at) == old:
            raise BuildError(f"old bracket pointer remains at 0x{at:X}")

    if v320.read_plane(comm, CLOSE_PLANE) != close_rows:
        raise BuildError("closing bracket plane readback mismatch")
    if v320.read_plane(comm, OPEN_PLANE) != open_rows:
        raise BuildError("opening bracket plane readback mismatch")
    changed_planes = [
        index for index in range(15 * 32 * 4)
        if v320.read_plane(before[COMM], index) != v320.read_plane(comm, index)
    ]
    if changed_planes != [CLOSE_PLANE, OPEN_PLANE]:
        raise BuildError(f"unexpected COMM plane changes: {changed_planes}")

    final_width_rows: list[dict[str, object]] = []
    for table, table_at, count in NAME_TABLES:
        for index in range(count):
            pointer = word(exe, table_at + index * 4)
            start = pointer - RAM_TO_FILE
            payload_now = c_string(exe, start)
            name_tokens = tokens(payload_now)
            old_width = len(name_tokens) * 12 + 15
            new_width = actual_name_width(payload_now)
            if simulate_width_helper(payload_now) != new_width:
                raise BuildError(f"postpatch width drift: {table}[{index}]")
            final_width_rows.append({
                "table": table,
                "index": index,
                "pointer": f"0x{pointer:08X}",
                "file": f"0x{start:X}",
                "tokens": len(name_tokens),
                "spaces": sum(token == b"\xA1" for token in name_tokens),
                "old_width": old_width,
                "new_width": new_width,
                "delta": new_width - old_width,
                "hex": payload_now[:-1].hex(" ").upper(),
            })
    if len(final_width_rows) != len(width_rows):
        raise BuildError("postpatch name-width census drift")

    actual = {
        name: changed_offsets(before[name], final[name])
        for name in before if before[name] != final[name]
    }
    if set(actual) != {PSX, COMM}:
        raise BuildError(f"changed member set drift: {sorted(actual)}")
    allowed_psx: set[int] = set()
    ranges = (
        (WIDTH_HOOK_FILE, WIDTH_HOOK_FILE + 8),
        (CAVE_FILE, PAYLOAD_END_FILE),
        (EQUIPMENT_NAME_FILE, EQUIPMENT_NAME_FILE + len(EQUIPMENT_NAME_OLD)),
        (DESCRIPTION_FILE, DESCRIPTION_FILE + len(DESCRIPTION_OLD)),
        (BATTLE_HELP_FILE, BATTLE_HELP_FILE + len(BATTLE_HELP_OLD)),
    )
    for start, end in ranges:
        allowed_psx.update(range(start, end))
    for at in (*OPEN_POINTERS, ITEM_CLOSE_POINTER, SKILL_CLOSE_POINTER, POSSESSIVE_POINTER,
               NAME_Y_FILE, EQUIPMENT_QUANTITY_CALL_FILE, BATTLE_HELP_Y_FILE,
               ACQUISITION_Y_FILE, LEVEL_NOTICE_Y_FILE):
        allowed_psx.update(range(at, at + 4))
    if not actual[PSX] <= allowed_psx:
        raise BuildError(f"PSX Expected-Write escape: {sorted(actual[PSX] - allowed_psx)[:8]}")

    expected_comm = changed_offsets(before[COMM], bytes(comm))
    if actual[COMM] != expected_comm:
        raise BuildError("COMM Expected-Write mismatch")
    if any(len(before[name]) != len(final[name]) for name in before):
        raise BuildError("archive member length changed")

    metadata: dict[str, object] = {
        "changed_members": [name for name in before if name in actual],
        "changed_bytes": {name: len(offsets) for name, offsets in actual.items()},
        "changed_offsets": {name: sorted(offsets) for name, offsets in actual.items()},
        "width_rows": final_width_rows,
        "helper_words": list(helper_words),
        "helper_sha256": sha256_bytes(helper),
        "quote_rows": {"close": list(close_rows), "open": list(open_rows)},
        "changed_planes": changed_planes,
    }
    return final, metadata


def purpose_for(name: str, offset: int) -> str:
    if name == COMM:
        return "restore 16px corner-bracket plane"
    if WIDTH_HOOK_FILE <= offset < WIDTH_HOOK_FILE + 8:
        return "tail-jump shared name width to leaf helper"
    if CAVE_FILE <= offset < CAVE_FILE + WIDTH_HELPER_SIZE:
        return "real 14px/6px name-width helper"
    if OPEN_FILE <= offset < PAYLOAD_END_FILE:
        return "bracketed item/skill acquisition strings"
    if offset in range(EQUIPMENT_NAME_FILE, EQUIPMENT_NAME_FILE + len(EQUIPMENT_NAME_OLD)):
        return "equipment name 모조상"
    if offset in range(DESCRIPTION_FILE, DESCRIPTION_FILE + len(DESCRIPTION_OLD)):
        return "compact description to keep 복 on first line"
    if offset in range(BATTLE_HELP_FILE, BATTLE_HELP_FILE + len(BATTLE_HELP_OLD)):
        return "battle help 링 열기 with E7 tokens preserved"
    return "targeted UI pointer or one-pixel geometry"


def write_analysis(
    before: dict[str, bytes], final: dict[str, bytes], metadata: dict[str, object],
    output_path: Path, output_hash: str, delta_path: Path, delta_hash: str,
) -> None:
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    with (ANALYSIS / "expected_writes.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("member", "offset", "before", "after", "purpose"))
        for name in before:
            for offset in metadata["changed_offsets"].get(name, []):
                writer.writerow((name, f"0x{offset:X}", f"{before[name][offset]:02X}",
                                 f"{final[name][offset]:02X}", purpose_for(name, offset)))

    with (ANALYSIS / "name_width_census.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        fields = ("table", "index", "pointer", "file", "tokens", "spaces", "old_width", "new_width", "delta", "hex")
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(metadata["width_rows"])

    string_rows = (
        ("equipment_name", "가짜 상", "모조상", "name only moves -1; quantity screen Y preserved"),
        ("equipment_description", "아크 매 행동 MP 회복", "아크 매행동 MP회복", "remove two spaces; keep 복 on line one"),
        ("battle_help", "공격 / 연결 열기", "공격 / 링 열기", "E7 controller icons preserved"),
        ("item_acquisition", "unbracketed", "｢item｣ suffix", "both opening and closing brackets restored"),
        ("skill_acquisition", "unbracketed", "｢skill｣ suffix", "both opening and closing brackets restored"),
    )
    with (ANALYSIS / "string_repairs.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("scope", "before", "after", "note"))
        writer.writerows(string_rows)

    with (ANALYSIS / "width_helper_words.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("index", "ram", "file", "word"))
        for index, value in enumerate(metadata["helper_words"]):
            writer.writerow((index, f"0x{CAVE_RAM + index * 4:08X}",
                             f"0x{CAVE_FILE + index * 4:X}", f"0x{value:08X}"))

    with (ANALYSIS / "quote_slot_safety.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("plane", "token", "u", "v", "runtime_text_uses", "runtime_nontext_overlaps", "states_read", "note"))
        writer.writerow((CLOSE_PLANE, CLOSE_TOKEN.hex(" ").upper(), 64, 192, 0, 0, 629, "current 16px rect U64..79,V192..207"))
        writer.writerow((OPEN_PLANE, OPEN_TOKEN.hex(" ").upper(), 208, 192, 0, 0, 629, "current 16px rect U208..223,V192..207"))

    deltas = [int(row["delta"]) for row in metadata["width_rows"]]
    manifest = {
        "build": "V339 TEST_ONLY UI/banner geometry",
        "base": {"path": str(BASE), "sha256": BASE_SHA256},
        "original_art_source": {"path": str(ORIGINAL), "sha256": ORIGINAL_SHA256},
        "output": {"path": str(output_path), "sha256": output_hash},
        "delta": {"path": str(delta_path), "sha256": delta_hash},
        "changed_members": metadata["changed_members"],
        "changed_bytes": metadata["changed_bytes"],
        "name_windows": {
            "entries": len(metadata["width_rows"]),
            "formula_before": "12*N+15",
            "formula_after": "14*glyphs+6*spaces+15",
            "delta_min": min(deltas),
            "delta_max": max(deltas),
            "name_y": -1,
            "equipment_quantity_screen_y": 0,
            "consumable_quantity_screen_y": -1,
            "consumable_relative_to_name": 1,
        },
        "vertical": {
            "skills": -1,
            "bottom_battle_help": -1,
            "item_and_skill_acquisition": -1,
            "level_up_notice": -1,
        },
        "quotes": {
            "planes": list(QUOTE_PLANES),
            "tokens": [CLOSE_TOKEN.hex(" ").upper(), OPEN_TOKEN.hex(" ").upper()],
            "art": "original Japanese COMM.IMG physical89/90, padded x+2 y+2",
            "safety": QUOTE_STATIC_AUDIT,
        },
        "preserved": "164 member sizes/order; all DAT; renderer advance; dialogue/control topology; protected 0x82938 pointer words; forbidden BSS cave",
        "runtime": "PENDING user cold boot and eight-screen replay",
        "release_status": "TEST ONLY; DO NOT DISTRIBUTE",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = (
        "V339 TEST ONLY - UI/banner geometry\n"
        f"base={BASE.name}\noutput={output_path.name}\nsha256={output_hash}\n"
        f"delta={delta_path.name}\ndelta_sha256={delta_hash}\n"
        f"changed_members={','.join(metadata['changed_members'])}\n"
        f"changed_bytes={json.dumps(metadata['changed_bytes'], ensure_ascii=False, sort_keys=True)}\n"
        "name_width=155 entries, 14px glyph / 6px space / 15px margin\n"
        "name_y=-1; equipment quantity unchanged; consumable name+quantity=-1 with +1 relative offset\n"
        "bottom_help=-1; acquisition=-1; level_up=-1\n"
        "wording=모조상; 아크 매행동 MP회복; 링 열기\n"
        f"quotes=planes {CLOSE_PLANE}/{OPEN_PLANE}; 629-state exact-rect nontext overlaps=0\n"
        "runtime=PENDING; TEST_ONLY\n"
    )
    (ANALYSIS / "build_report.txt").write_text(report, encoding="utf-8")
    checklist = (
        "V339 cold-boot checklist\n\n"
        "- Start V339.cue from power-off; do not load a V338 state into V339.\n"
        "- Equipment: expect 모조상; equipment name 1px up; quantity 01 at its V338 Y.\n"
        "- Consumable: name and quantity both 1px up; quantity remains 1px below name.\n"
        "- Skill: name 1px up and brown bar sized to actual 14px/6px text width.\n"
        "- Confirm long/short item, equipment, and skill bars end with consistent padding.\n"
        "- Confirm description reads 아크 매행동 MP회복 with 복 on the first line.\n"
        "- Confirm bottom help reads 링 열기 and both controller icons remain visible.\n"
        "- Trigger item acquisition, skill acquisition, and level-up: text 1px up and ｢ ｣ visible.\n"
        "- Recheck dialogue, choices, status numbers, damage, world map, and loading screens for regression.\n"
    )
    (ANALYSIS / "runtime_checklist.txt").write_text(checklist, encoding="utf-8")


def main() -> None:
    if not BASE.is_file() or v324.sha256_file(BASE) != BASE_SHA256:
        raise BuildError(f"V338 base hash mismatch: {BASE}")
    if not ORIGINAL.is_file() or v324.sha256_file(ORIGINAL) != ORIGINAL_SHA256:
        raise BuildError(f"original archive hash mismatch: {ORIGINAL}")
    infos, before = v324.read_archive(BASE)
    with ZipFile(ORIGINAL) as archive:
        original = {COMM: archive.read(COMM)}
    final, metadata = build_once(before, original)
    rebuilt, rebuilt_metadata = build_once(before, original)
    if final != rebuilt or metadata != rebuilt_metadata:
        raise BuildError("in-memory deterministic rebuild mismatch")

    output_path, output_hash = v324.write_archive(OUTPUT_STEM, infos, final, None)
    delta_path, delta_hash = v324.write_archive(
        DELTA_STEM, infos, final, set(metadata["changed_members"])
    )
    with ZipFile(output_path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        expected = [item.filename for item in infos if not item.is_dir()]
        if names != expected or any(archive.read(name) != final[name] for name in final):
            raise BuildError("full ZIP round-trip/topology mismatch")
    with ZipFile(delta_path) as archive:
        expected = [name for name in final if name in set(metadata["changed_members"])]
        if archive.namelist() != expected or any(archive.read(name) != final[name] for name in expected):
            raise BuildError("delta ZIP round-trip/topology mismatch")

    write_analysis(before, final, metadata, output_path, output_hash, delta_path, delta_hash)
    print(f"V339 full ZIP: {output_path}")
    print(f"V339 full SHA256: {output_hash}")
    print(f"V339 delta ZIP: {delta_path}")
    print(f"V339 delta SHA256: {delta_hash}")
    print(f"changed members: {metadata['changed_members']}")
    print(f"changed bytes: {metadata['changed_bytes']}")


if __name__ == "__main__":
    main()
