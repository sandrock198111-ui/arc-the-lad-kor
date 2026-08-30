#!/usr/bin/env python3
"""Build V341: runtime battle UI recovery on top of V340.

This is a deliberately narrow TEST_ONLY successor.  It keeps V340's approved
battle-answer payloads and configuration geometry, then repairs four runtime
defects proven by the uploaded V340 DUCCU states:

* skip a redundant explicit E6 after the 15 prompts that already auto-wrap;
* move only ordinary W16 bottom-help glyphs at Y=214 up one pixel while
  leaving E7 controller icons and reused non-bottom objects untouched;
* make the shared region/location label read ``오르카스 언덕``; and
* refresh the relocated item/skill range texture immediately before DrawOT
  while the fixed range object is initialized and active.

No archive member changes size.  COMM.IMG and all cursor descriptors, UV data,
RLE art, translated answer payloads, and V340 configuration bars are preserved.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import build_arc1_v128_all_battle_choices as v128  # noqa: E402
import build_arc1_v320_hanme_static_recovery as v320  # noqa: E402
import build_arc1_v323_skill_range_relocation as v323  # noqa: E402
import build_arc1_v324_static_ui_cursor_recovery as v324  # noqa: E402
import build_arc1_v340_battle_choice_ui_geometry as v340  # noqa: E402


BASE = ROOT / "03_output/arc1_v340_battle_choice_ui_geometry_TEST_ONLY_3F63BFD1.zip"
BASE_SHA256 = "3F63BFD149A100152DE8B1B3223136CC501AF5AC19E19F443D4519142F9C783E"
BASE_PSX_SHA256 = "9EE5CD445BA98B2B2BFB92C11772AB2A1DDCA656BE0926FC9D95E611176F6180"
BASE_COMM_SHA256 = "A6681F1355007725328372CC6143EF21EEE43A9FDE91FD3DC2EF3461C6805405"
OUTPUT_STEM = "arc1_v341_runtime_ui_recovery_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v340"
ANALYSIS = ROOT / "01_work/analysis/arc1_v341_runtime_ui_recovery"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
RAM_TO_FILE = 0x8011A800
SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT_META = 0x7F

# V340 bottom-help changes to replace.  The producer immediate is restored to
# V339.  The compact E7 helper remains equivalent for all v1 values but no
# longer changes Y.  A new exact object+Y helper owns the ordinary W16 store.
BATTLE_HELP_Y_RAM = 0x8016C7B0
BATTLE_HELP_Y_FILE = BATTLE_HELP_Y_RAM - RAM_TO_FILE
BATTLE_HELP_Y_V340 = 0x3406000A
BATTLE_HELP_Y_V339 = 0x3406000B
BOTTOM_HELP_OBJECT = 0x801F0E18
BOTTOM_HELP_PACKET_Y = 214

E7_HELPER_RAM = 0x8019D000
E7_HELPER_FILE = E7_HELPER_RAM - RAM_TO_FILE
E7_HELPER_SIZE = 0x48
W16_HELPER_RAM = E7_HELPER_RAM + 0x24
E7_Y_HOOK_RAM = 0x8016B6FC
E7_Y_HOOK_FILE = E7_Y_HOOK_RAM - RAM_TO_FILE
E7_Y_V340 = v340.jump(v340.E7_Y_HELPER_RAM, link=True)
E7_Y_STOCK = 0x340501EB
E7_Y_DELAY = 0x34040010
E7_CLUT_CALL = 0x0C05E399
E7_PACKET_Y_STORE = 0xA602002E
W16_Y_HOOK_RAM = 0x8016B5F4
W16_Y_HOOK_FILE = W16_Y_HOOK_RAM - RAM_TO_FILE
W16_Y_OLD = (0x00000000, 0xA4A2002E)

# Shared world/region name.  The packed legacy spelling is one byte too short,
# so use the proven-zero live UI-pool tail and repoint exactly two consumers.
REGION_POINTER_FILE = 0x81E44
LOCATION_POINTER_FILE = 0x821B4
OLD_ORKAS_POINTER = 0x8019BABE
ORKAS_POOL_FILE = 0x82928
ORKAS_POOL_RAM = ORKAS_POOL_FILE + RAM_TO_FILE
ORKAS_POOL_SIZE = 0x10
ORKAS_BYTES = bytes.fromhex("46 70 DD 38 30 A1 DD 30 5A 00")
V340_REGION_COUNT = 8612
V340_REGION_SHA256 = "AC09A0775C088D03A09367825BC2D897977E0BE4C7BECF1B913E469768B79072"

# V324's cursor uploader was called once from an initializer.  V340 states
# prove that its packets remain live while the relocated destination is zero.
# Restore the displaced initializer and conditionally call the same uploader
# immediately before DrawOT.
INIT_HOOK_RAM = v323.INIT_HOOK
INIT_HOOK_FILE = INIT_HOOK_RAM - RAM_TO_FILE
INIT_V340 = (v323.jal(v324.HELPER_RAM), 0)
INIT_STOCK = v323.INIT_HOOK_WORDS

FRAME_DRAWOT_RAM = 0x8011C860
FRAME_DRAWOT_FILE = FRAME_DRAWOT_RAM - RAM_TO_FILE
DRAWOT_RAM = 0x80176E1C
FRAME_DRAWOT_OLD = v323.jal(DRAWOT_RAM)
FRAME_DRAWOT_DELAY = 0x26040070

CURSOR_GATE_RAM = 0x8018FD90
CURSOR_GATE_FILE = CURSOR_GATE_RAM - RAM_TO_FILE
CURSOR_GATE_SIZE = 0x34  # 13 words, leaving the final zero byte untouched.
CURSOR_CAVE_SIZE = 0x35
RANGE_OWNER_RAM = 0x801EDFB4
RANGE_OWNER_POINTER_RAM = RANGE_OWNER_RAM + 0xA4
RANGE_OWNER_ACTIVE_RAM = RANGE_OWNER_RAM + 0x70
RANGE_OWNER_EXPECTED_POINTER = 0x801F52BC

CURSOR_HELPER_FILE = v324.HELPER_SOURCE_FILE
CURSOR_HELPER_SIZE = v324.HELPER_SIZE
CURSOR_EPILOGUE_FILE = CURSOR_HELPER_FILE + CURSOR_HELPER_SIZE - 9 * 4
CURSOR_RLE_FILE = CURSOR_HELPER_FILE + CURSOR_HELPER_SIZE
CURSOR_RLE_SIZE = 652
RELOCATED_DESCRIPTOR_SHA256 = "47DF81B0E91A262A8C77EEF9C095A01D7FEF222A1D1BEB249EC92287987623A6"
CURSOR_EPILOGUE_V340 = (
    0x3C11801F, 0x263152BC, 0x8FBF01CC, 0x8FB401BC, 0x8FB301C0,
    0x8FB201C4, 0x8FB001C8, 0x03E00008, 0x27BD01D0,
)


class BuildError(RuntimeError):
    pass


@dataclass(frozen=True)
class ChoiceCompletion:
    member: str
    body: int
    slot: int
    old_meta: int

    @property
    def new_meta(self) -> int:
        return self.old_meta + 2

    @property
    def disk_id(self) -> int:
        return self.slot + (0x81 if self.slot < 40 else 0x82)

    @property
    def meta_offset(self) -> int:
        return SLOT_BASE + self.slot * SLOT_SIZE + SLOT_META


CHOICE_COMPLETIONS = (
    ChoiceCompletion("C1/SC011.DAT", 0x46F0E, 8, 12),
    ChoiceCompletion("C1/SC011.DAT", 0x46F74, 11, 10),
    ChoiceCompletion("C1/SC021.DAT", 0x46F0E, 8, 12),
    ChoiceCompletion("C1/SC021.DAT", 0x46F74, 11, 10),
    ChoiceCompletion("C1/SC031.DAT", 0x46F0E, 8, 12),
    ChoiceCompletion("C1/SC031.DAT", 0x46F74, 11, 10),
    ChoiceCompletion("C1/SC041.DAT", 0x46F0E, 37, 12),
    ChoiceCompletion("C1/SC041.DAT", 0x46F74, 40, 10),
    ChoiceCompletion("C1/SC051.DAT", 0x46F0E, 8, 12),
    ChoiceCompletion("C1/SC051.DAT", 0x46F74, 11, 10),
    ChoiceCompletion("C1/SC061.DAT", 0x46F0E, 13, 12),
    ChoiceCompletion("C1/SC061.DAT", 0x46F74, 16, 10),
    ChoiceCompletion("C1/SC081.DAT", 0x46F70, 12, 10),
    ChoiceCompletion("C2/SC0A1.DAT", 0x46F00, 6, 12),
    ChoiceCompletion("C2/SC0A1.DAT", 0x46F66, 9, 10),
)
CHANGED_DATS = tuple(dict.fromkeys(item.member for item in CHOICE_COMPLETIONS))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def word(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def write_word(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value)


def i_type(op: int, rs: int, rt: int, immediate: int) -> int:
    return (op << 26) | (rs << 21) | (rt << 16) | (immediate & 0xFFFF)


def r_type(rs: int, rt: int, rd: int, shift: int, function: int) -> int:
    return (rs << 21) | (rt << 16) | (rd << 11) | (shift << 6) | function


def jump(address: int, link: bool = False) -> int:
    return ((3 if link else 2) << 26) | ((address >> 2) & 0x03FFFFFF)


def branch(op: int, rs: int, rt: int, pc: int, target: int) -> int:
    delta = target - (pc + 4)
    if delta % 4 or not -0x20000 <= delta < 0x20000:
        raise BuildError(f"invalid branch 0x{pc:08X}->0x{target:08X}")
    return i_type(op, rs, rt, delta // 4)


def build_e7_w16_helper() -> tuple[int, ...]:
    """Return a 9-word exact E7 selector plus a 9-word exact W16 Y leaf."""
    zero, v0, v1, a1, a2, t0, s0, ra = 0, 2, 3, 5, 6, 8, 16, 31
    e7_store = E7_HELPER_RAM + 7 * 4
    w16_store = W16_HELPER_RAM + 7 * 4
    words = (
        i_type(0x0B, v1, t0, 15),                  # sltiu t0,v1,15
        i_type(0x0D, zero, v0, 0x4114),            # bitset {2,4,8,14}
        r_type(v1, v0, v0, 0, 0x06),               # srlv v0,v0,v1
        r_type(t0, v0, t0, 0, 0x24),               # and t0,t0,v0
        branch(0x04, t0, zero, E7_HELPER_RAM + 0x10, e7_store),
        i_type(0x0D, zero, v0, 0x82),               # delay: default V
        i_type(0x0D, zero, v0, 0xE4),               # controller V
        jump(0x8016B6D0),
        i_type(0x28, s0, v0, 0x29),                 # delay: packet V store

        i_type(0x0F, zero, t0, 0x801F),             # W16 helper
        i_type(0x09, t0, t0, 0x0E18),
        branch(0x05, a2, t0, W16_HELPER_RAM + 0x08, w16_store),
        i_type(0x0D, zero, t0, BOTTOM_HELP_PACKET_Y),  # delay
        branch(0x05, v0, t0, W16_HELPER_RAM + 0x10, w16_store),
        0,
        i_type(0x09, v0, v0, -1),
        r_type(ra, zero, zero, 0, 0x08),
        i_type(0x29, a1, v0, 0x2E),                 # delay: packet Y store
    )
    if len(words) * 4 != E7_HELPER_SIZE:
        raise BuildError("combined E7/W16 helper size drift")
    return words


def build_cursor_gate() -> tuple[int, ...]:
    """Return the exact-owner/active pre-DrawOT cursor refresh gate."""
    zero, a0, t0, t1, t2, t3, sp = 0, 4, 8, 9, 10, 11, 29
    skip = CURSOR_GATE_RAM + 11 * 4
    words = (
        i_type(0x0F, zero, t0, 0x801F),             # base for 0x801E....
        i_type(0x23, t0, t1, 0xE058),               # owner+0xA4 pointer
        i_type(0x25, t0, t2, 0xE024),               # load-delay filler; active flag
        i_type(0x0F, zero, t3, 0x801F),
        i_type(0x09, t3, t3, 0x52BC),               # exact initialized pointer
        branch(0x05, t1, t3, CURSOR_GATE_RAM + 0x14, skip),
        0,
        branch(0x05, t2, zero, CURSOR_GATE_RAM + 0x1C, skip),
        i_type(0x2B, sp, a0, -0x18),                # delay: future helper frame slot
        jump(v324.HELPER_RAM),
        0,
        jump(DRAWOT_RAM),
        0,
    )
    if len(words) * 4 != CURSOR_GATE_SIZE:
        raise BuildError("cursor gate size drift")
    return words


def build_cursor_epilogue() -> tuple[int, ...]:
    """Restore saved DrawOT a0, draw, then return to the stock frame caller."""
    zero, a0, s0, s2, s3, s4, sp, ra = 0, 4, 16, 18, 19, 20, 29, 31
    return (
        i_type(0x23, sp, a0, 0x1B8),
        i_type(0x23, sp, s4, 0x1BC),                # a0 load-delay filler
        jump(DRAWOT_RAM, link=True),
        i_type(0x23, sp, s3, 0x1C0),                # DrawOT delay slot
        i_type(0x23, sp, ra, 0x1CC),
        i_type(0x23, sp, s2, 0x1C4),                # ra load-delay filler
        i_type(0x23, sp, s0, 0x1C8),
        r_type(ra, zero, zero, 0, 0x08),
        i_type(0x09, sp, sp, 0x1D0),
    )


def iter_e2_calls(data: bytes, start: int, end: int):
    offset = start
    while offset < end:
        value = data[offset]
        if v320.is_control(data, offset):
            if offset + 2 > end:
                break
            if value == 0xE2:
                yield offset, data[offset + 1]
            offset += 2
        else:
            width = v320.token_width(value)
            if offset + width > end:
                break
            offset += width


def text_region_callers(members: dict[str, bytes]) -> Counter[tuple[str, int]]:
    regions = list(v320.text_regions(members))
    if len(regions) != V340_REGION_COUNT or v320.region_fingerprint(regions) != V340_REGION_SHA256:
        raise BuildError("text-region catalogue drift")
    calls: Counter[tuple[str, int]] = Counter()
    for member, start, end in regions:
        for _offset, disk_id in iter_e2_calls(members[member], start, end):
            calls[(member, disk_id)] += 1
    return calls


def marker_topology(members: dict[str, bytes]):
    result = {}
    for member in v128.BATTLE_FILES:
        data = members[member]
        for body in v128.OFFSETS[member]:
            end = data.find(b"\x00", body, body + 0x80)
            payload = data[body:end]
            result[(member, body)] = (
                tuple(i for i, value in enumerate(payload) if value == 0xE5),
                tuple(i for i, value in enumerate(payload) if value == 0xE6),
            )
    return result


def pointer_hits(data: bytes | bytearray, address: int) -> list[int]:
    needle = struct.pack("<I", address)
    return [at for at in range(len(data) - 3) if data[at:at + 4] == needle]


def assert_base(before: dict[str, bytes]) -> list[dict[str, object]]:
    if len(before) != 164:
        raise BuildError(f"V340 member count drift: {len(before)}")
    if sha256_bytes(before[PSX]) != BASE_PSX_SHA256:
        raise BuildError("V340 PSX hash drift")
    if sha256_bytes(before[COMM]) != BASE_COMM_SHA256:
        raise BuildError("V340 COMM hash drift")
    exe = before[PSX]

    old_helper, _ = v340.build_e7_helper()
    if word(exe, BATTLE_HELP_Y_FILE) != BATTLE_HELP_Y_V340:
        raise BuildError("V340 bottom-help producer premise drift")
    if exe[E7_HELPER_FILE:E7_HELPER_FILE + E7_HELPER_SIZE] != old_helper:
        raise BuildError("V340 E7/Y helper premise drift")
    if word(exe, E7_Y_HOOK_FILE) != E7_Y_V340 or word(exe, E7_Y_HOOK_FILE + 4) != E7_Y_DELAY:
        raise BuildError("V340 E7 Y hook premise drift")
    if (word(exe, E7_Y_HOOK_FILE + 8), word(exe, E7_Y_HOOK_FILE + 12)) != (
        E7_CLUT_CALL, E7_PACKET_Y_STORE,
    ):
        raise BuildError("E7 CLUT/Y context drift")
    if struct.unpack_from("<2I", exe, W16_Y_HOOK_FILE) != W16_Y_OLD:
        raise BuildError("stock W16 Y-store premise drift")

    if struct.unpack_from("<2I", exe, INIT_HOOK_FILE) != INIT_V340:
        raise BuildError("V340 one-shot cursor init premise drift")
    if word(exe, FRAME_DRAWOT_FILE) != FRAME_DRAWOT_OLD or word(exe, FRAME_DRAWOT_FILE + 4) != FRAME_DRAWOT_DELAY:
        raise BuildError("frame DrawOT premise drift")
    if any(exe[CURSOR_GATE_FILE:CURSOR_GATE_FILE + CURSOR_CAVE_SIZE]):
        raise BuildError("cursor gate cave is no longer zero")
    if struct.unpack_from("<9I", exe, CURSOR_EPILOGUE_FILE) != CURSOR_EPILOGUE_V340:
        raise BuildError("V340 cursor helper epilogue drift")
    if sha256_bytes(exe[CURSOR_RLE_FILE:CURSOR_RLE_FILE + CURSOR_RLE_SIZE]) != v323.EXPECTED_RLE_SHA256:
        raise BuildError("cursor RLE drift")
    if sha256_bytes(exe[v323.DESCRIPTOR_FILE:v323.DESCRIPTOR_FILE + v323.DESCRIPTOR_SIZE]) != RELOCATED_DESCRIPTOR_SHA256:
        raise BuildError("cursor descriptor drift")
    relocated_uv = tuple(struct.unpack_from("<8H", exe, v323.UV_FILE + i * 16) for i in range(9))
    expected_uv = tuple(
        tuple(value + v323.UV_V_DELTA if j in (1, 3, 5, 7) else value for j, value in enumerate(entry))
        for entry in v323.BASE_UV
    )
    if relocated_uv != expected_uv:
        raise BuildError("relocated range UV table drift")

    if word(exe, REGION_POINTER_FILE) != OLD_ORKAS_POINTER or word(exe, LOCATION_POINTER_FILE) != OLD_ORKAS_POINTER:
        raise BuildError("shared Orkas pointer premise drift")
    if any(exe[ORKAS_POOL_FILE:ORKAS_POOL_FILE + ORKAS_POOL_SIZE]):
        raise BuildError("Orkas destination pool is not zero")
    if pointer_hits(exe, ORKAS_POOL_RAM):
        raise BuildError("Orkas destination pool already has a pointer")

    calls = text_region_callers(before)
    rows: list[dict[str, object]] = []
    for item in CHOICE_COMPLETIONS:
        data = before[item.member]
        if data[item.meta_offset] != item.old_meta:
            raise BuildError(f"choice metadata drift: {item}")
        body = data[item.body:data.find(b"\x00", item.body, item.body + 0x80)]
        if body[:2] != bytes((0xE2, item.disk_id)):
            raise BuildError(f"choice prompt caller drift: {item}")
        if body[2:2 + item.old_meta] != bytes((0xA1,)) * item.old_meta:
            raise BuildError(f"choice padding drift: {item}")
        if body[2 + item.old_meta:4 + item.old_meta] != b"\xE6\x01":
            raise BuildError(f"redundant E6 premise drift: {item}")
        if body[2 + item.new_meta:4 + item.new_meta] != b"\xE5\x03":
            raise BuildError(f"first E5 resume target drift: {item}")
        if calls[(item.member, item.disk_id)] != 1:
            raise BuildError(f"choice prompt slot is shared: {item} callers={calls[(item.member, item.disk_id)]}")
        rows.append({
            "member": item.member,
            "body": f"0x{item.body:X}",
            "slot": item.slot,
            "disk_id": f"0x{item.disk_id:02X}",
            "meta_offset": f"0x{item.meta_offset:X}",
            "before_meta": item.old_meta,
            "after_meta": item.new_meta,
            "before_resume": "E6 01",
            "after_resume": "E5 03",
            "structural_callers": 1,
        })
    return rows


def build_once(before: dict[str, bytes]) -> tuple[dict[str, bytes], dict[str, object]]:
    choice_rows = assert_base(before)
    topology_before = marker_topology(before)
    final = dict(before)

    for member in CHANGED_DATS:
        data = bytearray(before[member])
        for item in CHOICE_COMPLETIONS:
            if item.member == member:
                data[item.meta_offset] = item.new_meta
        final[member] = bytes(data)

    exe = bytearray(before[PSX])
    helper_words = build_e7_w16_helper()
    struct.pack_into("<18I", exe, E7_HELPER_FILE, *helper_words)
    write_word(exe, BATTLE_HELP_Y_FILE, BATTLE_HELP_Y_V339)
    write_word(exe, E7_Y_HOOK_FILE, E7_Y_STOCK)
    write_word(exe, W16_Y_HOOK_FILE, jump(W16_HELPER_RAM, link=True))
    write_word(exe, W16_Y_HOOK_FILE + 4, 0)

    struct.pack_into("<2I", exe, INIT_HOOK_FILE, *INIT_STOCK)
    gate_words = build_cursor_gate()
    struct.pack_into("<13I", exe, CURSOR_GATE_FILE, *gate_words)
    write_word(exe, FRAME_DRAWOT_FILE, jump(CURSOR_GATE_RAM, link=True))
    cursor_epilogue = build_cursor_epilogue()
    struct.pack_into("<9I", exe, CURSOR_EPILOGUE_FILE, *cursor_epilogue)

    exe[ORKAS_POOL_FILE:ORKAS_POOL_FILE + len(ORKAS_BYTES)] = ORKAS_BYTES
    write_word(exe, REGION_POINTER_FILE, ORKAS_POOL_RAM)
    write_word(exe, LOCATION_POINTER_FILE, ORKAS_POOL_RAM)
    final[PSX] = bytes(exe)

    if marker_topology(final) != topology_before:
        raise BuildError("battle E5/E6 body topology changed")
    for item in CHOICE_COMPLETIONS:
        if final[item.member][item.meta_offset] != item.new_meta:
            raise BuildError(f"choice metadata readback failed: {item}")

    # Exhaustive E7 truth table and W16 scoping truth table.
    for value in range(0x200):
        expected = 0xE4 if value in (2, 4, 8, 14) else 0x82
        in_range = int(value < 15)
        selected = in_range & ((0x4114 >> (value & 31)) & 1)
        actual = 0xE4 if selected else 0x82
        if actual != expected:
            raise BuildError(f"E7 selector mismatch at v1={value}")
    for obj in (BOTTOM_HELP_OBJECT, 0x801F9D44, 0x801F031C, 0x801F1DB4):
        for y in (104, 122, 213, 214, 215):
            actual = y - int(obj == BOTTOM_HELP_OBJECT and y == BOTTOM_HELP_PACKET_Y)
            expected = 213 if (obj, y) == (BOTTOM_HELP_OBJECT, 214) else y
            if actual != expected:
                raise BuildError("W16 Y scope simulation failed")

    if word(final[PSX], FRAME_DRAWOT_FILE + 4) != FRAME_DRAWOT_DELAY:
        raise BuildError("DrawOT argument delay slot changed")
    if final[PSX][CURSOR_RLE_FILE:CURSOR_RLE_FILE + CURSOR_RLE_SIZE] != before[PSX][CURSOR_RLE_FILE:CURSOR_RLE_FILE + CURSOR_RLE_SIZE]:
        raise BuildError("cursor RLE changed")
    if final[PSX][v323.DESCRIPTOR_FILE:v323.DESCRIPTOR_FILE + v323.DESCRIPTOR_SIZE] != before[PSX][v323.DESCRIPTOR_FILE:v323.DESCRIPTOR_FILE + v323.DESCRIPTOR_SIZE]:
        raise BuildError("cursor descriptor changed")
    if final[PSX][v323.UV_FILE:v323.UV_FILE + v323.UV_SIZE] != before[PSX][v323.UV_FILE:v323.UV_FILE + v323.UV_SIZE]:
        raise BuildError("cursor UV table changed")
    if any(final[PSX][CURSOR_GATE_FILE + CURSOR_GATE_SIZE:CURSOR_GATE_FILE + CURSOR_CAVE_SIZE]):
        raise BuildError("cursor gate tail byte changed")
    if pointer_hits(final[PSX], ORKAS_POOL_RAM) != [REGION_POINTER_FILE, LOCATION_POINTER_FILE]:
        raise BuildError("Orkas pointer census failed")
    if final[PSX][ORKAS_POOL_FILE:ORKAS_POOL_FILE + len(ORKAS_BYTES)] != ORKAS_BYTES:
        raise BuildError("Orkas string readback failed")

    return final, {
        "choice_rows": choice_rows,
        "helper_words": helper_words,
        "gate_words": gate_words,
        "cursor_epilogue": cursor_epilogue,
    }


def changed_offsets(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise BuildError("member size changed")
    return {i for i, (old, new) in enumerate(zip(before, after, strict=True)) if old != new}


def allowed_offsets() -> dict[str, set[int]]:
    allowed: dict[str, set[int]] = defaultdict(set)
    for start, size in (
        (BATTLE_HELP_Y_FILE, 4),
        (E7_HELPER_FILE, E7_HELPER_SIZE),
        (E7_Y_HOOK_FILE, 4),
        (W16_Y_HOOK_FILE, 8),
        (INIT_HOOK_FILE, 8),
        (FRAME_DRAWOT_FILE, 4),
        (CURSOR_GATE_FILE, CURSOR_GATE_SIZE),
        (CURSOR_EPILOGUE_FILE, 9 * 4),
        (REGION_POINTER_FILE, 4),
        (LOCATION_POINTER_FILE, 4),
        (ORKAS_POOL_FILE, len(ORKAS_BYTES)),
    ):
        allowed[PSX].update(range(start, start + size))
    for item in CHOICE_COMPLETIONS:
        allowed[item.member].add(item.meta_offset)
    return dict(allowed)


def purpose_for(name: str, offset: int) -> str:
    if name != PSX:
        return "choice_completion_skip_redundant_e6"
    ranges = (
        (BATTLE_HELP_Y_FILE, 4, "restore_v339_help_producer"),
        (E7_HELPER_FILE, E7_HELPER_SIZE, "e7_equivalent_and_w16_exact_y_helper"),
        (E7_Y_HOOK_FILE, 4, "restore_stock_e7_y"),
        (W16_Y_HOOK_FILE, 8, "w16_bottom_help_y_minus_1"),
        (INIT_HOOK_FILE, 8, "restore_stock_range_initializer"),
        (FRAME_DRAWOT_FILE, 4, "pre_drawot_cursor_refresh_gate"),
        (CURSOR_GATE_FILE, CURSOR_GATE_SIZE, "cursor_active_owner_gate"),
        (CURSOR_EPILOGUE_FILE, 36, "cursor_upload_then_drawot_epilogue"),
        (REGION_POINTER_FILE, 4, "region_name_orkas_pointer"),
        (LOCATION_POINTER_FILE, 4, "location_name_orkas_pointer"),
        (ORKAS_POOL_FILE, len(ORKAS_BYTES), "orkas_shared_string"),
    )
    for start, size, label in ranges:
        if start <= offset < start + size:
            return label
    raise BuildError(f"unclassified PSX write at 0x{offset:X}")


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        raise BuildError(f"refusing empty CSV: {path.name}")
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    if not BASE.is_file() or v324.sha256_file(BASE) != BASE_SHA256:
        raise BuildError(f"V340 base hash mismatch: {BASE}")
    infos, before = v324.read_archive(BASE)
    final, evidence = build_once(before)
    rebuilt, _ = build_once(before)
    if final != rebuilt:
        raise BuildError("in-memory deterministic rebuild mismatch")
    if any(len(before[name]) != len(final[name]) for name in before):
        raise BuildError("archive member size changed")

    changed_members = [name for name in before if before[name] != final[name]]
    expected_members = [name for name in before if name == PSX or name in CHANGED_DATS]
    if changed_members != expected_members:
        raise BuildError(f"changed member order/set drift: {changed_members}")
    actual = {name: changed_offsets(before[name], final[name]) for name in changed_members}
    allowed = allowed_offsets()
    for name in changed_members:
        if not actual[name] or not actual[name] <= allowed[name]:
            raise BuildError(f"Expected-Write envelope violation: {name}")

    output_path, output_hash = v324.write_archive(OUTPUT_STEM, infos, final, None)
    delta_path, delta_hash = v324.write_archive(DELTA_STEM, infos, final, set(changed_members))
    with ZipFile(output_path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        expected_names = [item.filename for item in infos if not item.is_dir()]
        if names != expected_names or any(archive.read(name) != final[name] for name in final):
            raise BuildError("full ZIP topology/readback mismatch")
    with ZipFile(delta_path) as archive:
        if archive.namelist() != expected_members or any(archive.read(name) != final[name] for name in expected_members):
            raise BuildError("delta ZIP topology/readback mismatch")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    expected_rows: list[dict[str, object]] = []
    for name in changed_members:
        for offset in sorted(actual[name]):
            expected_rows.append({
                "member": name,
                "offset": f"0x{offset:X}",
                "before": f"{before[name][offset]:02X}",
                "after": f"{final[name][offset]:02X}",
                "purpose": purpose_for(name, offset),
            })
    write_csv(ANALYSIS / "expected_writes.csv", expected_rows)
    write_csv(ANALYSIS / "choice_completion_repairs.csv", evidence["choice_rows"])
    write_csv(ANALYSIS / "mips_words.csv", [
        {"section": "e7_w16", "index": i, "ram": f"0x{E7_HELPER_RAM + i * 4:08X}", "word": f"0x{value:08X}"}
        for i, value in enumerate(evidence["helper_words"])
    ] + [
        {"section": "cursor_gate", "index": i, "ram": f"0x{CURSOR_GATE_RAM + i * 4:08X}", "word": f"0x{value:08X}"}
        for i, value in enumerate(evidence["gate_words"])
    ] + [
        {"section": "cursor_epilogue", "index": i, "ram": f"0x{v324.HELPER_RAM + CURSOR_HELPER_SIZE - 36 + i * 4:08X}", "word": f"0x{value:08X}"}
        for i, value in enumerate(evidence["cursor_epilogue"])
    ])

    manifest = {
        "build": "V341 TEST_ONLY runtime UI recovery",
        "base": {"path": str(BASE), "sha256": BASE_SHA256},
        "output": {"path": str(output_path), "sha256": output_hash},
        "delta": {"path": str(delta_path), "sha256": delta_hash},
        "changed_members": changed_members,
        "changed_bytes": {name: len(actual[name]) for name in changed_members},
        "choice_alignment": {
            "repairs": len(CHOICE_COMPLETIONS),
            "method": "slot +0x7F completion metadata +2; body bytes and E5/E6 offsets unchanged",
        },
        "bottom_help": {
            "ordinary_W16": "object 0x801F0E18 AND original Y=214 -> Y=213",
            "E7_icons": "Y unchanged; V selector equivalent for v1=0..511",
        },
        "map_label": "region_name and location_name -> 오르카스 언덕",
        "range_cursor": {
            "method": "exact owner+active gate; five synchronous LoadImage chunks immediately before DrawOT",
            "descriptor_uv_rle": "byte exact from V340",
        },
        "runtime": "PENDING user cold boot",
        "release_status": "TEST_ONLY; DO NOT DISTRIBUTE",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V341 TEST ONLY - runtime battle UI recovery",
        f"base={BASE.name}",
        f"output={output_path.name}",
        f"sha256={output_hash}",
        f"delta={delta_path.name}",
        f"delta_sha256={delta_hash}",
        f"changed_members={','.join(changed_members)}",
        "choice_alignment=15 metadata-only completions; first E5 rows align with preserved triangle",
        "bottom_help=ordinary W16 exact object+Y -1; E7 icons unchanged",
        "map_label=오르카스 언덕 shared by region/location pointers",
        "range_cursor=active-only pre-DrawOT refresh; descriptor/UV/RLE unchanged",
        "runtime=PENDING user cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    checklist = [
        "V341 cold-boot runtime checklist",
        "",
        "- Cold boot V341; do not resume a pre-patch save state.",
        "- Revisit the screenshot-1 battle choice: first row must align with the unchanged triangle; second row must follow at +16px.",
        "- Check bottom help: Korean W16 text is 1px higher, while O/□/×/START icons remain at the V339/V340-correct Y.",
        "- Check both dialogue/map labels read 오르카스 언덕.",
        "- Enter item and skill targeting on the reported battle maps: range tiles/cursor must be visible and controls usable.",
        "- Watch for frame-rate stalls while the item/skill range object is active.",
        "- Recheck configuration bars, dialogue, item/equipment/skill names, acquisition/level-up banners and world-map transition.",
        "- Save fresh DUCCU states for V341 attribution.",
        "",
        "Static result: PASS in builder. Runtime result: PENDING.",
    ]
    (ANALYSIS / "runtime_checklist.txt").write_text("\n".join(checklist) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
