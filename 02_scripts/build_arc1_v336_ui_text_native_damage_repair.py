#!/usr/bin/env python3
"""Build V336: historical reproduction of an INVALID branch-wrapped build.

DO NOT RUN V336 ON HARDWARE.  Its common glyph-remap helper encodes an
out-of-range conditional branch whose actual target is 0x801AB524.  V337
repairs the branch while preserving this build's intended payload.

V335 is the frozen base.  This build deliberately combines only defects proven
by the user's V335 save states:

* restore the current, approved S1023 choice text and make E5 indentation use a
  truly blank 16px plane without moving the triangle cursor;
* restore the L/R help label, add the missing space in ``병사 2``, and restore
  the later approved two-line warehouse translation;
* size the dedicated 55-entry location-name window with the real 14px advance;
* move equipment/consumable names four pixels left and only the consumable
  quantity two pixels down;
* relocate the 16 text planes which overlap the native damage-number texture
  into a proven text-only bank, preserve that bank's three nonblank owners in
  three audited spare planes, then restore the native cells from the disc.

Every E2 slot rewrite preserves byte +0x7F completion metadata.  The common
glyph remap is bounded to physical 804..819 and is simulated across every
catalogued text token before an archive is emitted.
"""

from __future__ import annotations

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
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import build_arc1_v320_hanme_static_recovery as v320  # noqa: E402
import build_arc1_v324_static_ui_cursor_recovery as v324  # noqa: E402


BASE = ROOT / "03_output/arc1_v335_dialogue_text_y_minus4_TEST_ONLY_CF4FB2E5.zip"
BASE_SHA256 = "CF4FB2E518ADD6CE6B528C44D2AD4696DCD9DAF2940FE0A105F60B50C76C70D0"
ORIGINAL = ROOT / "00_original/arc.zip"
ORIGINAL_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"
ASSIGNMENTS = ROOT / "01_work/analysis/arc1_v320_hanme_static_recovery/character_assignments.csv"
ASSIGNMENTS_SHA256 = "933BDAC4BC4C39D33DB134D2FF836902B5053B93725C96E19DED714CB7DE98A4"
ATLAS_MAPPING = ROOT / "01_work/analysis/arc1_v319_pilgi16_integration/atlas_mapping.csv"
ATLAS_MAPPING_SHA256 = "9553E7643621CC80C23355067611EAE7650FEF7CB547DC9115B62157DB0C3122"
CELL_AUDIT = ROOT / "01_work/analysis/font_cell_audit_full/cell_consumers.csv"
CELL_AUDIT_SHA256 = "63EF327777CC8A4E072AF68B8A1FE2B2EF4DFD8570D6176980157B7BBF7D5A73"

OUTPUT_STEM = "arc1_v336_ui_text_native_damage_repair_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v335"
ANALYSIS = ROOT / "01_work/analysis/arc1_v336_ui_text_native_damage_repair"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
ROW_BYTES = 896
RAM_TO_FILE = 0x8011A800
SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT_META = 0x7F

BASE_MEMBER_SHA256 = {
    PSX: "B64C7F42AEAF173903CDF7A3B947B09ACE12C83A7E763F72F720240CC9AA2C54",
    COMM: "095885C3EA58F1A886BEE20033EE8313FE07476088AC27FD726F53AE44D8331B",
    "1/S1023.DAT": "F3BA6C04F80434F93EB3BFE42BD836ABDC7036DE4D856D70C40A0929E1FCA026",
    "21/S2042.DAT": "53DB8B587850EEE22A351B294707437C3D9B0DC8BD35338C15260631BF142BE1",
    "4/S4021.DAT": "E51637C2542F845BC291126E09B96061E9AF651EC9A40AADD5EC8331EBFCC3E8",
    "4/S4011.DAT": "1B9C2C4A730551E5964BD314F8A588A3A04D11F9D5F2057F48CD52272FB08ED9",
}
ORIGINAL_COMM_SHA256 = "6C7565B6C326A99A29266482868F17A144FF7D15B871D7D8F8B852EC41014A26"

EXPECTED_REGION_COUNT = 8567
EXPECTED_REGION_FINGERPRINT = "7FF2227365F89E56292A0DDE7649B8F25A13190A8FA3054FDA514BEA887D7625"

# Common text planes currently collide with the native 12px damage-number
# bank.  Physical 161..176 are all in text-only cells.  Their only nonblank
# owners are 168..170, which move to audited, unused planes 741..743.  The
# remaining destination planes are visually blank and are redirected to the
# canonical blank physical 116 by the bounded common gate.
DAMAGE_TEXT_SOURCE = tuple(range(804, 820))
DAMAGE_TEXT_DEST = tuple(range(161, 177))
DAMAGE_DISPLACED = (168, 169, 170)
DAMAGE_BACKUP = (741, 742, 743)
DAMAGE_BLANK_CANONICAL = 116
DAMAGE_REMAP_DELTA = -643
NATIVE_CELL_X = 96
NATIVE_CELL_Y = 208
NATIVE_CELL_W = 64
NATIVE_CELL_H = 16
E5_BLANK_INDEX = 746

# V335 has a seven-word zero island at 0x808F4 and a 39-word zero tail at
# 0x809F8.  Equipment uses the island; the tail holds consumable/common,
# quantity and the bounded two-range glyph remap without extending the EXE.
EQUIPMENT_CAVE_FILE = 0x808F4
EQUIPMENT_CAVE_RAM = 0x8019B0F4
EQUIPMENT_CAVE_SIZE = 0x1C
CAVE_FILE = 0x809F8
CAVE_RAM = 0x8019B1F8
CAVE_SIZE = 0x9C
EQUIPMENT_HELPER = EQUIPMENT_CAVE_RAM
CONSUMABLE_HELPER = CAVE_RAM
ITEM_COMMON = CAVE_RAM + 0x1C
QUANTITY_HELPER = CAVE_RAM + 0x40
DAMAGE_REMAP_HELPER = CAVE_RAM + 0x54

EQUIPMENT_CALL_FILE = 0x494A8       # 0x80163CA8
CONSUMABLE_CALL_FILE = 0x4A32C      # 0x80164B2C
QUANTITY_CALL_FILE = 0x4A35C        # 0x80164B5C
GLYPH_GATE_JUMP_FILE = 0x809DC      # 0x8019B1DC

LOCATION_WORDS = (
    (0x51DBC, 0x00028040, "location_width_sll2"),
    (0x51DC0, 0x02028021, "location_width_add"),
    (0x51DC8, 0x00108080, "location_width_sll4"),
)
E5_PLACEHOLDER_FILE = 0x51604
E5_PLACEHOLDER_OLD = 0x340403C0

CHOICE_MEMBER = "1/S1023.DAT"
CHOICE_BODY_AT = 0x47952
CHOICE_BODY = bytes.fromhex(
    "E2 81 A1 A1 A1 A1 A1 E6 01 "
    "A1 A1 A1 A1 A1 A1 A1 A1 A1 A1 A1 A1 A1 A1 A1 A1 A1 A1 A1 A1 "
    "E6 01 E5 03 DD 3B DD 3A 09 A1 A1 E6 01 E5 03 E2 84 A1"
)
CHOICE_REPAIRS = {
    0: "어머니: 아버지 편지 볼래?",
    2: "다음",
    3: "읽는다",
}
CHOICE_OLD_PAYLOADS = {
    0: bytes.fromhex("14 DD 5D 07 DD 02 A1 09 67 04 0C A1 DD 3D DD FB A1 DD 79 04 A1 DD 50 DD 12 DD 03"),
    2: bytes.fromhex("78 C6"),
    3: bytes.fromhex("DF 16 84 78"),
}
CHOICE_METADATA = {0: 5, 2: 5, 3: 1}

L_MEMBER = "21/S2042.DAT"
L_SLOT = 1
L_BAD_TOKEN = bytes.fromhex("EA 9E")
L_GOOD_TOKEN = bytes.fromhex("DD D8")  # physical 435, atlas semantic L
L_META = 45

SOLDIER_MEMBER = "4/S4021.DAT"
SOLDIER_SLOT = 4
SOLDIER_PREFIX_OLD = bytes.fromhex("82 34 0B")  # 병사2
SOLDIER_PREFIX_NEW = bytes.fromhex("82 34 A1 0B")  # 병사 2
SOLDIER_META = 29

WAREHOUSE_MEMBER = "4/S4011.DAT"
WAREHOUSE_AT = 0x485A2
WAREHOUSE_OLD = bytes.fromhex(
    "DE D4 E9 35 0D 9C E1 E9 8F 9C E6 01 DE 3C CD 74 0F 9C 9C 9C 9C"
)
WAREHOUSE_LINE1 = "잠깐, 뭔가"
WAREHOUSE_LINE2 = "이상해."

EXPECTED_CHANGED_MEMBERS = {
    PSX, COMM, CHOICE_MEMBER, L_MEMBER, SOLDIER_MEMBER, WAREHOUSE_MEMBER,
}

# Whole-EXE opcode scans necessarily interpret the mixed string/data pool as
# instructions.  This single pre-existing word looks like a branch into the
# zero cave; V335 already ran with an all-NOP target, proving it is data.  Pin
# it explicitly so any new accidental control-flow-looking word still fails.
BASE_FALSE_CONTROL = {(0x8019AF0C, 0x8019B254)}


class BuildError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def file_offset(address: int) -> int:
    return address - RAM_TO_FILE


def i_type(op: int, rs: int, rt: int, immediate: int) -> int:
    return (op << 26) | (rs << 21) | (rt << 16) | (immediate & 0xFFFF)


def r_type(rs: int, rt: int, rd: int, shift: int, function: int) -> int:
    return (rs << 21) | (rt << 16) | (rd << 11) | (shift << 6) | function


def jump(address: int) -> int:
    return 0x08000000 | ((address >> 2) & 0x03FFFFFF)


def jal(address: int) -> int:
    return 0x0C000000 | ((address >> 2) & 0x03FFFFFF)


def changed_offsets(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise BuildError("member size changed")
    return {
        offset
        for offset, (old, new) in enumerate(zip(before, after, strict=True))
        if old != new
    }


def assert_word(data: bytes | bytearray, offset: int, expected: int, label: str) -> None:
    actual = struct.unpack_from("<I", data, offset)[0]
    if actual != expected:
        raise BuildError(
            f"{label} drift at 0x{offset:X}: 0x{actual:08X} != 0x{expected:08X}"
        )


def load_codes() -> tuple[dict[str, bytes], dict[bytes, str]]:
    choices: dict[str, list[bytes]] = defaultdict(list)
    code_char: dict[bytes, str] = {}
    with ASSIGNMENTS.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            code = bytes.fromhex(row["code_hex"])
            char = row["char"]
            choices[char].append(code)
            old = code_char.setdefault(code, char)
            if old != char:
                raise BuildError(f"assignment collision: {code.hex()} {old!r}/{char!r}")
    preferred = {
        char: min(codes, key=lambda code: (len(code), code))
        for char, codes in choices.items()
    }
    return preferred, code_char


def encode_text(text: str, preferred: dict[str, bytes]) -> bytes:
    output = bytearray()
    for char in text:
        code = preferred.get(char)
        if code is None:
            raise BuildError(f"no current code for {char!r} in {text!r}")
        output.extend(code)
    return bytes(output)


def decode_text(payload: bytes, code_char: dict[bytes, str]) -> str:
    output: list[str] = []
    offset = 0
    while offset < len(payload):
        width = v320.token_width(payload[offset])
        token = payload[offset : offset + width]
        if len(token) != width or token not in code_char:
            raise BuildError(f"cannot decode token {token.hex()} at +0x{offset:X}")
        output.append(code_char[token])
        offset += width
    return "".join(output)


def read_slot(data: bytes | bytearray, slot: int) -> tuple[bytes, int]:
    start = SLOT_BASE + slot * SLOT_SIZE
    body = bytes(data[start : start + SLOT_META])
    try:
        end = body.index(0)
    except ValueError as exc:
        raise BuildError(f"slot {slot} has no terminator") from exc
    if any(body[end + 1 :]):
        raise BuildError(f"slot {slot} has nonzero padding after its terminator")
    return body[:end], data[start + SLOT_META]


def write_slot_preserve_meta(data: bytearray, slot: int, payload: bytes) -> set[int]:
    if not payload or b"\0" in payload or len(payload) >= SLOT_META:
        raise BuildError(f"invalid slot {slot} payload length {len(payload)}")
    start = SLOT_BASE + slot * SLOT_SIZE
    _old, metadata = read_slot(data, slot)
    data[start : start + SLOT_META] = payload + bytes(SLOT_META - len(payload))
    if data[start + SLOT_META] != metadata:
        raise BuildError(f"slot {slot} metadata changed")
    return set(range(start, start + SLOT_META))


def glyph_target(exe: bytes | bytearray, token: bytes) -> int | None:
    slot = v320.virtual_slot(token)
    if slot is not None:
        return v320.lookup_get(exe, slot) if slot < v320.LOOKUP_SLOTS else None
    return v320.direct_index(token)


def glyph_usage(members: dict[str, bytes]) -> Counter[int]:
    exe = members[PSX]
    usage: Counter[int] = Counter()
    for name, start, end in v320.text_regions(members):
        data = members[name]
        offset = start
        while offset < end:
            if v320.is_control(data, offset):
                offset += 2
                continue
            width = v320.token_width(data[offset])
            token = data[offset : offset + width]
            target = glyph_target(exe, token)
            if target is not None:
                usage[target] += 1
            offset += width
    return usage


def control_targets(exe: bytes) -> list[tuple[int, int]]:
    targets: list[tuple[int, int]] = []
    for offset in range(0, len(exe) - 3, 4):
        word = struct.unpack_from("<I", exe, offset)[0]
        op = word >> 26
        pc = RAM_TO_FILE + offset
        target: int | None = None
        if op in (2, 3):
            target = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
        elif op in (1, 4, 5, 6, 7):
            immediate = word & 0xFFFF
            if immediate & 0x8000:
                immediate -= 0x10000
            target = pc + 4 + immediate * 4
        if target is not None:
            targets.append((pc, target))
    return targets


def pointer_hits(exe: bytes, start_file: int, end_file: int) -> list[tuple[int, int]]:
    hits: list[tuple[int, int]] = []
    for offset in range(0, len(exe) - 3):
        value = struct.unpack_from("<I", exe, offset)[0]
        target_file = value - RAM_TO_FILE
        if start_file <= target_file < end_file:
            hits.append((offset, value))
    return hits


def equipment_cave_words() -> tuple[int, ...]:
    # Copy the caller's fifth argument into a private frame, then preserve the
    # original return address across the stock equipment-name renderer.
    words = (
        i_type(0x09, 29, 29, -0x20),
        i_type(0x23, 29, 2, 0x30),
        i_type(0x2B, 29, 31, 0x1C),
        jal(0x8016C38C),
        i_type(0x2B, 29, 2, 0x10),
        jump(ITEM_COMMON),
        0,
    )
    if len(words) * 4 != EQUIPMENT_CAVE_SIZE:
        raise BuildError(f"equipment cave layout drift: {len(words) * 4}")
    return words


def cave_words() -> tuple[int, ...]:
    # Registers: v0=2, v1=3, a0..a3=4..7, t0=8, t1=9, sp=29, ra=31.
    words = (
        # consumable entry, old sp+0x10/+0x14 -> new frame
        i_type(0x09, 29, 29, -0x20),
        i_type(0x23, 29, 2, 0x30),
        i_type(0x23, 29, 3, 0x34),
        i_type(0x2B, 29, 31, 0x1C),
        i_type(0x2B, 29, 2, 0x10),
        jal(0x8016C400),
        i_type(0x2B, 29, 3, 0x14),
        # shared packet translation: object 0x801F1DB4, dx=-4, dy=0
        i_type(0x09, 0, 4, -4),
        i_type(0x0F, 0, 6, 0x801F),
        i_type(0x09, 6, 6, 0x1DB4),
        jal(0x8016B440),
        r_type(0, 0, 5, 0, 0x21),
        i_type(0x23, 29, 31, 0x1C),
        i_type(0x09, 29, 29, 0x20),
        r_type(31, 0, 0, 0, 0x08),
        0,
        # consumable quantity-only y += 2, then tail-jump to stock append
        i_type(0x25, 5, 2, 8),
        0,
        i_type(0x09, 2, 2, 2),
        jump(0x8016B324),
        i_type(0x29, 5, 2, 8),
        # Common glyph remap.  First preserve the old 161..176 owners:
        # blank planes -> 116, and nonblank 168..170 -> 741..743.  Then map
        # the damaged text range 804..819 into the vacated 161..176 bank.
        i_type(0x09, 4, 8, -161),
        i_type(0x0B, 8, 9, 16),
        i_type(0x04, 9, 0, 8),
        0,
        i_type(0x09, 8, 9, -7),
        i_type(0x0B, 9, 9, 3),
        i_type(0x04, 9, 0, 2),
        i_type(0x0D, 0, 4, DAMAGE_BLANK_CANONICAL),
        i_type(0x09, 8, 4, 734),
        jump(0x8016B524),
        0,
        i_type(0x09, 4, 8, -804),
        i_type(0x0B, 8, 9, 16),
        i_type(
            0x04,
            9,
            0,
            (0x8016B524 - (DAMAGE_REMAP_HELPER + 13 * 4 + 4)) // 4,
        ),
        0,
        i_type(0x09, 4, 4, DAMAGE_REMAP_DELTA),
        jump(0x8016B524),
        0,
    )
    if len(words) * 4 != CAVE_SIZE:
        raise BuildError(f"cave layout size drift: {len(words) * 4}")
    return words


def audit_nontext_safe(indices: tuple[int, ...]) -> None:
    audit: dict[tuple[int, int], int] = {}
    with CELL_AUDIT.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            audit[(int(row["row"]), int(row["col"]))] = int(row["nontext_reads"])
    for index in indices:
        cell = index // 4
        x0 = (cell % 15) * 16
        y0 = (cell // 15) * 16
        overlaps = {
            (y // 12, x // 12)
            for y in range(y0, y0 + 16)
            for x in range(x0, x0 + 16)
        }
        if any(audit.get(key, -1) != 0 for key in overlaps):
            raise BuildError(f"destination physical {index} is not nontext-safe")


def runtime_damage_target(index: int) -> int:
    if 161 <= index < 177:
        if 168 <= index <= 170:
            return 741 + (index - 168)
        return DAMAGE_BLANK_CANONICAL
    if 804 <= index < 820:
        return index + DAMAGE_REMAP_DELTA
    return index


def patch_comm(base_comm: bytes, original_comm: bytes) -> bytes:
    comm = bytearray(base_comm)
    source_rows = {index: v320.read_plane(base_comm, index) for index in DAMAGE_TEXT_SOURCE}
    displaced_rows = {index: v320.read_plane(base_comm, index) for index in DAMAGE_DISPLACED}

    for source, backup in zip(DAMAGE_DISPLACED, DAMAGE_BACKUP, strict=True):
        if any(v320.read_plane(comm, backup)):
            raise BuildError(f"damage backup destination {backup} is not blank")
        v320.put_plane(comm, backup, displaced_rows[source])
    for source, destination in zip(DAMAGE_TEXT_SOURCE, DAMAGE_TEXT_DEST, strict=True):
        if destination not in DAMAGE_DISPLACED and any(v320.read_plane(comm, destination)):
            raise BuildError(f"damage relocation destination {destination} is not blank")
        v320.put_plane(comm, destination, source_rows[source])

    # Restore the complete four 16px cells, not merely the currently sampled
    # 60x12 damage strip.  Original bytes are authoritative native texture.
    byte_x = NATIVE_CELL_X // 2
    byte_w = NATIVE_CELL_W // 2
    for y in range(NATIVE_CELL_Y, NATIVE_CELL_Y + NATIVE_CELL_H):
        start = y * ROW_BYTES + byte_x
        comm[start : start + byte_w] = original_comm[start : start + byte_w]

    for source, destination in zip(DAMAGE_TEXT_SOURCE, DAMAGE_TEXT_DEST, strict=True):
        if v320.read_plane(comm, destination) != source_rows[source]:
            raise BuildError(f"relocated plane mismatch {source}->{destination}")
    for source, backup in zip(DAMAGE_DISPLACED, DAMAGE_BACKUP, strict=True):
        if v320.read_plane(comm, backup) != displaced_rows[source]:
            raise BuildError(f"displaced plane backup mismatch {source}->{backup}")

    # Every byte of the original 13-cell 12px damage bank must now match.
    for y in range(208, 220):
        start = y * ROW_BYTES
        if comm[start : start + 78] != original_comm[start : start + 78]:
            raise BuildError(f"native damage-number row {y} did not restore")

    allowed_planes = set(DAMAGE_TEXT_SOURCE) | set(DAMAGE_TEXT_DEST) | set(DAMAGE_BACKUP)
    for index in range(960):
        if index in allowed_planes:
            continue
        if v320.read_plane(comm, index) != v320.read_plane(base_comm, index):
            raise BuildError(f"COMM neighbor plane changed: {index}")
    return bytes(comm)


def apply_text_repairs(
    members: dict[str, bytearray], preferred: dict[str, bytes], code_char: dict[bytes, str]
) -> tuple[dict[str, set[int]], list[dict[str, object]]]:
    allowed: dict[str, set[int]] = defaultdict(set)
    rows: list[dict[str, object]] = []

    choice = members[CHOICE_MEMBER]
    if bytes(choice[CHOICE_BODY_AT : CHOICE_BODY_AT + len(CHOICE_BODY)]) != CHOICE_BODY:
        raise BuildError("S1023 choice control body drift")
    for slot, text in CHOICE_REPAIRS.items():
        old_payload, metadata = read_slot(choice, slot)
        if old_payload != CHOICE_OLD_PAYLOADS[slot] or metadata != CHOICE_METADATA[slot]:
            raise BuildError(f"S1023 slot {slot} premise drift")
        payload = encode_text(text, preferred)
        allowed[CHOICE_MEMBER] |= write_slot_preserve_meta(choice, slot, payload)
        got, got_meta = read_slot(choice, slot)
        if got != payload or got_meta != metadata or decode_text(got, code_char) != text:
            raise BuildError(f"S1023 slot {slot} readback failed")
        rows.append({"member": CHOICE_MEMBER, "kind": "slot", "location": slot,
                     "before_hex": old_payload.hex(" ").upper(), "after": text,
                     "metadata": metadata})
    if bytes(choice[CHOICE_BODY_AT : CHOICE_BODY_AT + len(CHOICE_BODY)]) != CHOICE_BODY:
        raise BuildError("S1023 E5/E6 body changed while rewriting slots")

    ldata = members[L_MEMBER]
    old_l, lmeta = read_slot(ldata, L_SLOT)
    if lmeta != L_META or old_l.count(L_BAD_TOKEN) != 1:
        raise BuildError("L/R help slot premise drift")
    new_l = old_l.replace(L_BAD_TOKEN, L_GOOD_TOKEN)
    allowed[L_MEMBER] |= write_slot_preserve_meta(ldata, L_SLOT, new_l)
    got_l, got_lmeta = read_slot(ldata, L_SLOT)
    if got_l != new_l or got_lmeta != L_META or got_l.count(L_GOOD_TOKEN) != 1:
        raise BuildError("L/R help slot readback failed")
    rows.append({"member": L_MEMBER, "kind": "slot_token", "location": L_SLOT,
                 "before_hex": L_BAD_TOKEN.hex(" ").upper(), "after": "L",
                 "metadata": L_META})

    soldier = members[SOLDIER_MEMBER]
    old_soldier, soldier_meta = read_slot(soldier, SOLDIER_SLOT)
    if soldier_meta != SOLDIER_META or not old_soldier.startswith(SOLDIER_PREFIX_OLD):
        raise BuildError("병사2 slot premise drift")
    new_soldier = SOLDIER_PREFIX_NEW + old_soldier[len(SOLDIER_PREFIX_OLD):]
    allowed[SOLDIER_MEMBER] |= write_slot_preserve_meta(soldier, SOLDIER_SLOT, new_soldier)
    got_soldier, got_soldier_meta = read_slot(soldier, SOLDIER_SLOT)
    if got_soldier != new_soldier or got_soldier_meta != SOLDIER_META:
        raise BuildError("병사 2 slot readback failed")
    if decode_text(got_soldier[:4], code_char) != "병사 2":
        raise BuildError("병사 2 decoded prefix mismatch")
    rows.append({"member": SOLDIER_MEMBER, "kind": "slot_prefix", "location": SOLDIER_SLOT,
                 "before_hex": SOLDIER_PREFIX_OLD.hex(" ").upper(), "after": "병사 2",
                 "metadata": SOLDIER_META})

    warehouse = members[WAREHOUSE_MEMBER]
    if bytes(warehouse[WAREHOUSE_AT : WAREHOUSE_AT + len(WAREHOUSE_OLD)]) != WAREHOUSE_OLD:
        raise BuildError("warehouse two-line premise drift")
    line1 = encode_text(WAREHOUSE_LINE1, preferred)
    line2 = encode_text(WAREHOUSE_LINE2, preferred)
    if len(line1) > 10 or len(line2) > 9:
        raise BuildError(f"warehouse approved text does not fit: {len(line1)}/10 {len(line2)}/9")
    replacement = (
        line1 + b"\xA1" * (10 - len(line1))
        + bytes.fromhex("E6 01")
        + line2 + b"\xA1" * (9 - len(line2))
    )
    if len(replacement) != len(WAREHOUSE_OLD) or b"\0" in replacement:
        raise BuildError("warehouse replacement geometry drift")
    warehouse[WAREHOUSE_AT : WAREHOUSE_AT + len(replacement)] = replacement
    allowed[WAREHOUSE_MEMBER].update(range(WAREHOUSE_AT, WAREHOUSE_AT + len(replacement)))
    if decode_text(replacement[:10], code_char).rstrip() != WAREHOUSE_LINE1:
        raise BuildError("warehouse first line readback failed")
    if decode_text(replacement[12:], code_char).rstrip() != WAREHOUSE_LINE2:
        raise BuildError("warehouse second line readback failed")
    rows.append({"member": WAREHOUSE_MEMBER, "kind": "inline_two_line",
                 "location": f"0x{WAREHOUSE_AT:X}", "before_hex": WAREHOUSE_OLD.hex(" ").upper(),
                 "after": f"{WAREHOUSE_LINE1} / {WAREHOUSE_LINE2}", "metadata": "E6 01 preserved"})
    return allowed, rows


def build_once(
    before: dict[str, bytes], original_comm: bytes,
    preferred: dict[str, bytes], code_char: dict[bytes, str],
) -> tuple[dict[str, bytes], dict[str, set[int]], dict[str, object], list[dict[str, object]]]:
    exe = bytearray(before[PSX])
    if any(exe[EQUIPMENT_CAVE_FILE : EQUIPMENT_CAVE_FILE + EQUIPMENT_CAVE_SIZE]):
        raise BuildError("V335 equipment cave is not zero")
    if any(exe[CAVE_FILE : CAVE_FILE + CAVE_SIZE]):
        raise BuildError("V335 cave is not zero")
    if pointer_hits(bytes(exe), EQUIPMENT_CAVE_FILE, EQUIPMENT_CAVE_FILE + EQUIPMENT_CAVE_SIZE):
        raise BuildError("V335 equipment cave gained a data pointer")
    if pointer_hits(bytes(exe), CAVE_FILE, CAVE_FILE + CAVE_SIZE):
        raise BuildError("V335 cave gained a data pointer")
    old_inbound = [
        (source, target) for source, target in control_targets(bytes(exe))
        if (
            EQUIPMENT_CAVE_RAM <= target < EQUIPMENT_CAVE_RAM + EQUIPMENT_CAVE_SIZE
            or CAVE_RAM <= target < CAVE_RAM + CAVE_SIZE
        )
    ]
    if set(old_inbound) != BASE_FALSE_CONTROL:
        raise BuildError(f"V335 cave gained control flow: {old_inbound}")

    assert_word(exe, EQUIPMENT_CALL_FILE, jal(0x8016C38C), "equipment name call")
    assert_word(exe, CONSUMABLE_CALL_FILE, jal(0x8016C400), "consumable name call")
    assert_word(exe, QUANTITY_CALL_FILE, jal(0x8016B324), "consumable quantity call")
    assert_word(exe, GLYPH_GATE_JUMP_FILE, jump(0x8016B524), "common glyph gate return")
    for offset, word, label in LOCATION_WORDS:
        assert_word(exe, offset, word, label)
    assert_word(exe, E5_PLACEHOLDER_FILE, E5_PLACEHOLDER_OLD, "E5 placeholder")

    equipment_code = struct.pack("<7I", *equipment_cave_words())
    exe[EQUIPMENT_CAVE_FILE : EQUIPMENT_CAVE_FILE + EQUIPMENT_CAVE_SIZE] = equipment_code
    code = struct.pack("<39I", *cave_words())
    exe[CAVE_FILE : CAVE_FILE + CAVE_SIZE] = code
    struct.pack_into("<I", exe, EQUIPMENT_CALL_FILE, jal(EQUIPMENT_HELPER))
    struct.pack_into("<I", exe, CONSUMABLE_CALL_FILE, jal(CONSUMABLE_HELPER))
    struct.pack_into("<I", exe, QUANTITY_CALL_FILE, jal(QUANTITY_HELPER))
    struct.pack_into("<I", exe, GLYPH_GATE_JUMP_FILE, jump(DAMAGE_REMAP_HELPER))

    # Dedicated location-name width: 12*n -> 14*n, window remains centered.
    struct.pack_into("<I", exe, 0x51DBC, r_type(0, 2, 16, 4, 0))
    struct.pack_into("<I", exe, 0x51DC0, r_type(0, 2, 3, 1, 0))
    struct.pack_into("<I", exe, 0x51DC8, r_type(16, 3, 16, 0, 0x23))
    struct.pack_into("<I", exe, E5_PLACEHOLDER_FILE, i_type(0x0D, 0, 4, E5_BLANK_INDEX))

    expected_inbound = BASE_FALSE_CONTROL | {
        (0x80163CA8, EQUIPMENT_HELPER),
        (0x80164B2C, CONSUMABLE_HELPER),
        (0x8019B108, ITEM_COMMON),
        (0x80164B5C, QUANTITY_HELPER),
        (0x8019B1DC, DAMAGE_REMAP_HELPER),
        (DAMAGE_REMAP_HELPER + 0x08, DAMAGE_REMAP_HELPER + 0x2C),
        (DAMAGE_REMAP_HELPER + 0x18, DAMAGE_REMAP_HELPER + 0x24),
    }
    new_inbound = {
        (source, target) for source, target in control_targets(bytes(exe))
        if (
            EQUIPMENT_CAVE_RAM <= target < EQUIPMENT_CAVE_RAM + EQUIPMENT_CAVE_SIZE
            or CAVE_RAM <= target < CAVE_RAM + CAVE_SIZE
        )
    }
    if new_inbound != expected_inbound:
        raise BuildError(f"cave inbound topology mismatch: {sorted(new_inbound)}")

    usage = glyph_usage(before)
    if any(usage[index] for index in DAMAGE_BACKUP + (E5_BLANK_INDEX,)):
        raise BuildError("backup/blank destination has an existing text owner")
    audit_nontext_safe(DAMAGE_TEXT_DEST + DAMAGE_BACKUP + (E5_BLANK_INDEX,))
    for index in tuple(range(161, 168)) + tuple(range(171, 177)):
        if any(v320.read_plane(before[COMM], index)):
            raise BuildError(f"expected blank displacement plane is not blank: {index}")
    if any(
        any(v320.read_plane(before[COMM], index))
        for index in DAMAGE_BACKUP + (E5_BLANK_INDEX,)
    ):
        raise BuildError("backup/E5 destination is not blank")

    comm = patch_comm(before[COMM], original_comm)
    if any(v320.read_plane(comm, E5_BLANK_INDEX)):
        raise BuildError("E5 blank plane changed")

    # Prove the bounded runtime remap preserves every existing text bitmap.
    compared = affected = 0
    for name, start, end in v320.text_regions(before):
        data = before[name]
        offset = start
        while offset < end:
            if v320.is_control(data, offset):
                offset += 2
                continue
            width = v320.token_width(data[offset])
            token = data[offset : offset + width]
            target = glyph_target(before[PSX], token)
            if target is not None and target < 960:
                final_target = runtime_damage_target(target)
                if v320.read_plane(before[COMM], target) != v320.read_plane(comm, final_target):
                    raise BuildError(f"text bitmap changed at {name}:0x{offset:X} target {target}")
                compared += 1
                affected += target in DAMAGE_TEXT_SOURCE
            offset += width
    if not affected:
        raise BuildError("damage overlap text census unexpectedly empty")

    mutable = {name: bytearray(data) for name, data in before.items()}
    mutable[PSX] = exe
    mutable[COMM] = bytearray(comm)
    text_allowed, text_rows = apply_text_repairs(mutable, preferred, code_char)
    final = {name: bytes(data) for name, data in mutable.items()}

    allowed: dict[str, set[int]] = defaultdict(set)
    allowed[PSX].update(range(EQUIPMENT_CAVE_FILE, EQUIPMENT_CAVE_FILE + EQUIPMENT_CAVE_SIZE))
    allowed[PSX].update(range(CAVE_FILE, CAVE_FILE + CAVE_SIZE))
    for offset in (
        EQUIPMENT_CALL_FILE, CONSUMABLE_CALL_FILE, QUANTITY_CALL_FILE,
        GLYPH_GATE_JUMP_FILE, E5_PLACEHOLDER_FILE, 0x51DBC, 0x51DC0, 0x51DC8,
    ):
        allowed[PSX].update(range(offset, offset + 4))
    byte_x = NATIVE_CELL_X // 2
    byte_w = NATIVE_CELL_W // 2
    for y in range(NATIVE_CELL_Y, NATIVE_CELL_Y + NATIVE_CELL_H):
        start = y * ROW_BYTES + byte_x
        allowed[COMM].update(range(start, start + byte_w))
    for index in DAMAGE_TEXT_DEST + DAMAGE_BACKUP:
        cell = index // 4
        col, row = cell % 15, cell // 15
        for y in range(16):
            start = (row * 16 + y) * ROW_BYTES + col * 8
            allowed[COMM].update(range(start, start + 8))
    for name, offsets in text_allowed.items():
        allowed[name].update(offsets)

    metadata = {
        "text_bitmap_comparisons": compared,
        "damage_overlap_token_occurrences": affected,
        "damage_source_usage": {str(index): usage[index] for index in DAMAGE_TEXT_SOURCE},
        "damage_relocation": [
            {"source": source, "destination": destination}
            for source, destination in zip(DAMAGE_TEXT_SOURCE, DAMAGE_TEXT_DEST, strict=True)
        ],
        "damage_displaced_backup": [
            {"source": source, "destination": destination}
            for source, destination in zip(DAMAGE_DISPLACED, DAMAGE_BACKUP, strict=True)
        ],
        "e5_blank_index": E5_BLANK_INDEX,
        "item_geometry": {"equipment_name_dx": -4, "consumable_name_dx": -4,
                          "consumable_quantity_dy": 2},
        "location_width": "12*n -> 14*n; 55-entry dedicated location-name table",
    }
    return final, allowed, metadata, text_rows


def purpose_for(member: str, offset: int) -> str:
    if member == PSX:
        if EQUIPMENT_CAVE_FILE <= offset < EQUIPMENT_CAVE_FILE + EQUIPMENT_CAVE_SIZE:
            return "equipment_name_dx_minus4_wrapper"
        if CAVE_FILE <= offset < CAVE_FILE + CAVE_SIZE:
            return "item_wrappers_quantity_and_damage_text_remap"
        if offset in range(EQUIPMENT_CALL_FILE, EQUIPMENT_CALL_FILE + 4):
            return "equipment_name_dx_minus4_call"
        if offset in range(CONSUMABLE_CALL_FILE, CONSUMABLE_CALL_FILE + 4):
            return "consumable_name_dx_minus4_call"
        if offset in range(QUANTITY_CALL_FILE, QUANTITY_CALL_FILE + 4):
            return "consumable_quantity_dy_plus2_call"
        if offset in range(GLYPH_GATE_JUMP_FILE, GLYPH_GATE_JUMP_FILE + 4):
            return "damage_overlap_text_remap_gate"
        if offset in range(E5_PLACEHOLDER_FILE, E5_PLACEHOLDER_FILE + 4):
            return "E5_invisible_14px_placeholder"
        return "location_name_width_14px"
    if member == COMM:
        return "relocate_text_planes_and_restore_native_damage_texture"
    if member == CHOICE_MEMBER:
        return "choice_prompt_and_options_current_encoding"
    if member == L_MEMBER:
        return "restore_L_in_LR_help"
    if member == SOLDIER_MEMBER:
        return "병사2_to_병사_2"
    if member == WAREHOUSE_MEMBER:
        return "approved_v204_translation_restore"
    return "declared_repair"


def main() -> None:
    fixed = (
        (BASE, BASE_SHA256, "V335 base"),
        (ORIGINAL, ORIGINAL_SHA256, "original archive"),
        (ASSIGNMENTS, ASSIGNMENTS_SHA256, "character assignments"),
        (ATLAS_MAPPING, ATLAS_MAPPING_SHA256, "atlas mapping"),
        (CELL_AUDIT, CELL_AUDIT_SHA256, "nontext cell audit"),
    )
    for path, expected, label in fixed:
        if not path.is_file() or v324.sha256_file(path) != expected:
            raise BuildError(f"{label} hash mismatch: {path}")

    infos, before = v324.read_archive(BASE)
    if len(before) != 164:
        raise BuildError(f"V335 member count drift: {len(before)}")
    for name, expected in BASE_MEMBER_SHA256.items():
        if sha256_bytes(before[name]) != expected:
            raise BuildError(f"V335 member hash drift: {name}")
    regions = list(v320.text_regions(before))
    if len(regions) != EXPECTED_REGION_COUNT or v320.region_fingerprint(regions) != EXPECTED_REGION_FINGERPRINT:
        raise BuildError("V335 text-region topology drift")

    with ZipFile(ORIGINAL) as archive:
        original_comm = archive.read(COMM)
    if sha256_bytes(original_comm) != ORIGINAL_COMM_SHA256:
        raise BuildError("original COMM.IMG hash drift")

    preferred, code_char = load_codes()
    atlas_rows = list(csv.DictReader(ATLAS_MAPPING.open(encoding="utf-8-sig", newline="")))
    if atlas_rows[435]["char"] != "L" or v320.direct_index(L_GOOD_TOKEN) != 435:
        raise BuildError("physical 435 is no longer the proven L glyph")

    final, allowed, metadata, text_rows = build_once(
        before, original_comm, preferred, code_char
    )
    rebuilt, rebuilt_allowed, rebuilt_metadata, rebuilt_rows = build_once(
        before, original_comm, preferred, code_char
    )
    if final != rebuilt or allowed != rebuilt_allowed or metadata != rebuilt_metadata or text_rows != rebuilt_rows:
        raise BuildError("in-memory deterministic rebuild mismatch")

    if any(len(final[name]) != len(before[name]) for name in before):
        raise BuildError("member size changed")
    changed_members = [name for name in before if before[name] != final[name]]
    if set(changed_members) != EXPECTED_CHANGED_MEMBERS:
        raise BuildError(f"changed member set drift: {changed_members}")

    diffs: dict[str, set[int]] = {}
    for name in changed_members:
        actual = changed_offsets(before[name], final[name])
        if not actual or not actual <= allowed[name]:
            escaped = sorted(actual - allowed[name])[:20]
            raise BuildError(f"Expected-Write escape in {name}: {escaped}")
        diffs[name] = actual

    output_path, output_hash = v324.write_archive(OUTPUT_STEM, infos, final, None)
    delta_path, delta_hash = v324.write_archive(
        DELTA_STEM, infos, final, EXPECTED_CHANGED_MEMBERS
    )
    with ZipFile(output_path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        expected_names = [item.filename for item in infos if not item.is_dir()]
        if names != expected_names or any(archive.read(name) != final[name] for name in final):
            raise BuildError("full ZIP round-trip/topology mismatch")
    with ZipFile(delta_path) as archive:
        if set(archive.namelist()) != EXPECTED_CHANGED_MEMBERS:
            raise BuildError("delta member set mismatch")
        if any(archive.read(name) != final[name] for name in EXPECTED_CHANGED_MEMBERS):
            raise BuildError("delta payload mismatch")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    with (ANALYSIS / "expected_writes.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow(("member", "offset", "before", "after", "purpose"))
        for name in changed_members:
            for offset in sorted(diffs[name]):
                writer.writerow((name, f"0x{offset:X}", f"{before[name][offset]:02X}",
                                 f"{final[name][offset]:02X}", purpose_for(name, offset)))

    with (ANALYSIS / "text_repairs.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=(
            "member", "kind", "location", "before_hex", "after", "metadata"
        ))
        writer.writeheader()
        writer.writerows(text_rows)

    with (ANALYSIS / "damage_text_relocation.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow(("source_physical", "destination_physical", "base_uses"))
        for row in metadata["damage_relocation"]:
            source = int(row["source"])
            writer.writerow((source, row["destination"], metadata["damage_source_usage"][str(source)]))

    manifest = {
        "build": "V336 INVALID UI/text/native damage repair; superseded by V337",
        "fatal_defect": {
            "branch_ram": "0x8019B280",
            "word": "0x112040A8",
            "actual_target": "0x801AB524",
            "required_target": "0x8016B524",
            "status": "DO NOT RUN; fixed by V337",
        },
        "base": {"path": str(BASE), "sha256": BASE_SHA256},
        "output": {"path": str(output_path), "sha256": output_hash},
        "delta": {"path": str(delta_path), "sha256": delta_hash},
        "changed_members": changed_members,
        "changed_bytes": {name: len(diffs[name]) for name in changed_members},
        **metadata,
        "text_repairs": text_rows,
        "preserved": (
            "V335 dialogue Y shift and triangle cursor; V332 skill/config alignment; "
            "all undeclared DAT; E2 +0x7F metadata; member sizes and archive order"
        ),
        "runtime": "BLOCKED; DO NOT RUN; superseded by V337",
        "release_status": "INVALID; DO NOT RUN OR DISTRIBUTE",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V336 INVALID - DO NOT RUN - superseded by V337",
        "fatal_common_gate_branch=0x8019B280 word 0x112040A8 -> actual 0x801AB524 (required 0x8016B524)",
        "V336 TEST ONLY - UI/text/native damage repair",
        f"base={BASE.name}",
        f"output={output_path.name}",
        f"sha256={output_hash}",
        f"delta={delta_path.name}",
        f"delta_sha256={delta_hash}",
        "changed_members=" + ",".join(changed_members),
        "changed_bytes=" + ",".join(f"{name}:{len(diffs[name])}" for name in changed_members),
        f"text_bitmap_comparisons={metadata['text_bitmap_comparisons']} affected={metadata['damage_overlap_token_occurrences']}",
        "choice=short prompt + 다음 + 읽는다; E5 blank index 746; triangle unchanged",
        "LR=L restored; 병사2=병사 2; warehouse=v204 approved two lines",
        "location_width=14*n; item names dx=-4; consumable quantity dy=+2",
        "native_damage=13/13 cells original; text 804..819->161..176; old 168..170->741..743",
        "runtime=BLOCKED; DO NOT RUN; use V337",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    (ANALYSIS / "runtime_checklist.txt").write_text(
        "\n".join((
            "V336 INVALID - DO NOT COLD BOOT - use V337",
            "",
            "The common glyph-remap BEQ at 0x8019B280 wraps to unmapped 0x801AB524.",
            "The former checklist is retained below only as historical context.",
            "",
            "V336 cold-boot checklist (superseded)",
            "",
            "- Cold boot V336.cue; never load an older-build savestate.",
            "- S1023: prompt stays on one row, choices show 괜찮아 / 읽는다, blank prefixes are invisible, triangle remains aligned.",
            "- Help: L/R button label shows both L and R.",
            "- Dialogue: 병사 2 has a gap; warehouse line is 잠깐, 뭔가 / 이상해.",
            "- Visit several maps: every full location name appears, not only its final character.",
            "- Equipment and consumable names are 4px left; consumable count is 2px lower; other battle/UI numbers do not move.",
            "- Damage values use clean native digits with no Hangul/odd glyphs.",
            "- Dialogue, skill/config screens, icons, combat progression and loading match V335 otherwise.",
            "",
            "Until these pass, V336 remains TEST_ONLY and bible_current.txt stays unchanged.",
        )) + "\n",
        encoding="utf-8",
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
