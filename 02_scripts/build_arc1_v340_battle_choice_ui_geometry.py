#!/usr/bin/env python3
"""Build V340: repair battle-choice answers and finish 16px battle UI geometry.

V340 is a narrow TEST_ONLY successor to V339.  It keeps every accepted V339
change and applies three independently bounded repairs:

* replace the 29 battle-choice answer payloads whose legacy codes render the
  wrong 16px glyphs, while preserving all 63 bodies' E5/E6 offsets;
* move only ordinary W=16 bottom-help glyphs one pixel up, while keeping E7
  controller icons at their V339 screen Y;
* enlarge the configuration selection rectangles from 51x14 to 62x16.

No member changes size.  The E7 extension reuses the existing 72-byte helper
at 0x8019D000..0x8019D048; it does not allocate another code cave.
"""

from __future__ import annotations

import csv
import hashlib
import json
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
import build_arc1_v324_static_ui_cursor_recovery as v324  # noqa: E402


BASE = ROOT / "03_output/arc1_v339_ui_banner_geometry_TEST_ONLY_FD442C74.zip"
BASE_SHA256 = "FD442C7492F7BE2FCFAED5B3BE377D67FE9794B6767C356AC275D407F2030C17"
BASE_PSX_SHA256 = "5DD4244A12BDB0314CDB8C608CDF6640488EBC6F967F91B3C0F2094EBAA5E62D"
BASE_COMM_SHA256 = "A6681F1355007725328372CC6143EF21EEE43A9FDE91FD3DC2EF3461C6805405"
OUTPUT_STEM = "arc1_v340_battle_choice_ui_geometry_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v339"
ANALYSIS = ROOT / "01_work/analysis/arc1_v340_battle_choice_ui_geometry"

ASSIGNMENTS = ROOT / "01_work/analysis/arc1_v320_hanme_static_recovery/character_assignments.csv"
ASSIGNMENTS_SHA256 = "933BDAC4BC4C39D33DB134D2FF836902B5053B93725C96E19DED714CB7DE98A4"
TRANSLATIONS = ROOT / "05_docs/script_translated_full.csv"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
RAM_TO_FILE = 0x8011A800
SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT_META = 0x7F

# V339 bottom-help producer.  0x0B produced runtime packet Y=214 in the
# uploaded states; 0x0A moves the whole object one pixel up.  The E7-only
# helper below restores controller icons by +1, leaving W=16 text at Y=213.
BATTLE_HELP_Y_RAM = 0x8016C7B0
BATTLE_HELP_Y_FILE = BATTLE_HELP_Y_RAM - RAM_TO_FILE
BATTLE_HELP_Y_OLD = 0x3406000B
BATTLE_HELP_Y_NEW = 0x3406000A
BATTLE_HELP_STATE = 0x801F0E18

# Existing E7 V helper and new second entry point.  The first entry remains
# equivalent for every possible v1: only v1 in {2,4,8,14} selects V=0xE4.
E7_V_HELPER_RAM = 0x8019D000
E7_V_HELPER_FILE = E7_V_HELPER_RAM - RAM_TO_FILE
E7_V_HELPER_SIZE = 0x48
E7_Y_HELPER_RAM = E7_V_HELPER_RAM + 0x2C
E7_Y_HOOK_RAM = 0x8016B6FC
E7_Y_HOOK_FILE = E7_Y_HOOK_RAM - RAM_TO_FILE
E7_Y_HOOK_OLD = 0x340501EB  # ori a1,zero,0x1EB
E7_Y_HOOK_DELAY = 0x34040010  # ori a0,zero,16
E7_CLUT_CALL = 0x0C05E399  # jal 0x80178E64
E7_PACKET_Y_STORE = 0xA602002E  # sh v0,0x2E(s0)
E7_V_SITE_RAM = 0x8016B6C8
E7_V_SITE_WORD = 0x0806724D  # j 0x8019C934
E7_V_TRAMPOLINE_RAM = 0x8019C934
E7_V_TRAMPOLINE_WORD = 0x08067400  # j 0x8019D000

E7_V_HELPER_OLD = (
    0x2468FFFE, 0x1100000C, 0x00000000, 0x2468FFFC,
    0x11000009, 0x00000000, 0x2468FFF8, 0x11000006,
    0x00000000, 0x2468FFF2, 0x11000003, 0x34020082,
    0x0806740F, 0x00000000, 0x340200E4, 0xA2020029,
    0x0805ADB4, 0x00000000,
)

# Configuration bar size at the config-only producer.
BAR_WIDTH_RAM = 0x801607A8
BAR_HEIGHT_RAM = 0x801607B0
BAR_WIDTH_FILE = BAR_WIDTH_RAM - RAM_TO_FILE
BAR_HEIGHT_FILE = BAR_HEIGHT_RAM - RAM_TO_FILE
BAR_WIDTH_OLD = 0x34050033   # 51
BAR_WIDTH_NEW = 0x3405003E   # 62
BAR_HEIGHT_OLD = 0x3406000E  # 14
BAR_HEIGHT_NEW = 0x34060010  # 16
BAR_CALL_WORD = 0x0C05B57B   # jal 0x8016D5EC

# Canonical V320 direct encodings.  These are also re-derived from the
# assignment CSV before any write is allowed.
PAYLOADS = {
    "물론": bytes.fromhex("6D DF 30"),
    "괜찮아": bytes.fromhex("DD 3B DD 3A 09"),
    "괜찮다": bytes.fromhex("DD 3B DD 3A 01"),
    "싸운다": bytes.fromhex("DD 14 86 01"),
    "간다": bytes.fromhex("DD 1B 01"),
}


@dataclass(frozen=True)
class SlotRepair:
    member: str
    slot: int
    text: str
    old: bytes


@dataclass(frozen=True)
class InlineRepair:
    member: str
    body: int
    offset: int
    text: str
    slot: int
    old: bytes


SLOT_REPAIRS = tuple(
    SlotRepair(member, slot, text, bytes.fromhex(old))
    for member, rows in (
        ("C1/SC011.DAT", ((6, "물론", "AA E1 C7"), (9, "괜찮아", "DF 85 DF ED 95"),
                           (12, "괜찮다", "DF 85 DF ED 78"), (17, "싸운다", "DE AD DA 78"))),
        ("C1/SC021.DAT", ((6, "물론", "AA E1 C7"), (9, "괜찮아", "DF 85 DF ED 95"),
                           (12, "괜찮다", "DF 85 DF ED 78"), (17, "싸운다", "DE AD DA 78"))),
        ("C1/SC031.DAT", ((6, "물론", "AA E1 C7"), (9, "괜찮아", "DF 85 DF ED 95"),
                           (12, "괜찮다", "DF 85 DF ED 78"), (17, "싸운다", "DE AD DA 78"))),
        ("C1/SC051.DAT", ((6, "물론", "AA E1 C7"), (9, "괜찮아", "DF 85 DF ED 95"),
                           (12, "괜찮다", "DF 85 DF ED 78"), (17, "싸운다", "DE AD DA 78"))),
        ("C1/SC061.DAT", ((11, "물론", "AA E1 C7"), (14, "괜찮아", "DF 85 DF ED 95"),
                           (17, "괜찮다", "DF 85 DF ED 78"), (22, "싸운다", "DE AD DA 78"))),
        ("C1/SC081.DAT", ((13, "괜찮다", "DF 85 DF ED 78"), (16, "간다", "DE C5 78"))),
        ("C2/SC0A1.DAT", ((8, "괜찮아", "DF 85 DF ED 95"),
                           (11, "괜찮다", "DF 85 DF ED 78"), (15, "싸운다", "DE AD DA 78"))),
    )
    for slot, text, old in rows
)

# SC041 had four answers left inline.  Reuse its four proven unreferenced
# legacy answer slots.  disk_id() accounts for reserved original ID 0xA9.
SC041_SLOT_REPAIRS = (
    SlotRepair("C1/SC041.DAT", 35, "물론", bytes.fromhex("AA DF D1")),
    SlotRepair("C1/SC041.DAT", 38, "괜찮아", bytes.fromhex("DF 85 DF ED 95")),
    SlotRepair("C1/SC041.DAT", 41, "괜찮다", bytes.fromhex("E0 3F DF ED 78")),
    SlotRepair("C1/SC041.DAT", 46, "싸운다", bytes.fromhex("E0 FB DA 78")),
)
INLINE_REPAIRS = (
    InlineRepair("C1/SC041.DAT", 0x46EAA, 0x46EBA, "물론", 35, bytes.fromhex("7E A1")),
    InlineRepair("C1/SC041.DAT", 0x46F0E, 0x46F20, "괜찮아", 38, bytes.fromhex("7E A1")),
    InlineRepair("C1/SC041.DAT", 0x46F74, 0x46F84, "괜찮다", 41, bytes.fromhex("7E A1")),
    InlineRepair("C1/SC041.DAT", 0x47034, 0x4703F, "싸운다", 46, bytes.fromhex("53 01")),
)
ALL_SLOT_REPAIRS = SLOT_REPAIRS + SC041_SLOT_REPAIRS
CHANGED_DATS = tuple(dict.fromkeys(repair.member for repair in ALL_SLOT_REPAIRS))


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


def jump(address: int, link: bool = False) -> int:
    return ((3 if link else 2) << 26) | ((address >> 2) & 0x03FFFFFF)


def disk_id(slot: int) -> int:
    if not 0 <= slot < 79:
        raise BuildError(f"slot outside expanded E2 bank: {slot}")
    return slot + (0x81 if slot < 40 else 0x82)


def slot_from_disk_id(value: int) -> int:
    if 0x81 <= value <= 0xA8:
        return value - 0x81
    if 0xAA <= value <= 0xD0:
        return value - 0x82
    raise BuildError(f"not an expanded E2 disk id: 0x{value:02X}")


def build_e7_helper() -> tuple[bytes, tuple[int, ...]]:
    """Return exact-equivalent V routing plus help-object-only Y compensation."""
    zero, v0, v1, a1, t0, s0, s1, ra = 0, 2, 3, 5, 8, 16, 17, 31
    words = (
        i_type(0x0B, v1, t0, 15),                   # sltiu t0,v1,15
        i_type(0x04, t0, zero, 7),                  # beqz t0,store
        i_type(0x0D, zero, v0, 0x82),               # delay: default V
        i_type(0x0D, zero, t0, 0x4114),             # bitset {2,4,8,14}
        r_type(v1, t0, t0, 0, 0x06),                # srlv t0,t0,v1
        i_type(0x0C, t0, t0, 1),                    # andi t0,t0,1
        i_type(0x04, t0, zero, 2),                  # beqz t0,store
        0,
        i_type(0x0D, zero, v0, 0xE4),               # controller V
        jump(0x8016B6D0),                           # return to stock E7 path
        i_type(0x28, s0, v0, 0x29),                 # delay: sb v0,0x29(s0)
        i_type(0x0F, zero, t0, 0x801F),             # Y helper entry 0x8019D02C
        i_type(0x09, t0, t0, 0x0E18),               # exact state pointer
        i_type(0x05, s1, t0, 2),                    # bne s1,t0,return
        0,
        i_type(0x09, v0, v0, 1),                    # bottom-help E7 Y +1
        r_type(ra, zero, zero, 0, 0x08),            # jr ra
        i_type(0x0D, zero, a1, 0x01EB),             # delay: restore CLUT arg
    )
    code = struct.pack("<18I", *words)
    if len(code) != E7_V_HELPER_SIZE:
        raise BuildError("E7 helper size drift")
    return code, words


def load_preferred_codes() -> dict[str, bytes]:
    if sha256_bytes(ASSIGNMENTS.read_bytes()) != ASSIGNMENTS_SHA256:
        raise BuildError("character assignment CSV hash drift")
    candidates: dict[str, list[bytes]] = defaultdict(list)
    with ASSIGNMENTS.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            candidates[row["char"]].append(bytes.fromhex(row["code_hex"]))
    preferred = {char: min(codes, key=lambda code: (len(code), code)) for char, codes in candidates.items()}
    for text, expected in PAYLOADS.items():
        actual = b"".join(preferred[char] for char in text)
        if actual != expected:
            raise BuildError(f"canonical encoding drift for {text}: {actual.hex()}")
    return preferred


def load_approved_answers() -> dict[tuple[str, int], str]:
    expected_offsets = {
        (member, offset)
        for member in v128.BATTLE_FILES
        for offset in v128.OFFSETS[member]
    }
    answers: dict[tuple[str, int], str] = {}
    with TRANSLATIONS.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            key = (row["source file"], int(row["offset"], 16))
            if key not in expected_offsets:
                continue
            parts = row["korean"].split("|")
            if len(parts) != 3:
                raise BuildError(f"battle translation is not prompt|accept|decline: {key}")
            if key in answers:
                raise BuildError(f"duplicate battle translation row: {key}")
            answers[key] = parts[1]
    if set(answers) != expected_offsets or len(answers) != 63:
        raise BuildError(f"approved battle answer census drift: {len(answers)}/63")
    return answers


def tokenize(payload: bytes) -> list[bytes]:
    tokens: list[bytes] = []
    at = 0
    while at < len(payload):
        width = v320.token_width(payload[at])
        if at + width > len(payload):
            raise BuildError("truncated glyph token")
        token = payload[at:at + width]
        if v320.is_control(payload, at):
            raise BuildError(f"control token inside answer payload: {token.hex()}")
        tokens.append(token)
        at += width
    return tokens


def token_plane(exe: bytes, comm: bytes, token: bytes) -> tuple[int, ...]:
    index = v320.direct_index(token)
    if index is None:
        slot = v320.virtual_slot(token)
        if slot is None:
            raise BuildError(f"undecodable answer token: {token.hex()}")
        index = v320.lookup_get(exe, slot)
    return v320.read_plane(comm, index)


def payload_planes(exe: bytes, comm: bytes, payload: bytes) -> tuple[tuple[int, ...], ...]:
    return tuple(token_plane(exe, comm, token) for token in tokenize(payload))


def read_slot(data: bytes | bytearray, slot: int) -> bytes:
    start = SLOT_BASE + slot * SLOT_SIZE
    try:
        end = data.index(0, start, start + SLOT_META)
    except ValueError as error:
        raise BuildError(f"unterminated E2 slot {slot}") from error
    return bytes(data[start:end])


def answer_payload(data: bytes, body_offset: int) -> bytes:
    end = data.find(b"\x00", body_offset, body_offset + 0x80)
    if end < 0:
        raise BuildError(f"body 0x{body_offset:X} has no terminator")
    body = data[body_offset:end]
    e5 = [at for at, value in enumerate(body) if value == 0xE5]
    e6 = [at for at, value in enumerate(body) if value == 0xE6]
    if len(e5) != 2 or len(e6) < 2:
        raise BuildError(f"choice topology drift at 0x{body_offset:X}")
    start = e5[0] + 2
    if body[start] == 0xE2:
        slot = slot_from_disk_id(body[start + 1])
        return read_slot(data, slot)
    finish = min(at for at in e6 if at > start)
    return bytes(body[start:finish]).rstrip(b"\xA1")


def e5_e6_topology(data: bytes) -> dict[tuple[str, int], tuple[tuple[int, ...], tuple[int, ...]]]:
    result: dict[tuple[str, int], tuple[tuple[int, ...], tuple[int, ...]]] = {}
    for member in v128.BATTLE_FILES:
        block = data if member == "" else None
        del block
    return result


def choice_audit(members: dict[str, bytes], approved: dict[tuple[str, int], str],
                 preferred: dict[str, bytes]) -> list[dict[str, object]]:
    exe, comm = members[PSX], members[COMM]
    rows: list[dict[str, object]] = []
    for member in v128.BATTLE_FILES:
        data = members[member]
        for index, body in enumerate(v128.OFFSETS[member]):
            current = answer_payload(data, body)
            text = approved[(member, body)]
            expected = b"".join(preferred[char] for char in text)
            match = payload_planes(exe, comm, current) == payload_planes(exe, comm, expected)
            rows.append({
                "member": member,
                "row": index,
                "body": f"0x{body:X}",
                "approved_answer": text,
                "payload_hex": current.hex(" ").upper(),
                "canonical_hex": expected.hex(" ").upper(),
                "bitmap_match": int(match),
            })
    if len(rows) != 63:
        raise BuildError(f"choice audit census drift: {len(rows)}")
    return rows


def control_edges(exe: bytes, lo: int, hi: int) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    text_size = word(exe, 0x1C)
    for at in range(0x800, min(len(exe), 0x800 + text_size), 4):
        instruction = word(exe, at)
        op = instruction >> 26
        pc = at + RAM_TO_FILE
        target: int | None = None
        if op in (2, 3):
            target = ((pc + 4) & 0xF0000000) | ((instruction & 0x03FFFFFF) << 2)
        elif op in (4, 5, 6, 7):
            immediate = instruction & 0xFFFF
            if immediate & 0x8000:
                immediate -= 0x10000
            target = (pc + 4 + immediate * 4) & 0xFFFFFFFF
        if target is not None and lo <= target < hi:
            result.append((pc, target))
    return result


def assert_base(before: dict[str, bytes]) -> tuple[dict[str, bytes], list[dict[str, object]]]:
    if len(before) != 164:
        raise BuildError(f"V339 member count drift: {len(before)}")
    if sha256_bytes(before[PSX]) != BASE_PSX_SHA256:
        raise BuildError("V339 PSX hash drift")
    if sha256_bytes(before[COMM]) != BASE_COMM_SHA256:
        raise BuildError("V339 COMM hash drift")
    preferred = load_preferred_codes()
    approved = load_approved_answers()
    baseline = choice_audit(before, approved, preferred)
    mismatches = [row for row in baseline if not row["bitmap_match"]]
    if len(mismatches) != 29 or Counter(row["approved_answer"] for row in mismatches) != Counter(
        {"괜찮아": 7, "괜찮다": 8, "물론": 6, "싸운다": 7, "간다": 1}
    ):
        raise BuildError(f"V339 battle-answer mismatch census drift: {len(mismatches)}")

    exe = before[PSX]
    if word(exe, BATTLE_HELP_Y_FILE) != BATTLE_HELP_Y_OLD:
        raise BuildError("V339 bottom-help Y anchor drift")
    if struct.unpack_from("<18I", exe, E7_V_HELPER_FILE) != E7_V_HELPER_OLD:
        raise BuildError("V339 E7 V helper drift")
    if word(exe, E7_V_SITE_RAM - RAM_TO_FILE) != E7_V_SITE_WORD:
        raise BuildError("V339 E7 V site drift")
    if word(exe, E7_V_TRAMPOLINE_RAM - RAM_TO_FILE) != E7_V_TRAMPOLINE_WORD:
        raise BuildError("V339 E7 V trampoline drift")
    if word(exe, E7_Y_HOOK_FILE) != E7_Y_HOOK_OLD:
        raise BuildError("V339 E7 Y hook anchor drift")
    if word(exe, E7_Y_HOOK_FILE + 4) != E7_Y_HOOK_DELAY:
        raise BuildError("V339 E7 Y hook delay slot drift")
    if word(exe, E7_Y_HOOK_FILE + 8) != E7_CLUT_CALL or word(exe, E7_Y_HOOK_FILE + 12) != E7_PACKET_Y_STORE:
        raise BuildError("V339 E7 CLUT/Y-store context drift")
    external = [edge for edge in control_edges(exe, E7_V_HELPER_RAM, E7_V_HELPER_RAM + E7_V_HELPER_SIZE)
                if not E7_V_HELPER_RAM <= edge[0] < E7_V_HELPER_RAM + E7_V_HELPER_SIZE]
    # 0x80197FC4 is an aligned word inside the mixed UI string/data pool that
    # decodes as a branch to 0x8019D018; it is not reachable code and already
    # targeted the middle of the V339 helper.  Pin it so a new surprise edge
    # cannot be silently accepted.
    expected_external = [
        (0x80197FC4, 0x8019D018),
        (E7_V_TRAMPOLINE_RAM, E7_V_HELPER_RAM),
    ]
    if external != expected_external:
        raise BuildError(f"V339 E7 helper external inbound topology drift: {external}")
    if word(exe, BAR_WIDTH_FILE) != BAR_WIDTH_OLD or word(exe, BAR_HEIGHT_FILE) != BAR_HEIGHT_OLD:
        raise BuildError("V339 configuration bar size anchor drift")
    if word(exe, BAR_WIDTH_FILE + 4) != BAR_CALL_WORD:
        raise BuildError("configuration bar call context drift")

    # Exact DAT premises, metadata, and unreferenced SC041 target slots.
    for repair in ALL_SLOT_REPAIRS:
        data = before[repair.member]
        start = SLOT_BASE + repair.slot * SLOT_SIZE
        if read_slot(data, repair.slot) != repair.old:
            raise BuildError(f"slot premise drift: {repair.member} slot {repair.slot}")
        if data[start + SLOT_META] != 0:
            raise BuildError(f"repair slot metadata is not zero: {repair.member} slot {repair.slot}")
    sc041 = before["C1/SC041.DAT"]
    target_ids = {disk_id(repair.slot) for repair in SC041_SLOT_REPAIRS}
    old_refs = Counter()
    for body in v128.OFFSETS["C1/SC041.DAT"]:
        end = sc041.find(b"\x00", body, body + 0x80)
        for at in range(body, end - 1):
            if sc041[at] == 0xE2 and sc041[at + 1] in target_ids:
                old_refs[sc041[at + 1]] += 1
    if old_refs:
        raise BuildError(f"SC041 target slots already referenced: {old_refs}")
    for repair in INLINE_REPAIRS:
        if sc041[repair.offset:repair.offset + len(repair.old)] != repair.old:
            raise BuildError(f"inline answer anchor drift at 0x{repair.offset:X}")
        if repair.offset < repair.body or repair.offset + 2 >= repair.body + 0x80:
            raise BuildError("inline repair outside declared body")
    return preferred, baseline


def marker_topology(members: dict[str, bytes]) -> dict[tuple[str, int], tuple[tuple[int, ...], tuple[int, ...]]]:
    result: dict[tuple[str, int], tuple[tuple[int, ...], tuple[int, ...]]] = {}
    for member in v128.BATTLE_FILES:
        data = members[member]
        for body in v128.OFFSETS[member]:
            end = data.find(b"\x00", body, body + 0x80)
            payload = data[body:end]
            e5 = tuple(at for at, value in enumerate(payload) if value == 0xE5)
            e6 = tuple(at for at, value in enumerate(payload) if value == 0xE6)
            result[(member, body)] = (e5, e6)
    return result


def build_once(before: dict[str, bytes]) -> tuple[dict[str, bytes], dict[str, object]]:
    preferred, baseline = assert_base(before)
    approved = load_approved_answers()
    final = dict(before)
    exe = bytearray(before[PSX])
    topology_before = marker_topology(before)

    helper, helper_words = build_e7_helper()
    write_word(exe, BATTLE_HELP_Y_FILE, BATTLE_HELP_Y_NEW)
    exe[E7_V_HELPER_FILE:E7_V_HELPER_FILE + E7_V_HELPER_SIZE] = helper
    write_word(exe, E7_Y_HOOK_FILE, jump(E7_Y_HELPER_RAM, link=True))
    write_word(exe, BAR_WIDTH_FILE, BAR_WIDTH_NEW)
    write_word(exe, BAR_HEIGHT_FILE, BAR_HEIGHT_NEW)
    final[PSX] = bytes(exe)

    repairs_by_member: dict[str, list[SlotRepair]] = defaultdict(list)
    for repair in ALL_SLOT_REPAIRS:
        repairs_by_member[repair.member].append(repair)
    for member, repairs in repairs_by_member.items():
        data = bytearray(before[member])
        for repair in repairs:
            start = SLOT_BASE + repair.slot * SLOT_SIZE
            payload = PAYLOADS[repair.text]
            if len(payload) != len(repair.old):
                raise BuildError(f"same-length slot invariant failed: {repair}")
            data[start:start + len(payload)] = payload
            if data[start + len(payload)] != 0 or data[start + SLOT_META] != 0:
                raise BuildError(f"slot terminator/metadata moved: {member} slot {repair.slot}")
        if member == "C1/SC041.DAT":
            for repair in INLINE_REPAIRS:
                replacement = bytes((0xE2, disk_id(repair.slot)))
                if len(replacement) != len(repair.old):
                    raise BuildError("SC041 inline replacement width drift")
                data[repair.offset:repair.offset + 2] = replacement
        final[member] = bytes(data)

    if marker_topology(final) != topology_before:
        raise BuildError("E5/E6 marker topology changed")
    final_audit = choice_audit(final, approved, preferred)
    if any(not row["bitmap_match"] for row in final_audit):
        raise BuildError("not all 63 battle answers match approved 16px bitmaps")

    # Each reused SC041 slot gains exactly one option caller, and its zero skip
    # metadata makes completion resume directly at the preserved E6 marker.
    sc041 = final["C1/SC041.DAT"]
    refs = Counter()
    for body in v128.OFFSETS["C1/SC041.DAT"]:
        end = sc041.find(b"\x00", body, body + 0x80)
        for at in range(body, end - 1):
            if sc041[at] == 0xE2:
                try:
                    refs[slot_from_disk_id(sc041[at + 1])] += 1
                except BuildError:
                    pass
    for repair in SC041_SLOT_REPAIRS:
        if refs[repair.slot] != 1:
            raise BuildError(f"SC041 slot {repair.slot} caller census={refs[repair.slot]}")

    # Exhaustive equivalence of the compressed V selector.
    for value in range(0x200):
        old_v = 0xE4 if value in (2, 4, 8, 14) else 0x82
        bit = ((0x4114 >> value) & 1) if value < 15 else 0
        new_v = 0xE4 if bit else 0x82
        if old_v != new_v:
            raise BuildError(f"E7 V helper equivalence failed for v1={value}")
    if word(final[PSX], E7_Y_HOOK_FILE + 4) != E7_Y_HOOK_DELAY:
        raise BuildError("E7 JAL delay slot changed")
    if word(final[PSX], E7_Y_HOOK_FILE + 8) != E7_CLUT_CALL:
        raise BuildError("E7 CLUT call moved")

    return final, {
        "helper_words": helper_words,
        "baseline_audit": baseline,
        "final_audit": final_audit,
    }


def changed_offsets(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise BuildError("member size changed")
    return {at for at, (old, new) in enumerate(zip(before, after, strict=True)) if old != new}


def allowed_offsets() -> dict[str, set[int]]:
    allowed: dict[str, set[int]] = defaultdict(set)
    for start, size in (
        (BATTLE_HELP_Y_FILE, 4), (E7_V_HELPER_FILE, E7_V_HELPER_SIZE),
        (E7_Y_HOOK_FILE, 4), (BAR_WIDTH_FILE, 4), (BAR_HEIGHT_FILE, 4),
    ):
        allowed[PSX].update(range(start, start + size))
    for repair in ALL_SLOT_REPAIRS:
        start = SLOT_BASE + repair.slot * SLOT_SIZE
        allowed[repair.member].update(range(start, start + len(repair.old)))
    for repair in INLINE_REPAIRS:
        allowed[repair.member].update(range(repair.offset, repair.offset + 2))
    return dict(allowed)


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        raise BuildError(f"refusing empty CSV: {path.name}")
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    if not BASE.is_file() or v324.sha256_file(BASE) != BASE_SHA256:
        raise BuildError(f"V339 base hash mismatch: {BASE}")
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
            if name == PSX:
                if E7_V_HELPER_FILE <= offset < E7_V_HELPER_FILE + E7_V_HELPER_SIZE:
                    purpose = "e7_v_equivalent_and_help_icon_y_compensation"
                elif offset in range(E7_Y_HOOK_FILE, E7_Y_HOOK_FILE + 4):
                    purpose = "e7_y_helper_call"
                elif offset in range(BATTLE_HELP_Y_FILE, BATTLE_HELP_Y_FILE + 4):
                    purpose = "bottom_help_text_y_minus_1"
                elif offset in range(BAR_WIDTH_FILE, BAR_WIDTH_FILE + 4):
                    purpose = "config_bar_width_51_to_62"
                else:
                    purpose = "config_bar_height_14_to_16"
            else:
                purpose = "approved_battle_answer_reencode"
            expected_rows.append({
                "member": name,
                "offset": f"0x{offset:X}",
                "before": f"{before[name][offset]:02X}",
                "after": f"{final[name][offset]:02X}",
                "purpose": purpose,
            })
    write_csv(ANALYSIS / "expected_writes.csv", expected_rows)
    write_csv(ANALYSIS / "battle_choice_before.csv", evidence["baseline_audit"])
    write_csv(ANALYSIS / "battle_choice_after.csv", evidence["final_audit"])
    write_csv(ANALYSIS / "e7_helper_words.csv", [
        {"index": index, "ram": f"0x{E7_V_HELPER_RAM + index * 4:08X}", "word": f"0x{value:08X}"}
        for index, value in enumerate(evidence["helper_words"])
    ])

    manifest = {
        "build": "V340 TEST_ONLY battle choice and battle UI geometry",
        "base": {"path": str(BASE), "sha256": BASE_SHA256},
        "output": {"path": str(output_path), "sha256": output_hash},
        "delta": {"path": str(delta_path), "sha256": delta_hash},
        "changed_members": changed_members,
        "changed_bytes": {name: len(actual[name]) for name in changed_members},
        "battle_choices": {
            "families": 9,
            "bodies": 63,
            "v339_bitmap_mismatches": 29,
            "v340_bitmap_mismatches": 0,
            "repaired_answers": dict(Counter(row["approved_answer"] for row in evidence["baseline_audit"] if not row["bitmap_match"])),
            "e5_e6_offsets": "63/63 unchanged",
        },
        "bottom_help": {
            "object": "0x801F0E18",
            "ordinary_W16": "predicted y 214 -> 213",
            "E7_W12_W20": "predicted y 214 -> 214",
            "implementation": "base y -1 plus object-scoped E7 +1 at existing 72-byte helper",
        },
        "configuration": {"bar": "51x14 -> 62x16", "text_and_bar_x": "unchanged from V339"},
        "runtime": "PENDING user cold boot",
        "release_status": "TEST_ONLY; DO NOT DISTRIBUTE",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V340 TEST ONLY - battle choice and battle UI geometry",
        f"base={BASE.name}",
        f"output={output_path.name}",
        f"sha256={output_hash}",
        f"delta={delta_path.name}",
        f"delta_sha256={delta_hash}",
        f"changed_members={','.join(changed_members)}",
        "battle_answers=29 stale visual payloads repaired; 63/63 bitmap match; E5/E6 unchanged",
        "bottom_help=ordinary W16 y-1; E7 W12/W20 current y retained",
        "configuration_bar=51x14 -> 62x16",
        "runtime=PENDING user cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    checklist = [
        "V340 cold-boot runtime checklist",
        "",
        "- Boot the newly packaged V340 cue from a cold emulator start.",
        "- Revisit the screenshot-1 battle question and confirm first answer is 괜찮아, not 4 호.",
        "- Sample the nine battle-question families; especially 물론/괜찮다/싸운다/간다 answers.",
        "- In bottom battle help, confirm ordinary Korean text moved up 1px while ○/□/×/START stayed put.",
        "- Open configuration: every blue bar must be 62px wide and 16px high; 안/함 bottom pixels must stay inside.",
        "- Confirm dialogue, item/equipment/skill names, acquisition/level-up banners and icons match V339.",
        "- Save fresh DUCCU states for runtime attribution.",
        "",
        "Static result: PASS in builder. Runtime result: PENDING.",
    ]
    (ANALYSIS / "runtime_checklist.txt").write_text("\n".join(checklist) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
