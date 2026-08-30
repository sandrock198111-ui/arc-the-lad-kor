#!/usr/bin/env python3
"""Build V345: restore Orkas-stone wording/timing and live range cursors.

This build is deliberately based on the runtime-working V344 archive.

Data fixes:

* repair the equal-width ``스톤 서서`` glyph token to ``스톤 서클``;
* standardize two adjacent 4/S4031 lines on V210's ``고대의 기록`` term,
  without moving either body, its terminator, or any control marker;
* move the already-visible Korean 4/S4041 stone message to a proven-free
  external slot and restore the pristine body tail so completion resumes at
  the stock ``E4 79 E4 3D E4 3D`` control run.

Executable fix:

* restore only the four V341 item/skill range-cursor refresh ranges that V342
  rolled back.  The V343 RA-safe W16 hook and every later V344 byte remain
  intact.

The V199 no-relocation recovery bodies and V210 D/SD031 controls are guarded
and remain byte exact.  No member changes size.
"""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import sys
from collections import defaultdict
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import build_arc1_v320_hanme_static_recovery as v320  # noqa: E402
import build_arc1_v323_skill_range_relocation as v323  # noqa: E402
import build_arc1_v324_static_ui_cursor_recovery as v324  # noqa: E402
import build_arc1_v343_ra_safe_w16_hook as v343  # noqa: E402


BASE = ROOT / "03_output/arc1_v344_location_name_vertical_center_TEST_ONLY_69B3EC07.zip"
BASE_SHA256 = "69B3EC07D300C28EF6C7F42588E6B392025F0392AE1207A586562B0D23001886"
BASE_PSX_SHA256 = "0CB561EC6B79BCF06F45D5F1D9E62DE7ABB7F545A4099127AAC2EA7D5165DF70"
V340 = ROOT / "03_output/arc1_v340_battle_choice_ui_geometry_TEST_ONLY_3F63BFD1.zip"
V340_SHA256 = "3F63BFD149A100152DE8B1B3223136CC501AF5AC19E19F443D4519142F9C783E"
V341 = ROOT / "03_output/arc1_v341_runtime_ui_recovery_TEST_ONLY_FCAF5CFB.zip"
V341_SHA256 = "FCAF5CFB8BAC230A041DC68E9B23B0F6916112D8F5406B2312DD19CE2A4E33D2"
V341_PSX_SHA256 = "A1FBE5F54F4669D2A4DDF1049B8CCD98C8C085FE09799C014513DA7C454FDDFF"
PRISTINE = ROOT / "00_original/arc.zip"
OUTPUT_STEM = "arc1_v345_story_timing_cursor_recovery_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v344"
ANALYSIS = ROOT / "01_work/analysis/arc1_v345_story_timing_cursor_recovery"

ASSIGNMENTS = ROOT / "01_work/analysis/arc1_v320_hanme_static_recovery/character_assignments.csv"
ASSIGNMENTS_SHA256 = "933BDAC4BC4C39D33DB134D2FF836902B5053B93725C96E19DED714CB7DE98A4"
ATLAS = ROOT / "01_work/analysis/arc1_v319_pilgi16_integration/atlas_mapping.csv"
ATLAS_SHA256 = "9553E7643621CC80C23355067611EAE7650FEF7CB547DC9115B62157DB0C3122"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
S4031 = "4/S4031.DAT"
S4041 = "4/S4041.DAT"
SD031 = "D/SD031.DAT"
SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT_COUNT = 64
SLOT_META = 0x7F
PAD = 0xA1

BASE_MEMBER_SHA256 = {
    COMM: "A6681F1355007725328372CC6143EF21EEE43A9FDE91FD3DC2EF3461C6805405",
    S4031: "7D81278E09FE6FC7D04230C160B4D4BFC20B6E5BF8B3B9DF72C4A0B39E075B67",
    S4041: "06F007C647FFB66C7F560CE882237958CC290B8B216B8261959D8158DA095E3E",
    SD031: "11DDDE33D07E3E26FDA993E753CFEEE5559679D0A902B1FF20065B9C6AE1B789",
    "4/S4021.DAT": "BB07EE131F48005359B38FDE8E4C8D10A2FF2DE09B6B5862FF1ED503A0C5DC2D",
    "4/S4022.DAT": "6474F028B069A147896E4D41F3301723B64AC8B817E8ADFAF85D3EE65662CB4B",
    "F/SF081.DAT": "7BEA54E4DB7EA72CEFBF1971A926215C45787FF1CE4A10C851646F9D92B93E1C",
}

# Same-size in-place text repairs.  The expected encodings are pinned so a
# future assignment-table change cannot silently alter this build.
S4031_TEXT_A_AT = 0x47F7A
S4031_TEXT_A_ROOM = 40
S4031_TEXT_A = "앞으로 네 여행에 도움이 될 고대의 기록은 토우빌 안쪽,"
S4031_TEXT_A_CODE = bytes.fromhex(
    "DD BA 4E D5 A1 7E A1 1A DD 31 0E A1 33 DD 70 03 A1 DD D9 A1 "
    "1C 37 0F A1 24 DD 72 26 A1 83 3D DD A7 A1 94 DD 69 0D"
)
S4031_TEXT_B_AT = 0x48516
S4031_TEXT_B_ROOM = 19
S4031_TEXT_B = "좋아! 고대의 기록을 찾자."
S4031_TEXT_B_CODE = bytes.fromhex(
    "DD 0D 09 02 A1 1C 37 0F A1 24 DD 72 0D A1 DD 56 28 0F"
)
S4031_OLD_A = bytes.fromhex(
    "DD BA 4E DD 04 A1 7E A1 1A DD 31 0E A1 33 DD 70 DD 01 A1 DD "
    "D9 A1 DE 4E A1 4F 24 06 A1 83 3D DD A7 A1 94 DD 69 0F A1 A1"
)
S4031_OLD_B = bytes.fromhex(
    "DD 0D 09 A9 A1 3D DD 53 A1 4F 24 36 A1 85 0E A1 6F 28 21"
)

# Slot 34 owns the 0x47FD4 E2 A3 body.  Only the second 서 token changes,
# keeping the two-byte width, reference, completion and all neighboring bytes.
S4031_CIRCLE_BODY = 0x47FD4
S4031_CIRCLE_SLOT = 34
S4031_CIRCLE_TOKEN_AT = SLOT_BASE + S4031_CIRCLE_SLOT * SLOT_SIZE + 0x10
S4031_CIRCLE_OLD = bytes.fromhex("E9 88")
S4031_CIRCLE_NEW = bytes.fromhex("DE 01")  # direct physical 475 == 클
S4031_SLOT34_SHA256 = "4F8FD6CFFBFBDDC9387E14A1CB9820C125110C12816363312FAED59BB8D761E2"

# The visible Korean body is 41 bytes plus two padding cells.  Store those 41
# bytes in free slot 4.  Completion 35 resumes at body relative 37, the stock
# E4 79, while the body tail itself is returned byte-for-byte to pristine.
S4041_BODY_AT = 0x47AA4
S4041_BODY_ROOM = 43
S4041_SLOT = 4
S4041_PAYLOAD_LEN = 41
S4041_COMPLETION = 35
S4041_RESUME_REL = 37
S4041_CURRENT_BODY = bytes.fromhex(
    "72 0E A1 DE 04 DD 26 A1 24 DD 52 0D A1 09 06 A1 28 1A B3 A1 "
    "15 A1 74 4E DD 04 A1 47 A1 DE 90 0E A1 DE 17 DE A0 19 DD 05 "
    "21 A1 A1"
)
S4041_STOCK_BODY = bytes.fromhex(
    "94 23 DD B9 39 1E DD F5 DE FA 2F DE 79 51 1E 7E E6 01 E6 01 "
    "41 1C 61 2F 38 29 21 BE 2A DD E2 23 2E 1F 46 3D 37 E4 79 E4 "
    "3D E4 3D"
)
S4041_FINAL_CONTROLS = bytes.fromhex("E4 79 E4 3D E4 3D")
S4041_SLOT4_SHA256 = "38723A2E5E8A17AA7950DC008209944E898F69A7BD10A23C839D341E935FD5CA"

# Exactly the four ranges V342 rolled back.  Copy their V341 bytes; do not
# regenerate them from assumptions.
CURSOR_RANGES = (
    ("frame_predrawot_gate", 0x2060, 4),
    ("restore_stock_range_initializer", 0x3E14, 8),
    ("active_owner_cursor_gate", 0x75590, 0x34),
    ("uploader_drawot_epilogue", 0x8F0D0, 36),
)
FRAME_DELAY_FILE = 0x2064
FRAME_DELAY_WORD = 0x26040070
LOCATION_Y_FILE = 0x51DE8
LOCATION_Y_WORD = 0x34020004

# V199 fixed-body topology that must not regress again.
V199_GUARDS = (
    ("4/S4021.DAT", 0x47992, 32, False, ()),
    ("4/S4021.DAT", 0x47AFA, 25, False, ()),
    ("4/S4021.DAT", 0x47B8E, 30, True, ((8, 0xE6, 0x01), (21, 0xE6, 0x01))),
    ("4/S4022.DAT", 0x47A0C, 40, True, ((4, 0xE6, 0x01),)),
    ("4/S4022.DAT", 0x47AFA, 33, True, ((12, 0xE6, 0x01), (21, 0xE6, 0x01))),
    ("4/S4022.DAT", 0x47D34, 37, True, ((4, 0xE6, 0x01), (15, 0xE6, 0x01))),
    ("4/S4022.DAT", 0x47E1E, 26, False, ()),
    ("F/SF081.DAT", 0x479EC, 33, False, ()),
)


class BuildError(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def word(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def body(data: bytes | bytearray, offset: int) -> bytes:
    end = bytes(data).find(b"\0", offset)
    if end < 0:
        raise BuildError(f"unterminated body at 0x{offset:X}")
    return bytes(data[offset:end])


def marker_topology(payload: bytes) -> tuple[tuple[int, int, int], ...]:
    return tuple(
        (index, payload[index], payload[index + 1])
        for index in range(len(payload) - 1)
        if payload[index] in (0xE4, 0xE5, 0xE6)
    )


def disk_id(slot: int) -> int:
    return slot + (0x81 if slot < 40 else 0x82)


def slot_block(data: bytes | bytearray, slot: int) -> bytes:
    start = SLOT_BASE + slot * SLOT_SIZE
    return bytes(data[start:start + SLOT_SIZE])


def slot_references(data: bytes | bytearray, slot: int) -> list[int]:
    wanted = bytes((0xE2, disk_id(slot)))
    result: list[int] = []
    cursor = SLOT_BASE + SLOT_COUNT * SLOT_SIZE
    source = bytes(data)
    while True:
        cursor = source.find(wanted, cursor)
        if cursor < 0:
            return result
        result.append(cursor)
        cursor += 2


def read_archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        return names, {name: archive.read(name) for name in names}


def write_archive(path: Path, names: list[str], members: dict[str, bytes]) -> None:
    with ZipFile(path, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for name in names:
            info = ZipInfo(name, date_time=(2026, 8, 30, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, members[name], compress_type=ZIP_DEFLATED, compresslevel=9)


def changed_offsets(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise BuildError("member size changed")
    return {
        index for index, pair in enumerate(zip(before, after, strict=True))
        if pair[0] != pair[1]
    }


def character_codes() -> dict[str, bytes]:
    if sha(ASSIGNMENTS.read_bytes()) != ASSIGNMENTS_SHA256:
        raise BuildError("character assignments hash drift")
    if sha(ATLAS.read_bytes()) != ATLAS_SHA256:
        raise BuildError("atlas mapping hash drift")
    candidates: dict[str, list[bytes]] = defaultdict(list)
    with ASSIGNMENTS.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            char = row.get("char", "")
            code = row.get("code_hex", "").replace(" ", "")
            if len(char) == 1 and code:
                candidates[char].append(bytes.fromhex(code))
    with ATLAS.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        char = row.get("char", "")
        code = v320.encode_index(int(row["index"]))
        if len(char) == 1 and code is not None:
            candidates[char].append(code)
    candidates[" "].append(bytes((PAD,)))
    candidates[","].append(bytes((0x0D,)))
    candidates["."].append(bytes((0x0F,)))
    candidates["!"].append(bytes((0x02,)))
    candidates["?"].append(bytes.fromhex("E0 47"))
    selected = {
        char: min(values, key=lambda value: (len(value), value))
        for char, values in candidates.items()
    }
    if int(rows[475]["index"]) != 475 or rows[475]["char"] != "클":
        raise BuildError("physical 475 no longer owns 클")
    if v320.encode_index(475) != S4031_CIRCLE_NEW:
        raise BuildError("physical 475 direct code drift")
    return selected


def encode(text: str, table: dict[str, bytes]) -> bytes:
    missing = sorted({char for char in text if char not in table})
    if missing:
        raise BuildError(f"missing glyphs for {text!r}: {missing}")
    payload = b"".join(table[char] for char in text)
    if not payload or 0 in payload:
        raise BuildError(f"invalid encoded payload for {text!r}")
    return payload


def assert_v199_guards(members: dict[str, bytes]) -> None:
    for member, offset, expected_len, expected_e2, expected_markers in V199_GUARDS:
        payload = body(members[member], offset)
        actual = (len(payload), payload.startswith(b"\xE2"), marker_topology(payload))
        expected = (expected_len, expected_e2, expected_markers)
        if actual != expected:
            raise BuildError(f"V199 topology drift: {member} 0x{offset:X} {actual} != {expected}")


def assert_v210_sd031(data: bytes) -> None:
    checks = (
        (0x45AAA, 14, bytes.fromhex("E6 01")),
        (0x45B3E, 4, bytes.fromhex("E6 01")),
        (0x463DA, 5, bytes.fromhex("E4 1F E6 01")),
        (0x463DA, 23, bytes.fromhex("E4 3D")),
        (0x463FC, 17, bytes.fromhex("E4 3D")),
    )
    for offset, relative, expected in checks:
        if data[offset + relative:offset + relative + len(expected)] != expected:
            raise BuildError(f"V210 SD031 control drift at 0x{offset + relative:X}")


def assert_base(base: dict[str, bytes], v340: bytes, v341: bytes, pristine: dict[str, bytes]) -> None:
    if len(base) != 164 or sha(base[PSX]) != BASE_PSX_SHA256:
        raise BuildError("V344 member topology or PSX hash drift")
    for member, expected in BASE_MEMBER_SHA256.items():
        if sha(base[member]) != expected:
            raise BuildError(f"V344 member hash drift: {member}")
    if sha(v341) != V341_PSX_SHA256:
        raise BuildError("V341 PSX hash drift")

    for label, offset, size in CURSOR_RANGES:
        if base[PSX][offset:offset + size] != v340[offset:offset + size]:
            raise BuildError(f"V344 is not V340-rolled-back at {label}")
        if v341[offset:offset + size] == v340[offset:offset + size]:
            raise BuildError(f"V341 cursor source unexpectedly equals V340 at {label}")
    if word(base[PSX], FRAME_DELAY_FILE) != FRAME_DELAY_WORD:
        raise BuildError("DrawOT delay slot drift")
    if word(base[PSX], v343.HOOK_FILE) != v343.NEW_HOOK:
        raise BuildError("V343 RA-safe W16 hook drift")
    if word(base[PSX], v343.HELPER_TAIL_FILE) != v343.NEW_HELPER_TAIL:
        raise BuildError("V343 helper continuation drift")
    if word(base[PSX], v343.DELAY_FILE) != v343.HELPER_DELAY:
        raise BuildError("V343 helper delay slot drift")
    if word(base[PSX], LOCATION_Y_FILE) != LOCATION_Y_WORD:
        raise BuildError("V344 location-name centering drift")

    if body(base[S4031], S4031_TEXT_A_AT) != S4031_OLD_A:
        raise BuildError("S4031 first wording premise drift")
    if body(base[S4031], S4031_TEXT_B_AT) != S4031_OLD_B:
        raise BuildError("S4031 second wording premise drift")
    if sha(slot_block(base[S4031], S4031_CIRCLE_SLOT)) != S4031_SLOT34_SHA256:
        raise BuildError("S4031 slot34 drift")
    if base[S4031][S4031_CIRCLE_TOKEN_AT:S4031_CIRCLE_TOKEN_AT + 2] != S4031_CIRCLE_OLD:
        raise BuildError("S4031 wrong-circle token drift")
    if slot_references(base[S4031], S4031_CIRCLE_SLOT) != [S4031_CIRCLE_BODY]:
        raise BuildError("S4031 slot34 ownership drift")

    if body(base[S4041], S4041_BODY_AT) != S4041_CURRENT_BODY:
        raise BuildError("S4041 Korean body drift")
    if sha(slot_block(base[S4041], S4041_SLOT)) != S4041_SLOT4_SHA256:
        raise BuildError("S4041 slot4 is no longer zero")
    if slot_references(base[S4041], S4041_SLOT):
        raise BuildError("S4041 slot4 already has a caller")
    if body(pristine[S4041], S4041_BODY_AT) != S4041_STOCK_BODY:
        raise BuildError("pristine S4041 control body drift")
    if S4041_STOCK_BODY[S4041_RESUME_REL:] != S4041_FINAL_CONTROLS:
        raise BuildError("pristine S4041 final controls drift")
    if 2 + S4041_COMPLETION != S4041_RESUME_REL:
        raise BuildError("S4041 completion arithmetic drift")

    assert_v199_guards(base)
    assert_v210_sd031(base[SD031])


def build_once(
    base: dict[str, bytes], v340: bytes, v341: bytes, pristine: dict[str, bytes]
) -> tuple[dict[str, bytes], list[dict[str, object]]]:
    assert_base(base, v340, v341, pristine)
    table = character_codes()
    if encode(S4031_TEXT_A, table) != S4031_TEXT_A_CODE:
        raise BuildError("S4031 first encoded wording drift")
    if encode(S4031_TEXT_B, table) != S4031_TEXT_B_CODE:
        raise BuildError("S4031 second encoded wording drift")

    final = dict(base)
    story_rows: list[dict[str, object]] = []

    s4031 = bytearray(base[S4031])
    s4031[S4031_TEXT_A_AT:S4031_TEXT_A_AT + S4031_TEXT_A_ROOM] = (
        S4031_TEXT_A_CODE + bytes((PAD,)) * (S4031_TEXT_A_ROOM - len(S4031_TEXT_A_CODE))
    )
    s4031[S4031_TEXT_B_AT:S4031_TEXT_B_AT + S4031_TEXT_B_ROOM] = (
        S4031_TEXT_B_CODE + bytes((PAD,)) * (S4031_TEXT_B_ROOM - len(S4031_TEXT_B_CODE))
    )
    s4031[S4031_CIRCLE_TOKEN_AT:S4031_CIRCLE_TOKEN_AT + 2] = S4031_CIRCLE_NEW
    if body(s4031, S4031_TEXT_A_AT) != S4031_TEXT_A_CODE + b"\xA1\xA1":
        raise BuildError("S4031 first wording readback failed")
    if body(s4031, S4031_TEXT_B_AT) != S4031_TEXT_B_CODE + b"\xA1":
        raise BuildError("S4031 second wording readback failed")
    if slot_references(s4031, S4031_CIRCLE_SLOT) != [S4031_CIRCLE_BODY]:
        raise BuildError("S4031 slot34 ownership changed")
    if slot_block(s4031, S4031_CIRCLE_SLOT)[SLOT_META] != 24:
        raise BuildError("S4031 slot34 completion changed")
    final[S4031] = bytes(s4031)
    story_rows.extend((
        {"member": S4031, "offset": f"0x{S4031_TEXT_A_AT:X}", "mode": "inline_same_size", "room": 40, "used": 38, "text": S4031_TEXT_A},
        {"member": S4031, "offset": f"0x{S4031_CIRCLE_TOKEN_AT:X}", "mode": "equal_width_token", "room": 2, "used": 2, "text": "스톤 서서 -> 스톤 서클"},
        {"member": S4031, "offset": f"0x{S4031_TEXT_B_AT:X}", "mode": "inline_same_size", "room": 19, "used": 18, "text": S4031_TEXT_B},
    ))

    s4041 = bytearray(base[S4041])
    payload = S4041_CURRENT_BODY[:S4041_PAYLOAD_LEN]
    block = bytearray(SLOT_SIZE)
    block[:len(payload)] = payload
    block[len(payload)] = 0
    block[SLOT_META] = S4041_COMPLETION
    slot_at = SLOT_BASE + S4041_SLOT * SLOT_SIZE
    s4041[slot_at:slot_at + SLOT_SIZE] = block
    s4041[S4041_BODY_AT:S4041_BODY_AT + S4041_BODY_ROOM] = S4041_STOCK_BODY
    s4041[S4041_BODY_AT:S4041_BODY_AT + 2] = bytes((0xE2, disk_id(S4041_SLOT)))
    if slot_references(s4041, S4041_SLOT) != [S4041_BODY_AT]:
        raise BuildError("S4041 slot4 ownership readback failed")
    stored = slot_block(s4041, S4041_SLOT)
    if stored[:len(payload)] != payload or stored[len(payload)] != 0 or stored[SLOT_META] != S4041_COMPLETION:
        raise BuildError("S4041 slot4 payload/completion readback failed")
    new_body = body(s4041, S4041_BODY_AT)
    if new_body[2:] != S4041_STOCK_BODY[2:]:
        raise BuildError("S4041 body tail is not pristine")
    if new_body[S4041_RESUME_REL:] != S4041_FINAL_CONTROLS:
        raise BuildError("S4041 final controls not restored")
    final[S4041] = bytes(s4041)
    story_rows.append({
        "member": S4041,
        "offset": f"0x{S4041_BODY_AT:X}",
        "mode": "slot4_resume_stock_controls",
        "room": S4041_BODY_ROOM,
        "used": len(payload),
        "text": "돌에 잠든 기억을 아는 자여, 그 힘으로 내 뜻에 응답",
    })

    exe = bytearray(base[PSX])
    for _label, offset, size in CURSOR_RANGES:
        exe[offset:offset + size] = v341[offset:offset + size]
    final[PSX] = bytes(exe)

    # Post-build regression guards.
    if word(final[PSX], v343.HOOK_FILE) != v343.NEW_HOOK:
        raise BuildError("V343 RA-safe hook changed during cursor recovery")
    if word(final[PSX], v343.HELPER_TAIL_FILE) != v343.NEW_HELPER_TAIL:
        raise BuildError("V343 fixed continuation changed during cursor recovery")
    if word(final[PSX], LOCATION_Y_FILE) != LOCATION_Y_WORD:
        raise BuildError("V344 location Y changed during cursor recovery")
    for _label, offset, size in CURSOR_RANGES:
        if final[PSX][offset:offset + size] != v341[offset:offset + size]:
            raise BuildError(f"V341 cursor range readback failed at 0x{offset:X}")
    if final[COMM] != base[COMM] or final[SD031] != base[SD031]:
        raise BuildError("COMM or V210 SD031 changed")
    assert_v199_guards(final)
    assert_v210_sd031(final[SD031])
    return final, story_rows


def allowed_offsets() -> dict[str, set[int]]:
    result: dict[str, set[int]] = defaultdict(set)
    for _label, offset, size in CURSOR_RANGES:
        result[PSX].update(range(offset, offset + size))
    result[S4031].update(range(S4031_TEXT_A_AT, S4031_TEXT_A_AT + S4031_TEXT_A_ROOM))
    result[S4031].update(range(S4031_CIRCLE_TOKEN_AT, S4031_CIRCLE_TOKEN_AT + 2))
    result[S4031].update(range(S4031_TEXT_B_AT, S4031_TEXT_B_AT + S4031_TEXT_B_ROOM))
    result[S4041].update(range(SLOT_BASE + S4041_SLOT * SLOT_SIZE, SLOT_BASE + (S4041_SLOT + 1) * SLOT_SIZE))
    result[S4041].update(range(S4041_BODY_AT, S4041_BODY_AT + S4041_BODY_ROOM))
    return dict(result)


def purpose(member: str, offset: int) -> str:
    if member == PSX:
        for label, start, size in CURSOR_RANGES:
            if start <= offset < start + size:
                return label
    elif member == S4031:
        if S4031_TEXT_A_AT <= offset < S4031_TEXT_A_AT + S4031_TEXT_A_ROOM:
            return "standardize_ancient_record_first_line"
        if S4031_CIRCLE_TOKEN_AT <= offset < S4031_CIRCLE_TOKEN_AT + 2:
            return "stone_circle_equal_width_glyph_fix"
        if S4031_TEXT_B_AT <= offset < S4031_TEXT_B_AT + S4031_TEXT_B_ROOM:
            return "standardize_ancient_record_second_line"
    elif member == S4041:
        slot_start = SLOT_BASE + S4041_SLOT * SLOT_SIZE
        if slot_start <= offset < slot_start + SLOT_SIZE:
            return "timed_stone_message_slot4"
        if S4041_BODY_AT <= offset < S4041_BODY_AT + S4041_BODY_ROOM:
            return "restore_pristine_tail_and_resume_controls"
    raise BuildError(f"unclassified write {member} 0x{offset:X}")


def main() -> None:
    for path, expected in ((BASE, BASE_SHA256), (V340, V340_SHA256), (V341, V341_SHA256)):
        if not path.is_file() or sha(path.read_bytes()) != expected:
            raise BuildError(f"archive hash drift: {path.name}")
    names, base = read_archive(BASE)
    _v340_names, v340_members = read_archive(V340)
    _v341_names, v341_members = read_archive(V341)
    with ZipFile(PRISTINE) as archive:
        pristine = {S4041: archive.read(S4041)}

    final, story_rows = build_once(base, v340_members[PSX], v341_members[PSX], pristine)
    rebuilt, rebuilt_rows = build_once(base, v340_members[PSX], v341_members[PSX], pristine)
    if final != rebuilt or story_rows != rebuilt_rows:
        raise BuildError("in-memory deterministic rebuild mismatch")
    if any(len(final[name]) != len(base[name]) for name in names):
        raise BuildError("archive member size changed")

    changed_members = [name for name in names if base[name] != final[name]]
    expected_members = [S4031, S4041, PSX]
    if changed_members != expected_members:
        raise BuildError(f"changed member order/set drift: {changed_members}")
    actual = {name: changed_offsets(base[name], final[name]) for name in changed_members}
    allowed = allowed_offsets()
    for name in changed_members:
        if not actual[name] or not actual[name] <= allowed[name]:
            raise BuildError(f"Expected-Write envelope violation: {name}")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    temporary = ROOT / "03_output" / f"{OUTPUT_STEM}.zip"
    temporary_delta = ROOT / "03_output" / f"{DELTA_STEM}.zip"
    for path in (temporary, temporary_delta):
        if path.exists():
            path.unlink()
    write_archive(temporary, names, final)
    write_archive(temporary_delta, changed_members, final)
    output_hash = sha(temporary.read_bytes())
    delta_hash = sha(temporary_delta.read_bytes())
    output = temporary.with_name(f"{OUTPUT_STEM}_{output_hash[:8]}.zip")
    delta = temporary_delta.with_name(f"{DELTA_STEM}_{delta_hash[:8]}.zip")
    for source, target in ((temporary, output), (temporary_delta, delta)):
        if target.exists():
            if sha(target.read_bytes()) != sha(source.read_bytes()):
                raise BuildError(f"existing output differs: {target.name}")
            source.unlink()
        else:
            source.replace(target)

    expected_rows: list[dict[str, str]] = []
    for name in changed_members:
        for offset in sorted(actual[name]):
            expected_rows.append({
                "member": name,
                "offset": f"0x{offset:X}",
                "before": f"{base[name][offset]:02X}",
                "after": f"{final[name][offset]:02X}",
                "purpose": purpose(name, offset),
            })
    with (ANALYSIS / "expected_writes.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(expected_rows[0]))
        writer.writeheader()
        writer.writerows(expected_rows)
    with (ANALYSIS / "story_fixes.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(story_rows[0]))
        writer.writeheader()
        writer.writerows(story_rows)

    manifest = {
        "version": "V345",
        "status": "STATIC_PASS_RUNTIME_PENDING",
        "base": {"file": BASE.name, "sha256": BASE_SHA256, "runtime": "PASS_GAMEPLAY"},
        "output": {"file": output.name, "sha256": output_hash},
        "delta": {"file": delta.name, "sha256": delta_hash},
        "changed_members_vs_v344": changed_members,
        "changed_bytes": {name: len(actual[name]) for name in changed_members},
        "story": {
            "S4031": [S4031_TEXT_A, "오르카스 언덕의 스톤 서클에 남겨져 있다.", S4031_TEXT_B],
            "S4041": {
                "slot": S4041_SLOT,
                "payload_bytes": S4041_PAYLOAD_LEN,
                "completion": S4041_COMPLETION,
                "resume_relative": S4041_RESUME_REL,
                "restored_controls": S4041_FINAL_CONTROLS.hex(" ").upper(),
            },
        },
        "range_cursor": {
            "source": V341.name,
            "ranges": [{"purpose": label, "offset": f"0x{offset:X}", "size": size} for label, offset, size in CURSOR_RANGES],
            "V343_RA_safe_hook_preserved": True,
        },
        "regression_guards": {
            "V199_fixed_bodies": len(V199_GUARDS),
            "V210_SD031": "member and known controls byte exact",
            "COMM_IMG": "byte exact",
            "all_member_sizes": "byte exact",
        },
        "runtime": "PENDING user cold boot; TEST_ONLY",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V345 story timing + range cursor recovery",
        f"base={BASE.name} sha256={BASE_SHA256}",
        f"output={output.name} sha256={output_hash}",
        f"delta={delta.name} sha256={delta_hash}",
        f"PSX.EXE sha256={sha(final[PSX])}",
        f"changed_members={','.join(changed_members)}",
        f"changed_bytes={json.dumps({name: len(actual[name]) for name in changed_members}, ensure_ascii=False)}",
        "S4031=in-place ancient-record terminology + equal-width 서클 fix; body topology unchanged",
        "S4041=free slot4 + completion35 -> pristine E4 79/E4 3D/E4 3D",
        "cursor=V341 four exact ranges restored on V344; V343 RA-safe W16 hook preserved",
        "V199 safe-body topology and V210 SD031 controls guarded byte exact",
        "runtime=PENDING user cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    (ANALYSIS / "runtime_checklist.txt").write_text(
        "V345 cold-boot checklist\n"
        "1. DuckStation을 종료한 뒤 V345.cue를 콜드부팅하고 V345_1.mcd에서 불러온다.\n"
        "2. 오르카스 언덕 전후 문구가 '고대의 기록', '스톤 서클'로 보이는지 확인한다.\n"
        "3. 아이템과 스킬 사용 시 범위 타일/커서가 보이고 실제 선택 가능한지 확인한다.\n"
        "4. 돌 메시지가 입력 대기 없이 휘리릭 지나가지 않고 다음 진행도 반복하지 않는지 확인한다.\n"
        "5. V343 이후 대화/하단 도움말/지형명/UI 정렬과 아이콘이 그대로인지 확인한다.\n",
        encoding="utf-8",
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
