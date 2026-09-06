#!/usr/bin/env python3
"""Independent static verifier for V358.

The verifier does not import the V358 builder.  It compares the pinned V357
and V358 archives, checks the exact dialogue bytes and E2 ownership, decodes
the Korean payload through the independently loaded current code map, checks
the three MIPS immediates and their call topology, and verifies the delta and
Expected-Write ledger.
"""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from v354_dialogue_codec import load_v354, tokens  # noqa: E402


BASE = ROOT / "03_output/arc1_v357_user_reviewed_full_dialogue_bankb_TEST_ONLY_34854022.zip"
BASE_SHA256 = "34854022BB0CA1C17BF4D798B8405009F8CC04914253E1D48476B2A2DBC3397A"
FULL = ROOT / "03_output/arc1_v358_dialogue_target_panel_fix_TEST_ONLY_D499D9D4.zip"
FULL_SHA256 = "D499D9D463A66B343A9D794A49753454788B3F18C6DC38B7CDE7A77304838061"
DELTA = ROOT / "03_output/arc1_v358_dialogue_target_panel_fix_TEST_ONLY_delta_from_v357_AB190119.zip"
DELTA_SHA256 = "AB190119680DC4A0F5A46E619D01EF9AAD6F690ED3378B1B01CFB8A5C8E9164A"
ANALYSIS = ROOT / "01_work/analysis/arc1_v358_dialogue_target_panel_fix"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
DAT = "F/SF0F1.DAT"
SLOT_START = 0x45000
SLOT_META = 0x7F
CALLER = 0x47910
CALL = bytes.fromhex("E2 81")
METADATA = 0x2D
EXPECTED_TEXT = "알겠느냐? 우리에게 봉인의 기술 따위는 필요 없다. 산으로 돌아가는 건 다른 볼일이 있어서다."
OLD_PAYLOAD = bytes.fromhex(
    "DD 1E 54 DD 99 DD 51 B3 A1 3D 2E 0E 41 A1 DD B6 35 0F A1 24 DD E5 "
    "A1 DD B9 8E 06 A1 DE 4A 2C A1 71 01 21 A1 DD 45 4E DD 04 A1 72 09 "
    "0C 06 A1 81 0E 06 A1 01 DD BF A1 DD 1A 5F 0C A1 1F 01 21"
)
NEW_PAYLOAD = bytes.fromhex(
    "DD 1E 54 4D DD 51 D1 A1 3D 2E 0E 41 A1 DD B6 35 0F A1 24 DD E5 A1 "
    "DD B9 8E 06 A1 DE 4A 2C A1 71 01 21 A1 DD 45 4E D5 A1 72 09 0C 06 "
    "A1 DD 16 A1 01 DD BF A1 DD 50 6B 03 A1 1F 14 25 01 21"
)

RAM_TO_FILE = 0x8011A800
PANEL_FUNCTION_RAM = 0x80166AC4
PANEL_FUNCTION_FILE = 0x4C2C4
PANEL_CALLER_FILE = 0x4C098
PATCHES = (
    (0x4C2EC, 0x340600AC, 0x340600C6),
    (0x4C2F4, 0x34070022, 0x34070028),
    (0x4C334, 0x34050081, 0x34050083),
)
UI_POINTERS = (0x82374, 0x82378)
UI_RAW = (
    bytes.fromhex("35 6D 0D A1 DD 53 DF 9A 19 8C 2C"),
    bytes.fromhex("DD 47 31 19 3A A1 4F DD 39 36 A1 29 DD 64 DD 1D 07 01"),
)


def sha(value: bytes | Path) -> str:
    raw = value.read_bytes() if isinstance(value, Path) else value
    return hashlib.sha256(raw).hexdigest().upper()


def assert_hash(path: Path, expected: str, label: str) -> None:
    if not path.is_file() or sha(path) != expected:
        raise AssertionError(f"{label} hash drift")


def archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as z:
        names = [info.filename for info in z.infolist() if not info.is_dir()]
        return names, {name: z.read(name) for name in names}


def find_all(data: bytes, needle: bytes) -> list[int]:
    found: list[int] = []
    start = 0
    while True:
        at = data.find(needle, start)
        if at < 0:
            return found
        found.append(at)
        start = at + 1


def payload(data: bytes) -> bytes:
    raw = data[SLOT_START:SLOT_START + SLOT_META]
    end = raw.find(b"\0")
    if end < 0:
        raise AssertionError("unterminated slot0")
    return raw[:end]


def jal_word(target: int) -> int:
    return 0x0C000000 | ((target >> 2) & 0x03FFFFFF)


def aligned_word_hits(data: bytes, word: int) -> list[int]:
    needle = struct.pack("<I", word)
    return [offset for offset in range(0x800, len(data) - 3, 4) if data[offset:offset + 4] == needle]


def branch_targets(exe: bytes) -> dict[int, list[int]]:
    """Collect direct MIPS-I jump/branch targets in the loaded text image."""
    targets: dict[int, list[int]] = {}
    load = 0x8011B000
    for offset in range(0x800, len(exe) - 3, 4):
        word = struct.unpack_from("<I", exe, offset)[0]
        opcode = word >> 26
        pc = load + offset - 0x800
        target = None
        if opcode in (2, 3):
            target = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
        elif opcode in (1, 4, 5, 6, 7):
            imm = word & 0xFFFF
            if imm & 0x8000:
                imm -= 0x10000
            target = pc + 4 + (imm << 2)
        if target is not None:
            targets.setdefault(target, []).append(pc)
    return targets


def read_c_string(exe: bytes, pointer_file: int) -> bytes:
    pointer = struct.unpack_from("<I", exe, pointer_file)[0]
    offset = pointer - RAM_TO_FILE
    if not 0 <= offset < len(exe):
        raise AssertionError(f"UI pointer outside PSX.EXE: 0x{pointer:08X}")
    end = exe.find(b"\0", offset)
    if end < 0:
        raise AssertionError("unterminated UI string")
    return exe[offset:end]


def text_advance(raw: bytes) -> tuple[int, int]:
    stream = list(tokens(raw))
    advance = sum(6 if token == b"\xA1" else 14 for token in stream)
    visible_width = advance + 2  # final 16px sprite extends 2px past 14px advance
    return advance, visible_width


def main() -> None:
    assert_hash(BASE, BASE_SHA256, "V357 base")
    assert_hash(FULL, FULL_SHA256, "V358 full")
    assert_hash(DELTA, DELTA_SHA256, "V358 delta")
    old_names, old = archive(BASE)
    new_names, new = archive(FULL)
    if old_names != new_names or len(new_names) != 164:
        raise AssertionError("archive topology/order changed")
    changed = [name for name in old_names if old[name] != new[name]]
    if changed != [name for name in old_names if name in {DAT, PSX}]:
        raise AssertionError(f"changed-member drift: {changed}")
    for name in old_names:
        if len(old[name]) != len(new[name]):
            raise AssertionError(f"member size changed: {name}")

    if payload(old[DAT]) != OLD_PAYLOAD or payload(new[DAT]) != NEW_PAYLOAD:
        raise AssertionError("dialogue payload transition drift")
    if old[DAT][SLOT_START + SLOT_META] != METADATA or new[DAT][SLOT_START + SLOT_META] != METADATA:
        raise AssertionError("slot metadata changed")
    if find_all(old[DAT], CALL) != [CALLER] or find_all(new[DAT], CALL) != [CALLER]:
        raise AssertionError("E2 caller/ownership changed")
    expected_old_slot = OLD_PAYLOAD + b"\0" + bytes(SLOT_META - len(OLD_PAYLOAD) - 1) + bytes((METADATA,))
    expected_new_slot = NEW_PAYLOAD + b"\0" + bytes(SLOT_META - len(NEW_PAYLOAD) - 1) + bytes((METADATA,))
    if old[DAT][SLOT_START:SLOT_START + 0x80] != expected_old_slot:
        raise AssertionError("V357 slot0 padding drift")
    if new[DAT][SLOT_START:SLOT_START + 0x80] != expected_new_slot:
        raise AssertionError("V358 slot0 padding/readback drift")

    _v354_exe, _comm, _encoder, decoder = load_v354()
    decoded = "".join(decoder.get(token, f"<{token.hex().upper()}>") for token in tokens(NEW_PAYLOAD))
    if decoded != EXPECTED_TEXT:
        raise AssertionError(f"independent dialogue decode mismatch: {decoded!r}")
    structural = [token for token in tokens(NEW_PAYLOAD) if len(token) == 2 and 0xE2 <= token[0] <= 0xE8]
    if structural:
        raise AssertionError(f"unexpected control token in prose: {structural}")
    if sum(token == b"\x21" for token in tokens(NEW_PAYLOAD)) != 2:
        raise AssertionError("period token count is not 2")
    if sum(token == b"\xD1" for token in tokens(NEW_PAYLOAD)) != 1:
        raise AssertionError("question-mark token count is not 1")

    old_exe, new_exe = old[PSX], new[PSX]
    if PANEL_FUNCTION_RAM - RAM_TO_FILE != PANEL_FUNCTION_FILE:
        raise AssertionError("RAM/file coordinate conversion failed")
    if aligned_word_hits(new_exe, jal_word(PANEL_FUNCTION_RAM)) != [PANEL_CALLER_FILE]:
        raise AssertionError("panel function is not sole-called from 0x80166898")
    for offset, before, after in PATCHES:
        if struct.unpack_from("<I", old_exe, offset)[0] != before:
            raise AssertionError(f"V357 word drift at 0x{offset:X}")
        if struct.unpack_from("<I", new_exe, offset)[0] != after:
            raise AssertionError(f"V358 word mismatch at 0x{offset:X}")
    expected_psx_diff = {offset for offset, _before, _after in PATCHES}
    psx_diff = {
        offset for offset, (before, after) in enumerate(zip(old_exe, new_exe, strict=True))
        if before != after
    }
    if psx_diff != expected_psx_diff:
        raise AssertionError(f"PSX Expected-Write mismatch: {sorted(psx_diff ^ expected_psx_diff)}")
    targets = branch_targets(old_exe)
    unexpected_inbound = {
        f"0x{RAM_TO_FILE + offset:08X}": [f"0x{x:08X}" for x in targets.get(RAM_TO_FILE + offset, [])]
        for offset in expected_psx_diff if targets.get(RAM_TO_FILE + offset)
    }
    if unexpected_inbound:
        raise AssertionError(f"patched instruction has an inbound edge: {unexpected_inbound}")

    if struct.unpack_from("<I", new_exe, 0x4C2E4)[0] != 0x3404004A:
        raise AssertionError("panel x changed")
    if struct.unpack_from("<I", new_exe, 0x4C2E8)[0] != 0x3405006F:
        raise AssertionError("panel y changed")
    if struct.unpack_from("<I", new_exe, 0x4C2F8)[0] != 0x34040052:
        raise AssertionError("text x changed")
    if struct.unpack_from("<I", new_exe, 0x4C308)[0] != 0x34050073:
        raise AssertionError("first-row y changed")
    if struct.unpack_from("<I", new_exe, 0x4C2F0)[0] != jal_word(0x8016C61C):
        raise AssertionError("window call changed")
    if struct.unpack_from("<I", new_exe, 0x4C330)[0] != jal_word(0x8016B418):
        raise AssertionError("second-row state initializer call changed")

    raw_strings = tuple(read_c_string(new_exe, pointer) for pointer in UI_POINTERS)
    if raw_strings != UI_RAW:
        raise AssertionError("target-panel UI strings changed")
    advances = tuple(text_advance(raw) for raw in raw_strings)
    if advances != ((118, 120), (180, 182)):
        raise AssertionError(f"target-panel text metrics drift: {advances}")
    box_x, box_y, box_w, box_h = 74, 111, 198, 40
    text_x, first_y, second_y = 82, 115, 131
    left = text_x - box_x
    right = box_x + box_w - (text_x + advances[1][1])
    top = first_y - box_y
    bottom = box_y + box_h - (second_y + 16)
    line_gap = second_y - (first_y + 16)
    if (left, right, top, bottom, line_gap) != (8, 8, 4, 4, 0):
        raise AssertionError(f"panel geometry mismatch: {(left, right, top, bottom, line_gap)}")

    if new[COMM] != old[COMM]:
        raise AssertionError("COMM.IMG changed")
    for name in old_names:
        if name not in {DAT, PSX} and new[name] != old[name]:
            raise AssertionError(f"non-target member changed: {name}")
    if old_exe[:0x800] != new_exe[:0x800] or new_exe[:8] != b"PS-X EXE":
        raise AssertionError("PS-X EXE header changed")

    delta_names, delta = archive(DELTA)
    if delta_names != changed:
        raise AssertionError(f"delta member order/content drift: {delta_names}")
    if any(delta[name] != new[name] for name in changed):
        raise AssertionError("delta member readback differs from full archive")

    with (ANALYSIS / "expected_writes.csv").open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    actual_triplets = {
        (row["member"], int(row["offset"], 16), int(row["before"], 16), int(row["after"], 16))
        for row in rows
    }
    expected_triplets = {
        (name, offset, old[name][offset], new[name][offset])
        for name in changed
        for offset in range(len(old[name]))
        if old[name][offset] != new[name][offset]
    }
    if actual_triplets != expected_triplets or len(rows) != 62:
        raise AssertionError("expected_writes.csv does not equal the full diff")

    manifest = json.loads((ANALYSIS / "build_manifest.json").read_text(encoding="utf-8"))
    if manifest["output"]["sha256"] != FULL_SHA256 or manifest["delta"]["sha256"] != DELTA_SHA256:
        raise AssertionError("manifest archive hashes disagree")

    result = {
        "version": "V358",
        "result": "PASS_STATIC_RUNTIME_PENDING",
        "full": {"file": FULL.name, "sha256": FULL_SHA256},
        "delta": {"file": DELTA.name, "sha256": DELTA_SHA256},
        "checks": {
            "archive_topology_order": "PASS 164/164",
            "changed_members": changed,
            "expected_writes": "PASS 62 bytes total (PSX 3, DAT 59)",
            "dialogue_decode": EXPECTED_TEXT,
            "slot_capacity": f"{len(NEW_PAYLOAD)}/127 bytes",
            "e2_caller_metadata": "PASS caller 0x47910, metadata 0x2D",
            "panel_geometry": "PASS box 74,111,198,40; rows 115/131; margins 8/8/4/4",
            "panel_caller": "PASS sole caller 0x80166898",
            "patched_word_inbound_edges": 0,
            "comm_and_non_target_preservation": "PASS",
            "delta_readback": "PASS",
        },
        "runtime": "PENDING user cold boot and representative UI/dialogue review",
    }
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    text = [
        "Arc the Lad 1 V358 independent static verification",
        "STATIC PASS / RUNTIME PENDING / TEST_ONLY",
        "archive topology/order: PASS 164/164",
        f"changed members: {','.join(changed)}",
        "Expected-Write: PASS 62 bytes total (PSX.EXE 3, F/SF0F1.DAT 59)",
        f"dialogue: PASS {EXPECTED_TEXT}",
        f"slot: PASS {len(NEW_PAYLOAD)}/127 bytes; caller 0x{CALLER:X}; metadata 0x{METADATA:02X}",
        "panel: PASS box 74,111,198,40; rows 115/131; margins 8/8/4/4",
        "panel isolation: PASS sole caller 0x80166898; patched-word inbound edges 0",
        "COMM.IMG/all non-target members/header/delta: PASS",
        "runtime: PENDING user cold boot",
    ]
    (ANALYSIS / "independent_verification.txt").write_text("\n".join(text) + "\n", encoding="utf-8")
    print("\n".join(text))


if __name__ == "__main__":
    main()
