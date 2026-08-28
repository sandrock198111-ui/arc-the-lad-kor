#!/usr/bin/env python3
"""Build V332: keep V331 text alignment and move both selection bars -4px.

V331 already moves the dedicated skill-name object by four pixels and moves
the two configuration choice columns from X=166/226 to X=162/222 while
changing ``사용 안 함`` to ``사용안함``.  Runtime packet pointers and the
static table at 0x8019B9C0 prove that the V331 skill wrapper covers both
reported skill screens and no equipment/item table.

The configuration loop passes the selection-bar X coordinate in ``a1`` to
0x8016D620.  Its two alternatives are 164/224, so V332 changes only those two
immediates to 160/220.  This preserves the original two-pixel inset between
each 51-pixel bar and its text column.
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
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import build_arc1_v324_static_ui_cursor_recovery as v324  # noqa: E402


BASE = ROOT / "03_output/arc1_v331_skill_config_alignment_TEST_ONLY_4D5F9D16.zip"
BASE_SHA256 = "4D5F9D165B54F8EE740DE313D8524E999DFEC2763BB0E3018F767C499A2E1DD5"
BASE_PSX_SHA256 = "F627891E1219844CBAB269A789A9ADEF11D2CE61715632D48B0FBD7A96192E46"
OUTPUT_STEM = "arc1_v332_skill_config_bar_alignment_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v331"
ANALYSIS = ROOT / "01_work/analysis/arc1_v332_skill_config_bar_alignment"

PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800

BAR_LEFT_RAM = 0x801608F4
BAR_RIGHT_RAM = 0x801608F8
BAR_LEFT_FILE = BAR_LEFT_RAM - RAM_TO_FILE
BAR_RIGHT_FILE = BAR_RIGHT_RAM - RAM_TO_FILE
BAR_LEFT_OLD = 0x26650082   # addiu a1,s3,130; s3=34 -> X=164
BAR_RIGHT_OLD = 0x266500BE  # addiu a1,s3,190; s3=34 -> X=224
BAR_LEFT_NEW = 0x2665007E   # X=160
BAR_RIGHT_NEW = 0x266500BA  # X=220

# The complete choice/position dispatch fixes the branch target and jump
# delay-slot topology.  Only the two immediate fields may change.
BAR_CONTEXT_RAM = 0x801608E4
BAR_CONTEXT_FILE = BAR_CONTEXT_RAM - RAM_TO_FILE
BAR_CONTEXT_OLD = (
    0x30420001,  # andi v0,v0,1
    0x14400003,  # bnez v0,0x801608F8
    0x02002021,  # move a0,s0
    0x0805823F,  # j 0x801608FC
    BAR_LEFT_OLD,  # jump delay slot
    BAR_RIGHT_OLD,  # branch target
    0x0C05B588,  # jal 0x8016D620
    0x02403021,  # move a2,s2 (JAL delay slot)
)

# Configuration text and geometry already accepted in V331.
CONFIG_BASE_RAM = 0x80160854
CONFIG_BASE_FILE = CONFIG_BASE_RAM - RAM_TO_FILE
CONFIG_BASE_WORD = 0x34130022  # ori s3,zero,34
CONFIG_FIRST_FILE = 0x8016089C - RAM_TO_FILE
CONFIG_SECOND_FILE = 0x801608BC - RAM_TO_FILE
CONFIG_FIRST_WORD = 0x26640080   # text X=162
CONFIG_SECOND_WORD = 0x266400BC  # text X=222
BAR_WIDTH_FILE = 0x801607A8 - RAM_TO_FILE
BAR_HEIGHT_FILE = 0x801607B0 - RAM_TO_FILE
BAR_WIDTH_WORD = 0x34050033   # 51 pixels
BAR_HEIGHT_WORD = 0x3406000E  # 14 pixels
CONFIG_PAYLOAD_FILE = 0x8019C2A4 - RAM_TO_FILE
CONFIG_PAYLOAD = bytes.fromhex("34 DD 1A 94 DD CF 00 00 00")  # 사용안함\0 + tail

# V330/V331 dedicated skill route.  The table entries and end pointers match
# the two uploaded V329 runtime objects exactly.
SKILL_CALL_RAM = 0x80162080
SKILL_CALL_FILE = SKILL_CALL_RAM - RAM_TO_FILE
SKILL_CALL_WORDS = (0x0C066C2C, 0xAFA20010)  # wrapper JAL + delay slot
SKILL_WRAPPER_RAM = 0x8019B0B0
SKILL_WRAPPER_FILE = SKILL_WRAPPER_RAM - RAM_TO_FILE
SKILL_WRAPPER_SIZE = 92
SKILL_WRAPPER_SHA256 = "C6F127C8C0F5602F2582207B3E4643C6CA5457530CF0CD866BAC84EFAF4C60ED"
SKILL_TABLE_RAM = 0x8019B9C0
SKILL_TABLE_FILE = SKILL_TABLE_RAM - RAM_TO_FILE
SKILL_ENTRY_GROUND = 0x8019ADEA
SKILL_ENTRY_SLOW = 0x8019C1EE
SKILL_GROUND_BYTES = bytes.fromhex("9B A1 15 8F 86 17 00")
SKILL_SLOW_BYTES = bytes.fromhex("DD FC D5 3D A1 0E 89 DD 2F 00")

# 0x8016D620 stores a1/a2 as the selected primitive's x/y fields.
BAR_STORE_RAM = 0x8016D620
BAR_STORE_FILE = BAR_STORE_RAM - RAM_TO_FILE
BAR_STORE_WORDS = (
    0x000410C0, 0x00441023, 0x000210C0, 0x3C01801B,
    0x2421DF0C, 0x00220821, 0xA4250000, 0x3C01801B,
    0x2421DF0E, 0x00220821, 0xA4260000, 0x03E00008,
    0x00000000,
)


class BuildError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sign16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def control_target(pc: int, word: int) -> int | None:
    op = word >> 26
    if op in (1, 4, 5, 6, 7):
        return (pc + 4 + sign16(word & 0xFFFF) * 4) & 0xFFFFFFFF
    if op in (2, 3):
        return ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
    return None


def inbound_to(exe: bytes, targets: set[int]) -> list[tuple[int, int, int]]:
    hits: list[tuple[int, int, int]] = []
    for offset in range(0, len(exe) - 3, 4):
        word = struct.unpack_from("<I", exe, offset)[0]
        pc = RAM_TO_FILE + offset
        target = control_target(pc, word)
        if target in targets:
            hits.append((pc, word, target))
    return hits


def assert_v331_premises(exe: bytes) -> None:
    if struct.unpack_from("<8I", exe, BAR_CONTEXT_FILE) != BAR_CONTEXT_OLD:
        raise BuildError("V331 configuration bar dispatch context drift")
    if struct.unpack_from("<I", exe, CONFIG_BASE_FILE)[0] != CONFIG_BASE_WORD:
        raise BuildError("configuration s3=34 premise drift")
    if struct.unpack_from("<I", exe, CONFIG_FIRST_FILE)[0] != CONFIG_FIRST_WORD:
        raise BuildError("V331 first text column is not X=162")
    if struct.unpack_from("<I", exe, CONFIG_SECOND_FILE)[0] != CONFIG_SECOND_WORD:
        raise BuildError("V331 second text column is not X=222")
    if struct.unpack_from("<I", exe, BAR_WIDTH_FILE)[0] != BAR_WIDTH_WORD:
        raise BuildError("configuration bar width premise drift")
    if struct.unpack_from("<I", exe, BAR_HEIGHT_FILE)[0] != BAR_HEIGHT_WORD:
        raise BuildError("configuration bar height premise drift")
    if exe[CONFIG_PAYLOAD_FILE : CONFIG_PAYLOAD_FILE + len(CONFIG_PAYLOAD)] != CONFIG_PAYLOAD:
        raise BuildError("V331 사용안함 payload drift")
    if struct.unpack_from("<2I", exe, SKILL_CALL_FILE) != SKILL_CALL_WORDS:
        raise BuildError("V331 dedicated skill call drift")
    wrapper = exe[SKILL_WRAPPER_FILE : SKILL_WRAPPER_FILE + SKILL_WRAPPER_SIZE]
    if sha256_bytes(wrapper) != SKILL_WRAPPER_SHA256:
        raise BuildError("V331 skill wrapper drift")
    table = struct.unpack_from("<5I", exe, SKILL_TABLE_FILE)
    if table[1] != SKILL_ENTRY_GROUND or table[4] != SKILL_ENTRY_SLOW:
        raise BuildError("skill-name pointer table drift")
    ground_file = SKILL_ENTRY_GROUND - RAM_TO_FILE
    slow_file = SKILL_ENTRY_SLOW - RAM_TO_FILE
    if exe[ground_file : ground_file + len(SKILL_GROUND_BYTES)] != SKILL_GROUND_BYTES:
        raise BuildError("번 그라운드 source bytes drift")
    if exe[slow_file : slow_file + len(SKILL_SLOW_BYTES)] != SKILL_SLOW_BYTES:
        raise BuildError("슬로우 에너미 source bytes drift")
    if struct.unpack_from(f"<{len(BAR_STORE_WORDS)}I", exe, BAR_STORE_FILE) != BAR_STORE_WORDS:
        raise BuildError("0x8016D620 a1/a2 store contract drift")
    expected_inbound = [
        (0x801608E8, 0x14400003, 0x801608F8),
        (0x801608F0, 0x0805823F, 0x801608FC),
    ]
    if inbound_to(exe, {0x801608F4, 0x801608F8, 0x801608FC}) != expected_inbound:
        raise BuildError("configuration bar branch/jump topology drift")


def build_once(before: dict[str, bytes]) -> dict[str, bytes]:
    members = dict(before)
    exe = bytearray(before[PSX])
    assert_v331_premises(bytes(exe))

    # Preserve all V331 behavior except the two selection-bar X immediates.
    immutable_skill_call = bytes(exe[SKILL_CALL_FILE : SKILL_CALL_FILE + 8])
    immutable_skill_wrapper = bytes(
        exe[SKILL_WRAPPER_FILE : SKILL_WRAPPER_FILE + SKILL_WRAPPER_SIZE]
    )
    immutable_config = (
        bytes(exe[CONFIG_FIRST_FILE : CONFIG_FIRST_FILE + 4]),
        bytes(exe[CONFIG_SECOND_FILE : CONFIG_SECOND_FILE + 4]),
        bytes(exe[CONFIG_PAYLOAD_FILE : CONFIG_PAYLOAD_FILE + len(CONFIG_PAYLOAD)]),
    )

    struct.pack_into("<I", exe, BAR_LEFT_FILE, BAR_LEFT_NEW)
    struct.pack_into("<I", exe, BAR_RIGHT_FILE, BAR_RIGHT_NEW)

    if bytes(exe[SKILL_CALL_FILE : SKILL_CALL_FILE + 8]) != immutable_skill_call:
        raise BuildError("skill call changed while applying bar patch")
    if bytes(exe[SKILL_WRAPPER_FILE : SKILL_WRAPPER_FILE + SKILL_WRAPPER_SIZE]) != immutable_skill_wrapper:
        raise BuildError("skill wrapper changed while applying bar patch")
    if (
        bytes(exe[CONFIG_FIRST_FILE : CONFIG_FIRST_FILE + 4]),
        bytes(exe[CONFIG_SECOND_FILE : CONFIG_SECOND_FILE + 4]),
        bytes(exe[CONFIG_PAYLOAD_FILE : CONFIG_PAYLOAD_FILE + len(CONFIG_PAYLOAD)]),
    ) != immutable_config:
        raise BuildError("V331 configuration text/payload changed")

    # The patched words remain the jump delay slot and the branch target.
    expected_inbound = [
        (0x801608E8, 0x14400003, 0x801608F8),
        (0x801608F0, 0x0805823F, 0x801608FC),
    ]
    if inbound_to(bytes(exe), {0x801608F4, 0x801608F8, 0x801608FC}) != expected_inbound:
        raise BuildError("patched configuration control flow drift")
    members[PSX] = bytes(exe)
    return members


def main() -> None:
    if not BASE.is_file() or v324.sha256_file(BASE) != BASE_SHA256:
        raise BuildError(f"V331 base hash mismatch: {BASE}")
    infos, before = v324.read_archive(BASE)
    if len(before) != 164 or sha256_bytes(before[PSX]) != BASE_PSX_SHA256:
        raise BuildError("V331 archive/PSX premise drift")

    final = build_once(before)
    if final != build_once(before):
        raise BuildError("in-memory deterministic rebuild mismatch")
    changed_members = [name for name in before if before[name] != final[name]]
    if changed_members != [PSX]:
        raise BuildError(f"changed member set drift: {changed_members}")
    if any(len(before[name]) != len(final[name]) for name in before):
        raise BuildError("member size changed")

    actual = {
        offset
        for offset, (old, new) in enumerate(zip(before[PSX], final[PSX], strict=True))
        if old != new
    }
    envelope = (
        set(range(BAR_LEFT_FILE, BAR_LEFT_FILE + 4))
        | set(range(BAR_RIGHT_FILE, BAR_RIGHT_FILE + 4))
    )
    expected = {offset for offset in envelope if before[PSX][offset] != final[PSX][offset]}
    if actual != expected or len(actual) != 2:
        raise BuildError(f"Expected-Write mismatch: actual={len(actual)}")

    output_path, output_hash = v324.write_archive(OUTPUT_STEM, infos, final, None)
    delta_path, delta_hash = v324.write_archive(DELTA_STEM, infos, final, {PSX})
    with ZipFile(output_path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        expected_names = [item.filename for item in infos if not item.is_dir()]
        if names != expected_names or any(archive.read(name) != final[name] for name in final):
            raise BuildError("full ZIP round-trip/topology mismatch")
    with ZipFile(delta_path) as archive:
        if archive.namelist() != [PSX] or archive.read(PSX) != final[PSX]:
            raise BuildError("delta ZIP mismatch")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    with (ANALYSIS / "expected_writes.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("member", "offset", "before", "after", "purpose"))
        for offset in sorted(actual):
            purpose = (
                "config_first_bar_x_164_to_160"
                if offset == BAR_LEFT_FILE
                else "config_second_bar_x_224_to_220"
            )
            writer.writerow(
                (PSX, f"0x{offset:X}", f"{before[PSX][offset]:02X}", f"{final[PSX][offset]:02X}", purpose)
            )

    manifest = {
        "build": "V332 TEST_ONLY skill/config bar alignment",
        "base": {"path": str(BASE), "sha256": BASE_SHA256},
        "output": {"path": str(output_path), "sha256": output_hash},
        "delta": {"path": str(delta_path), "sha256": delta_hash},
        "changed_members": [PSX],
        "changed_bytes": {PSX: len(actual)},
        "skill": {
            "route": "inherit V331 dedicated call 0x80162080 and wrapper 0x8019B0B0",
            "effect": "번 그라운드 and 슬로우 에너미 packets dx=-4",
            "scope": "skill-name table 0x8019B9C0 only",
        },
        "configuration": {
            "text_x": "inherit V331 162/222",
            "bar_x": "164/224 -> 160/220",
            "bar_size": "51x14 unchanged",
            "text": "inherit V331 사용안함",
            "inset": "2px preserved for both columns",
        },
        "scope": "two bar X immediates only; all DAT, COMM.IMG and other PSX bytes unchanged from V331",
        "runtime": "PENDING user cold boot and skill/configuration comparison",
        "release_status": "DIAGNOSTIC; DO NOT DISTRIBUTE",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V332 TEST ONLY - skill/configuration bar alignment",
        f"base={BASE.name}",
        f"output={output_path.name}",
        f"sha256={output_hash}",
        f"delta={delta_path.name}",
        f"delta_sha256={delta_hash}",
        "changed_members=PSX.EXE only",
        f"changed_bytes={len(actual)} in two selection-bar X immediates",
        "skill=inherit V331 dedicated skill-name dx=-4 wrapper",
        "configuration=text X 162/222; bar X 164/224 -> 160/220; 2px inset retained",
        "text=inherit V331 사용안함",
        "DAT/COMM/items/equipment/status/dialogue=unchanged from V331",
        "runtime=PENDING; TEST_ONLY",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
