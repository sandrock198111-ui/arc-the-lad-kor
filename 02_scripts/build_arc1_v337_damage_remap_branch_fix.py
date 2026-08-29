#!/usr/bin/env python3
"""Build V337: repair V336's out-of-range damage-remap branch.

V336 encoded a direct ``beq`` from 0x8019B280 to 0x8016B524.  MIPS-I
conditional branches have a signed 16-bit word displacement, so the masked
immediate wrapped and actually targeted 0x801AB524.  V337 redirects that
conditional branch to the already-present local ``j 0x8016B524`` at
0x8019B270.  No V336 payload, atlas, DAT, UI geometry, or other member changes.

V336 is an invalid historical base and must not be used on hardware.
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


BASE = ROOT / "03_output/arc1_v336_ui_text_native_damage_repair_TEST_ONLY_28C9A039.zip"
BASE_SHA256 = "28C9A03986B549DD62B4B1517815327DDC52E776770221630557B360F0B0C0F4"
BASE_PSX_SHA256 = "3A6991E99492979552007C6705E8E635E279BBABE6E3F11F719767ED295A11DC"
BASE_COMM_SHA256 = "BDDDF442BC43926CF77A1356F9D0986B199A7A2F32745A3D47D5C1B6B654B9C3"

OUTPUT_STEM = "arc1_v337_damage_remap_branch_fix_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v336"
ANALYSIS = ROOT / "01_work/analysis/arc1_v337_damage_remap_branch_fix"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
RAM_TO_FILE = 0x8011A800

BRANCH_FILE = 0x80A80
BRANCH_RAM = BRANCH_FILE + RAM_TO_FILE
BRANCH_DELAY_FILE = BRANCH_FILE + 4
LOCAL_RETURN_JUMP_FILE = 0x80A70
LOCAL_RETURN_JUMP_RAM = LOCAL_RETURN_JUMP_FILE + RAM_TO_FILE
REMAP_FILE = 0x80A88

V336_WRAPPED_BRANCH = 0x112040A8  # beq t1,zero -> actually 0x801AB524
V337_LOCAL_BRANCH = 0x1120FFFB  # beq t1,zero -> 0x8019B270
RETURN_JUMP = 0x0805AD49  # j 0x8016B524
REMAP_WORD = 0x2484FD7D  # addiu a0,a0,-643 (804..819 -> 161..176)
NOP = 0
EXPECTED_CHANGED_OFFSETS = {BRANCH_FILE, BRANCH_FILE + 1}


class BuildError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def changed_offsets(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise BuildError("member size changed")
    return {
        offset
        for offset, (old, new) in enumerate(zip(before, after, strict=True))
        if old != new
    }


def word_at(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def signed16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def branch_target(word: int, pc: int) -> int:
    if word >> 26 not in {0x04, 0x05, 0x06, 0x07}:
        raise BuildError(f"not a supported conditional branch: 0x{word:08X}")
    return (pc + 4 + signed16(word) * 4) & 0xFFFFFFFF


def jump_target(word: int, pc: int) -> int:
    if word >> 26 not in {0x02, 0x03}:
        raise BuildError(f"not a jump: 0x{word:08X}")
    return ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)


def assert_base(members: dict[str, bytes]) -> None:
    if len(members) != 164:
        raise BuildError(f"V336 member count drift: {len(members)}")
    exe = members[PSX]
    if sha256_bytes(exe) != BASE_PSX_SHA256:
        raise BuildError("V336 PSX.EXE hash drift")
    if sha256_bytes(members[COMM]) != BASE_COMM_SHA256:
        raise BuildError("V336 COMM.IMG hash drift")
    if word_at(exe, BRANCH_FILE) != V336_WRAPPED_BRANCH:
        raise BuildError("V336 wrapped branch premise drift")
    if branch_target(V336_WRAPPED_BRANCH, BRANCH_RAM) != 0x801AB524:
        raise BuildError("V336 wrapped branch no longer reproduces the defect")
    anchors = {
        LOCAL_RETURN_JUMP_FILE: RETURN_JUMP,
        BRANCH_DELAY_FILE: NOP,
        REMAP_FILE: REMAP_WORD,
        REMAP_FILE + 4: RETURN_JUMP,
        REMAP_FILE + 8: NOP,
    }
    for offset, expected in anchors.items():
        actual = word_at(exe, offset)
        if actual != expected:
            raise BuildError(
                f"branch-fix anchor drift at 0x{offset:X}: "
                f"0x{actual:08X} != 0x{expected:08X}"
            )


def build_once(before: dict[str, bytes]) -> tuple[dict[str, bytes], dict[str, object]]:
    assert_base(before)
    exe = bytearray(before[PSX])
    struct.pack_into("<I", exe, BRANCH_FILE, V337_LOCAL_BRANCH)

    if branch_target(word_at(exe, BRANCH_FILE), BRANCH_RAM) != LOCAL_RETURN_JUMP_RAM:
        raise BuildError("V337 local branch target mismatch")
    if jump_target(word_at(exe, LOCAL_RETURN_JUMP_FILE), LOCAL_RETURN_JUMP_RAM) != 0x8016B524:
        raise BuildError("local return jump target mismatch")
    if jump_target(word_at(exe, REMAP_FILE + 4), REMAP_FILE + 4 + RAM_TO_FILE) != 0x8016B524:
        raise BuildError("mapped return jump target mismatch")
    if word_at(exe, BRANCH_DELAY_FILE) != NOP:
        raise BuildError("conditional branch delay slot changed")
    if word_at(exe, REMAP_FILE) != REMAP_WORD:
        raise BuildError("804..819 remap word changed")

    final = dict(before)
    final[PSX] = bytes(exe)
    metadata = {
        "fixed_branch": {
            "file_offset": f"0x{BRANCH_FILE:X}",
            "ram_address": f"0x{BRANCH_RAM:08X}",
            "before_word": f"0x{V336_WRAPPED_BRANCH:08X}",
            "before_actual_target": "0x801AB524",
            "after_word": f"0x{V337_LOCAL_BRANCH:08X}",
            "after_target": f"0x{LOCAL_RETURN_JUMP_RAM:08X}",
            "local_jump_target": "0x8016B524",
        },
        "control_flow": {
            "unmapped_glyph": "branch to local return jump, then 0x8016B524",
            "source_804_819": "fall through, addiu -643, then 0x8016B524",
            "delay_slots": "conditional and both return jumps remain NOP",
        },
    }
    return final, metadata


def main() -> None:
    if not BASE.is_file() or v324.sha256_file(BASE) != BASE_SHA256:
        raise BuildError(f"V336 base hash mismatch: {BASE}")
    infos, before = v324.read_archive(BASE)

    final, metadata = build_once(before)
    rebuilt, rebuilt_metadata = build_once(before)
    if final != rebuilt or metadata != rebuilt_metadata:
        raise BuildError("in-memory deterministic rebuild mismatch")

    changed_members = [name for name in before if before[name] != final[name]]
    if changed_members != [PSX]:
        raise BuildError(f"changed member set drift: {changed_members}")
    actual = changed_offsets(before[PSX], final[PSX])
    if actual != EXPECTED_CHANGED_OFFSETS:
        raise BuildError(
            f"Expected-Write mismatch: actual={sorted(actual)} "
            f"expected={sorted(EXPECTED_CHANGED_OFFSETS)}"
        )
    if any(before[name] != final[name] for name in before if name != PSX):
        raise BuildError("non-PSX member changed")

    output_path, output_hash = v324.write_archive(OUTPUT_STEM, infos, final, None)
    delta_path, delta_hash = v324.write_archive(DELTA_STEM, infos, final, {PSX})
    with ZipFile(output_path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        expected_names = [item.filename for item in infos if not item.is_dir()]
        if names != expected_names or any(archive.read(name) != final[name] for name in final):
            raise BuildError("full ZIP round-trip/topology mismatch")
    with ZipFile(delta_path) as archive:
        if archive.namelist() != [PSX] or archive.read(PSX) != final[PSX]:
            raise BuildError("delta ZIP round-trip mismatch")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    with (ANALYSIS / "expected_writes.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow(("member", "offset", "before", "after", "purpose"))
        for offset in sorted(actual):
            writer.writerow(
                (
                    PSX,
                    f"0x{offset:X}",
                    f"{before[PSX][offset]:02X}",
                    f"{final[PSX][offset]:02X}",
                    "repair out-of-range beq via local return jump",
                )
            )

    manifest = {
        "build": "V337 TEST_ONLY V336 damage-remap branch-range repair",
        "base": {
            "path": str(BASE),
            "sha256": BASE_SHA256,
            "status": "INVALID historical base; wrapped branch targets 0x801AB524",
        },
        "output": {"path": str(output_path), "sha256": output_hash},
        "delta": {"path": str(delta_path), "sha256": delta_hash},
        "changed_members": changed_members,
        "changed_bytes": {PSX: len(actual)},
        **metadata,
        "preserved": (
            "all V336 UI/text/location/item/count/damage payloads, COMM.IMG, all DAT, "
            "all non-PSX members, and every PSX byte outside the branch immediate"
        ),
        "runtime": "PENDING user cold boot",
        "release_status": "TEST ONLY; DO NOT DISTRIBUTE",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = (
        "V337 TEST ONLY - V336 damage-remap branch-range repair\n"
        f"base={BASE.name}\n"
        f"output={output_path.name}\nsha256={output_hash}\n"
        f"delta={delta_path.name}\ndelta_sha256={delta_hash}\n"
        "changed_members=PSX.EXE only\nchanged_bytes=2\n"
        "branch=0x8019B280: 0x112040A8 -> 0x1120FFFB\n"
        "old_actual_target=0x801AB524 INVALID\n"
        "new_target=0x8019B270 local j -> 0x8016B524\n"
        "V336 payload/COMM.IMG/all DAT preserved byte-exact\n"
        "runtime=PENDING; TEST_ONLY\n"
    )
    (ANALYSIS / "build_report.txt").write_text(report, encoding="utf-8")
    checklist = (
        "V337 cold-boot checklist\n\n"
        "- Do not boot V336; start V337.cue from power-off.\n"
        "- Confirm BIOS, title, load screen, and gameplay all progress without a black screen.\n"
        "- Confirm ordinary dialogue renders (exercises the repaired non-remapped path).\n"
        "- Confirm choices, L/R help, 병사 2, warehouse text, and all location names.\n"
        "- Confirm equipment/consumable names are 4px left and consumable count is 2px lower.\n"
        "- Confirm battle damage digits have no Hangul/odd-glyph contamination.\n"
        "- Confirm unrelated dialogue/UI/icons and native numbers match V335/V336 intent.\n"
    )
    (ANALYSIS / "runtime_checklist.txt").write_text(checklist, encoding="utf-8")

    print(f"V337 full ZIP: {output_path}")
    print(f"V337 full SHA256: {output_hash}")
    print(f"V337 delta ZIP: {delta_path}")
    print(f"V337 delta SHA256: {delta_hash}")


if __name__ == "__main__":
    main()
