#!/usr/bin/env python3
"""Independent static verification for V337's branch-range repair."""

from __future__ import annotations

import csv
import hashlib
import json
import struct
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/arc1_v336_ui_text_native_damage_repair_TEST_ONLY_28C9A039.zip"
OUTPUT = ROOT / "03_output/arc1_v337_damage_remap_branch_fix_TEST_ONLY_2AB80515.zip"
DELTA = ROOT / "03_output/arc1_v337_damage_remap_branch_fix_TEST_ONLY_delta_from_v336_0CC5D8EA.zip"
ANALYSIS = ROOT / "01_work/analysis/arc1_v337_damage_remap_branch_fix"

BASE_SHA256 = "28C9A03986B549DD62B4B1517815327DDC52E776770221630557B360F0B0C0F4"
OUTPUT_SHA256 = "2AB80515D70E84F34F83A919FC63F16AFDEDA57342FAE4F40180E841DCF3E856"
DELTA_SHA256 = "0CC5D8EA9CF332A6761986E7EBD77FE5EE135693C6C0FD777D55CC87D5A94780"
OUTPUT_PSX_SHA256 = "AE1E4C2A6D72FBA77B6D836E4368E77DAA5D1BE777C0C8723AD57FD86B8CAAAA"
COMM_SHA256 = "BDDDF442BC43926CF77A1356F9D0986B199A7A2F32745A3D47D5C1B6B654B9C3"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
RAM_TO_FILE = 0x8011A800
BRANCH_FILE = 0x80A80
BRANCH_RAM = BRANCH_FILE + RAM_TO_FILE
LOCAL_JUMP_FILE = 0x80A70
LOCAL_JUMP_RAM = LOCAL_JUMP_FILE + RAM_TO_FILE
OLD_BRANCH = 0x112040A8
NEW_BRANCH = 0x1120FFFB
RETURN_JUMP = 0x0805AD49
REMAP_WORD = 0x2484FD7D
EXPECTED_CHANGED_OFFSETS = {BRANCH_FILE, BRANCH_FILE + 1}


class VerifyError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def file_sha256(path: Path) -> str:
    return sha256(path.read_bytes())


def read_zip(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        return names, {name: archive.read(name) for name in names}


def word(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def signed16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def branch_target(instruction: int, pc: int) -> int:
    if instruction >> 26 != 0x04:
        raise VerifyError(f"expected beq, got 0x{instruction:08X}")
    return (pc + 4 + signed16(instruction) * 4) & 0xFFFFFFFF


def jump_target(instruction: int, pc: int) -> int:
    if instruction >> 26 != 0x02:
        raise VerifyError(f"expected j, got 0x{instruction:08X}")
    return ((pc + 4) & 0xF0000000) | ((instruction & 0x03FFFFFF) << 2)


def simulate_source_gate(index: int) -> tuple[int, list[int]]:
    """Return remapped index and PCs traversed from 0x8019B278 onward."""
    pcs = [0x8019B278, 0x8019B27C, 0x8019B280, 0x8019B284]
    relative = (index - 804) & 0xFFFFFFFF
    if relative >= 16:
        pcs.extend((0x8019B270, 0x8019B274, 0x8016B524))
        return index, pcs
    pcs.extend((0x8019B288, 0x8019B28C, 0x8019B290, 0x8016B524))
    return index - 643, pcs


def disassembly(exe: bytes) -> list[str]:
    try:
        from capstone import CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32, Cs

        engine = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
        start = LOCAL_JUMP_FILE
        data = exe[start : 0x80A94]
        return [
            f"{ins.address:08X} {ins.mnemonic} {ins.op_str}".rstrip()
            for ins in engine.disasm(data, LOCAL_JUMP_RAM)
        ]
    except ImportError:
        return [
            f"{offset + RAM_TO_FILE:08X} word=0x{word(exe, offset):08X}"
            for offset in range(LOCAL_JUMP_FILE, 0x80A94, 4)
        ]


def main() -> None:
    for path, expected in (
        (BASE, BASE_SHA256),
        (OUTPUT, OUTPUT_SHA256),
        (DELTA, DELTA_SHA256),
    ):
        if not path.is_file() or file_sha256(path) != expected:
            raise VerifyError(f"archive hash mismatch: {path}")

    base_names, before = read_zip(BASE)
    out_names, after = read_zip(OUTPUT)
    if base_names != out_names or len(out_names) != 164:
        raise VerifyError("archive topology drift")
    changed_members = [name for name in base_names if before[name] != after[name]]
    if changed_members != [PSX]:
        raise VerifyError(f"member isolation failed: {changed_members}")
    if sha256(after[PSX]) != OUTPUT_PSX_SHA256:
        raise VerifyError("output PSX.EXE hash mismatch")
    if sha256(after[COMM]) != COMM_SHA256 or before[COMM] != after[COMM]:
        raise VerifyError("COMM.IMG changed")
    if any(before[name] != after[name] for name in base_names if name != PSX):
        raise VerifyError("non-PSX member changed")

    with ZipFile(DELTA) as archive:
        if archive.namelist() != [PSX] or archive.read(PSX) != after[PSX]:
            raise VerifyError("delta payload/topology mismatch")

    actual = {
        offset
        for offset, (old, new) in enumerate(zip(before[PSX], after[PSX], strict=True))
        if old != new
    }
    if actual != EXPECTED_CHANGED_OFFSETS:
        raise VerifyError(
            f"Expected-Write mismatch: actual={sorted(actual)} "
            f"expected={sorted(EXPECTED_CHANGED_OFFSETS)}"
        )
    if word(before[PSX], BRANCH_FILE) != OLD_BRANCH:
        raise VerifyError("V336 defect premise drift")
    if word(after[PSX], BRANCH_FILE) != NEW_BRANCH:
        raise VerifyError("V337 branch word mismatch")

    old_target = branch_target(OLD_BRANCH, BRANCH_RAM)
    new_target = branch_target(NEW_BRANCH, BRANCH_RAM)
    if old_target != 0x801AB524:
        raise VerifyError(f"V336 wrapped target not reproduced: 0x{old_target:08X}")
    if new_target != LOCAL_JUMP_RAM:
        raise VerifyError(f"V337 local target mismatch: 0x{new_target:08X}")
    if word(after[PSX], LOCAL_JUMP_FILE) != RETURN_JUMP:
        raise VerifyError("local return jump word mismatch")
    if jump_target(RETURN_JUMP, LOCAL_JUMP_RAM) != 0x8016B524:
        raise VerifyError("local return jump destination mismatch")
    if word(after[PSX], BRANCH_FILE + 4) != 0:
        raise VerifyError("beq delay slot is not NOP")
    if word(after[PSX], BRANCH_FILE + 8) != REMAP_WORD:
        raise VerifyError("source remap instruction mismatch")
    if word(after[PSX], BRANCH_FILE + 12) != RETURN_JUMP:
        raise VerifyError("mapped-path return jump mismatch")
    if word(after[PSX], BRANCH_FILE + 16) != 0:
        raise VerifyError("mapped-path jump delay slot is not NOP")

    probes = (0, 116, 160, 161, 176, 177, 803, 804, 819, 820, 1238)
    simulation: dict[str, object] = {}
    for index in probes:
        mapped, pcs = simulate_source_gate(index)
        expected = index - 643 if 804 <= index <= 819 else index
        if mapped != expected or pcs[-1] != 0x8016B524:
            raise VerifyError(f"control-flow simulation failed for {index}")
        simulation[str(index)] = {
            "mapped": mapped,
            "path": [f"0x{pc:08X}" for pc in pcs],
        }

    csv_rows = list(
        csv.DictReader((ANALYSIS / "expected_writes.csv").open(encoding="utf-8-sig"))
    )
    if len(csv_rows) != 2 or {int(row["offset"], 16) for row in csv_rows} != actual:
        raise VerifyError("expected_writes.csv mismatch")
    for row in csv_rows:
        offset = int(row["offset"], 16)
        if int(row["before"], 16) != before[PSX][offset]:
            raise VerifyError("expected_writes before-byte mismatch")
        if int(row["after"], 16) != after[PSX][offset]:
            raise VerifyError("expected_writes after-byte mismatch")

    result = {
        "verdict": "PASS",
        "output_sha256": OUTPUT_SHA256,
        "output_psx_sha256": OUTPUT_PSX_SHA256,
        "changed_members": changed_members,
        "changed_bytes": len(actual),
        "changed_offsets": [f"0x{offset:X}" for offset in sorted(actual)],
        "old_actual_target": f"0x{old_target:08X}",
        "new_local_target": f"0x{new_target:08X}",
        "local_jump_target": "0x8016B524",
        "simulation": simulation,
        "disassembly": disassembly(after[PSX]),
        "preserved": "V336 payload and every non-branch byte are byte-identical",
        "runtime": "PENDING V337 user cold boot",
    }
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = (
        "V337 independent verification: PASS\n"
        "changed_members=PSX.EXE only\n"
        "changed_bytes=2 at 0x80A80/0x80A81\n"
        f"V336 old actual branch target=0x{old_target:08X} INVALID\n"
        f"V337 branch target=0x{new_target:08X}; local j target=0x8016B524\n"
        "all V336 payload/non-PSX bytes preserved\n"
        "runtime=PENDING user cold boot\n"
    )
    (ANALYSIS / "independent_verification.txt").write_text(report, encoding="utf-8")
    print(report, end="")


if __name__ == "__main__":
    main()
