#!/usr/bin/env python3
"""Independent verification for V334's V333 delay-slot repair."""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import struct
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/arc1_v333_dynamic_ui_glyph_recovery_TEST_ONLY_55D826DC.zip"
OUTPUT = ROOT / "03_output/arc1_v334_delay_slot_payload_relocation_TEST_ONLY_9089151E.zip"
DELTA = ROOT / "03_output/arc1_v334_delay_slot_payload_relocation_TEST_ONLY_delta_from_v333_CC9178C5.zip"
ANALYSIS = ROOT / "01_work/analysis/arc1_v334_delay_slot_payload_relocation"

BASE_SHA256 = "55D826DC02FE5A7DE5167EBB81623184409FA4F8FC395B2EB04369A17DC2D450"
OUTPUT_SHA256 = "9089151E90CDC53CDC4187D6DE403E6C8654B2D302E65462A38D2A7AAE1B8CFC"
DELTA_SHA256 = "CC9178C5C969D2653D87A6FDF1BB863FC0D9CD6A10B48D0D1C3E405717549179"
OUTPUT_PSX_SHA256 = "EED09C4AEA7EE826B5EB1368C69200075866DCCE6C822537A4A28C4ABED69BFC"
COMM_SHA256 = "095885C3EA58F1A886BEE20033EE8313FE07476088AC27FD726F53AE44D8331B"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
RAM_TO_FILE = 0x8011A800
JUMP_FILE = 0x809DC
DELAY_FILE = 0x809E0
POOL_START = 0x809E0
POOL_END = 0x809F9
LOAD_POINTER_FILE = 0x780FC
HUD_POINTERS_FILE = 0x823AC
UV_COUNT_FILE = 0x80918
E5_FILE = 0x51604

EXPECTED_LAYOUT = (
    (0x809E4, bytes.fromhex("DF E7 DF F4 00"), 0x8019B1E4, "hud_l"),
    (0x809E9, bytes.fromhex("DF E7 DF F5 00"), 0x8019B1E9, "hud_m"),
    (0x809EE, bytes.fromhex("DF F6 00"), 0x8019B1EE, "hud_p"),
    (0x809F1, bytes.fromhex("DF F4 00"), 0x8019B1F1, "load_l"),
)
EXPECTED_HUD = (0x8019B1E4, 0x8019B1F4, 0x8019C95C, 0x8019B1E9, 0x8019B1EE)
EXPECTED_POINTER_FILES = {0x780FC, 0x823AC, 0x823B0, 0x823B8, 0x823BC}


class VerifyError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def file_sha256(path: Path) -> str:
    return sha256(path.read_bytes())


def read_zip(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        names = [info.filename for info in archive.infolist() if not info.is_dir()]
        return names, {name: archive.read(name) for name in names}


def pointer_hits(exe: bytes, lo: int, hi: int) -> list[tuple[int, int]]:
    hits = []
    for offset in range(len(exe) - 3):
        value = struct.unpack_from("<I", exe, offset)[0]
        if lo <= value < hi:
            hits.append((offset, value))
    return hits


def control_targets(exe: bytes, lo: int, hi: int) -> list[tuple[int, int, int]]:
    hits = []
    for offset in range(0x800, len(exe) - 3, 4):
        word = struct.unpack_from("<I", exe, offset)[0]
        address = RAM_TO_FILE + offset
        opcode = word >> 26
        target = None
        if opcode in (2, 3):
            target = ((address + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
        elif opcode in (1, 4, 5, 6, 7):
            immediate = word & 0xFFFF
            immediate -= 0x10000 if immediate & 0x8000 else 0
            target = address + 4 + (immediate << 2)
        if target is not None and lo <= target < hi:
            hits.append((address, word, target))
    return hits


def disassemble_words(exe: bytes) -> list[str]:
    words = exe[JUMP_FILE : DELAY_FILE + 4]
    try:
        from capstone import CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32, Cs

        engine = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
        return [
            f"{insn.address:08X} {insn.mnemonic} {insn.op_str}".rstrip()
            for insn in engine.disasm(words, RAM_TO_FILE + JUMP_FILE)
        ]
    except Exception:
        return [
            f"{RAM_TO_FILE + JUMP_FILE:08X} word=0x{struct.unpack_from('<I', words, 0)[0]:08X}",
            f"{RAM_TO_FILE + DELAY_FILE:08X} word=0x{struct.unpack_from('<I', words, 4)[0]:08X}",
        ]


def parse_failure_state(path: Path) -> dict[str, object]:
    spec = importlib.util.spec_from_file_location(
        "arc_state_parser", ROOT / "02_scripts/analyze_arc1_v320c_savestates.py"
    )
    if spec is None or spec.loader is None:
        raise VerifyError("cannot load DUCCU parser")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    parsed = module.parse_state(path)
    blob = parsed["blob"]
    tag = struct.pack("<I", 3) + b"CPU"
    cpu = blob.find(tag)
    if cpu < 0:
        raise VerifyError("CPU section missing")
    cpu += len(tag)
    current_pc = struct.unpack_from("<I", blob, cpu + 0xB8)[0]
    status = struct.unpack_from("<I", blob, cpu + 0xC0)[0]
    cause = struct.unpack_from("<I", blob, cpu + 0xC4)[0]
    next_pc = struct.unpack_from("<I", blob, cpu + 0xD4)[0]
    result = {
        "sha256": parsed["file_sha256"],
        "game_id": parsed["game_id"],
        "current_pc": f"0x{current_pc:08X}",
        "next_pc": f"0x{next_pc:08X}",
        "status": f"0x{status:08X}",
        "cause": f"0x{cause:08X}",
        "exception_code": (cause >> 2) & 0x1F,
        "branch_delay": bool(cause & 0x80000000),
    }
    if parsed["game_id"] != "V333":
        raise VerifyError("failure state is not V333")
    if current_pc != 0x8019B1DC or next_pc != 0x8016B524:
        raise VerifyError(f"failure PC pair drift: {result}")
    if ((cause >> 2) & 0x1F) != 10 or not (cause & 0x80000000):
        raise VerifyError(f"failure is not RI in a branch delay slot: {result}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path)
    args = parser.parse_args()

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
    if sha256(after[PSX]) != OUTPUT_PSX_SHA256 or sha256(after[COMM]) != COMM_SHA256:
        raise VerifyError("output member hash mismatch")

    with ZipFile(DELTA) as archive:
        if archive.namelist() != [PSX] or archive.read(PSX) != after[PSX]:
            raise VerifyError("delta payload/topology mismatch")

    exe = after[PSX]
    if struct.unpack_from("<I", exe, JUMP_FILE)[0] != 0x0805AD49:
        raise VerifyError("return jump drift")
    if struct.unpack_from("<I", exe, DELAY_FILE)[0] != 0:
        raise VerifyError("live delay slot is not NOP")
    if struct.unpack_from("<I", before[PSX], DELAY_FILE)[0] != 0xF4DFE7DF:
        raise VerifyError("V333 failure premise drift")

    for offset, payload, _address, label in EXPECTED_LAYOUT:
        if exe[offset : offset + len(payload)] != payload:
            raise VerifyError(f"{label} payload mismatch")
    if exe[0x809F4] != 0:
        raise VerifyError("empty string is not NUL")
    if struct.unpack_from("<I", exe, LOAD_POINTER_FILE)[0] != 0x8019B1F1:
        raise VerifyError("load-L pointer mismatch")
    if struct.unpack_from("<5I", exe, HUD_POINTERS_FILE) != EXPECTED_HUD:
        raise VerifyError("HUD pointer table mismatch")

    hits = pointer_hits(exe, 0x8019B1E4, 0x8019B1F9)
    if {offset for offset, _value in hits} != EXPECTED_POINTER_FILES:
        raise VerifyError(f"payload pointer ownership mismatch: {hits}")
    if control_targets(exe, 0x8019B1E4, 0x8019B1F9):
        raise VerifyError("control transfer enters relocated payload data")

    # V333 functionality remains inherited exactly outside the relocation.
    if struct.unpack_from("<I", exe, UV_COUNT_FILE)[0] != 0x2D090011:
        raise VerifyError("synthetic UV count drift")
    if struct.unpack_from("<I", exe, E5_FILE)[0] != 0x340403C0:
        raise VerifyError("E5 synthetic blank drift")
    if before[COMM] != after[COMM]:
        raise VerifyError("COMM.IMG changed")
    if any(before[name] != after[name] for name in base_names if name != PSX):
        raise VerifyError("non-PSX member changed")

    actual = {
        offset
        for offset, (old, new) in enumerate(zip(before[PSX], after[PSX], strict=True))
        if old != new
    }
    if len(actual) != 25:
        raise VerifyError(f"changed-byte count drift: {len(actual)}")
    envelope = set(range(POOL_START, POOL_END))
    envelope |= set(range(LOAD_POINTER_FILE, LOAD_POINTER_FILE + 4))
    envelope |= set(range(HUD_POINTERS_FILE, HUD_POINTERS_FILE + 20))
    if not actual <= envelope:
        raise VerifyError(f"Expected-Write escape: {sorted(actual - envelope)[:8]}")

    expected_csv = list(csv.DictReader((ANALYSIS / "expected_writes.csv").open(encoding="utf-8-sig")))
    csv_offsets = {int(row["offset"], 16) for row in expected_csv}
    if csv_offsets != actual or len(expected_csv) != len(actual):
        raise VerifyError("expected_writes.csv mismatch")

    state_result = parse_failure_state(args.state) if args.state else None
    result = {
        "verdict": "PASS",
        "output_sha256": OUTPUT_SHA256,
        "changed_members": changed_members,
        "changed_bytes": len(actual),
        "delay_slot": "0x8019B1E0 NOP",
        "disassembly": disassemble_words(exe),
        "payload_layout": [
            {"name": label, "file": f"0x{offset:X}", "ram": f"0x{address:08X}", "size": len(payload)}
            for offset, payload, address, label in EXPECTED_LAYOUT
        ],
        "pointer_hits": [
            {"file": f"0x{offset:X}", "value": f"0x{value:08X}"}
            for offset, value in hits
        ],
        "failure_state": state_result,
        "preserved": {
            "COMM_IMG": "PASS",
            "all_DAT_and_other_members": "PASS",
            "V333_UV_count": "PASS",
            "V333_E5_blank": "PASS",
        },
        "runtime": "PENDING V334 cold boot",
    }
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V334 independent verification: PASS",
        f"output_sha256={OUTPUT_SHA256}",
        "changed_members=PSX.EXE only",
        f"changed_bytes={len(actual)}; Expected-Write PASS",
        "0x8019B1DC=j 0x8016B524; 0x8019B1E0=nop PASS",
        "payload data begins at 0x8019B1E4; inbound control transfers=0 PASS",
        "payload pointer ownership=5/5 PASS",
        "COMM.IMG/all DAT/V333 UV+E5/V332 alignment inherited PASS",
    ]
    if state_result:
        report.append(
            "V333 failure state: PC 0x8019B1DC -> next 0x8016B524, "
            "Cause ExcCode10+BD (Reserved Instruction in delay slot) PASS"
        )
    report.append("runtime=PENDING V334 user cold boot; TEST_ONLY")
    (ANALYSIS / "independent_verification.txt").write_text(
        "\n".join(report) + "\n", encoding="utf-8"
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
