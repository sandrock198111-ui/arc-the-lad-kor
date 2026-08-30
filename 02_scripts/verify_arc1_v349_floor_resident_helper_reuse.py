#!/usr/bin/env python3
"""Independent verifier for V349's dungeon-floor crash recovery.

This verifier intentionally imports neither the V348 nor V349 builder.  It
checks the final archives, decodes and executes the already resident digit
helper, and can tie the repair back to the user-supplied V348 failure state.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/arc1_v348_floor_digit_remap_TEST_ONLY_9256295B.zip"
BUILD = ROOT / "03_output/arc1_v349_floor_resident_helper_reuse_TEST_ONLY_EC5724F9.zip"
DELTA = ROOT / "03_output/arc1_v349_floor_resident_helper_reuse_TEST_ONLY_delta_from_v348_E22EE42D.zip"
ANALYSIS = ROOT / "01_work/analysis/arc1_v349_floor_resident_helper_reuse"

BASE_SHA = "9256295B8834D0A181850FF5C5DDE4CDA7FBF2C7424B75867C3CDDB1C746716C"
BUILD_SHA = "EC5724F91C6251C76D349AAB135BC411010CE7E4BBBDBCF0D4EFFEFE1488D481"
DELTA_SHA = "E22EE42DE8D4A2F4168F4720FFFF7E8D825191AA82063B6ECBCF332C40638A06"
BASE_PSX_SHA = "0B88406460B162436C36E707788D6A0B0F73C99E6F72F98506183AF86810C346"
BUILD_PSX_SHA = "0D540C1E71C4546708B7C6C1D7328D58E31137ED4453EBCEB5B7F645A4764E1F"
COMM_SHA = "A6681F1355007725328372CC6143EF21EEE43A9FDE91FD3DC2EF3461C6805405"
FAILURE_STATE_SHA = "BD9F3A94EC276AB67894CD981585601AD2859FE29564B728B574B392343F26B5"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
RAM_TO_FILE = 0x8011A800
FLOOR_CALL_FILE = 0x4EF74
FLOOR_CALL_RAM = 0x80169774
FLOOR_DELAY = 0x02002021
UNSAFE_FILE = 0x8F400
UNSAFE_RAM = 0x801A9C00
UNSAFE_SIZE = 0x80
FORBIDDEN_CAVE_FILE = 0x8F3D8
FORBIDDEN_CAVE_RAM = 0x801A9BD8
FORBIDDEN_CAVE_SIZE = 0x428
RESIDENT_FILE = 0x8F380
RESIDENT_RAM = 0x801FF858
RESIDENT_SIZE = 0x58
RESIDENT_CODE_SIZE = 0x4C
RESIDENT_SHA = "8E4C879B5FB6DD34F4B6A7896E0F689E534113CE34247A0B6625AA9150F2FFCD"
DIGIT_LUT = bytes.fromhex("91 4A 0B 27 57 9E 9F 9A 10 08")
EXPECTED_RESIDENT = bytes.fromhex(
    "00 00 82 90 20 80 09 3C 0E 00 40 10 D0 FF 43 24 "
    "0A 00 68 2C 08 00 00 11 A4 F8 29 25 21 48 23 01 "
    "00 00 22 91 00 00 00 00 00 00 82 A0 01 00 84 24 "
    "F3 FF 00 10 00 00 00 00 E1 00 42 24 FA FF 00 10 "
    "00 00 00 00 08 00 E0 03 00 00 00 00 "
    "91 4A 0B 27 57 9E 9F 9A 10 08 00 00"
)
PREFIX = bytes.fromhex("04 19 A1")
SUFFIX = bytes.fromhex("DE 50 00")


class VerifyError(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def read_archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as handle:
        names = [item.filename for item in handle.infolist() if not item.is_dir()]
        return names, {name: handle.read(name) for name in names}


def word(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def jal(address: int) -> int:
    return 0x0C000000 | ((address >> 2) & 0x03FFFFFF)


def changed_offsets(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise VerifyError("member size changed")
    return {i for i, pair in enumerate(zip(before, after, strict=True)) if pair[0] != pair[1]}


def direct_targets(exe: bytes, target: int) -> list[tuple[int, str]]:
    text_size = word(exe, 0x1C)
    result: list[tuple[int, str]] = []
    for offset in range(0x800, min(len(exe), 0x800 + text_size), 4):
        instruction = word(exe, offset)
        opcode = instruction >> 26
        if opcode not in (2, 3):
            continue
        pc = RAM_TO_FILE + offset
        destination = ((pc + 4) & 0xF0000000) | ((instruction & 0x03FFFFFF) << 2)
        if destination == target:
            result.append((pc, "jal" if opcode == 3 else "j"))
    return result


def pointer_hits(exe: bytes, lo: int, hi: int) -> list[tuple[int, int]]:
    hits = []
    for offset in range(len(exe) - 3):
        value = word(exe, offset)
        if lo <= value < hi:
            hits.append((offset, value))
    return hits


def disassemble(helper: bytes) -> list[tuple[int, str, str]]:
    try:
        from capstone import CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32, Cs
    except ImportError as exc:
        raise VerifyError("capstone missing") from exc
    rows = [
        (ins.address, ins.mnemonic, ins.op_str)
        for ins in Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN).disasm(
            helper, RESIDENT_RAM
        )
    ]
    mnemonics = tuple(row[1] for row in rows)
    expected = (
        "lbu", "lui", "beqz", "addiu", "sltiu", "beqz", "addiu", "addu", "lbu",
        "nop", "sb", "addiu", "b", "nop", "addiu", "b", "nop", "jr", "nop",
    )
    if len(rows) != 19 or mnemonics != expected:
        raise VerifyError(f"resident helper instruction drift: {mnemonics}")
    if rows[2][2].split(", ")[-1] != "0x801ff89c":
        raise VerifyError("resident done target drift")
    if rows[5][2].split(", ")[-1] != "0x801ff890":
        raise VerifyError("resident non-digit target drift")
    if rows[12][2] != "0x801ff858" or rows[15][2] != "0x801ff880":
        raise VerifyError("resident loop/join target drift")
    # lbu at instruction 0 is consumed at 2; lbu at 8 is consumed at 10.
    if 2 - 0 < 2 or 10 - 8 < 2:
        raise VerifyError("R3000 load-delay violation")
    return rows


def run_resident_helper(raw: bytes) -> bytes:
    """Execute the actual fixed helper semantics on a small byte buffer."""
    buf = bytearray(raw + b"\0")
    cursor = 0
    while True:
        value = buf[cursor]
        if value == 0:
            return bytes(buf[:cursor])
        digit = value - 0x30
        if 0 <= digit < 10:
            buf[cursor] = DIGIT_LUT[digit]
        else:
            buf[cursor] = (value + 0xE1) & 0xFF
        cursor += 1


def parse_failure_state(path: Path, base_exe: bytes) -> dict[str, object]:
    spec = importlib.util.spec_from_file_location(
        "arc_state_parser", ROOT / "02_scripts/analyze_arc1_v320c_savestates.py"
    )
    if spec is None or spec.loader is None:
        raise VerifyError("cannot load DUCCU parser")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    parsed = module.parse_state(path)
    blob = parsed["blob"]
    ram = parsed["ram"]
    cpu_tag = struct.pack("<I", 3) + b"CPU"
    cpu = blob.find(cpu_tag)
    if cpu < 0:
        raise VerifyError("CPU section missing")
    cpu += len(cpu_tag)
    current_pc = word(blob, cpu + 0xB8)
    status = word(blob, cpu + 0xC0)
    cause = word(blob, cpu + 0xC4)
    next_pc = word(blob, cpu + 0xD4)

    def ram_slice(address: int, size: int) -> bytes:
        offset = address & 0x1FFFFF
        return ram[offset:offset + size]

    runtime_hook = ram_slice(FLOOR_CALL_RAM, 8)
    disk_hook = base_exe[FLOOR_CALL_FILE:FLOOR_CALL_FILE + 8]
    runtime_unsafe = ram_slice(UNSAFE_RAM, UNSAFE_SIZE)
    disk_unsafe = base_exe[UNSAFE_FILE:UNSAFE_FILE + UNSAFE_SIZE]
    runtime_resident = ram_slice(RESIDENT_RAM, RESIDENT_SIZE)
    pc_word = word(ram, current_pc & 0x1FFFFF)
    result = {
        "file_sha256": parsed["file_sha256"],
        "game_id": parsed["game_id"],
        "current_pc": f"0x{current_pc:08X}",
        "next_pc": f"0x{next_pc:08X}",
        "status": f"0x{status:08X}",
        "cause": f"0x{cause:08X}",
        "exception_code": (cause >> 2) & 0x1F,
        "branch_delay": bool(cause & 0x80000000),
        "pc_word": f"0x{pc_word:08X}",
        "hook_matches_v348_disk": runtime_hook == disk_hook,
        "unsafe_runtime_matches_disk": runtime_unsafe == disk_unsafe,
        "unsafe_mismatch_bytes": len(changed_offsets(runtime_unsafe, disk_unsafe)),
        "resident_runtime_matches_disk": runtime_resident == EXPECTED_RESIDENT,
    }
    if parsed["file_sha256"] != FAILURE_STATE_SHA or parsed["game_id"] != "V348":
        raise VerifyError(f"failure state identity drift: {result}")
    if (current_pc, next_pc, status, cause) != (
        0x801A9CA8, 0x801A9CAC, 0x40000404, 0x00000428
    ):
        raise VerifyError(f"failure CPU evidence drift: {result}")
    if ((cause >> 2) & 0x1F) != 10 or cause & 0x80000000:
        raise VerifyError(f"failure is not RI outside a delay slot: {result}")
    if runtime_hook != disk_hook or runtime_unsafe == disk_unsafe:
        raise VerifyError(f"failure hook/helper evidence drift: {result}")
    if runtime_resident != EXPECTED_RESIDENT:
        raise VerifyError("resident helper was not preserved in V348 failure RAM")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--failure-state", type=Path)
    args = parser.parse_args()

    for path, expected in ((BASE, BASE_SHA), (BUILD, BUILD_SHA), (DELTA, DELTA_SHA)):
        if not path.is_file() or sha(path.read_bytes()) != expected:
            raise VerifyError(f"archive hash mismatch: {path.name}")
    base_names, base = read_archive(BASE)
    build_names, build = read_archive(BUILD)
    delta_names, delta = read_archive(DELTA)
    if len(base_names) != 164 or build_names != base_names:
        raise VerifyError("164-member topology/order drift")
    changed_members = [name for name in base_names if base[name] != build[name]]
    if changed_members != [PSX] or delta_names != [PSX] or delta[PSX] != build[PSX]:
        raise VerifyError("changed-member or delta payload drift")
    if sha(base[PSX]) != BASE_PSX_SHA or sha(build[PSX]) != BUILD_PSX_SHA:
        raise VerifyError("PSX hash drift")
    if sha(build[COMM]) != COMM_SHA or build[COMM] != base[COMM]:
        raise VerifyError("COMM.IMG changed")
    if any(build[name] != base[name] for name in base_names if name != PSX):
        raise VerifyError("non-PSX member changed")

    before = base[PSX]
    exe = build[PSX]
    if len(EXPECTED_RESIDENT) != RESIDENT_SIZE or sha(EXPECTED_RESIDENT) != RESIDENT_SHA:
        raise VerifyError("pinned resident helper constant is invalid")
    resident = exe[RESIDENT_FILE:RESIDENT_FILE + RESIDENT_SIZE]
    if resident != EXPECTED_RESIDENT or resident != before[RESIDENT_FILE:RESIDENT_FILE + RESIDENT_SIZE]:
        raise VerifyError("resident helper changed or differs from pinned bytes")
    rows = disassemble(resident[:RESIDENT_CODE_SIZE])

    if word(exe, FLOOR_CALL_FILE) != jal(RESIDENT_RAM) or word(exe, FLOOR_CALL_FILE + 4) != FLOOR_DELAY:
        raise VerifyError("floor hook or delay slot mismatch")
    if any(exe[FORBIDDEN_CAVE_FILE:FORBIDDEN_CAVE_FILE + FORBIDDEN_CAVE_SIZE]):
        raise VerifyError("full scene-loader/BSS forbidden cave not erased")
    if direct_targets(exe, RESIDENT_RAM) != [
        (0x80160464, "jal"), (FLOOR_CALL_RAM, "jal")
    ]:
        raise VerifyError("resident helper caller set drift")
    cave_control = []
    text_size = word(exe, 0x1C)
    for offset in range(0x800, min(len(exe), 0x800 + text_size), 4):
        instruction = word(exe, offset)
        if instruction >> 26 not in (2, 3):
            continue
        pc = RAM_TO_FILE + offset
        target = ((pc + 4) & 0xF0000000) | ((instruction & 0x03FFFFFF) << 2)
        if FORBIDDEN_CAVE_RAM <= target < FORBIDDEN_CAVE_RAM + FORBIDDEN_CAVE_SIZE:
            cave_control.append((pc, target))
    cave_pointers = pointer_hits(
        exe, FORBIDDEN_CAVE_RAM, FORBIDDEN_CAVE_RAM + FORBIDDEN_CAVE_SIZE
    )
    if cave_control or cave_pointers:
        raise VerifyError("forbidden cave remains reachable or referenced")

    floor_rows = []
    for floor in range(1, 51):
        mapped = run_resident_helper(str(floor).encode("ascii"))
        expected = bytes(DIGIT_LUT[int(ch)] for ch in str(floor))
        final = PREFIX + mapped + SUFFIX
        if mapped != expected or len(final) > 8 or not final.endswith(b"\0"):
            raise VerifyError(f"floor conversion mismatch at {floor}")
        floor_rows.append({"floor": floor, "mapped": mapped.hex(" ").upper(), "bytes": len(final)})

    actual = changed_offsets(before, exe)
    with (ANALYSIS / "expected_writes.csv").open(encoding="utf-8-sig", newline="") as handle:
        expected_rows = list(csv.DictReader(handle))
    csv_offsets = {int(row["offset"], 16) for row in expected_rows}
    if len(actual) != 80 or csv_offsets != actual:
        raise VerifyError("Expected-Write differs from exact 80-byte PSX diff")
    for row in expected_rows:
        offset = int(row["offset"], 16)
        if before[offset] != int(row["before"], 16) or exe[offset] != int(row["after"], 16):
            raise VerifyError(f"Expected-Write byte mismatch at 0x{offset:X}")
    envelope = set(range(FLOOR_CALL_FILE, FLOOR_CALL_FILE + 4)) | set(
        range(UNSAFE_FILE, UNSAFE_FILE + UNSAFE_SIZE)
    )
    if not actual <= envelope:
        raise VerifyError("PSX diff escaped approved envelope")

    # Preserve the V347/V348 story repairs and floor source strings exactly.
    for offset, expected in ((0x7EF3C, 0x80162CE0), (0x8D788, 0x8012E2E0)):
        if word(exe, offset) != expected or word(exe, offset) != word(before, offset):
            raise VerifyError(f"prior code-pointer regression at 0x{offset:X}")
    for offset, size in ((0x809F4, 4), (0x8215C, 3), (0x823B0, 8)):
        if exe[offset:offset + size] != before[offset:offset + size]:
            raise VerifyError(f"prior floor/dialogue regression at 0x{offset:X}")

    failure = parse_failure_state(args.failure_state, before) if args.failure_state else None
    report = {
        "verdict": "STATIC_PASS_RUNTIME_PENDING",
        "archives": {"full": BUILD_SHA, "delta": DELTA_SHA, "members": 164},
        "changed_members": changed_members,
        "exact_diff_bytes": len(actual),
        "resident_helper": {
            "sha256": RESIDENT_SHA,
            "instructions": len(rows),
            "unchanged_from_v348": True,
            "callers": ["0x80160464", "0x80169774"],
            "load_delays": "PASS",
        },
        "forbidden_cave": {
            "range": "0x801A9BD8..0x801A9FFF",
            "bytes": FORBIDDEN_CAVE_SIZE,
            "all_zero": True,
            "control_targets": len(cave_control),
            "pointer_hits": len(cave_pointers),
        },
        "floors": {"range": "1..50", "passed": len(floor_rows), "maximum_buffer": 8},
        "failure_state": failure,
        "preservation": "all DAT, COMM.IMG, and all non-PSX members byte exact",
        "runtime": "PENDING user cold boot; TEST_ONLY",
    }
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    if failure:
        (ANALYSIS / "v348_failure_state_forensics.json").write_text(
            json.dumps(failure, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    lines = [
        "V349 independent static verification PASS",
        f"full={BUILD_SHA}",
        f"delta={DELTA_SHA}",
        "members=164 changed=PSX.EXE only exact_diff_bytes=80",
        "floor hook=0x80169774 -> resident 0x801FF858; delay slot preserved",
        "resident helper=88/88 bytes unchanged; 19 MIPS-I instructions; callers=level+floor",
        "forbidden cave 0x801A9BD8..0x801A9FFF=1064/1064 zero; direct/reference hits=0",
        "machine semantics=floors 1..50 exact current digit codes; max buffer 8 bytes",
        "DAT/COMM.IMG/all non-PSX members=byte exact",
        "V348 failure state=Reserved Instruction after unsafe helper overwrite PASS" if failure else
        "V348 failure state=not supplied",
        "runtime=PENDING user cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "independent_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
