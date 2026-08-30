#!/usr/bin/env python3
"""Build V349: recover V348 dungeon entry by reusing the resident digit helper.

V348 put a floor-only wrapper at 0x801A9C00.  That area is cleared or reused
by scene loading, so the first dungeon transition executed overwritten bytes
and raised Reserved Instruction.  V338 already installed an equivalent ASCII
digit converter in the boot-copied resident block at 0x801FF858.  V349 points
the floor formatter at that proven helper and restores the unsafe tail to zero.
"""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import build_arc1_v338_v197_v210_catchup as v338  # noqa: E402
import build_arc1_v345_story_timing_cursor_recovery as v345  # noqa: E402
import build_arc1_v348_floor_digit_remap as v348  # noqa: E402


BASE = ROOT / "03_output/arc1_v348_floor_digit_remap_TEST_ONLY_9256295B.zip"
BASE_SHA256 = "9256295B8834D0A181850FF5C5DDE4CDA7FBF2C7424B75867C3CDDB1C746716C"
OUTPUT_STEM = "arc1_v349_floor_resident_helper_reuse_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v348"
ANALYSIS = ROOT / "01_work/analysis/arc1_v349_floor_resident_helper_reuse"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
BASE_PSX_SHA256 = "0B88406460B162436C36E707788D6A0B0F73C99E6F72F98506183AF86810C346"
BASE_COMM_SHA256 = "A6681F1355007725328372CC6143EF21EEE43A9FDE91FD3DC2EF3461C6805405"

FLOOR_CALL_FILE = 0x4EF74
FLOOR_CALL_RAM = 0x80169774
FLOOR_DELAY_WORD = 0x02002021  # move a0,s0
V348_BAD_HELPER_FILE = 0x8F400
V348_BAD_HELPER_RAM = 0x801A9C00
V348_BAD_PAYLOAD = v348.assemble_helper() + v348.DIGIT_LUT
V348_BAD_END_FILE = V348_BAD_HELPER_FILE + len(V348_BAD_PAYLOAD)
FORBIDDEN_CAVE_FILE = 0x8F3D8
FORBIDDEN_CAVE_RAM = 0x801A9BD8
FORBIDDEN_CAVE_SIZE = 0x428
FORBIDDEN_CAVE_END_FILE = FORBIDDEN_CAVE_FILE + FORBIDDEN_CAVE_SIZE

RESIDENT_HELPER_FILE = 0x8F380
RESIDENT_HELPER_RAM = 0x801FF858
RESIDENT_HELPER_CAPACITY = 0x58
RESIDENT_HELPER_SHA256 = "8E4C879B5FB6DD34F4B6A7896E0F689E534113CE34247A0B6625AA9150F2FFCD"
RESIDENT_CODE_SIZE = 0x4C
RESIDENT_LUT = bytes.fromhex("91 4A 0B 27 57 9E 9F 9A 10 08")

V348_STATE_SHA256 = "BD9F3A94EC276AB67894CD981585601AD2859FE29564B728B574B392343F26B5"
V348_FAILURE_PC = 0x801A9CA8
V348_FAILURE_CAUSE = 0x00000428


class BuildError(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def word(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def jal(address: int) -> int:
    return 0x0C000000 | ((address >> 2) & 0x03FFFFFF)


def archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    if not path.is_file() or sha(path.read_bytes()) != BASE_SHA256:
        raise BuildError("V348 base archive hash drift")
    return v345.read_archive(path)


def resident_helper_bytes() -> bytes:
    payload, _words = v338.build_level_digit_helper()
    if len(payload) != RESIDENT_HELPER_CAPACITY or sha(payload) != RESIDENT_HELPER_SHA256:
        raise BuildError("resident digit-helper definition drift")
    if payload[RESIDENT_CODE_SIZE:RESIDENT_CODE_SIZE + 10] != RESIDENT_LUT:
        raise BuildError("resident digit LUT drift")
    return payload


def direct_targets(exe: bytes, target: int) -> list[tuple[int, str]]:
    text_size = word(exe, 0x1C)
    result: list[tuple[int, str]] = []
    for offset in range(0x800, min(len(exe), 0x800 + text_size), 4):
        instruction = word(exe, offset)
        op = instruction >> 26
        if op not in (2, 3):
            continue
        pc = offset + v348.RAM_TO_FILE
        destination = ((pc + 4) & 0xF0000000) | ((instruction & 0x03FFFFFF) << 2)
        if destination == target:
            result.append((pc, "jal" if op == 3 else "j"))
    return result


def forbidden_control_targets(exe: bytes) -> list[tuple[int, int]]:
    text_size = word(exe, 0x1C)
    result: list[tuple[int, int]] = []
    for offset in range(0x800, min(len(exe), 0x800 + text_size), 4):
        instruction = word(exe, offset)
        if instruction >> 26 not in (2, 3):
            continue
        pc = offset + v348.RAM_TO_FILE
        destination = ((pc + 4) & 0xF0000000) | ((instruction & 0x03FFFFFF) << 2)
        if FORBIDDEN_CAVE_RAM <= destination < FORBIDDEN_CAVE_RAM + FORBIDDEN_CAVE_SIZE:
            result.append((pc, destination))
    return result


def forbidden_pointer_hits(exe: bytes) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    for offset in range(len(exe) - 3):
        value = word(exe, offset)
        if FORBIDDEN_CAVE_RAM <= value < FORBIDDEN_CAVE_RAM + FORBIDDEN_CAVE_SIZE:
            result.append((offset, value))
    return result


def assert_base(names: list[str], base: dict[str, bytes]) -> None:
    if len(names) != 164 or len(base) != 164:
        raise BuildError("V348 archive topology drift")
    if sha(base[PSX]) != BASE_PSX_SHA256 or sha(base[COMM]) != BASE_COMM_SHA256:
        raise BuildError("V348 member hash drift")
    exe = base[PSX]
    if word(exe, FLOOR_CALL_FILE) != jal(V348_BAD_HELPER_RAM):
        raise BuildError("V348 floor hook premise drift")
    if word(exe, FLOOR_CALL_FILE + 4) != FLOOR_DELAY_WORD:
        raise BuildError("floor delay-slot premise drift")
    if exe[V348_BAD_HELPER_FILE:V348_BAD_END_FILE] != V348_BAD_PAYLOAD:
        raise BuildError("V348 unsafe helper payload drift")
    expected_cave = bytearray(FORBIDDEN_CAVE_SIZE)
    cave_offset = V348_BAD_HELPER_FILE - FORBIDDEN_CAVE_FILE
    expected_cave[cave_offset:cave_offset + len(V348_BAD_PAYLOAD)] = V348_BAD_PAYLOAD
    if exe[FORBIDDEN_CAVE_FILE:FORBIDDEN_CAVE_END_FILE] != expected_cave:
        raise BuildError("V348 forbidden cave contains unclassified bytes")
    if exe[RESIDENT_HELPER_FILE:RESIDENT_HELPER_FILE + RESIDENT_HELPER_CAPACITY] != resident_helper_bytes():
        raise BuildError("resident digit helper differs from V338 definition")
    expected = [(0x80160464, "jal")]
    if direct_targets(exe, RESIDENT_HELPER_RAM) != expected:
        raise BuildError("V348 resident helper caller set drift")


def convert_ascii(raw: bytes) -> bytes:
    result = bytearray()
    for value in raw:
        if value == 0:
            break
        if 0x30 <= value <= 0x39:
            result.append(RESIDENT_LUT[value - 0x30])
        else:
            result.append((value + 0xE1) & 0xFF)
    return bytes(result)


def floor_payload(level: int) -> bytes:
    return v348.FLOOR_PREFIX[:-1] + convert_ascii(str(level).encode("ascii") + b"\0") + v348.FLOOR_SUFFIX


def build_once(names: list[str], base: dict[str, bytes]) -> dict[str, bytes]:
    assert_base(names, base)
    final = dict(base)
    exe = bytearray(base[PSX])
    struct.pack_into("<I", exe, FLOOR_CALL_FILE, jal(RESIDENT_HELPER_RAM))
    exe[V348_BAD_HELPER_FILE:V348_BAD_END_FILE] = bytes(len(V348_BAD_PAYLOAD))
    final[PSX] = bytes(exe)

    if word(exe, FLOOR_CALL_FILE + 4) != FLOOR_DELAY_WORD:
        raise BuildError("floor delay slot changed")
    if any(exe[FORBIDDEN_CAVE_FILE:FORBIDDEN_CAVE_END_FILE]):
        raise BuildError("full scene-loader/BSS forbidden cave was not restored")
    if exe[RESIDENT_HELPER_FILE:RESIDENT_HELPER_FILE + RESIDENT_HELPER_CAPACITY] != resident_helper_bytes():
        raise BuildError("resident helper changed")
    if direct_targets(bytes(exe), RESIDENT_HELPER_RAM) != [
        (0x80160464, "jal"), (FLOOR_CALL_RAM, "jal")
    ]:
        raise BuildError("resident helper caller set mismatch")
    if direct_targets(bytes(exe), V348_BAD_HELPER_RAM):
        raise BuildError("unsafe helper remains reachable")
    if forbidden_control_targets(bytes(exe)) or forbidden_pointer_hits(bytes(exe)):
        raise BuildError("forbidden cave remains reachable or referenced")

    for level in range(1, 51):
        expected_digits = bytes(RESIDENT_LUT[int(ch)] for ch in str(level))
        payload = floor_payload(level)
        if payload != v348.FLOOR_PREFIX[:-1] + expected_digits + v348.FLOOR_SUFFIX:
            raise BuildError(f"floor {level} conversion mismatch")
        if len(payload) > 8 or not payload.endswith(b"\0"):
            raise BuildError(f"floor {level} buffer invariant failed")
    if any(final[name] != base[name] for name in names if name != PSX):
        raise BuildError("non-PSX member changed")
    return final


def purpose(offset: int) -> str:
    if FLOOR_CALL_FILE <= offset < FLOOR_CALL_FILE + 4:
        return "redirect_floor_converter_to_boot_copied_resident_digit_helper"
    if V348_BAD_HELPER_FILE <= offset < V348_BAD_END_FILE:
        return "erase_runtime_overwritten_v348_helper_and_lut"
    raise BuildError(f"unclassified write at 0x{offset:X}")


def main() -> None:
    names, base = archive(BASE)
    final = build_once(names, base)
    if final != build_once(names, base):
        raise BuildError("in-memory deterministic rebuild mismatch")
    changed_members = [name for name in names if final[name] != base[name]]
    if changed_members != [PSX]:
        raise BuildError(f"changed-member drift: {changed_members}")
    if any(len(final[name]) != len(base[name]) for name in names):
        raise BuildError("member size changed")

    actual = v345.changed_offsets(base[PSX], final[PSX])
    envelope = set(range(FLOOR_CALL_FILE, FLOOR_CALL_FILE + 4)) | set(
        range(V348_BAD_HELPER_FILE, V348_BAD_END_FILE)
    )
    if not actual or not actual <= envelope:
        raise BuildError("Expected-Write envelope violation")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    output_temp = ROOT / "03_output" / f"{OUTPUT_STEM}.zip"
    delta_temp = ROOT / "03_output" / f"{DELTA_STEM}.zip"
    for path in (output_temp, delta_temp):
        if path.exists():
            path.unlink()
    v345.write_archive(output_temp, names, final)
    v345.write_archive(delta_temp, changed_members, final)
    output_hash = sha(output_temp.read_bytes())
    delta_hash = sha(delta_temp.read_bytes())
    output = output_temp.with_name(f"{OUTPUT_STEM}_{output_hash[:8]}.zip")
    delta = delta_temp.with_name(f"{DELTA_STEM}_{delta_hash[:8]}.zip")
    for source, target in ((output_temp, output), (delta_temp, delta)):
        if target.exists():
            if sha(target.read_bytes()) != sha(source.read_bytes()):
                raise BuildError(f"existing output differs: {target.name}")
            source.unlink()
        else:
            source.replace(target)

    with (ANALYSIS / "expected_writes.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=("member", "offset", "before", "after", "purpose"))
        writer.writeheader()
        for offset in sorted(actual):
            writer.writerow({
                "member": PSX,
                "offset": f"0x{offset:X}",
                "before": f"{base[PSX][offset]:02X}",
                "after": f"{final[PSX][offset]:02X}",
                "purpose": purpose(offset),
            })

    with (ANALYSIS / "floor_1_to_50.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=("floor", "ascii", "mapped", "final", "bytes"))
        writer.writeheader()
        for level in range(1, 51):
            payload = floor_payload(level)
            writer.writerow({
                "floor": level,
                "ascii": str(level).encode("ascii").hex(" ").upper(),
                "mapped": convert_ascii(str(level).encode("ascii") + b"\0").hex(" ").upper(),
                "final": payload.hex(" ").upper(),
                "bytes": len(payload),
            })

    manifest = {
        "version": "V349",
        "status": "STATIC_PASS_RUNTIME_PENDING",
        "base": {"file": BASE.name, "sha256": BASE_SHA256},
        "output": {"file": output.name, "sha256": output_hash},
        "delta": {"file": delta.name, "sha256": delta_hash},
        "changed_members_vs_v348": changed_members,
        "changed_bytes": {PSX: len(actual)},
        "failure_evidence": {
            "state_sha256": V348_STATE_SHA256,
            "pc": f"0x{V348_FAILURE_PC:08X}",
            "cause": f"0x{V348_FAILURE_CAUSE:08X}",
            "exception": "Reserved Instruction; V348 helper overwritten during scene load",
        },
        "repair": {
            "floor_hook_file": f"0x{FLOOR_CALL_FILE:X}",
            "resident_helper_ram": f"0x{RESIDENT_HELPER_RAM:08X}",
            "new_resident_bytes": 0,
            "unsafe_tail_restored": f"0x{V348_BAD_HELPER_FILE:X}..0x{V348_BAD_END_FILE - 1:X}",
            "verified_floors": "1..50",
        },
        "preserved": "all DAT, COMM.IMG, V347/V348 non-floor content byte exact",
        "runtime": "PENDING user cold boot; TEST_ONLY",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V349 floor resident-helper reuse",
        f"base={BASE.name} sha256={BASE_SHA256}",
        f"output={output.name} sha256={output_hash}",
        f"delta={delta.name} sha256={delta_hash}",
        f"changed_members={','.join(changed_members)} changed_bytes={len(actual)}",
        f"floor hook=0x{FLOOR_CALL_FILE:X} jal 0x{RESIDENT_HELPER_RAM:08X}; delay preserved",
        "forbidden cave 0x801A9BD8..0x801A9FFF=1064/1064 zero; inbound/pointer refs=0",
        "resident helper=existing V338 code, 88/88 bytes unchanged; callers=level+floor",
        "floors 1..50 exact current digit codes; max final buffer=8 bytes",
        "DAT/COMM.IMG/all non-PSX members=byte exact",
        "runtime=PENDING user cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    (ANALYSIS / "runtime_checklist.txt").write_text(
        "V349 cold-boot checklist\n"
        "1. V349.cue를 완전 콜드부팅하고 기존 메모리카드 저장을 불러온다.\n"
        "2. 유적 던전에 진입해 검은 화면/정지 없이 장면이 전환되는지 확인한다.\n"
        "3. 지하 1층, 2층, 9층, 10층 이상의 숫자와 중앙 정렬을 확인한다.\n"
        "4. 레벨업 숫자, 기술 사용, 범위 커서, 전투 후 대사도 회귀가 없는지 확인한다.\n",
        encoding="utf-8",
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
