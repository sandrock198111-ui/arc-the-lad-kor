#!/usr/bin/env python3
"""Build V348: remap dungeon-floor decimal digits in the floor-local path.

V347 changed the formatter's prefix/suffix to ``지하 `` and ``층`` but kept
the original ASCII-to-game conversion.  That converter emits raw 0x11..0x1A
for decimal 0..9, which no longer point at digits in the current 16px atlas.

This build redirects only the floor formatter's conversion call to a small
leaf wrapper.  The wrapper calls the stock converter, then translates its ten
legacy digit bytes through a local LUT.  Normal dialogue/UI decoding, DAT and
COMM.IMG are deliberately untouched.
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

import build_arc1_v345_story_timing_cursor_recovery as v345  # noqa: E402


BASE = ROOT / "03_output/arc1_v347_freeze_floor_dialogue_repair_TEST_ONLY_028303F6.zip"
BASE_SHA256 = "028303F62EFA7D1362DAA6AA57B2224B39A8692CD2D8CA0073980DA1DAF73302"
OUTPUT_STEM = "arc1_v348_floor_digit_remap_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v347"
ANALYSIS = ROOT / "01_work/analysis/arc1_v348_floor_digit_remap"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
BASE_MEMBER_SHA256 = {
    PSX: "826BD14337B287A656364FA4AB004535B85F276376072CA6FA6351AC3A64A337",
    COMM: "A6681F1355007725328372CC6143EF21EEE43A9FDE91FD3DC2EF3461C6805405",
    "5/S5011.DAT": "56C982F78305D61E81C4AA8A32194A492586EA7CA1AA3072798289C7D54EF12C",
    "5/S5021.DAT": "28F75F211C4AEDC797966D960C7033FB32F50928BC00282EB5861C5B86EB0057",
}

RAM_TO_FILE = 0x8011A800
TEXT_RAM = 0x8011B000
TEXT_FILE = 0x800
TEXT_SIZE = 0x8F000

FLOOR_CALL_FILE = 0x4EF74
FLOOR_CALL_RAM = RAM_TO_FILE + FLOOR_CALL_FILE
STOCK_CONVERTER_RAM = 0x8015E4C0
OLD_CALL_WORD = 0x0C057930
CALL_DELAY_WORD = 0x02002021  # move a0,s0

HELPER_FILE = 0x8F400
HELPER_RAM = RAM_TO_FILE + HELPER_FILE
HELPER_WORDS = 25
HELPER_SIZE = HELPER_WORDS * 4
LUT_FILE = HELPER_FILE + HELPER_SIZE
LUT_RAM = RAM_TO_FILE + LUT_FILE

# Current direct one-byte raw codes for physical digits 0..9.
DIGIT_LUT = bytes.fromhex("91 4A 0B 27 57 9E 9F 9A 10 08")
EXPECTED_HELPER_HEX = (
    "e8ffbd271400bfaf1000b0af218080003079050c00000000"
    "1b80083c649c082500000992000000000a002011efff2a25"
    "0a004b2d050060110000000021600a0100008d9100000000"
    "00000da208a70608010010261400bf8f1000b08f0800e003"
    "1800bd27"
)

FLOOR_PREFIX_POINTER = 0x823B0
FLOOR_SUFFIX_POINTER = 0x823B4
FLOOR_PREFIX_FILE = 0x809F4
FLOOR_SUFFIX_FILE = 0x8215C
FLOOR_PREFIX = bytes.fromhex("04 19 A1 00")
FLOOR_SUFFIX = bytes.fromhex("DE 50 00")

V347_CODE_POINTERS = {
    0x7EF3C: 0x80162CE0,
    0x8D788: 0x8012E2E0,
}


class BuildError(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def word(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def i_type(op: int, rs: int, rt: int, imm: int) -> int:
    return (op << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def r_type(rs: int, rt: int, rd: int, shift: int, funct: int) -> int:
    return (rs << 21) | (rt << 16) | (rd << 11) | (shift << 6) | funct


def j_type(op: int, target: int) -> int:
    return (op << 26) | ((target >> 2) & 0x03FFFFFF)


def assemble_helper() -> bytes:
    zero, a0, t0, t1, t2, t3, t4, t5, s0, sp, ra = 0, 4, 8, 9, 10, 11, 12, 13, 16, 29, 31
    words = (
        i_type(9, sp, sp, -0x18),
        i_type(43, sp, ra, 0x14),
        i_type(43, sp, s0, 0x10),
        r_type(a0, zero, s0, 0, 0x21),
        j_type(3, STOCK_CONVERTER_RAM),
        0,
        i_type(15, zero, t0, 0x801B),
        i_type(9, t0, t0, -0x639C),
        i_type(36, s0, t1, 0),
        0,
        i_type(4, t1, zero, 10),
        i_type(9, t1, t2, -0x11),
        i_type(11, t2, t3, 10),
        i_type(4, t3, zero, 5),
        0,
        r_type(t0, t2, t4, 0, 0x21),
        i_type(36, t4, t5, 0),
        0,
        i_type(40, s0, t5, 0),
        j_type(2, HELPER_RAM + 0x20),
        i_type(9, s0, s0, 1),
        i_type(35, sp, ra, 0x14),
        i_type(35, sp, s0, 0x10),
        r_type(ra, zero, zero, 0, 8),
        i_type(9, sp, sp, 0x18),
    )
    data = b"".join(struct.pack("<I", value) for value in words)
    if data.hex() != EXPECTED_HELPER_HEX:
        raise BuildError("helper assembly differs from pinned byte specification")
    return data


def archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    if not path.is_file() or sha(path.read_bytes()) != BASE_SHA256:
        raise BuildError("V347 base archive hash drift")
    return v345.read_archive(path)


def assert_base(names: list[str], base: dict[str, bytes]) -> None:
    if len(names) != 164 or len(base) != 164:
        raise BuildError("V347 archive topology drift")
    for name, expected in BASE_MEMBER_SHA256.items():
        if sha(base[name]) != expected:
            raise BuildError(f"V347 member hash drift: {name}")
    exe = base[PSX]
    if exe[:8] != b"PS-X EXE" or word(exe, 0x18) != TEXT_RAM or word(exe, 0x1C) != TEXT_SIZE:
        raise BuildError("PS-X EXE load range drift")
    if not (TEXT_RAM <= HELPER_RAM and HELPER_RAM + HELPER_SIZE + len(DIGIT_LUT) <= TEXT_RAM + TEXT_SIZE):
        raise BuildError("helper is outside the loaded executable range")
    if word(exe, FLOOR_CALL_FILE) != OLD_CALL_WORD or word(exe, FLOOR_CALL_FILE + 4) != CALL_DELAY_WORD:
        raise BuildError("floor conversion call-site drift")
    if any(exe[HELPER_FILE:HELPER_FILE + 0x80]):
        raise BuildError("resident helper cave is not zero")
    if word(exe, FLOOR_PREFIX_POINTER) != RAM_TO_FILE + FLOOR_PREFIX_FILE:
        raise BuildError("floor prefix pointer drift")
    if word(exe, FLOOR_SUFFIX_POINTER) != RAM_TO_FILE + FLOOR_SUFFIX_FILE:
        raise BuildError("floor suffix pointer drift")
    if exe[FLOOR_PREFIX_FILE:FLOOR_PREFIX_FILE + len(FLOOR_PREFIX)] != FLOOR_PREFIX:
        raise BuildError("V347 floor prefix drift")
    if exe[FLOOR_SUFFIX_FILE:FLOOR_SUFFIX_FILE + len(FLOOR_SUFFIX)] != FLOOR_SUFFIX:
        raise BuildError("V347 floor suffix drift")
    for offset, expected in V347_CODE_POINTERS.items():
        if word(exe, offset) != expected:
            raise BuildError(f"V347 code-pointer repair drift at 0x{offset:X}")

    cave_start = HELPER_RAM
    cave_end = LUT_RAM + len(DIGIT_LUT)
    for offset in range(TEXT_FILE, TEXT_FILE + TEXT_SIZE - 3, 4):
        value = word(exe, offset)
        if cave_start <= value < cave_end:
            raise BuildError(f"pre-existing aligned cave pointer at 0x{offset:X}")
        if value >> 26 in (2, 3):
            target = ((RAM_TO_FILE + offset + 4) & 0xF0000000) | ((value & 0x03FFFFFF) << 2)
            if cave_start <= target < cave_end:
                raise BuildError(f"pre-existing direct cave control flow at 0x{offset:X}")


def mapped_decimal(level: int) -> bytes:
    legacy = bytes(((ord(ch) + 0xE1) & 0xFF) for ch in str(level))
    result = bytearray(legacy)
    for index, value in enumerate(result):
        if 0x11 <= value <= 0x1A:
            result[index] = DIGIT_LUT[value - 0x11]
    return bytes(result)


def floor_payload(level: int) -> bytes:
    result = FLOOR_PREFIX[:-1] + mapped_decimal(level) + FLOOR_SUFFIX
    if len(result) > 8 or result[-1] != 0:
        raise BuildError(f"floor buffer overflow/termination failure at {level}")
    return result


def build_once(names: list[str], base: dict[str, bytes]) -> dict[str, bytes]:
    assert_base(names, base)
    helper = assemble_helper()
    final = dict(base)
    exe = bytearray(base[PSX])
    struct.pack_into("<I", exe, FLOOR_CALL_FILE, j_type(3, HELPER_RAM))
    exe[HELPER_FILE:HELPER_FILE + len(helper)] = helper
    exe[LUT_FILE:LUT_FILE + len(DIGIT_LUT)] = DIGIT_LUT
    final[PSX] = bytes(exe)

    if word(exe, FLOOR_CALL_FILE + 4) != CALL_DELAY_WORD:
        raise BuildError("floor call delay slot changed")
    if exe[HELPER_FILE:HELPER_FILE + HELPER_SIZE] != helper:
        raise BuildError("helper readback failed")
    if exe[LUT_FILE:LUT_FILE + len(DIGIT_LUT)] != DIGIT_LUT:
        raise BuildError("digit LUT readback failed")
    for level in range(1, 51):
        expected = FLOOR_PREFIX[:-1] + bytes(DIGIT_LUT[int(ch)] for ch in str(level)) + FLOOR_SUFFIX
        if floor_payload(level) != expected:
            raise BuildError(f"floor {level} conversion failed")
    if any(final[name] != base[name] for name in names if name != PSX):
        raise BuildError("non-PSX member changed")
    for offset, expected in V347_CODE_POINTERS.items():
        if word(final[PSX], offset) != expected:
            raise BuildError(f"V347 code-pointer repair regressed at 0x{offset:X}")
    return final


def purpose(offset: int) -> str:
    if FLOOR_CALL_FILE <= offset < FLOOR_CALL_FILE + 4:
        return "redirect_floor_digit_converter_to_local_wrapper"
    if HELPER_FILE <= offset < HELPER_FILE + HELPER_SIZE:
        return "floor_local_legacy_digit_remap_helper"
    if LUT_FILE <= offset < LUT_FILE + len(DIGIT_LUT):
        return "floor_digit_raw_code_lut_0_to_9"
    raise BuildError(f"unclassified PSX write at 0x{offset:X}")


def disassembly(data: bytes) -> list[str]:
    try:
        from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32
    except ImportError as exc:
        raise BuildError("capstone is required to verify the helper") from exc
    decoder = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    rows = [f"0x{ins.address:08X}  {ins.mnemonic:<7} {ins.op_str}".rstrip()
            for ins in decoder.disasm(data, HELPER_RAM)]
    if len(rows) != HELPER_WORDS:
        raise BuildError(f"helper disassembly count drift: {len(rows)}")
    return rows


def main() -> None:
    names, base = archive(BASE)
    final = build_once(names, base)
    if final != build_once(names, base):
        raise BuildError("in-memory deterministic rebuild mismatch")
    if any(len(final[name]) != len(base[name]) for name in names):
        raise BuildError("member size changed")
    changed_members = [name for name in names if final[name] != base[name]]
    if changed_members != [PSX]:
        raise BuildError(f"changed-member drift: {changed_members}")

    actual = v345.changed_offsets(base[PSX], final[PSX])
    envelope = set(range(FLOOR_CALL_FILE, FLOOR_CALL_FILE + 4))
    envelope.update(range(HELPER_FILE, HELPER_FILE + HELPER_SIZE))
    envelope.update(range(LUT_FILE, LUT_FILE + len(DIGIT_LUT)))
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
        writer = csv.DictWriter(handle, fieldnames=("level", "legacy_digit_bytes", "mapped_digit_bytes", "final_bytes", "final_size"))
        writer.writeheader()
        for level in range(1, 51):
            legacy = bytes(((ord(ch) + 0xE1) & 0xFF) for ch in str(level))
            payload = floor_payload(level)
            writer.writerow({
                "level": level,
                "legacy_digit_bytes": legacy.hex(" ").upper(),
                "mapped_digit_bytes": mapped_decimal(level).hex(" ").upper(),
                "final_bytes": payload.hex(" ").upper(),
                "final_size": len(payload),
            })

    disasm = disassembly(assemble_helper())
    (ANALYSIS / "helper_disassembly.txt").write_text("\n".join(disasm) + "\n", encoding="utf-8")
    manifest = {
        "version": "V348",
        "status": "STATIC_PASS_RUNTIME_PENDING",
        "base": {"file": BASE.name, "sha256": BASE_SHA256},
        "output": {"file": output.name, "sha256": output_hash},
        "delta": {"file": delta.name, "sha256": delta_hash},
        "changed_members_vs_v347": changed_members,
        "changed_bytes": {PSX: len(actual)},
        "floor_digit_fix": {
            "hook_file": f"0x{FLOOR_CALL_FILE:X}",
            "hook_ram": f"0x{FLOOR_CALL_RAM:08X}",
            "helper_file": f"0x{HELPER_FILE:X}",
            "helper_ram": f"0x{HELPER_RAM:08X}",
            "lut": DIGIT_LUT.hex(" ").upper(),
            "verified_levels": "1..50",
            "max_buffer_bytes_including_nul": 8,
        },
        "preserved": {
            "DAT_members": "byte exact",
            "COMM_IMG": "byte exact",
            "V347_code_pointer_repairs": "byte exact",
            "V347_dialogue_repairs": "byte exact",
        },
        "runtime": "PENDING user cold boot; TEST_ONLY",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V348 floor digit remap",
        f"base={BASE.name} sha256={BASE_SHA256}",
        f"output={output.name} sha256={output_hash}",
        f"delta={delta.name} sha256={delta_hash}",
        f"changed_members={','.join(changed_members)}",
        f"changed_bytes={len(actual)}",
        f"hook=0x{FLOOR_CALL_FILE:X} jal 0x{HELPER_RAM:08X}; delay slot preserved",
        f"helper=0x{HELPER_FILE:X}+0x{HELPER_SIZE:X}; lut=0x{LUT_FILE:X}+0x{len(DIGIT_LUT):X}",
        "floors=1..50 exact mapped digits; final buffer <=8 bytes including NUL",
        "DAT/COMM.IMG/V347 pointer and dialogue fixes=byte exact",
        "runtime=PENDING user cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    (ANALYSIS / "runtime_checklist.txt").write_text(
        "V348 cold-boot checklist\n"
        "1. 유적 지하 1층, 2층, 3층과 10층 이상 표시에서 숫자가 보이는지 확인.\n"
        "2. 표기가 '지하 1층' 형식이고 중앙 정렬되는지 확인.\n"
        "3. V347 기술 사용 프리징 수정, 다섯 대사, 선택지/커서가 유지되는지 확인.\n"
        "4. 일반 대화·UI 숫자와 COMM.IMG가 달라지지 않았는지 확인.\n",
        encoding="utf-8",
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
