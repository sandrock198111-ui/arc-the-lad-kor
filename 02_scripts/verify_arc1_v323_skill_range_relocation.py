#!/usr/bin/env python3
"""Independent static verifier for V323's relocated skill-range texture."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))

from capstone import (  # noqa: E402
    CS_ARCH_MIPS,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_MIPS32,
    Cs,
)


BASE = ROOT / "03_output/arc1_v322_e2_skip_restore_TEST_ONLY_480924F9.zip"
BASE_SHA256 = "480924F970C441BA819BC1F2FA003ED430FA76509ED138C8B33F444044057B32"
ORIGINAL = ROOT / "00_original/arc.zip"
OUTPUT = ROOT / "01_work/analysis/arc1_v323_skill_range_relocation"

PSX, COMM = "PSX.EXE", "COMM.IMG"
RAM_TO_FILE = 0x8011A800
HOOK_RAM, HOOK_FILE = 0x8011E614, 0x3E14
CAVE_RAM, CAVE_FILE, CAVE_SIZE = 0x801A9BD8, 0x8F3D8, 0x428
HELPER_SIZE, RLE_SIZE = 324, 652
DATA_RAM = CAVE_RAM + HELPER_SIZE
LOADIMAGE = 0x80177E4C
DESCRIPTOR_FILE = 0x74F40
UV_FILE = 0x750F8
SOURCE_Y = 128
DEST_Y = 447
DEST_V = 191
ROWS, WORDS_PER_ROW = 33, 25
CHUNK_HEIGHTS = (8, 8, 8, 8, 1)
RAW_SHA256 = "B0005B318220FC61C11C3290837A7DF245646254FFA5CEBE7EA9A11932C7F421"
RLE_SHA256 = "94CED131CFC00C7B4A249009DEA5BE2361ABC6DAF6C244EE9B6D134F621C7133"
FINAL_PSX_SHA256 = "B115BA94C28670EDE68D2F917204D5F3FE517D1D1956FA4A7DBCB012A7C56348"
EXPECTED_CHANGED_BYTES = 735

BASE_UV = (
    (0, 128, 32, 128, 0, 160, 32, 160),
    (32, 128, 64, 128, 32, 160, 64, 160),
    (32, 160, 32, 128, 64, 160, 64, 128),
    (64, 160, 32, 160, 64, 128, 32, 128),
    (64, 128, 64, 160, 32, 128, 32, 160),
    (96, 128, 96, 160, 64, 128, 64, 160),
    (64, 128, 96, 128, 64, 160, 96, 160),
    (64, 160, 64, 128, 96, 160, 96, 128),
    (96, 160, 64, 160, 96, 128, 64, 128),
)


class VerifyError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as handle:
        names = [info.filename for info in handle.infolist() if not info.is_dir()]
        return names, {name: handle.read(name) for name in names}


def decode_chunk(stream: bytes, offset: int, count: int) -> tuple[list[int], int]:
    out: list[int] = []
    while len(out) < count:
        if offset >= len(stream):
            raise VerifyError("RLE ends before its chunk")
        control = stream[offset]
        offset += 1
        run = (control & 0x3F) + 1
        if not control & 0x80:
            end = offset + run * 2
            if end > len(stream):
                raise VerifyError("RLE literal exceeds stream")
            out.extend(struct.unpack_from(f"<{run}H", stream, offset))
            offset = end
        elif not control & 0x40:
            out.extend([0] * run)
        else:
            if offset + 2 > len(stream):
                raise VerifyError("RLE repeat lacks its word")
            word = struct.unpack_from("<H", stream, offset)[0]
            offset += 2
            out.extend([word] * run)
        if len(out) > count:
            raise VerifyError("RLE run crosses a five-call upload boundary")
    return out, offset


def original_cursor(comm: bytes) -> bytes:
    rows = [
        comm[y * 896 : y * 896 + WORDS_PER_ROW * 2]
        for y in range(SOURCE_Y, SOURCE_Y + ROWS)
    ]
    raw = b"".join(rows)
    if len(raw) != 1650 or sha256_bytes(raw) != RAW_SHA256:
        raise VerifyError("original cursor source drift")
    return raw


def tpage(tp: int, abr: int, x: int, y: int) -> int:
    return (
        ((x // 64) & 0x0F)
        | (((y // 256) & 1) << 4)
        | ((abr & 3) << 5)
        | ((tp & 3) << 7)
    )


def read_registers(word: int) -> set[int]:
    """Return registers read by the helper's MIPS-I instruction subset."""
    opcode = word >> 26
    rs = (word >> 21) & 31
    rt = (word >> 16) & 31
    if opcode == 0:
        function = word & 0x3F
        if function == 0x08:  # jr
            return {rs}
        if function in (0x00, 0x02, 0x03):  # shifts
            return {rt}
        return {rs, rt} - {0}
    if opcode in (0x02, 0x03, 0x0F):  # j, jal, lui
        return set()
    if opcode in (0x04, 0x05):  # beq, bne
        return {rs, rt} - {0}
    if opcode in (0x01, 0x06, 0x07):
        return {rs} - {0}
    if opcode in (0x28, 0x29, 0x2A, 0x2B, 0x2E):  # stores
        return {rs, rt} - {0}
    # Loads and immediate arithmetic read only their base/source register.
    return {rs} - {0}


def verify_helper(helper: bytes) -> tuple[int, list[str]]:
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    instructions = list(md.disasm(helper, CAVE_RAM))
    if len(instructions) != HELPER_SIZE // 4:
        raise VerifyError("helper does not disassemble to 81 words")
    if (instructions[0].mnemonic, instructions[0].op_str) != (
        "addiu", "$sp, $sp, -0x1d0"
    ):
        raise VerifyError("helper stack frame differs")
    if instructions[-2].mnemonic != "jr" or instructions[-2].op_str != "$ra":
        raise VerifyError("helper return differs")
    if (instructions[-1].mnemonic, instructions[-1].op_str) != (
        "addiu", "$sp, $sp, 0x1d0"
    ):
        raise VerifyError("helper return delay slot differs")

    calls = []
    load_delay_issues: list[str] = []
    loads = {"lb", "lbu", "lh", "lhu", "lw", "lwl", "lwr"}
    words = struct.unpack(f"<{len(helper) // 4}I", helper)
    for index, instruction in enumerate(instructions):
        if instruction.mnemonic == "jal":
            calls.append(int(instruction.op_str, 16))
        if instruction.mnemonic in loads and index + 1 < len(instructions):
            destination = (words[index] >> 16) & 31
            if destination in read_registers(words[index + 1]):
                load_delay_issues.append(
                    f"0x{instruction.address:08X}->{instructions[index + 1].address:08X}"
                )
    if calls != [LOADIMAGE]:
        raise VerifyError(f"helper call targets differ: {calls}")
    if load_delay_issues:
        raise VerifyError(f"R3000 load-delay hazard: {load_delay_issues}")

    # The helper's only absolute data pointer must be its immediate RLE tail.
    if words[6] != 0x3C10801A or words[7] != (0x36100000 | (DATA_RAM & 0xFFFF)):
        raise VerifyError("helper RLE pointer differs")
    return len(instructions), [f"0x{address:08X}" for address in calls]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("build", type=Path)
    args = parser.parse_args()
    build = args.build.resolve()
    if sha256_file(BASE) != BASE_SHA256:
        raise VerifyError("V322 base archive hash drift")
    if not build.is_file():
        raise VerifyError(f"missing build: {build}")

    base_names, base = archive(BASE)
    final_names, final = archive(build)
    with ZipFile(ORIGINAL) as handle:
        original_comm = handle.read(COMM)
    if base_names != final_names or len(final_names) != 164:
        raise VerifyError("archive topology drift")
    changed = [name for name in final_names if base[name] != final[name]]
    if changed != [PSX]:
        raise VerifyError(f"changed member set differs: {changed}")
    if any(len(base[name]) != len(final[name]) for name in final_names):
        raise VerifyError("member size changed")
    if final[COMM] != base[COMM]:
        raise VerifyError("COMM.IMG differs from V322")
    for name in final_names:
        if name != PSX and final[name] != base[name]:
            raise VerifyError(f"non-PSX member differs: {name}")

    old, exe = base[PSX], final[PSX]
    if sha256_bytes(exe) != FINAL_PSX_SHA256:
        raise VerifyError("final PSX.EXE hash differs")
    actual = {
        offset for offset, pair in enumerate(zip(old, exe, strict=True))
        if pair[0] != pair[1]
    }
    if len(actual) != EXPECTED_CHANGED_BYTES:
        raise VerifyError(f"PSX changed-byte census differs: {len(actual)}")
    allowed = (
        set(range(HOOK_FILE, HOOK_FILE + 8))
        | set(range(CAVE_FILE, CAVE_FILE + HELPER_SIZE + RLE_SIZE))
        | set(range(DESCRIPTOR_FILE + 0x10, DESCRIPTOR_FILE + 0x18))
        | set(range(UV_FILE, UV_FILE + 9 * 16))
    )
    if not actual <= allowed:
        raise VerifyError("PSX changed outside the declared four regions")

    if struct.unpack_from("<2I", old, HOOK_FILE) != (0x3C11801F, 0x263152BC):
        raise VerifyError("V322 hook premise differs")
    expected_jal = 0x0C000000 | ((CAVE_RAM >> 2) & 0x03FFFFFF)
    if struct.unpack_from("<2I", exe, HOOK_FILE) != (expected_jal, 0):
        raise VerifyError("initializer hook is not jal helper / nop")

    helper = exe[CAVE_FILE : CAVE_FILE + HELPER_SIZE]
    encoded = exe[CAVE_FILE + HELPER_SIZE : CAVE_FILE + HELPER_SIZE + RLE_SIZE]
    if sha256_bytes(encoded) != RLE_SHA256:
        raise VerifyError("embedded RLE hash differs")
    if any(exe[CAVE_FILE + HELPER_SIZE + RLE_SIZE : CAVE_FILE + CAVE_SIZE]):
        raise VerifyError("unused cave tail is not zero")
    instruction_count, calls = verify_helper(helper)

    decoded = bytearray()
    offset = 0
    rectangles = []
    y = DEST_Y
    for height in CHUNK_HEIGHTS:
        words, offset = decode_chunk(encoded, offset, height * WORDS_PER_ROW)
        decoded.extend(struct.pack(f"<{len(words)}H", *words))
        rectangles.append((960, y, WORDS_PER_ROW, height))
        y += height
    if offset != len(encoded):
        raise VerifyError("RLE has trailing bytes")
    source = original_cursor(original_comm)
    if bytes(decoded) != source:
        raise VerifyError("decoded upload does not reproduce the original cursor")
    if rectangles != [
        (960, 447, 25, 8), (960, 455, 25, 8), (960, 463, 25, 8),
        (960, 471, 25, 8), (960, 479, 25, 1),
    ]:
        raise VerifyError("upload rectangles differ")

    old_descriptor = struct.unpack_from("<12I", old, DESCRIPTOR_FILE)
    new_descriptor = struct.unpack_from("<12I", exe, DESCRIPTOR_FILE)
    if new_descriptor[:4] != old_descriptor[:4] or new_descriptor[6:] != old_descriptor[6:]:
        raise VerifyError("descriptor changed outside tpage X/Y")
    if old_descriptor[4:6] != (320, 0) or new_descriptor[4:6] != (960, 256):
        raise VerifyError("descriptor tpage transition differs")
    if tpage(0, 0, *old_descriptor[4:6]) != 0x05:
        raise VerifyError("old tpage arithmetic differs")
    if tpage(0, 0, *new_descriptor[4:6]) != 0x1F:
        raise VerifyError("new tpage arithmetic differs")

    old_uv = tuple(struct.unpack_from("<8H", old, UV_FILE + i * 16) for i in range(9))
    new_uv = tuple(struct.unpack_from("<8H", exe, UV_FILE + i * 16) for i in range(9))
    if old_uv != BASE_UV:
        raise VerifyError("old nine-entry UV table differs")
    expected_uv = tuple(
        tuple(value + 63 if index & 1 else value for index, value in enumerate(entry))
        for entry in BASE_UV
    )
    if new_uv != expected_uv:
        raise VerifyError("new UV table is not exactly V+63")
    if min(value for entry in new_uv for index, value in enumerate(entry) if index & 1) != 191:
        raise VerifyError("new minimum V differs")
    if max(value for entry in new_uv for index, value in enumerate(entry) if index & 1) != 223:
        raise VerifyError("new maximum V differs")

    result = {
        "result": "PASS",
        "build": str(build),
        "build_sha256": sha256_file(build),
        "changed_members": changed,
        "changed_psx_bytes": len(actual),
        "comm_v322_byte_identical": True,
        "all_dat_v322_byte_identical": True,
        "helper": {
            "address": f"0x{CAVE_RAM:08X}",
            "bytes": len(helper),
            "instructions": instruction_count,
            "jal_targets": calls,
            "r3000_load_delay": "PASS",
            "stack_bytes": 0x1D0,
        },
        "source": {
            "raw_bytes": len(source),
            "raw_sha256": sha256_bytes(source),
            "rle_bytes": len(encoded),
            "rle_sha256": sha256_bytes(encoded),
            "roundtrip": "PASS",
        },
        "upload_rectangles": rectangles,
        "old_tpage": "0x05",
        "new_tpage": "0x1F",
        "uv_v_range": [191, 223],
        "runtime": "PENDING user cold boot and expanded skill-range test",
    }
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "independent_verification.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "V323 independent static verification: PASS",
        f"build_sha256={result['build_sha256']}",
        "changed_members=PSX.EXE only",
        f"changed_psx_bytes={len(actual)}",
        "COMM.IMG/all DAT=V322 byte-identical PASS",
        f"helper=0x{CAVE_RAM:08X}/{len(helper)}B/{instruction_count} instructions",
        "R3000_load_delay=PASS; RA and 464-byte stack frame=PASS",
        f"cursor_raw={len(source)}B {sha256_bytes(source)}",
        f"cursor_RLE={len(encoded)}B {sha256_bytes(encoded)} roundtrip PASS",
        "LoadImage rectangles=(960,447,25,8),(960,455,25,8),(960,463,25,8),(960,471,25,8),(960,479,25,1)",
        "tpage=0x05->0x1F; UV V=128/160 -> 191/223; CLUT unchanged",
        "runtime=PENDING user cold boot",
    ]
    (OUTPUT / "independent_verification.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    print("\n".join(lines))


if __name__ == "__main__":
    main()
