#!/usr/bin/env python3
"""Independent byte/pixel/MIPS verification for the V326 diagnostic build."""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = ROOT / "03_output/arc1_v325_ui_reencode_TEST_ONLY_7828AA04.zip"
FINAL = ROOT / "03_output/arc1_v326_compact_ui_recovery_TEST_ONLY_B1768404.zip"
DELTA = ROOT / "03_output/arc1_v326_compact_ui_recovery_TEST_ONLY_delta_from_v325_82BEDA2A.zip"
ORIGINAL = ROOT / "00_original/arc.zip"
ANALYSIS = ROOT / "01_work/analysis/arc1_v326_compact_ui_recovery"

BASE_SHA256 = "7828AA04F6A0684981332924C30B4139ABFCA5065138FA899C4D429E87C74CD1"
FINAL_SHA256 = "B1768404E175886882D49AFD1C34255D532750E3927B8696CD53A1885039D4BE"
DELTA_SHA256 = "82BEDA2ADF5069E63187A09CAE4ACF057738740A57DAD9E298269B01F53BBA1F"
ORIGINAL_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
RAM_TO_FILE = 0x8011A800
ROW_BYTES = 896

DIRECT_FILE = 0x808B0
DIRECT_RAM = 0x8019B0B0
DIRECT_SIZE = 92
DIRECT_SOURCE = 0x8EF44
DIRECT_RESIDENT = 0x801FF41C
DIRECT_RETURN = 0x8016B410
DIRECT_STOCK = 0x8016B3E0
UV_FILE = 0x80910
UV_RAM = 0x8019B110
UV_SIZE = 52
UV_HOOK_RAM = 0x8016B5A8
UV_HOOK_FILE = UV_HOOK_RAM - RAM_TO_FILE
UV_RETURN = 0x8016B5B0

FREE_START = 0x808AC
USED_END = 0x80982
FREE_END = 0x80A94
SYNTH_BASE = 960
STRIP_X = 240
STRIP_Y = 176

COMPACT = (
    (0, 0x01, 0),
    (1, 0x10, 15),
    (2, 0x11, 16),
    (3, 0x12, 17),
    (4, 0x13, 18),
    (5, 0x14, 19),
    (6, 0x15, 20),
    (7, 0x16, 21),
    (8, 0x17, 22),
    (9, 0x18, 23),
    (10, 0x19, 24),
    (11, 0x1A, 25),
    (12, 0x80, 127),
)
RAW_TO_SLOT = {raw: slot for slot, raw, _source in COMPACT}

EXPECTED_DIRECT_WORDS = (
    0x34080001, 0x1068000B, 0x34080010, 0x2469FFF0,
    0x2D28000B, 0x1500000A, 0x00000000, 0x34080080,
    0x1468000C, 0x00000000, 0x340303CC, 0x10000005,
    0x00000000, 0x340303C0, 0x10000002, 0x00000000,
    0x252303C1, 0x24A20001, 0xACC20000, 0x0805AD04,
    0x00000000, 0x0805ACF8, 0x00000000,
)
EXPECTED_UV_WORDS = (
    0xA0A20029, 0x2488FC40, 0x2D09000D, 0x11200007,
    0x00000000, 0x340900F0, 0xA0A90028, 0x00084082,
    0x00084100, 0x250800B0, 0xA0A80029, 0x0805AD6C,
    0x00000000,
)

EXPECTED_MANUAL = {
    0x8234C: (0x80950, bytes.fromhex("E7 02 DD 10 DD 0A E7 05 DD AD DD 47 A1 DD 89 24")),
    0x82350: (0x80961, bytes.fromhex("E7 03 DD 31 DD 32 A1 DD A3 E7 08 8B DD D2 A1 DE 2B 35")),
    0x825F0: (0x80974, bytes.fromhex("DE 2B 35 DD CF")),
    0x825F4: (0x8097A, bytes.fromhex("60 24")),
    0x825F8: (0x8097D, bytes.fromhex("94 A1 60 24")),
}
EMPTY_POINTERS = (
    0x811C0, 0x81708, 0x81B6C, 0x81B70, 0x81B74, 0x81C34,
    0x81C90, 0x81CB0, 0x81CB4, 0x81CB8, 0x81CBC, 0x81CC0,
    0x81CC4, 0x81CC8, 0x81CCC, 0x81CD0, 0x81CD4, 0x81CD8,
    0x82170,
)


class VerifyError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def read_zip(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        return names, {name: archive.read(name) for name in names}


def changed(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise VerifyError("member size changed")
    return {index for index, pair in enumerate(zip(before, after, strict=True)) if pair[0] != pair[1]}


def raw_string(data: bytes, offset: int) -> bytes:
    end = data.find(b"\x00", offset, min(len(data), offset + 512))
    if end < 0:
        raise VerifyError(f"unterminated string at 0x{offset:X}")
    return data[offset:end]


def pointer_target(exe: bytes, pointer: int) -> int:
    target = struct.unpack_from("<I", exe, pointer)[0] - RAM_TO_FILE
    if not 0 <= target < len(exe):
        raise VerifyError(f"bad pointer 0x{pointer:X}")
    return target


def read_original_plane(comm: bytes, physical: int) -> tuple[int, ...]:
    cell, plane = divmod(physical, 4)
    row, col = divmod(cell, 21)
    bit = 1 << plane
    result: list[int] = []
    for y in range(12):
        bits = 0
        for x in range(12):
            px = col * 12 + x
            at = (row * 12 + y) * ROW_BYTES + px // 2
            nibble = (comm[at] >> (0 if px % 2 == 0 else 4)) & 0xF
            if nibble & bit:
                bits |= 1 << (11 - x)
        result.append(bits)
    return tuple(result)


def get_nibble(comm: bytes | bytearray, x: int, y: int) -> int:
    value = comm[y * ROW_BYTES + x // 2]
    return (value >> (0 if x % 2 == 0 else 4)) & 0xF


def set_bit(comm: bytearray, x: int, y: int, plane: int, enabled: bool) -> None:
    at = y * ROW_BYTES + x // 2
    shift = 0 if x % 2 == 0 else 4
    nibble = (comm[at] >> shift) & 0xF
    mask = 1 << plane
    nibble = nibble | mask if enabled else nibble & (~mask & 0xF)
    if shift:
        comm[at] = (comm[at] & 0x0F) | (nibble << 4)
    else:
        comm[at] = (comm[at] & 0xF0) | nibble


def independently_expected_comm(base: bytes, original: bytes) -> bytes:
    output = bytearray(base)
    for y in range(176, 240):
        for x in range(240, 252):
            if get_nibble(base, x, y):
                raise VerifyError(f"base strip not blank: {x},{y}")
    for slot, _raw, source in COMPACT:
        rows = read_original_plane(original, source)
        plane = slot & 3
        y0 = STRIP_Y + (slot >> 2) * 16
        for y, bits in enumerate(rows):
            for x in range(12):
                set_bit(output, STRIP_X + x, y0 + y, plane, bool(bits & (1 << (11 - x))))
    return bytes(output)


def sign16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def run_helper(words: tuple[int, ...], base: int, stop: set[int], registers: dict[int, int]) -> tuple[int, dict[int, int], dict[int, int]]:
    """Tiny independent interpreter for exactly the MIPS-I subset used here."""
    memory: dict[int, int] = {}
    regs = {index: 0 for index in range(32)}
    regs.update({index: value & 0xFFFFFFFF for index, value in registers.items()})
    pc = base
    pending: int | None = None
    for _step in range(256):
        if pc in stop:
            return pc, regs, memory
        if not base <= pc < base + len(words) * 4 or (pc - base) % 4:
            raise VerifyError(f"helper PC escaped: 0x{pc:08X}")
        word = words[(pc - base) // 4]
        op = word >> 26
        rs, rt = (word >> 21) & 31, (word >> 16) & 31
        imm = word & 0xFFFF
        new_target: int | None = None
        if word == 0:
            pass
        elif op == 0:
            rd, shift, funct = (word >> 11) & 31, (word >> 6) & 31, word & 63
            if funct == 0x00:  # sll
                regs[rd] = (regs[rt] << shift) & 0xFFFFFFFF
            elif funct == 0x02:  # srl
                regs[rd] = (regs[rt] >> shift) & 0xFFFFFFFF
            else:
                raise VerifyError(f"unsupported R instruction 0x{word:08X}")
        elif op == 0x09:  # addiu
            regs[rt] = (regs[rs] + sign16(imm)) & 0xFFFFFFFF
        elif op == 0x0B:  # sltiu; immediate is sign extended before unsigned compare
            rhs = sign16(imm) & 0xFFFFFFFF
            regs[rt] = int((regs[rs] & 0xFFFFFFFF) < rhs)
        elif op == 0x0D:  # ori
            regs[rt] = (regs[rs] | imm) & 0xFFFFFFFF
        elif op == 0x04:  # beq
            if regs[rs] == regs[rt]:
                new_target = (pc + 4 + sign16(imm) * 4) & 0xFFFFFFFF
        elif op == 0x05:  # bne
            if regs[rs] != regs[rt]:
                new_target = (pc + 4 + sign16(imm) * 4) & 0xFFFFFFFF
        elif op == 0x28:  # sb
            address = (regs[rs] + sign16(imm)) & 0xFFFFFFFF
            memory[address] = regs[rt] & 0xFF
        elif op == 0x2B:  # sw, byte map is sufficient for readback
            address = (regs[rs] + sign16(imm)) & 0xFFFFFFFF
            for index in range(4):
                memory[address + index] = (regs[rt] >> (index * 8)) & 0xFF
        elif op == 0x02:  # j
            new_target = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
        else:
            raise VerifyError(f"unsupported opcode {op} word=0x{word:08X}")
        regs[0] = 0
        if pending is not None:
            pc = pending
            pending = None
        else:
            pc = (pc + 4) & 0xFFFFFFFF
            if new_target is not None:
                pending = new_target
    raise VerifyError("helper interpreter step limit")


def read_u32(memory: dict[int, int], address: int) -> int | None:
    if any(address + index not in memory for index in range(4)):
        return None
    return sum(memory[address + index] << (index * 8) for index in range(4))


def branch_targets(exe: bytes) -> dict[int, list[tuple[int, int]]]:
    interesting = {UV_HOOK_RAM, UV_HOOK_RAM + 4, UV_RETURN, DIRECT_RAM, UV_RAM}
    hits = {target: [] for target in interesting}
    for offset in range(0, len(exe) - 3, 4):
        word = struct.unpack_from("<I", exe, offset)[0]
        pc = RAM_TO_FILE + offset
        op = word >> 26
        target: int | None = None
        if op in (1, 4, 5, 6, 7):
            target = (pc + 4 + sign16(word & 0xFFFF) * 4) & 0xFFFFFFFF
        elif op in (2, 3):
            target = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
        if target in hits:
            hits[target].append((pc, word))
    return hits


def main() -> None:
    if sha256(BASE.read_bytes()) != BASE_SHA256:
        raise VerifyError("base ZIP hash mismatch")
    if sha256(FINAL.read_bytes()) != FINAL_SHA256:
        raise VerifyError("final ZIP hash mismatch")
    if sha256(DELTA.read_bytes()) != DELTA_SHA256:
        raise VerifyError("delta ZIP hash mismatch")
    if sha256(ORIGINAL.read_bytes()) != ORIGINAL_SHA256:
        raise VerifyError("original ZIP hash mismatch")

    base_names, base = read_zip(BASE)
    final_names, final = read_zip(FINAL)
    if base_names != final_names or len(final_names) != 164:
        raise VerifyError("full archive topology mismatch")
    changed_members = [name for name in base_names if base[name] != final[name]]
    if set(changed_members) != {PSX, COMM} or len(changed_members) != 2:
        raise VerifyError(f"changed member set mismatch: {changed_members}")
    with ZipFile(DELTA) as archive:
        if set(archive.namelist()) != {PSX, COMM}:
            raise VerifyError("delta member set mismatch")
        if any(archive.read(name) != final[name] for name in (PSX, COMM)):
            raise VerifyError("delta payload mismatch")

    with ZipFile(ORIGINAL) as archive:
        original_comm = archive.read(COMM)
    expected_comm = independently_expected_comm(base[COMM], original_comm)
    if expected_comm != final[COMM]:
        mismatch = changed(expected_comm, final[COMM])
        raise VerifyError(f"independent compact-strip rebuild mismatch: {sorted(mismatch)[:8]}")

    exe0, exe1 = base[PSX], final[PSX]
    direct_words = struct.unpack_from(f"<{DIRECT_SIZE // 4}I", exe1, DIRECT_FILE)
    uv_words = struct.unpack_from(f"<{UV_SIZE // 4}I", exe1, UV_FILE)
    if direct_words != EXPECTED_DIRECT_WORDS:
        raise VerifyError("direct helper word array mismatch")
    if uv_words != EXPECTED_UV_WORDS:
        raise VerifyError("UV helper word array mismatch")
    if struct.unpack_from("<I", exe1, DIRECT_SOURCE)[0] != 0x08066C2C:
        raise VerifyError("resident direct trampoline does not jump to helper")
    if exe1[DIRECT_SOURCE + 4:DIRECT_SOURCE + 8] != b"\x00" * 4:
        raise VerifyError("resident direct trampoline delay slot changed")
    if struct.unpack_from("<I", exe1, UV_HOOK_FILE)[0] != 0x08066C44:
        raise VerifyError("UV hook does not jump to helper")
    if struct.unpack_from("<I", exe1, UV_HOOK_FILE + 4)[0] != 0x90C3000D:
        raise VerifyError("UV hook delay-slot lbu changed")

    # No helper may write RA or use JAL.  Neither helper contains a load, so
    # there is no internal R3000 load-delay hazard.  The hook's lbu delay slot
    # is separated from its first consumer by the entire helper.
    for label, words in (("direct", direct_words), ("uv", uv_words)):
        for word in words:
            op = word >> 26
            if op == 3:
                raise VerifyError(f"{label} helper contains JAL")
            if ((word >> 16) & 31) == 31 and op not in (2, 4, 5):
                raise VerifyError(f"{label} helper may write RA: 0x{word:08X}")
            if op in (0x20, 0x21, 0x23, 0x24, 0x25):
                raise VerifyError(f"{label} helper unexpectedly contains a load")

    # Execute every stock direct byte through the actual final helper words.
    direct_results: dict[str, dict[str, object]] = {}
    for raw in range(1, 0xDD):
        stop, regs, memory = run_helper(
            direct_words, DIRECT_RAM, {DIRECT_RETURN, DIRECT_STOCK},
            {3: raw, 5: 0x1000, 6: 0x2000},
        )
        if raw in RAW_TO_SLOT:
            expected_index = SYNTH_BASE + RAW_TO_SLOT[raw]
            if stop != DIRECT_RETURN or regs[3] != expected_index:
                raise VerifyError(f"direct target remap failed: 0x{raw:02X}")
            if read_u32(memory, 0x2000) != 0x1001:
                raise VerifyError(f"direct source-pointer update failed: 0x{raw:02X}")
            direct_results[f"0x{raw:02X}"] = {
                "synthetic_index": expected_index, "return": f"0x{stop:08X}"
            }
        else:
            if stop != DIRECT_STOCK or regs[3] != raw or memory:
                raise VerifyError(f"non-target direct byte no longer tails to stock: 0x{raw:02X}")

    # Execute boundaries and every synthetic value through the U/V helper.
    uv_results: dict[str, dict[str, int | str]] = {}
    for index in (0, 959, *range(960, 973), 973, 1238):
        stop, _regs, memory = run_helper(
            uv_words, UV_RAM, {UV_RETURN},
            {2: 0x66, 3: 6, 4: index, 5: 0x3000},
        )
        if stop != UV_RETURN or memory.get(0x3029) is None:
            raise VerifyError(f"UV helper failed to recreate V store: {index}")
        if 960 <= index < 973:
            slot = index - 960
            expected_v = STRIP_Y + (slot >> 2) * 16
            if memory.get(0x3028) != STRIP_X or memory.get(0x3029) != expected_v:
                raise VerifyError(f"synthetic UV mismatch: {index}/{memory}")
            uv_results[str(index)] = {"u_before_halfwidth": STRIP_X, "v": expected_v, "plane": index & 3}
        else:
            if memory.get(0x3028) is not None or memory.get(0x3029) != 0x66:
                raise VerifyError(f"non-synthetic UV changed: {index}/{memory}")

    # Half-width stock adjustment occurs immediately after the helper return.
    # Its exact words are protected: width==6 adds four to U, samples W=6.
    expected_halfwidth = bytes.fromhex(
        "06 00 02 34 05 00 62 14 00 00 00 00 28 00 A2 90"
    )
    if exe1[UV_HOOK_FILE + 8:UV_HOOK_FILE + 24] != expected_halfwidth:
        raise VerifyError("stock half-width U+4 path changed")
    for slot, _raw, source in COMPACT:
        source_rows = read_original_plane(original_comm, source)
        y0 = STRIP_Y + (slot >> 2) * 16
        plane = slot & 3
        for y in range(12):
            # The six displayed pixels are original x=4..9 byte-for-byte.
            displayed = [bool(get_nibble(final[COMM], STRIP_X + 4 + x, y0 + y) & (1 << plane)) for x in range(6)]
            expected = [bool(source_rows[y] & (1 << (11 - (4 + x)))) for x in range(6)]
            if displayed != expected:
                raise VerifyError(f"half-width source sample mismatch: slot={slot} row={y}")

    # Manual string pointers and their control arrays are exact.
    for pointer, (target, payload) in EXPECTED_MANUAL.items():
        if pointer_target(exe1, pointer) != target or raw_string(exe1, target) != payload:
            raise VerifyError(f"manual string mismatch at pointer 0x{pointer:X}")
    if tuple(EXPECTED_MANUAL[0x8234C][1][index:index + 2]
             for index in range(len(EXPECTED_MANUAL[0x8234C][1]) - 1)
             if EXPECTED_MANUAL[0x8234C][1][index] == 0xE7) != (b"\xE7\x02", b"\xE7\x05"):
        raise VerifyError("first E7 token array mismatch")
    if tuple(EXPECTED_MANUAL[0x82350][1][index:index + 2]
             for index in range(len(EXPECTED_MANUAL[0x82350][1]) - 1)
             if EXPECTED_MANUAL[0x82350][1][index] == 0xE7) != (b"\xE7\x03", b"\xE7\x08"):
        raise VerifyError("second E7 token array mismatch")
    if exe1[FREE_START:DIRECT_FILE] != b"\x00" * (DIRECT_FILE - FREE_START):
        raise VerifyError("empty-string sentinel bytes changed")
    for pointer in EMPTY_POINTERS:
        if pointer_target(exe1, pointer) != 0x808AD or raw_string(exe1, 0x808AD):
            raise VerifyError(f"empty pointer changed: 0x{pointer:X}")

    # Rebuild the complete Expected-Write envelope without builder metadata.
    psx_diff = changed(exe0, exe1)
    comm_diff = changed(base[COMM], final[COMM])
    allowed_psx = (
        set(range(DIRECT_FILE, USED_END))
        | set(range(DIRECT_SOURCE, DIRECT_SOURCE + 4))
        | set(range(UV_HOOK_FILE, UV_HOOK_FILE + 4))
        | {offset for pointer in EXPECTED_MANUAL for offset in range(pointer, pointer + 4)}
    )
    allowed_comm = {
        y * ROW_BYTES + x // 2
        for y in range(STRIP_Y, STRIP_Y + 64)
        for x in range(STRIP_X, STRIP_X + 12)
    }
    if len(psx_diff) != 149 or not psx_diff <= allowed_psx:
        raise VerifyError(f"PSX Expected-Write mismatch: {len(psx_diff)}/{sorted(psx_diff - allowed_psx)[:8]}")
    if len(comm_diff) != 99 or not comm_diff <= allowed_comm:
        raise VerifyError(f"COMM Expected-Write mismatch: {len(comm_diff)}/{sorted(comm_diff - allowed_comm)[:8]}")

    targets = branch_targets(exe1)
    if targets[UV_HOOK_RAM] or targets[UV_HOOK_RAM + 4]:
        raise VerifyError(f"branch enters overwritten UV hook words: {targets}")
    if targets[UV_RAM] != [(UV_HOOK_RAM, 0x08066C44)]:
        raise VerifyError(f"UV helper inbound target drift: {targets[UV_RAM]}")
    if targets[UV_RETURN] != [(UV_RAM + 44, 0x0805AD6C)]:
        raise VerifyError(f"UV return target drift: {targets[UV_RETURN]}")
    source_pc = RAM_TO_FILE + DIRECT_SOURCE
    if targets[DIRECT_RAM] != [(source_pc, 0x08066C2C)]:
        raise VerifyError(f"direct helper source inbound drift: {targets[DIRECT_RAM]}")

    # Post-audit live-register check.  The helper-local truth table above is
    # intentionally retained as evidence of why the original verifier missed
    # this: stock 0x8016B518 defines t1=160 before the mid-function hook and
    # consumes it after the helper returns.  V326 returns with t1=0 or 240.
    if struct.unpack_from("<I", exe1, 0x8016B524 - RAM_TO_FILE)[0] != 0x340900A0:
        raise VerifyError("stock t1=160 definition drift")
    if struct.unpack_from("<I", exe1, 0x8016B640 - RAM_TO_FILE)[0] != 0x14890002:
        raise VerifyError("stock blank comparison drift")
    if uv_words[-1] != 0:
        raise VerifyError("V326 known-blocker premise drift")

    verification = {
        "result": "FAIL_KNOWN_LIVE_T1_CLOBBER",
        "structural_checks": "PASS",
        "hashes": {"base": BASE_SHA256, "final": FINAL_SHA256, "delta": DELTA_SHA256},
        "archive": {"members": len(final_names), "changed_members": changed_members},
        "changed_bytes": {PSX: len(psx_diff), COMM: len(comm_diff)},
        "compact": {
            "raw_truth_table": direct_results,
            "uv_truth_table": uv_results,
            "source": "original COMM.IMG 12x12 planes",
            "halfwidth_sample": "original x=4..9 reproduced for all 13 glyphs/12 rows",
        },
        "mips": {
            "direct_words": len(direct_words), "uv_words": len(uv_words),
            "jal": 0, "ra_writes": 0, "helper_loads": 0,
            "uv_hook_inbound_middle": 0,
            "resident_direct_destination": f"0x{DIRECT_RESIDENT:08X}",
        },
        "manual_strings": {f"0x{pointer:X}": payload.hex(" ").upper()
                           for pointer, (_target, payload) in EXPECTED_MANUAL.items()},
        "known_blocker": (
            "UV helper clobbers caller-live t1=160; physical blank 160 advances "
            "14px instead of stock 6px. Fixed by V327."
        ),
        "runtime": "PENDING user cold boot",
    }
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(verification, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "V326 independent verification: OVERALL FAIL (structural checks PASS)",
        f"full_sha256={FINAL_SHA256}",
        f"delta_sha256={DELTA_SHA256}",
        f"archive=164 members; changed={','.join(changed_members)}",
        f"changed_bytes=PSX.EXE:{len(psx_diff)},COMM.IMG:{len(comm_diff)}",
        "direct_helper=220 raw bytes executed; targets 13/13, stock tails 207/207",
        "uv_helper=boundaries + synthetic 960..972 executed; 13/13 coordinates pass",
        "R3000=J-only hooks, no JAL/RA writes/helper loads; delay slots and inbound targets pass",
        "compact_pixels=independent original-COMM rebuild and central-six sample pass",
        "E7 arrays=02/05 and 03/08 pass; configuration strings=3/3 pass",
        "Expected-Write=exact envelope pass; every DAT and 162 other members byte exact",
        "BLOCKER=UV helper fails to restore live t1=160; physical blank advance 6px -> 14px",
        "status=DO NOT USE; fixed by V327",
    ]
    (ANALYSIS / "independent_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    raise SystemExit(1)


if __name__ == "__main__":
    main()
