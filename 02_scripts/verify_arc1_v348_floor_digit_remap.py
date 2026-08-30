#!/usr/bin/env python3
"""Independent static and executable-model verifier for V348.

This file intentionally imports neither the V348 nor V347 builder.  It reads
the final machine code, disassembles it and executes the small MIPS routine in
a separate interpreter for every supported dungeon level.
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
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = ROOT / "03_output/arc1_v347_freeze_floor_dialogue_repair_TEST_ONLY_028303F6.zip"
BASE_SHA = "028303F62EFA7D1362DAA6AA57B2224B39A8692CD2D8CA0073980DA1DAF73302"
BUILD = ROOT / "03_output/arc1_v348_floor_digit_remap_TEST_ONLY_9256295B.zip"
BUILD_SHA = "9256295B8834D0A181850FF5C5DDE4CDA7FBF2C7424B75867C3CDDB1C746716C"
DELTA = ROOT / "03_output/arc1_v348_floor_digit_remap_TEST_ONLY_delta_from_v347_B4EF2635.zip"
DELTA_SHA = "B4EF2635FD37732ABA20A92559AF5436D3C9F85EDCCA1D4DD0BC5F7E20619F96"
ANALYSIS = ROOT / "01_work/analysis/arc1_v348_floor_digit_remap"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
BASE_PSX_SHA = "826BD14337B287A656364FA4AB004535B85F276376072CA6FA6351AC3A64A337"
BASE_COMM_SHA = "A6681F1355007725328372CC6143EF21EEE43A9FDE91FD3DC2EF3461C6805405"

RAM_TO_FILE = 0x8011A800
CALL_FILE = 0x4EF74
CALL_RAM = RAM_TO_FILE + CALL_FILE
HELPER_FILE = 0x8F400
HELPER_RAM = RAM_TO_FILE + HELPER_FILE
HELPER_SIZE = 100
LUT_FILE = HELPER_FILE + HELPER_SIZE
LUT_RAM = RAM_TO_FILE + LUT_FILE
DIGIT_LUT = bytes.fromhex("91 4A 0B 27 57 9E 9F 9A 10 08")
PREFIX = bytes.fromhex("04 19 A1")
SUFFIX = bytes.fromhex("DE 50 00")
STOCK_CONVERTER = 0x8015E4C0
RETURN_SENTINEL = 0xDEADBEEF


class VerificationError(RuntimeError):
    pass


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha_file(path: Path) -> str:
    return sha_bytes(path.read_bytes())


def archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as handle:
        names = [item.filename for item in handle.infolist() if not item.is_dir()]
        return names, {name: handle.read(name) for name in names}


def word(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def signed16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def expected_helper_words() -> tuple[int, ...]:
    def i(op: int, rs: int, rt: int, imm: int) -> int:
        return (op << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)

    def r(rs: int, rt: int, rd: int, shift: int, funct: int) -> int:
        return (rs << 21) | (rt << 16) | (rd << 11) | (shift << 6) | funct

    def j(op: int, target: int) -> int:
        return (op << 26) | ((target >> 2) & 0x03FFFFFF)

    z, a0, t0, t1, t2, t3, t4, t5, s0, sp, ra = 0, 4, 8, 9, 10, 11, 12, 13, 16, 29, 31
    return (
        i(9, sp, sp, -24), i(43, sp, ra, 20), i(43, sp, s0, 16), r(a0, z, s0, 0, 33),
        j(3, STOCK_CONVERTER), 0, i(15, z, t0, 0x801B), i(9, t0, t0, -0x639C),
        i(36, s0, t1, 0), 0, i(4, t1, z, 10), i(9, t1, t2, -17),
        i(11, t2, t3, 10), i(4, t3, z, 5), 0, r(t0, t2, t4, 0, 33),
        i(36, t4, t5, 0), 0, i(40, s0, t5, 0), j(2, HELPER_RAM + 0x20),
        i(9, s0, s0, 1), i(35, sp, ra, 20), i(35, sp, s0, 16), r(ra, z, z, 0, 8),
        i(9, sp, sp, 24),
    )


def changed_offsets(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise VerificationError("member size changed")
    return {i for i, (a, b) in enumerate(zip(before, after, strict=True)) if a != b}


def disassemble(helper: bytes) -> list[tuple[int, str, str]]:
    try:
        from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32
    except ImportError as exc:
        raise VerificationError("capstone missing") from exc
    decoder = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    rows = [(ins.address, ins.mnemonic, ins.op_str) for ins in decoder.disasm(helper, HELPER_RAM)]
    if len(rows) != 25:
        raise VerificationError(f"helper is not 25 MIPS instructions: {len(rows)}")
    expected_mnemonics = (
        "addiu", "sw", "sw", "move", "jal", "nop", "lui", "addiu", "lbu", "nop",
        "beqz", "addiu", "sltiu", "beqz", "nop", "addu", "lbu", "nop", "sb", "j",
        "addiu", "lw", "lw", "jr", "addiu",
    )
    if tuple(row[1] for row in rows) != expected_mnemonics:
        raise VerificationError("helper instruction sequence drift")
    if rows[4][2] != "0x8015e4c0" or rows[10][2].split(", ")[-1] != "0x801a9c54":
        raise VerificationError("helper call/done target drift")
    if rows[13][2].split(", ")[-1] != "0x801a9c4c" or rows[19][2] != "0x801a9c20":
        raise VerificationError("helper branch/loop target drift")
    return rows


class TinyMips:
    """Interpreter for the exact fixed MIPS-I subset used by the V348 helper."""

    def __init__(self, helper_words: tuple[int, ...], lut: bytes, ascii_number: bytes):
        self.code = {HELPER_RAM + i * 4: value for i, value in enumerate(helper_words)}
        self.mem: dict[int, int] = {}
        self.reg = [0] * 32
        self.buffer = 0x00100000
        self.reg[4] = self.buffer
        self.reg[16] = 0x13579BDF
        self.reg[29] = 0x00201000
        self.reg[31] = RETURN_SENTINEL
        for i, value in enumerate(ascii_number + b"\0"):
            self.mem[self.buffer + i] = value
        for i, value in enumerate(lut):
            self.mem[LUT_RAM + i] = value

    def read8(self, address: int) -> int:
        return self.mem.get(address & 0xFFFFFFFF, 0)

    def write8(self, address: int, value: int) -> None:
        self.mem[address & 0xFFFFFFFF] = value & 0xFF

    def read32(self, address: int) -> int:
        return sum(self.read8(address + i) << (8 * i) for i in range(4))

    def write32(self, address: int, value: int) -> None:
        for i in range(4):
            self.write8(address + i, value >> (8 * i))

    def ordinary(self, pc: int, instr: int) -> None:
        op = instr >> 26
        rs, rt = (instr >> 21) & 31, (instr >> 16) & 31
        rd, funct, imm = (instr >> 11) & 31, instr & 63, signed16(instr)
        if instr == 0:
            pass
        elif op == 0 and funct == 33:  # addu/move
            self.reg[rd] = (self.reg[rs] + self.reg[rt]) & 0xFFFFFFFF
        elif op == 9:  # addiu
            self.reg[rt] = (self.reg[rs] + imm) & 0xFFFFFFFF
        elif op == 11:  # sltiu
            self.reg[rt] = int((self.reg[rs] & 0xFFFFFFFF) < (imm & 0xFFFFFFFF))
        elif op == 15:  # lui
            self.reg[rt] = (instr & 0xFFFF) << 16
        elif op == 36:  # lbu
            self.reg[rt] = self.read8(self.reg[rs] + imm)
        elif op == 35:  # lw
            self.reg[rt] = self.read32(self.reg[rs] + imm)
        elif op == 40:  # sb
            self.write8(self.reg[rs] + imm, self.reg[rt])
        elif op == 43:  # sw
            self.write32(self.reg[rs] + imm, self.reg[rt])
        else:
            raise VerificationError(f"unsupported ordinary instruction 0x{instr:08X} at 0x{pc:08X}")
        self.reg[0] = 0

    def run(self) -> bytes:
        pc = HELPER_RAM
        for _step in range(512):
            if pc == RETURN_SENTINEL:
                end = 0
                while self.read8(self.buffer + end):
                    end += 1
                if self.reg[16] != 0x13579BDF or self.reg[29] != 0x00201000:
                    raise VerificationError("helper did not preserve s0/sp")
                return bytes(self.read8(self.buffer + i) for i in range(end))
            instr = self.code.get(pc)
            if instr is None:
                raise VerificationError(f"execution left helper at 0x{pc:08X}")
            op, rs, rt = instr >> 26, (instr >> 21) & 31, (instr >> 16) & 31
            if op in (2, 3):
                target = ((pc + 4) & 0xF0000000) | ((instr & 0x03FFFFFF) << 2)
                if op == 3:
                    self.reg[31] = (pc + 8) & 0xFFFFFFFF
                self.ordinary(pc + 4, self.code[pc + 4])
                if op == 3 and target == STOCK_CONVERTER:
                    at = self.reg[4]
                    while self.read8(at):
                        self.write8(at, self.read8(at) + 0xE1)
                        at += 1
                    pc = self.reg[31]
                else:
                    pc = target
                continue
            if op == 4:  # beq + delay
                target = (pc + 4 + (signed16(instr) << 2)) & 0xFFFFFFFF
                take = self.reg[rs] == self.reg[rt]
                self.ordinary(pc + 4, self.code[pc + 4])
                pc = target if take else pc + 8
                continue
            if op == 0 and (instr & 63) == 8:  # jr + delay
                target = self.reg[rs]
                self.ordinary(pc + 4, self.code[pc + 4])
                pc = target
                continue
            self.ordinary(pc, instr)
            pc += 4
        raise VerificationError("helper execution did not terminate")


def main() -> None:
    for path, expected in ((BASE, BASE_SHA), (BUILD, BUILD_SHA), (DELTA, DELTA_SHA)):
        if not path.is_file() or sha_file(path) != expected:
            raise VerificationError(f"archive hash mismatch: {path.name}")
    base_names, base = archive(BASE)
    build_names, build = archive(BUILD)
    delta_names, delta = archive(DELTA)
    if len(base_names) != 164 or base_names != build_names:
        raise VerificationError("164-member topology/order drift")
    changed_members = [name for name in base_names if base[name] != build[name]]
    if changed_members != [PSX] or delta_names != [PSX] or delta[PSX] != build[PSX]:
        raise VerificationError("changed-member or delta payload drift")
    if sha_bytes(base[PSX]) != BASE_PSX_SHA or sha_bytes(base[COMM]) != BASE_COMM_SHA:
        raise VerificationError("V347 member hash drift")
    if build[COMM] != base[COMM] or any(build[n] != base[n] for n in base_names if n != PSX):
        raise VerificationError("non-PSX payload changed")

    exe = build[PSX]
    helper = exe[HELPER_FILE:HELPER_FILE + HELPER_SIZE]
    lut = exe[LUT_FILE:LUT_FILE + len(DIGIT_LUT)]
    expected_words = expected_helper_words()
    expected_bytes = b"".join(struct.pack("<I", value) for value in expected_words)
    if helper != expected_bytes or lut != DIGIT_LUT:
        raise VerificationError("helper/LUT machine bytes drift")
    hook = (3 << 26) | ((HELPER_RAM >> 2) & 0x03FFFFFF)
    if word(exe, CALL_FILE) != hook or word(exe, CALL_FILE + 4) != 0x02002021:
        raise VerificationError("hook or preserved delay slot mismatch")
    rows = disassemble(helper)

    # Explicit R3000 load-delay audit for every loaded value consumed in helper.
    load_use_pairs = ((8, 10), (16, 18), (21, 23))
    if any(use - load < 2 for load, use in load_use_pairs):
        raise VerificationError("R3000 load delay violation")

    floor_rows = []
    for level in range(1, 51):
        result = TinyMips(expected_words, lut, str(level).encode("ascii")).run()
        expected_digits = bytes(DIGIT_LUT[int(ch)] for ch in str(level))
        if result != expected_digits:
            raise VerificationError(f"machine execution mismatch at floor {level}: {result.hex()}")
        final = PREFIX + result + SUFFIX
        if len(final) > 8 or not final.endswith(b"\0"):
            raise VerificationError(f"floor buffer invariant failed at {level}")
        floor_rows.append({"level": level, "digit_bytes": result.hex(" ").upper(), "final_size": len(final)})

    # Expected-Write is compared with the exact full-file diff, not only an envelope.
    actual = changed_offsets(base[PSX], exe)
    with (ANALYSIS / "expected_writes.csv").open(encoding="utf-8-sig", newline="") as handle:
        expected_rows = list(csv.DictReader(handle))
    csv_offsets = {int(row["offset"], 16) for row in expected_rows}
    if csv_offsets != actual:
        raise VerificationError("Expected-Write rows differ from exact PSX diff")
    for row in expected_rows:
        offset = int(row["offset"], 16)
        if base[PSX][offset] != int(row["before"], 16) or exe[offset] != int(row["after"], 16):
            raise VerificationError(f"Expected-Write byte mismatch at 0x{offset:X}")
    envelope = set(range(CALL_FILE, CALL_FILE + 4)) | set(range(HELPER_FILE, LUT_FILE + len(DIGIT_LUT)))
    if not actual <= envelope:
        raise VerificationError("PSX diff escaped the approved envelope")

    # V347 success repairs and floor prefix/suffix remain byte exact.
    for offset, expected in ((0x7EF3C, 0x80162CE0), (0x8D788, 0x8012E2E0)):
        if word(exe, offset) != expected or word(exe, offset) != word(base[PSX], offset):
            raise VerificationError(f"V347 code-pointer regression at 0x{offset:X}")
    for offset, size in ((0x809F4, 4), (0x8215C, 3), (0x823B0, 8)):
        if exe[offset:offset + size] != base[PSX][offset:offset + size]:
            raise VerificationError(f"V347 floor input regression at 0x{offset:X}")

    report = {
        "verdict": "PASS",
        "archives": {"full": BUILD_SHA, "delta": DELTA_SHA, "members": 164},
        "changed_members": changed_members,
        "changed_bytes": len(actual),
        "machine_code": {"instructions": len(rows), "load_delays": "PASS", "ra_sp_s0": "PASS"},
        "floors": {"range": "1..50", "passed": len(floor_rows), "maximum_buffer": 8},
        "preservation": "all non-PSX members, COMM.IMG, V347 pointers/dialogues byte exact",
        "runtime": "PENDING user cold boot; TEST_ONLY",
    }
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "V348 independent verification PASS",
        f"full={BUILD_SHA}",
        f"delta={DELTA_SHA}",
        f"members=164 changed=PSX.EXE only exact_diff_bytes={len(actual)}",
        "helper=25 MIPS-I instructions; targets/delay slots/load delays/RA-SP-S0 PASS",
        "machine execution=floors 1..50 exact current digit codes; max buffer 8 bytes",
        "DAT/COMM.IMG/V347 pointers and dialogue fixes=byte exact",
        "runtime=PENDING user cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "independent_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
