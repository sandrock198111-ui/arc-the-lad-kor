"""Execute the generated v214 selector in a tiny MIPS subset emulator.

This is independent of the builder's Python decision model: instructions are
read back from the archived PSX.EXE, branches and delay slots are executed, and
synthetic OT packet chains exercise A, B, marker, ABR and false-positive cases.
No game or emulator is launched.
"""
from __future__ import annotations

import struct
from pathlib import Path
from zipfile import ZipFile

import build_arc1_v214_marked_ab_cache_selector as v214


ROOT = Path(__file__).resolve().parents[1]
R2F = 0x8011A800
FRAME = 0x801FF668
CONTEXT = 0x80100000
PACKET0 = 0x80101000


def sx16(value: int) -> int:
    return (value ^ 0x8000) - 0x8000


class Machine:
    def __init__(self, exe: bytes, memory: dict[int, int]):
        self.exe = exe
        self.mem = memory
        self.r = [0] * 32
        self.pc = v214.build.ENTRY
        self.r[v214.build.A0] = CONTEXT
        self.steps = 0

    def byte(self, address: int) -> int:
        if address in self.mem:
            return self.mem[address]
        at = address - R2F
        if 0 <= at < len(self.exe):
            return self.exe[at]
        return 0

    def load(self, address: int, size: int) -> int:
        return sum(self.byte(address + i) << (8 * i) for i in range(size))

    def store(self, address: int, value: int, size: int) -> None:
        for i in range(size):
            self.mem[address + i] = (value >> (8 * i)) & 0xFF

    def word(self, address: int) -> int:
        return self.load(address, 4)

    def execute_plain(self, word: int) -> None:
        op = word >> 26
        rs, rt, rd = (word >> 21) & 31, (word >> 16) & 31, (word >> 11) & 31
        shamt, funct = (word >> 6) & 31, word & 63
        imm = word & 0xFFFF
        a, b = self.r[rs], self.r[rt]
        if word == 0:
            return
        if op == 0:
            if funct == 0x00:
                self.r[rd] = (b << shamt) & 0xFFFFFFFF
            elif funct == 0x02:
                self.r[rd] = (b & 0xFFFFFFFF) >> shamt
            elif funct == 0x21:
                self.r[rd] = (a + b) & 0xFFFFFFFF
            elif funct == 0x25:
                self.r[rd] = a | b
            elif funct == 0x27:
                self.r[rd] = (~(a | b)) & 0xFFFFFFFF
            else:
                raise AssertionError(f"unsupported SPECIAL 0x{funct:X} at 0x{self.pc:08X}")
        elif op == 0x09:
            self.r[rt] = (a + sx16(imm)) & 0xFFFFFFFF
        elif op == 0x0B:
            self.r[rt] = int((a & 0xFFFFFFFF) < (sx16(imm) & 0xFFFFFFFF))
        elif op == 0x0C:
            self.r[rt] = a & imm
        elif op == 0x0D:
            self.r[rt] = a | imm
        elif op == 0x0E:
            self.r[rt] = a ^ imm
        elif op == 0x0F:
            self.r[rt] = (imm << 16) & 0xFFFFFFFF
        elif op == 0x23:
            self.r[rt] = self.load((a + sx16(imm)) & 0xFFFFFFFF, 4)
        elif op == 0x25:
            self.r[rt] = self.load((a + sx16(imm)) & 0xFFFFFFFF, 2)
        elif op == 0x24:
            self.r[rt] = self.load((a + sx16(imm)) & 0xFFFFFFFF, 1)
        elif op == 0x28:
            self.store((a + sx16(imm)) & 0xFFFFFFFF, b, 1)
        elif op == 0x29:
            self.store((a + sx16(imm)) & 0xFFFFFFFF, b, 2)
        else:
            raise AssertionError(f"unsupported plain op 0x{op:X} at 0x{self.pc:08X}")
        self.r[0] = 0

    def step(self) -> None:
        word = self.word(self.pc)
        op = word >> 26
        rs, rt = (word >> 21) & 31, (word >> 16) & 31
        taken = False
        target = self.pc + 8
        if op == 0x02:
            taken = True
            target = ((self.pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
        elif op in (0x04, 0x05):
            equal = self.r[rs] == self.r[rt]
            taken = equal if op == 0x04 else not equal
            target = self.pc + 4 + sx16(word & 0xFFFF) * 4
        elif op == 0x01:
            if rt != 1:
                raise AssertionError(f"unsupported REGIMM rt={rt}")
            taken = (self.r[rs] & 0x80000000) == 0
            target = self.pc + 4 + sx16(word & 0xFFFF) * 4
        else:
            self.execute_plain(word)
            self.pc += 4
            self.steps += 1
            return

        delay_pc = self.pc + 4
        delay = self.word(delay_pc)
        if delay >> 26 in (0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07):
            raise AssertionError(f"control instruction in delay slot 0x{delay_pc:08X}")
        saved_pc = self.pc
        self.pc = delay_pc
        self.execute_plain(delay)
        self.pc = target if taken else saved_pc + 8
        self.steps += 2

    def run(self) -> None:
        while self.pc != FRAME and self.steps < 10000:
            self.step()
        if self.pc != FRAME:
            raise AssertionError(f"selector did not reach frame: pc=0x{self.pc:08X}")


def put(memory: dict[int, int], address: int, data: bytes) -> None:
    for i, value in enumerate(data):
        memory[address + i] = value


def packet(link: int, count: int, cmd: int, *, tpage: int = 0,
           u: int = 0, v: int = 0, clut: int = 0,
           width: int = 0, height: int = 0) -> bytearray:
    data = bytearray(20)
    struct.pack_into("<I", data, 0, ((count & 0xFF) << 24) | (link & 0xFFFFFF))
    struct.pack_into("<I", data, 4, ((cmd & 0xFF) << 24) | (tpage & 0xFFFF))
    data[12], data[13] = u & 0xFF, v & 0xFF
    struct.pack_into("<H", data, 14, clut & 0xFFFF)
    data[16], data[17] = width & 0xFF, height & 0xFF
    return data


def run_case(exe: bytes, specs: list[dict[str, int]]) -> tuple[int, list[int], int]:
    memory: dict[int, int] = {}
    addresses = [PACKET0 + i * 0x100 for i in range(len(specs))]
    put(memory, CONTEXT, struct.pack("<I", addresses[0] & 0xFFFFFF))
    for index, spec in enumerate(specs):
        link = addresses[index + 1] & 0xFFFFFF if index + 1 < len(specs) else 0
        put(memory, addresses[index], packet(link, **spec))
    machine = Machine(exe, memory)
    machine.run()
    vs = [machine.load(address + 13, 1) for address in addresses]
    rect = v214.build.v190.resident_layout()[0]["upload_rect"][0]
    rect_y = machine.load(rect + 2, 2)
    return machine.r[v214.build.A1], vs, rect_y


def main() -> None:
    candidates = sorted((ROOT / "03_output").glob(
        "arc1_v214_marked_ab_cache_selector_TEST_ONLY_????????.zip"
    ))
    if len(candidates) != 1:
        raise SystemExit(f"expected one v214 archive, found {candidates}")
    with ZipFile(candidates[0]) as archive:
        exe = archive.read("PSX.EXE")

    tpage31 = {"count": 1, "cmd": 0xE1, "tpage": 31}
    tpage63 = {"count": 1, "cmd": 0xE1, "tpage": 63}
    font_a = {
        "count": 4, "cmd": 0x64, "u": 4, "v": 224,
        "clut": v214.build.v171.v166.FONT_CLUT_MIN, "width": 12, "height": 12,
    }
    font_b = dict(font_a, v=128)
    font_marker = dict(font_a, v=v214.MARKER_V)
    game_a = dict(font_a, u=0, v=160, clut=0x79C0, width=128, height=96)
    game_b = dict(font_a, v=128, clut=0x0010)
    bad_size = dict(font_a, width=13)
    both = dict(font_a, u=0, v=120, clut=0x79C0, width=128, height=128)

    cases = [
        ("A canonical", [tpage31, font_a], (224, [0, 255], 480)),
        ("B canonical", [tpage63, font_b], (224, [0, 255], 480)),
        ("marker persistent", [tpage31, font_marker], (224, [0, 255], 480)),
        ("A conflict chooses B", [tpage31, font_b, game_a], (128, [0, 255, 160], 384)),
        ("B conflict chooses A", [tpage31, game_b, font_a], (224, [0, 128, 255], 480)),
        ("simultaneous fallback A", [tpage31, both, font_a], (224, [0, 120, 255], 480)),
        ("wrong size not marked", [tpage31, bad_size], (224, [0, 224], 480)),
    ]
    for name, specs, expected in cases:
        actual = run_case(exe, specs)
        if actual != expected:
            raise SystemExit(f"{name}: expected {expected}, got {actual}")
        print(f"PASS {name}: {actual}")
    print(f"archive={candidates[0].name}")
    print("selector_instruction_execution=PASS")


if __name__ == "__main__":
    main()
