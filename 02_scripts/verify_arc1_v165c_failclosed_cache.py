"""Independently verify the assembled v165c resident routines.

The builder checks its source-level plan.  This verifier instead reads the final
archive, maps the copied resident bytes to their runtime addresses and executes
the assembled R3000 instructions in a small interpreter.  It proves:

* all 370 Huffman sources decode to the rows stored in the final archive;
* the direct-code range hook redirects exactly 162 indices and preserves width;
* the 409-entry E9/EA table returns the expected static/dynamic destination;
* a twenty-fifth simultaneous miss produces a blank without replacing an owner;
* the pre-DrawOT routine composes six complete 4-plane cells and uploads the
  expected x/y/width/height rectangles before one DrawOT call.

No game member or patch archive is modified.
"""
from __future__ import annotations

import csv
import hashlib
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v165_failclosed_cache as build  # noqa: E402
import plan_dynamic_cache_v165_failclosed as plan  # noqa: E402


PATCH = ROOT / "03_output/arc1_v165c_failclosed_24slot_cache_checkpoint_fix_D1ADC357.zip"
PATCH_SHA256 = "D1ADC3570E8690CAE66CCDD54ED1686DA081D1E0A908B3E3BB6B7083ECE8F618"
ANALYSIS = ROOT / "01_work/analysis/arc1_v165c_failclosed_cache_verification"
REPORT = ANALYSIS / "verification_report.txt"

SENTINEL = 0x90000000
TOKEN_RAM = 0x80010000
RESULT_RAM = 0x80010100
STACK_TOP = 0x801E0000


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def u32(value: int) -> int:
    return value & 0xFFFFFFFF


def signed16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def signed32(value: int) -> int:
    return value - 0x100000000 if value & 0x80000000 else value


class Memory:
    def __init__(self) -> None:
        self.data: dict[int, int] = {}

    def clone(self) -> "Memory":
        out = Memory()
        out.data = dict(self.data)
        return out

    def write(self, address: int, blob: bytes) -> None:
        for offset, value in enumerate(blob):
            self.data[u32(address + offset)] = value

    def read(self, address: int, size: int) -> bytes:
        return bytes(self.data.get(u32(address + offset), 0) for offset in range(size))

    def load8(self, address: int) -> int:
        return self.data.get(u32(address), 0)

    def load16(self, address: int) -> int:
        if address & 1:
            raise RuntimeError(f"unaligned halfword read at 0x{address:08X}")
        return int.from_bytes(self.read(address, 2), "little")

    def load32(self, address: int) -> int:
        if address & 3:
            raise RuntimeError(f"unaligned word read at 0x{address:08X}")
        return int.from_bytes(self.read(address, 4), "little")

    def store8(self, address: int, value: int) -> None:
        self.data[u32(address)] = value & 0xFF

    def store16(self, address: int, value: int) -> None:
        if address & 1:
            raise RuntimeError(f"unaligned halfword write at 0x{address:08X}")
        self.write(address, (value & 0xFFFF).to_bytes(2, "little"))

    def store32(self, address: int, value: int) -> None:
        if address & 3:
            raise RuntimeError(f"unaligned word write at 0x{address:08X}")
        self.write(address, u32(value).to_bytes(4, "little"))


@dataclass
class ExternalCall:
    target: int
    a0: int
    a1: int
    rect: tuple[int, int, int, int] | None = None
    payload: bytes | None = None


class R3000:
    """Small delayed-branch/load interpreter for the v165b instruction subset."""

    def __init__(self, memory: Memory, pc: int) -> None:
        self.memory = memory
        self.reg = [0] * 32
        self.pc = pc
        self.pending_load: tuple[int, int] | None = None
        self.pending_branch: int | None = None
        self.calls: list[ExternalCall] = []
        self.steps = 0

    def set_reg(self, register: int, value: int) -> None:
        if register:
            self.reg[register] = u32(value)

    def external(self) -> bool:
        if self.pc == SENTINEL:
            return True
        if self.pc not in (build.LOADIMAGE, build.DRAWOT):
            return False
        if self.pending_load is not None or self.pending_branch is not None:
            raise RuntimeError("external function reached with a pending CPU delay")
        if self.pc == build.LOADIMAGE:
            x, y, width, height = struct.unpack(
                "<4H", self.memory.read(self.reg[build.A0], 8)
            )
            payload = self.memory.read(self.reg[build.A1], width * height * 2)
            self.calls.append(
                ExternalCall(self.pc, self.reg[build.A0], self.reg[build.A1],
                             (x, y, width, height), payload)
            )
        else:
            self.calls.append(ExternalCall(self.pc, self.reg[build.A0], self.reg[build.A1]))
        self.pc = self.reg[build.RA]
        return False

    def run(self, maximum_steps: int = 2_000_000) -> None:
        while self.steps < maximum_steps:
            if self.pc in (
                SENTINEL, build.DECODE_RETURN, build.SINGLE_PATH, build.WIDE_PATH,
                build.GLYPH_PACKET_RETURN,
            ):
                return
            if self.external():
                continue
            self.step()
        raise RuntimeError(f"R3000 step limit exceeded at 0x{self.pc:08X}")

    def step(self) -> None:
        pc = self.pc
        instruction = self.memory.load32(pc)
        op = instruction >> 26
        rs = (instruction >> 21) & 31
        rt = (instruction >> 16) & 31
        rd = (instruction >> 11) & 31
        shift = (instruction >> 6) & 31
        function = instruction & 0x3F
        immediate = instruction & 0xFFFF
        old_load = self.pending_load
        self.pending_load = None
        old_branch = self.pending_branch
        self.pending_branch = None
        next_branch: int | None = None

        def write(register: int, value: int) -> None:
            self.set_reg(register, value)

        if op == 0:
            if function == 0x00:                         # sll / nop
                write(rd, self.reg[rt] << shift)
            elif function == 0x02:                       # srl
                write(rd, self.reg[rt] >> shift)
            elif function == 0x04:                       # sllv
                write(rd, self.reg[rt] << (self.reg[rs] & 31))
            elif function == 0x06:                       # srlv
                write(rd, self.reg[rt] >> (self.reg[rs] & 31))
            elif function == 0x08:                       # jr
                next_branch = self.reg[rs]
            elif function == 0x09:                       # jalr
                write(rd, pc + 8)
                next_branch = self.reg[rs]
            elif function == 0x21:                       # addu
                write(rd, self.reg[rs] + self.reg[rt])
            elif function == 0x23:                       # subu
                write(rd, self.reg[rs] - self.reg[rt])
            elif function == 0x24:
                write(rd, self.reg[rs] & self.reg[rt])
            elif function == 0x25:
                write(rd, self.reg[rs] | self.reg[rt])
            elif function == 0x2B:
                write(rd, int(self.reg[rs] < self.reg[rt]))
            else:
                raise RuntimeError(f"unsupported SPECIAL 0x{function:X} at 0x{pc:08X}")
        elif op == 0x01:                                 # REGIMM
            if rt != 0x01:                               # bgez
                raise RuntimeError(f"unsupported REGIMM rt=0x{rt:X} at 0x{pc:08X}")
            if signed32(self.reg[rs]) >= 0:
                next_branch = pc + 4 + signed16(immediate) * 4
        elif op == 0x02:                                 # j
            next_branch = (pc & 0xF0000000) | ((instruction & 0x03FFFFFF) << 2)
        elif op == 0x03:                                 # jal
            write(build.RA, pc + 8)
            next_branch = (pc & 0xF0000000) | ((instruction & 0x03FFFFFF) << 2)
        elif op == 0x04:                                 # beq
            if self.reg[rs] == self.reg[rt]:
                next_branch = pc + 4 + signed16(immediate) * 4
        elif op == 0x05:                                 # bne
            if self.reg[rs] != self.reg[rt]:
                next_branch = pc + 4 + signed16(immediate) * 4
        elif op == 0x09:                                 # addiu
            write(rt, self.reg[rs] + signed16(immediate))
        elif op == 0x0A:                                 # slti
            write(rt, int(signed32(self.reg[rs]) < signed16(immediate)))
        elif op == 0x0B:                                 # sltiu
            write(rt, int(self.reg[rs] < u32(signed16(immediate))))
        elif op == 0x0C:
            write(rt, self.reg[rs] & immediate)
        elif op == 0x0D:
            write(rt, self.reg[rs] | immediate)
        elif op == 0x0E:
            write(rt, self.reg[rs] ^ immediate)
        elif op == 0x0F:
            write(rt, immediate << 16)
        elif op in (0x23, 0x24, 0x25):                   # lw/lbu/lhu
            address = u32(self.reg[rs] + signed16(immediate))
            if op == 0x23:
                value = self.memory.load32(address)
            elif op == 0x24:
                value = self.memory.load8(address)
            else:
                value = self.memory.load16(address)
            self.pending_load = (rt, value)
        elif op in (0x28, 0x29, 0x2B):                   # sb/sh/sw
            address = u32(self.reg[rs] + signed16(immediate))
            if op == 0x28:
                self.memory.store8(address, self.reg[rt])
            elif op == 0x29:
                self.memory.store16(address, self.reg[rt])
            else:
                self.memory.store32(address, self.reg[rt])
        else:
            raise RuntimeError(f"unsupported opcode 0x{op:X} at 0x{pc:08X}")

        # A load becomes visible only after the immediately following instruction.
        if old_load is not None:
            register, value = old_load
            self.set_reg(register, value)
        self.reg[0] = 0

        if old_branch is not None:
            if next_branch is not None:
                raise RuntimeError(f"control transfer in delay slot at 0x{pc:08X}")
            self.pc = u32(old_branch)
        else:
            self.pc = u32(pc + 4)
            if next_branch is not None:
                self.pending_branch = u32(next_branch)
        self.steps += 1


def parse_routines() -> dict[str, tuple[int, int]]:
    text = build.DISASSEMBLY.read_text(encoding="utf-8")
    found = {
        name: (int(address, 16), int(size))
        for name, address, size in re.findall(
            r"^--- (decoder|huffman|helper|classifier|frame) 0x([0-9A-F]+) \((\d+) bytes\) ---$",
            text,
            re.MULTILINE,
        )
    }
    if set(found) != {"decoder", "huffman", "helper", "classifier", "frame"}:
        raise SystemExit(f"routine headers differ: {sorted(found)}")
    return found


def runtime_memory(exe: bytes) -> Memory:
    memory = Memory()
    memory.write(
        build.RESIDENT_BASE,
        exe[build.file_at(build.SOURCE_BASE):build.file_at(build.SOURCE_BASE) + build.COPY_N],
    )
    memory.write(
        build.LOOKUP_RAM,
        exe[build.file_at(build.LOOKUP_RAM):build.file_at(build.LOOKUP_RAM) + build.LOOKUP_N * 2],
    )
    memory.write(STACK_TOP - 0x200, bytes(0x400))
    memory.write(TOKEN_RAM, bytes(0x200))
    return memory


def python_sources(memory: Memory, layout: dict[str, tuple[int, int]]) -> list[tuple[int, ...]]:
    rows_at, rows_n = layout["huffman_rows"]
    counts_at, counts_n = layout["huffman_counts"]
    checkpoints_at, checkpoints_n = layout["source_checkpoints"]
    stream_at, stream_n = layout["source_bitstream"]
    rows = struct.unpack(f"<{rows_n // 2}H", memory.read(rows_at, rows_n))
    counts = memory.read(counts_at, counts_n)
    checkpoints = struct.unpack(
        f"<{checkpoints_n // 2}H", memory.read(checkpoints_at, checkpoints_n)
    )
    stream = memory.read(stream_at, stream_n)

    def symbol(bit_position: int) -> tuple[int, int]:
        code = first_code = first_symbol = 0
        for count in counts:
            byte, bit = divmod(bit_position, 8)
            code = (code << 1) | ((stream[byte] >> (7 - bit)) & 1)
            bit_position += 1
            delta = code - first_code
            if 0 <= delta < count:
                return rows[first_symbol + delta], bit_position
            first_symbol += count
            first_code = (first_code + count) << 1
        raise RuntimeError("invalid archive Huffman code")

    result = []
    for source in range(build.SOURCE_N):
        group, within = divmod(source, plan.CHECKPOINT_GROUP)
        position = checkpoints[group]
        decoded = []
        for ordinal in range((within + 1) * build.CELL):
            row, position = symbol(position)
            if ordinal >= within * build.CELL:
                decoded.append(row)
        result.append(tuple(decoded))
    return result


def run_huffman(base_memory: Memory, address: int,
                expected: list[tuple[int, ...]]) -> tuple[int, int]:
    total_steps = maximum_steps = 0
    for source, rows in enumerate(expected):
        memory = base_memory.clone()
        memory.write(RESULT_RAM, bytes(24))
        cpu = R3000(memory, address)
        cpu.reg[build.A0] = source
        cpu.reg[build.A1] = RESULT_RAM
        cpu.reg[build.RA] = SENTINEL
        cpu.run()
        got = struct.unpack("<12H", memory.read(RESULT_RAM, 24))
        if got != rows:
            raise SystemExit(f"assembled Huffman differs at source {source}")
        total_steps += cpu.steps
        maximum_steps = max(maximum_steps, cpu.steps)
    return total_steps, maximum_steps


def direct_token(index: int) -> bytes:
    if 0 <= index < 220:
        return bytes((index + 1,))
    group, remainder = divmod(index - 220, 255)
    if not 0 <= group < 12 or not 0 <= remainder < 254:
        raise ValueError(f"index has no valid direct token: {index}")
    return bytes((0xDD + group, remainder + 1))


def run_decoder_once(memory: Memory, decoder: int, token: bytes) -> tuple[int, int, int]:
    memory.write(TOKEN_RAM, token + b"\x00\x00")
    memory.store32(RESULT_RAM, 0)
    cpu = R3000(memory, decoder)
    cpu.reg[build.V1] = token[0]
    cpu.reg[build.A1] = TOKEN_RAM
    cpu.reg[build.A2] = RESULT_RAM
    cpu.run()
    consumed = u32(memory.load32(RESULT_RAM) - TOKEN_RAM)
    return cpu.pc, cpu.reg[build.V1], consumed


def run_decoder(base_memory: Memory, decoder: int,
                layout: dict[str, tuple[int, int]],
                ranges: dict[int, int], lookup: tuple[int, ...]) -> tuple[int, int, int]:
    owners_at = layout["owners"][0]
    active_at = layout["active_mask"][0]
    next_at = layout["next_slot"][0]

    # Every valid direct code either routes exactly one conflict source or returns
    # to the correct stock one-/two-byte path without consuming it here.
    direct_checked = dynamic_direct = 0
    for index in range(220 + 11 * 255 + 254):
        try:
            token = direct_token(index)
        except ValueError:
            continue
        memory = base_memory.clone()
        pc, glyph, consumed = run_decoder_once(memory, decoder, token)
        if index in ranges:
            if pc != build.DECODE_RETURN or glyph != build.CACHE_INDEX_BASE or \
                    consumed != len(token):
                raise SystemExit(
                    f"direct dynamic route differs at {index}: "
                    f"pc=0x{pc:08X} glyph={glyph} consumed={consumed}"
                )
            dynamic_direct += 1
        else:
            expected_pc = build.SINGLE_PATH if len(token) == 1 else build.WIDE_PATH
            if pc != expected_pc:
                raise SystemExit(f"direct static path differs at {index}: 0x{pc:08X}")
        direct_checked += 1
    if dynamic_direct != 162:
        raise SystemExit(f"assembled direct dynamic count differs: {dynamic_direct}")

    # E9/EA entries: static values pass through; dynamic values get one cache slot.
    lookup_checked = lookup_dynamic = 0
    for slot, entry in enumerate(lookup):
        token = bytes((0xE9 + slot // 254, slot % 254 + 1))
        memory = base_memory.clone()
        pc, glyph, consumed = run_decoder_once(memory, decoder, token)
        if pc != build.DECODE_RETURN or consumed != 2:
            raise SystemExit(f"lookup route/width differs at slot {slot}")
        if entry & 0x8000:
            if glyph != build.CACHE_INDEX_BASE:
                raise SystemExit(f"lookup dynamic glyph differs at slot {slot}: {glyph}")
            lookup_dynamic += 1
        elif glyph != entry:
            raise SystemExit(f"lookup static glyph differs at slot {slot}: {glyph} != {entry}")
        lookup_checked += 1

    # Twenty-four distinct requests fill every slot.  The twenty-fifth must be
    # blank and must not alter any owner or next-slot state.
    memory = base_memory.clone()
    dynamic_indices = sorted(ranges)[:25]
    for expected_slot, index in enumerate(dynamic_indices[:24]):
        pc, glyph, consumed = run_decoder_once(memory, decoder, direct_token(index))
        if (pc, glyph, consumed) != (
            build.DECODE_RETURN, build.CACHE_INDEX_BASE + expected_slot,
            len(direct_token(index)),
        ):
            raise SystemExit(f"cache fill differs at slot {expected_slot}")
    owners_before = memory.read(owners_at, build.CACHE_N * 2)
    next_before = memory.load8(next_at)
    pc, glyph, consumed = run_decoder_once(memory, decoder, direct_token(dynamic_indices[24]))
    if pc != build.DECODE_RETURN or glyph != 0 or consumed != len(direct_token(dynamic_indices[24])):
        raise SystemExit("twenty-fifth cache miss did not fail closed")
    if memory.read(owners_at, build.CACHE_N * 2) != owners_before or \
            memory.load8(next_at) != next_before or memory.load32(active_at) != 0xFFFFFF:
        raise SystemExit("twenty-fifth cache miss changed resident cache state")

    # Clearing the frame mask makes a replacement legal again.
    memory.store32(active_at, 0)
    _pc, glyph, _consumed = run_decoder_once(
        memory, decoder, direct_token(dynamic_indices[24])
    )
    if glyph != build.CACHE_INDEX_BASE:
        raise SystemExit("post-frame replacement did not reuse slot zero")
    return direct_checked, lookup_checked, lookup_dynamic


def payload_plane_rows(payload: bytes, plane: int) -> tuple[int, ...]:
    if len(payload) != 72:
        raise ValueError("cache-cell payload is not 72 bytes")
    rows = []
    for y in range(build.CELL):
        row = 0
        for x in range(build.CELL):
            byte = payload[y * 6 + x // 2]
            nibble = (byte >> (4 if x & 1 else 0)) & 0x0F
            row = (row << 1) | ((nibble >> plane) & 1)
        rows.append(row)
    return tuple(rows)


def run_frame(base_memory: Memory, frame: int,
              layout: dict[str, tuple[int, int]],
              expected_rows: list[tuple[int, ...]]) -> tuple[int, int, int]:
    owners_at = layout["owners"][0]
    active_at = layout["active_mask"][0]
    memory = base_memory.clone()
    memory.write(owners_at, struct.pack("<24H", *range(24)))
    memory.store32(active_at, 0xFFFFFF)
    cpu = R3000(memory, frame)
    cpu.reg[build.SP] = STACK_TOP
    cpu.reg[build.RA] = SENTINEL
    cpu.reg[build.A0] = 0x81234560
    preserved = {}
    for register in range(build.S0, build.S7 + 1):
        value = 0x11110000 + register
        cpu.reg[register] = value
        preserved[register] = value
    cpu.run()
    uploads = [call for call in cpu.calls if call.target == build.LOADIMAGE]
    draw = [call for call in cpu.calls if call.target == build.DRAWOT]
    if len(uploads) != 6 or len(draw) != 1 or draw[0].a0 != 0x81234560:
        raise SystemExit(
            f"frame call topology differs: uploads={len(uploads)} draw={len(draw)}"
        )
    for cell, call in enumerate(uploads):
        expected_rect = (build.CACHE_X + cell * 3, build.CACHE_Y, 3, build.CELL)
        if call.rect != expected_rect or call.payload is None:
            raise SystemExit(f"cache upload rectangle differs at cell {cell}: {call.rect}")
        for plane in range(build.PLANES):
            source = cell * build.PLANES + plane
            if payload_plane_rows(call.payload, plane) != expected_rows[source]:
                raise SystemExit(f"cache cell composition differs: cell={cell} plane={plane}")
    if memory.load32(active_at) != 0:
        raise SystemExit("frame routine did not consume the active mask")
    for register, value in preserved.items():
        if cpu.reg[register] != value:
            raise SystemExit(f"frame routine did not preserve r{register}")
    full_frame_steps = cpu.steps

    # Partial activity uploads only the three touched cells and leaves all inactive
    # planes zero in their rebuilt complete-cell payloads.
    memory = base_memory.clone()
    memory.write(owners_at, struct.pack("<24H", *range(24)))
    partial_mask = (1 << 0) | (1 << 5) | (1 << 23)
    memory.store32(active_at, partial_mask)
    cpu = R3000(memory, frame)
    cpu.reg[build.SP] = STACK_TOP
    cpu.reg[build.RA] = SENTINEL
    cpu.reg[build.A0] = 0x81234560
    cpu.run()
    uploads = [call for call in cpu.calls if call.target == build.LOADIMAGE]
    if [call.rect[0] for call in uploads if call.rect] != [961, 964, 976]:
        raise SystemExit("partial active mask uploaded the wrong cells")
    active_slots = {0, 5, 23}
    for cell, call in zip((0, 1, 5), uploads):
        assert call.payload is not None
        for plane in range(4):
            source = cell * 4 + plane
            expected = expected_rows[source] if source in active_slots else (0,) * 12
            if payload_plane_rows(call.payload, plane) != expected:
                raise SystemExit(f"partial composition differs at source {source}")
    return 6, full_frame_steps, cpu.steps


def run_helper_classifier(base_memory: Memory, helper: int, classifier: int) -> int:
    packet = TOKEN_RAM + 0x80
    metadata = TOKEN_RAM + 0x100

    # The helper must add U=4 only for row 40 and must always execute the stock
    # displaced lbu v0,0x0e(a2).
    cases = ((39, 27), (40, 31), (41, 35))
    for row, initial_u in cases:
        memory = base_memory.clone()
        memory.store8(packet + 0x28, initial_u)
        memory.store8(metadata + 0x0E, 0x5A)
        cpu = R3000(memory, helper)
        cpu.reg[build.T0] = row
        cpu.reg[build.A1] = packet
        cpu.reg[build.A2] = metadata
        cpu.run()
        expected_u = initial_u + build.CACHE_U if row == build.CACHE_ROW else initial_u
        if memory.load8(packet + 0x28) != expected_u or cpu.reg[build.V0] != 0x5A:
            raise SystemExit(f"U helper differs for row {row}")

    checked = 0
    for v in (0, build.CACHE_V, 216, 228):
        for clut in (*range(0x7FC0, 0x7FD0), 0x0010, 0x7FBF, 0x7FD0):
            memory = base_memory.clone()
            memory.store8(packet + 0x29, v)
            memory.store16(packet + 0x30, clut)
            cpu = R3000(memory, classifier)
            cpu.reg[build.V1] = packet
            cpu.reg[build.RA] = SENTINEL
            cpu.run()
            expected = int(v == build.CACHE_V and 0x7FC0 <= clut < 0x7FD0)
            if cpu.reg[build.V0] != expected:
                raise SystemExit(
                    f"classifier differs for V={v} CLUT=0x{clut:04X}: "
                    f"{cpu.reg[build.V0]} != {expected}"
                )
            checked += 1
    return checked


def main() -> None:
    if digest(PATCH.read_bytes()) != PATCH_SHA256:
        raise SystemExit("v165b patch archive hash differs")
    if digest(build.BASE.read_bytes()) != build.BASE_SHA256:
        raise SystemExit("v164 base archive hash differs")
    with ZipFile(PATCH) as archive:
        members = {info.filename: archive.read(info.filename) for info in archive.infolist()}
    with ZipFile(build.BASE) as archive:
        base_members = {info.filename: archive.read(info.filename) for info in archive.infolist()}
    changed = sorted(name for name in members if members[name] != base_members[name])
    if changed != [build.COMM, build.PSX]:
        raise SystemExit(f"changed member set differs: {changed}")
    exe = members[build.PSX]
    with ZipFile(build.ORIGINAL) as archive:
        original_font = archive.read(build.COMM)
    final_font = members[build.COMM]
    changed_cells = set()
    for row in range(21):
        for col in range(21):
            if build.cell_bytes(original_font, row, col) != \
                    build.cell_bytes(final_font, row, col):
                changed_cells.add((row, col))
    with plan.CELL_MANIFEST.open(encoding="utf-8-sig", newline="") as handle:
        rejected_cells = {
            (int(record["row"]), int(record["col"]))
            for record in csv.DictReader(handle)
            if record["status"] == "rejected_known_nontext"
        }
    known_nontext_intersection = changed_cells & rejected_cells
    if len(changed_cells) != 119 or known_nontext_intersection:
        raise SystemExit(
            f"final static-cell collision set differs: changed={len(changed_cells)} "
            f"known_nontext={sorted(known_nontext_intersection)}"
        )
    layout = build.read_layout()
    routines = parse_routines()
    memory = runtime_memory(exe)
    expected_sources = python_sources(memory, layout)
    total_huffman_steps, maximum_huffman_steps = run_huffman(
        memory, routines["huffman"][0], expected_sources
    )
    ranges = build.unpack_ranges(memory.read(*layout["conflict_ranges"]))
    lookup = struct.unpack(
        f"<{build.LOOKUP_N}H", memory.read(build.LOOKUP_RAM, build.LOOKUP_N * 2)
    )
    direct_checked, lookup_checked, lookup_dynamic = run_decoder(
        memory, routines["decoder"][0], layout, ranges, lookup
    )
    upload_cells, full_frame_steps, partial_frame_steps = run_frame(
        memory, routines["frame"][0], layout, expected_sources
    )
    classifier_cases = run_helper_classifier(
        memory, routines["helper"][0], routines["classifier"][0]
    )

    # Hook words must point at the exact routines just executed.
    expected_hooks = (
        (build.DECODER_ENTRY, build.j(routines["decoder"][0])),
        (build.GLYPH_PACKET_HOOK, build.j(routines["helper"][0])),
        (build.CLASSIFIER_CALL, build.jal(routines["classifier"][0])),
        (build.LATE_HOOK, build.jal(routines["frame"][0])),
    )
    for address, expected in expected_hooks:
        if build.word(exe, address) != expected:
            raise SystemExit(f"hook target differs at 0x{address:08X}")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    lines = [
        "v165c independent assembled-code verification",
        "",
        f"patch={PATCH.name}",
        f"sha256={PATCH_SHA256}",
        "changed_members=COMM.IMG PSX.EXE only PASS",
        f"final_static_changed_cells={len(changed_cells)}",
        "final_static_cells_with_sampled_nontext_consumer=0/82 PASS",
        f"assembled_Huffman_sources=370/370 PASS",
        f"assembled_Huffman_total_steps={total_huffman_steps}",
        f"assembled_Huffman_max_steps_per_source={maximum_huffman_steps}",
        f"direct_codes_checked={direct_checked}",
        "direct_dynamic_indices=162/162 PASS",
        f"lookup_entries_checked={lookup_checked}",
        f"lookup_dynamic_entries={lookup_dynamic}",
        "twenty_fifth_simultaneous_miss=blank/no-owner-change PASS",
        "post_frame_replacement=PASS",
        f"full_active_cache_upload_cells={upload_cells}/6 PASS",
        "full_active_cell_plane_composition=24/24 PASS",
        f"full_active_frame_interpreter_steps={full_frame_steps}",
        "partial_active_cell_plane_composition=PASS",
        f"partial_frame_interpreter_steps={partial_frame_steps}",
        "row40_U_helper=PASS",
        f"text_CLUT_classifier_cases={classifier_cases} PASS",
        "pre_DrawOT_call_topology=PASS",
        "callee_saved_registers=PASS",
        "hook_targets=PASS",
        "unaligned_runtime_accesses=0",
        "",
        "static_verification=PASS",
        "runtime_verification=PENDING user cold boot",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
