#!/usr/bin/env python3
"""Independent MIPS and real-state regressions for v219."""
from __future__ import annotations

import struct
from pathlib import Path
from zipfile import ZipFile

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32

import build_arc1_v190_dynamic_owner_repair as v190
import build_arc1_v219_failclosed_borrow_restore as v219
import analyze_arc1_v214_runtime as ownership
import analyze_arc1_v165c_runtime as glyph_tools
import verify_arc1_v165c_failclosed_cache as cpu_tools
import verify_arc1_v216_runtime_regressions as v216_tests
from analyze_arc1_v163_runtime import trace_active_text_ot
from extract_savestate_vram import load
from verify_arc1_v214_selector_execution import CONTEXT, PACKET0, put
from verify_arc1_v215_selector_execution import packet


ROOT = Path(__file__).resolve().parents[1]
SAVE_DIR = Path(r"C:\Users\Administrator\AppData\Local\DuckStation\savestates")
BIOS_FAILURE = SAVE_DIR / "HASH-EB6915FE435E3501_1.sav"
BIOS_FALSE_NODE = 0x801AEA44
BACKUP_PATTERN = bytes((index * 37 + 11) & 0xFF for index in range(v219.BACKUP_BYTES))


def ram_at(address: int) -> int:
    return address & 0x1FFFFF


def output_zip() -> Path:
    matches = sorted((ROOT / "03_output").glob(f"{v219.OUT_STEM}_????????.zip"))
    if len(matches) != 1:
        raise SystemExit(f"expected one v219 archive, found: {matches}")
    return matches[0]


class BorrowCPU(cpu_tools.R3000):
    """Model GPU library calls and count real Huffman entries."""

    def __init__(self, memory: cpu_tools.Memory, pc: int, huffman: int) -> None:
        super().__init__(memory, pc)
        self.huffman = huffman
        self.huffman_entries = 0

    def step(self) -> None:
        if self.pc == self.huffman:
            self.huffman_entries += 1
        super().step()

    def external(self) -> bool:
        if self.pc not in (v219.STOREIMAGE, v219.GPU_SYNC):
            return super().external()
        if self.pending_load is not None or self.pending_branch is not None:
            raise RuntimeError("v219 external reached with a pending CPU delay")
        if self.pc == v219.STOREIMAGE:
            rect = struct.unpack("<4H", self.memory.read(self.reg[v219.A0], 8))
            size = rect[2] * rect[3] * 2
            if size != v219.BACKUP_BYTES:
                raise RuntimeError(f"StoreImage size differs: {rect}")
            self.memory.write(self.reg[v219.A1], BACKUP_PATTERN)
            self.calls.append(cpu_tools.ExternalCall(
                self.pc, self.reg[v219.A0], self.reg[v219.A1], rect, BACKUP_PATTERN
            ))
        else:
            self.calls.append(cpu_tools.ExternalCall(
                self.pc, self.reg[v219.A0], self.reg[v219.A1]
            ))
        self.pc = self.reg[v219.RA]
        return False


def resident_memory(exe: bytes, ram: bytes, a0: int,
                    selector_cpu: object, addresses: list[int], active: int,
                    owners_blob: bytes,
                    layout: dict[str, tuple[int, int]]) -> cpu_tools.Memory:
    source_at = v219.old.file_at(v219.build.v171.SOURCE_BASE)
    resident = exe[source_at:source_at + v219.build.v171.COPY_N]
    memory = cpu_tools.Memory()
    memory.write(v219.build.v171.RESIDENT_BASE, resident)

    checkpoint_n = (
        (v190.plan.SOURCE_N + v190.plan.CHECKPOINT_GROUP - 1)
        // v190.plan.CHECKPOINT_GROUP
    ) * 2
    checkpoints = v219.build.v171.HUFFMAN_CHECKPOINTS_RAM
    memory.write(
        checkpoints,
        ram[ram_at(checkpoints):ram_at(checkpoints) + checkpoint_n],
    )
    owners_at, owners_n = layout["owners"]
    if len(owners_blob) != owners_n:
        raise SystemExit("v219 owner fixture size differs")
    memory.write(owners_at, owners_blob)
    memory.store32(layout["active_mask"][0], active)
    memory.write(a0, bytes(selector_cpu.load(a0 + offset, 1) for offset in range(4)))
    for address in addresses:
        memory.write(
            address,
            bytes(selector_cpu.load(address + offset, 1) for offset in range(52)),
        )
    memory.write(cpu_tools.STACK_TOP - 0x1000, bytes(0x1200))
    return memory


def run_frame(memory: cpu_tools.Memory, a0: int, condition: int,
              huffman: int) -> BorrowCPU:
    cpu = BorrowCPU(memory, v219.FRAME, huffman)
    cpu.reg[v219.SP] = cpu_tools.STACK_TOP
    cpu.reg[v219.RA] = cpu_tools.SENTINEL
    cpu.reg[v219.A0] = a0
    cpu.reg[v219.A1] = condition
    preserved: dict[int, int] = {}
    for register in range(v219.S0, v219.S7 + 1):
        value = 0x51510000 + register
        cpu.reg[register] = value
        preserved[register] = value
    cpu.run()
    if cpu.reg[v219.SP] != cpu_tools.STACK_TOP:
        raise SystemExit("v219 did not restore SP")
    for register, value in preserved.items():
        if cpu.reg[register] != value:
            raise SystemExit(f"v219 did not preserve r{register}")
    return cpu


def selector_case(exe: bytes, specs: list[dict[str, int]]) -> tuple[object, list[int]]:
    addresses = [PACKET0 + index * 0x100 for index in range(len(specs))]
    memory: dict[int, int] = {}
    put(memory, CONTEXT, struct.pack("<I", addresses[0] & 0xFFFFFF))
    for index, spec in enumerate(specs):
        link = addresses[index + 1] & 0xFFFFFF if index + 1 < len(specs) else 0
        put(memory, addresses[index], packet(link, **spec))
    selector_cpu, _visited = v216_tests.selector_to_frame(exe, memory, CONTEXT)
    return selector_cpu, addresses


def synthetic_active(exe: bytes, ram: bytes,
                     layout: dict[str, tuple[int, int]], huffman: int) -> None:
    specs = [
        {"count": 1, "cmd": 0xE1, "tpage": 31},
        {
            "count": 4, "cmd": 0x65, "u": 4, "v": 224,
            "clut": v219.build.v171.v166.FONT_CLUT_MIN,
            "width": 12, "height": 12,
        },
        {
            "count": 4, "cmd": 0x65, "u": 0, "v": 160,
            "clut": 0x79C0, "width": 128, "height": 96,
        },
    ]
    selector_cpu, addresses = selector_case(exe, specs)
    condition = selector_cpu.r[v219.build.A1]
    selected_v, selected_y = v216_tests.selected(condition)
    if (selected_v, selected_y) != (128, 384):
        raise SystemExit("v219 synthetic A conflict did not select B")
    if selector_cpu.load(addresses[1] + 13, 1) != 0xFF - 4:
        raise SystemExit("v219 selector did not write paired marker V=255-U")

    owners = struct.pack("<28H", *([0] * 28))
    memory = resident_memory(
        exe, ram, CONTEXT, selector_cpu, addresses, 0xFFFFFFFF, owners, layout
    )
    cpu = run_frame(memory, CONTEXT, condition, huffman)
    targets = [call.target for call in cpu.calls]
    expected = (
        [v219.STOREIMAGE, v219.GPU_SYNC]
        + [v219.old.LOADIMAGE] * 7
        + [v219.old.DRAWOT, v219.GPU_SYNC, v219.old.LOADIMAGE]
    )
    if targets != expected:
        raise SystemExit(f"v219 active call order differs: {[hex(x) for x in targets]}")
    if cpu.huffman_entries != 28:
        raise SystemExit(f"v219 valid owner decode count differs: {cpu.huffman_entries}")

    # Call topology alone missed v219's in-place expansion bug: decoded 12-bit
    # rows and the expanded 4bpp cell shared SP+0, so row 0 overwrote rows 1/2.
    # Compare every plane of every uploaded cell against the requested source.
    sources = ownership.runtime_sources(ram, layout)
    expected = glyph_tools.expected_shape(sources[0])
    cache_uploads = [
        call for call in cpu.calls
        if call.target == v219.old.LOADIMAGE
        and call.rect is not None and call.rect[2] == 3
    ]
    if len(cache_uploads) != v219.v190.CACHE_CELLS:
        raise SystemExit(f"v219 cache upload count differs: {len(cache_uploads)}")
    for cell, call in enumerate(cache_uploads):
        if call.payload is None:
            raise SystemExit(f"v219 cache cell {cell} has no captured payload")
        for plane in range(v219.old.PLANES):
            got = glyph_tools.selected_plane(call.payload, plane)
            if got != expected:
                raise SystemExit(
                    f"v219 cache upload pixels differ: cell={cell} plane={plane}"
                )
    if memory.load8(addresses[1] + 13) != selected_v:
        raise SystemExit("v219 did not rewrite paired marker to selected V")
    if memory.load32(layout["active_mask"][0]) != 0xFFFFFFFF:
        raise SystemExit("v219 did not persist a valid marker")
    if cpu.calls[0].rect != (v219.build.v171.CACHE_X, selected_y, 21, 12):
        raise SystemExit("v219 borrow rectangle differs")
    if cpu.calls[-1].payload != BACKUP_PATTERN:
        raise SystemExit("v219 exact restore payload differs")
    print("PASS synthetic dynamic text: paired marker -> 28 valid decodes -> exact restore")


def bios_false_marker(exe: bytes, layout: dict[str, tuple[int, int]],
                      huffman: int) -> None:
    if not BIOS_FAILURE.exists():
        raise SystemExit("v218 BIOS failure state is missing")
    ram, _vram = load(BIOS_FAILURE)
    _context, _parity, rows = trace_active_text_ot(ram)
    a0 = 0x801AE254
    memory_dict, addresses = v216_tests.selector_memory(ram, a0, rows)
    selector_cpu, _visited = v216_tests.selector_to_frame(exe, memory_dict, a0)
    if BIOS_FALSE_NODE not in addresses:
        raise SystemExit("v218 BIOS false-marker node is absent from real OT")
    before = bytes(selector_cpu.load(BIOS_FALSE_NODE + i, 1) for i in range(52))
    if before[3] != 0 or before[12:14] != b"\xFF\xFF":
        raise SystemExit("BIOS control-node fixture bytes differ")

    owners_at, owners_n = layout["owners"]
    owners = ram[ram_at(owners_at):ram_at(owners_at) + owners_n]
    if owners != b"\xFF" * owners_n:
        raise SystemExit("BIOS fixture owners are no longer all FFFF")
    memory = resident_memory(
        exe, ram, a0, selector_cpu, addresses, 0xFFFFFFFF, owners, layout
    )
    condition = selector_cpu.r[v219.build.A1]
    cpu = run_frame(memory, a0, condition, huffman)
    after = memory.read(BIOS_FALSE_NODE, 52)
    if after != before:
        raise SystemExit("v219 rewrote the BIOS OT control node")
    if cpu.huffman_entries != 0:
        raise SystemExit(f"v219 decoded FFFF owners {cpu.huffman_entries} times")
    if memory.load32(layout["active_mask"][0]) != 0:
        raise SystemExit("v219 retained a false BIOS active mask")
    print(
        "PASS real v218 BIOS-failure fixture: count0 FF/FF node untouched; "
        "FFFF owners decoded 0 times; next mask 0"
    )


def static_guards(exe: bytes, layout: dict[str, tuple[int, int]],
                  huffman: int) -> None:
    source_at = v219.old.file_at(v219.build.v171.SOURCE_BASE)
    frame_at = source_at + v219.FRAME - v219.build.v171.RESIDENT_BASE
    frame = exe[frame_at:frame_at + v219.FRAME_N]
    first = struct.unpack_from("<I", frame)[0]
    expected_first = v219.old.i_type(0x09, v219.SP, v219.SP, -v219.STACK_SIZE)
    if first != expected_first:
        raise SystemExit("v219 compact stack prologue differs")
    if frame != v219.failclosed_frame(v219.FRAME, huffman, layout):
        raise SystemExit("archived v219 frame differs from builder")

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    kernel = [
        insn for insn in md.disasm(frame, v219.FRAME)
        if "$k0" in insn.op_str or "$k1" in insn.op_str
    ]
    if kernel:
        raise SystemExit(f"v219 frame still uses kernel registers: {kernel}")
    print(
        f"PASS static frame: {len(frame)} bytes, stack 0x{v219.STACK_SIZE:X}, "
        "k0/k1 references 0"
    )


def main() -> None:
    archive = output_zip()
    with ZipFile(archive) as handle:
        exe = handle.read(v219.build.PSX)
    with ZipFile(v219.build.BASE) as handle:
        base_exe = handle.read(v219.build.PSX)

    v216_tests.configure_runtime()
    layout, _blobs, code = v190.resident_layout()
    decoder = v190.build_decoder(code, layout)
    huffman = (code + len(decoder) + 3) & ~3
    fixture_ram, _vram = load(BIOS_FAILURE)

    static_guards(exe, layout, huffman)
    synthetic_active(exe, fixture_ram, layout, huffman)
    bios_false_marker(exe, layout, huffman)
    v216_tests.run_worldmap_regression(exe, base_exe)
    print(f"archive={archive.name}")
    print("v219_failclosed_borrow_restore_regressions=PASS")


if __name__ == "__main__":
    main()
