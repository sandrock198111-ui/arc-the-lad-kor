#!/usr/bin/env python3
"""Execute v215 selector -> resident frame handoff on four copied real OTs."""
from __future__ import annotations

import struct
from pathlib import Path
from zipfile import ZipFile

import analyze_arc1_v163_runtime as runtime
import build_arc1_v215_correct_packet_layout_selector as v215
import verify_arc1_v165c_failclosed_cache as cpu_tools
from extract_savestate_vram import load
from verify_arc1_v214_selector_execution import Machine, put


ROOT = Path(__file__).resolve().parents[1]
SAVE_DIR = Path(r"C:\Users\Administrator\AppData\Local\DuckStation\savestates")
PREFIX = "HASH-DA2823B0BBB822CA"
FRAME = 0x801FF668


def ram_at(address: int) -> int:
    return address & 0x1FFFFF


def slot_number(path: Path) -> int:
    return int(path.stem.rsplit("_", 1)[1])


def main() -> None:
    states = sorted(
        (path for path in SAVE_DIR.glob(f"{PREFIX}_*.sav")
         if path.stem.rsplit("_", 1)[-1].isdigit()),
        key=slot_number,
    )
    archives = sorted((ROOT / "03_output").glob(
        "arc1_v215_correct_packet_layout_selector_TEST_ONLY_????????.zip"
    ))
    if len(archives) != 1:
        raise SystemExit(f"expected one v215 archive, found {archives}")
    with ZipFile(archives[0]) as archive:
        exe = archive.read("PSX.EXE")
    build = v215.parent.build
    layout, _blobs, _code = build.v190.resident_layout()

    runtime.CACHE_SLOTS = 28
    runtime.CACHE_CELLS = 7
    runtime.CACHE_U = (4, 16, 28, 40, 52, 64, 76)
    runtime.CACHE_U_END = 88
    runtime.CACHE_V = 224
    runtime.CACHE_V_END = 236

    resident_source = build.old.file_at(build.v171.SOURCE_BASE)
    resident_blob = exe[resident_source:resident_source + build.v171.COPY_N]
    active_at = layout["active_mask"][0]
    rect_at = layout["upload_rect"][0]
    checkpoint_n = ((build.v190.plan.SOURCE_N + build.v190.plan.CHECKPOINT_GROUP - 1)
                    // build.v190.plan.CHECKPOINT_GROUP) * 2

    for state in states:
        ram, _vram = load(state)
        context, _parity, rows = runtime.trace_active_text_ot(ram)
        a0 = 0x80000000 | (ram_at(context) + 0x70)
        selector_memory: dict[int, int] = {}
        put(selector_memory, a0, ram[ram_at(a0):ram_at(a0) + 4])
        addresses: list[int] = []
        expected_mask = 0
        for row in rows:
            address = int(row["address"])
            addresses.append(address)
            at = ram_at(address)
            put(selector_memory, address, ram[at:at + 52])
            if row["text_cache"]:
                expected_mask |= 1 << int(row["slot"])

        selector_cpu = Machine(exe, selector_memory)
        selector_cpu.r[build.A0] = a0
        while selector_cpu.pc != FRAME and selector_cpu.steps < 100000:
            selector_cpu.step()
        if selector_cpu.pc != FRAME:
            raise SystemExit(f"slot{slot_number(state)} selector did not reach frame")
        selected_v = selector_cpu.r[build.A1]

        memory = cpu_tools.Memory()
        memory.write(build.v171.RESIDENT_BASE, resident_blob)
        memory.write(
            build.v171.HUFFMAN_CHECKPOINTS_RAM,
            ram[ram_at(build.v171.HUFFMAN_CHECKPOINTS_RAM):
                ram_at(build.v171.HUFFMAN_CHECKPOINTS_RAM) + checkpoint_n],
        )
        memory.write(
            layout["owners"][0],
            ram[ram_at(layout["owners"][0]):ram_at(layout["owners"][0]) + 56],
        )
        memory.store32(active_at, 0)
        memory.write(rect_at, bytes(selector_cpu.load(rect_at + i, 1) for i in range(8)))
        memory.write(a0, bytes(selector_cpu.load(a0 + i, 1) for i in range(4)))
        for address in addresses:
            memory.write(address, bytes(selector_cpu.load(address + i, 1) for i in range(52)))
        memory.write(cpu_tools.STACK_TOP - 0x200, bytes(0x400))

        frame_cpu = cpu_tools.R3000(memory, FRAME)
        frame_cpu.reg[build.SP] = cpu_tools.STACK_TOP
        frame_cpu.reg[build.RA] = cpu_tools.SENTINEL
        frame_cpu.reg[build.A0] = a0
        frame_cpu.reg[build.A1] = selected_v
        frame_cpu.run()
        actual_mask = memory.load32(active_at)
        cache_addresses = [int(row["address"]) for row in rows if row["text_cache"]]
        wrong_v = [address for address in cache_addresses
                   if memory.load8(address + 13) != selected_v]
        draws = [call for call in frame_cpu.calls if call.target == build.old.DRAWOT]
        print(
            f"slot{slot_number(state)}: expected=0x{expected_mask:08X} "
            f"actual=0x{actual_mask:08X} selected_V={selected_v} "
            f"wrong_V={len(wrong_v)} DrawOT={len(draws)} steps={frame_cpu.steps}"
        )
        if actual_mask != expected_mask or wrong_v or len(draws) != 1:
            raise SystemExit(f"slot{slot_number(state)} selector/frame handoff differs")
    print("v215_selector_frame_handoff=PASS")


if __name__ == "__main__":
    main()
