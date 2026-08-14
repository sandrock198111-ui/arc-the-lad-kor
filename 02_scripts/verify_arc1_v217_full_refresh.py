#!/usr/bin/env python3
"""MIPS/static regression for v217's selected-page full refresh."""
from __future__ import annotations

import struct
from pathlib import Path
from zipfile import ZipFile

import analyze_arc1_v214_runtime as ownership
import build_arc1_v217_full_selected_destination_refresh as v217
import build_arc1_v190_dynamic_owner_repair as v190
import verify_arc1_v165c_failclosed_cache as cpu_tools
import verify_arc1_v216_runtime_regressions as v216_tests
from extract_savestate_vram import load


ROOT = Path(__file__).resolve().parents[1]
SAVE_DIR = Path(r"C:\Users\Administrator\AppData\Local\DuckStation\savestates")
RUNTIME_PREFIX = "HASH-61AED07119A5524A"
FRAME = v217.FRAME


def ram_at(address: int) -> int:
    return address & 0x1FFFFF


def slot_number(path: Path) -> int:
    return int(path.stem.rsplit("_", 1)[1])


def output_zip() -> Path:
    matches = sorted((ROOT / "03_output").glob(f"{v217.OUT_STEM}_????????.zip"))
    if len(matches) != 1:
        raise SystemExit(f"expected one v217 archive, found: {matches}")
    return matches[0]


def prepare_frame_memory(exe: bytes, ram: bytes, a0: int,
                         selector_cpu: object, addresses: list[int],
                         layout: dict[str, tuple[int, int]]) -> cpu_tools.Memory:
    source_at = v217.old.file_at(v217.build.v171.SOURCE_BASE)
    resident = exe[source_at:source_at + v217.build.v171.COPY_N]
    memory = cpu_tools.Memory()
    memory.write(v217.build.v171.RESIDENT_BASE, resident)

    checkpoint_n = (
        (v190.plan.SOURCE_N + v190.plan.CHECKPOINT_GROUP - 1)
        // v190.plan.CHECKPOINT_GROUP
    ) * 2
    checkpoints = v217.build.v171.HUFFMAN_CHECKPOINTS_RAM
    memory.write(
        checkpoints,
        ram[ram_at(checkpoints):ram_at(checkpoints) + checkpoint_n],
    )
    owners_at, owners_n = layout["owners"]
    memory.write(owners_at, ram[ram_at(owners_at):ram_at(owners_at) + owners_n])
    # Decisive regression: even zero prior activity must rebuild all seven cells.
    memory.store32(layout["active_mask"][0], 0)
    memory.write(a0, bytes(selector_cpu.load(a0 + i, 1) for i in range(4)))
    for address in addresses:
        memory.write(
            address,
            bytes(selector_cpu.load(address + i, 1) for i in range(52)),
        )
    memory.write(cpu_tools.STACK_TOP - 0x200, bytes(0x400))
    return memory


def run_runtime_states(exe: bytes) -> None:
    states = sorted(
        (path for path in SAVE_DIR.glob(f"{RUNTIME_PREFIX}_*.sav")
         if path.stem.rsplit("_", 1)[-1].isdigit()),
        key=slot_number,
    
    )
    if len(states) != 3:
        raise SystemExit(f"expected three v216 runtime states, found: {states}")

    layout, _blobs, _code = v190.resident_layout()
    for state in states:
        ram, _vram = load(state)
        sources = ownership.runtime_sources(ram, layout)
        owners = struct.unpack_from(
            "<28H", ram, ram_at(layout["owners"][0])
        )
        a0, rows = v216_tests.state_rows(ram)
        selector_memory, addresses = v216_tests.selector_memory(ram, a0, rows)
        selector_cpu, _visited = v216_tests.selector_to_frame(
            exe, selector_memory, a0
        )
        condition = selector_cpu.r[v217.build.A1]
        selected_v, selected_y = v216_tests.selected(condition)

        memory = prepare_frame_memory(
            exe, ram, a0, selector_cpu, addresses, layout
        )
        cpu = cpu_tools.R3000(memory, FRAME)
        cpu.reg[v217.build.SP] = cpu_tools.STACK_TOP
        cpu.reg[v217.build.RA] = cpu_tools.SENTINEL
        cpu.reg[v217.build.A0] = a0
        cpu.reg[v217.build.A1] = condition
        cpu.run()

        uploads = [call for call in cpu.calls if call.target == v217.old.LOADIMAGE]
        draws = [call for call in cpu.calls if call.target == v217.old.DRAWOT]
        if len(uploads) != 7 or len(draws) != 1:
            raise SystemExit(
                f"slot{slot_number(state)} call topology differs: "
                f"uploads={len(uploads)} draws={len(draws)}"
            )
        for cell, call in enumerate(uploads):
            expected_rect = (
                v217.build.v171.CACHE_X + cell * 3,
                selected_y,
                3,
                v217.old.CELL,
            )
            if call.rect != expected_rect or call.payload is None:
                raise SystemExit(
                    f"slot{slot_number(state)} cell{cell} rect differs: {call.rect}"
                )
            for plane in range(4):
                owner = owners[cell * 4 + plane]
                expected_rows = ((0,) * 12 if owner == 0xFFFF else sources[owner])
                actual_rows = cpu_tools.payload_plane_rows(call.payload, plane)
                if actual_rows != expected_rows:
                    raise SystemExit(
                        f"slot{slot_number(state)} cell{cell} plane{plane} "
                        f"owner={owner} payload differs"
                    )
        packet_v = [
            memory.load8(int(row["address"]) + 13)
            for row in rows if row["text_cache"]
        ]
        if any(value != selected_v for value in packet_v):
            raise SystemExit(f"slot{slot_number(state)} packet V handoff differs")
        print(
            f"PASS runtime slot{slot_number(state)}: prior_active=0 "
            f"uploads=7 planes=28 selected_V={selected_v} selected_Y={selected_y}"
        )


def main() -> None:
    archive = output_zip()
    with ZipFile(archive) as handle:
        exe = handle.read(v217.build.PSX)
    v216_tests.run_synthetic(exe)
    with ZipFile(v217.build.BASE) as handle:
        base_exe = handle.read(v217.build.PSX)
    v216_tests.run_worldmap_regression(exe, base_exe)
    run_runtime_states(exe)
    print(f"archive={archive.name}")
    print("v217_full_refresh_regressions=PASS")


if __name__ == "__main__":
    main()
