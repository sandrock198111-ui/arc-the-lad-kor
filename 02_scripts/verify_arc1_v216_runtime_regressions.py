#!/usr/bin/env python3
"""Static/MIPS regressions for v216 without launching an emulator."""
from __future__ import annotations

import struct
from pathlib import Path
from zipfile import ZipFile

import analyze_arc1_v163_runtime as runtime
import build_arc1_v216_relocate_selector_handoff as v216
import verify_arc1_v165c_failclosed_cache as cpu_tools
from extract_savestate_vram import load
from verify_arc1_v214_selector_execution import CONTEXT, PACKET0, Machine, put
from verify_arc1_v215_selector_execution import packet


ROOT = Path(__file__).resolve().parents[1]
SAVE_DIR = Path(r"C:\Users\Administrator\AppData\Local\DuckStation\savestates")
ACTUAL_PREFIX = "HASH-DA2823B0BBB822CA"
WORLD_FREEZE = SAVE_DIR / "HASH-831CF4578EDC3915_1.sav"
V215_ARCHIVE = ROOT / "03_output/arc1_v215_correct_packet_layout_selector_TEST_ONLY_716DA311.zip"
FRAME = 0x801FF668
OLD_FINISH = 0x801A2060
OLD_FINISH_N = 36

build = v216.build


def ram_at(address: int) -> int:
    return address & 0x1FFFFF


def selected(condition: int) -> tuple[int, int]:
    y = build.CACHE_B_Y if condition == 0 else build.CACHE_A_Y
    return y & 0xFF, y


def selector_to_frame(exe: bytes, memory: dict[int, int], a0: int,
                      limit: int = 100000) -> tuple[Machine, set[int]]:
    machine = Machine(exe, memory)
    machine.r[build.A0] = a0
    visited: set[int] = set()
    while machine.pc != FRAME and machine.steps < limit:
        visited.add(machine.pc)
        machine.step()
    if machine.pc != FRAME:
        raise SystemExit(f"selector did not reach frame: 0x{machine.pc:08X}")
    if any(OLD_FINISH <= address < OLD_FINISH + OLD_FINISH_N for address in visited):
        raise SystemExit("selector executed the game-owned old finish range")
    if v216.HANDOFF not in visited:
        raise SystemExit("selector did not execute the guarded overlap handoff")
    return machine, visited


def synthetic_case(exe: bytes, specs: list[dict[str, int]]) -> tuple[int, list[int]]:
    memory: dict[int, int] = {}
    addresses = [PACKET0 + i * 0x100 for i in range(len(specs))]
    put(memory, CONTEXT, struct.pack("<I", addresses[0] & 0xFFFFFF))
    for index, spec in enumerate(specs):
        link = addresses[index + 1] & 0xFFFFFF if index + 1 < len(specs) else 0
        put(memory, addresses[index], packet(link, **spec))
    machine, _visited = selector_to_frame(exe, memory, CONTEXT)
    vs = [machine.load(address + 13, 1) for address in addresses]
    return selected(machine.r[build.A1])[0], vs


def run_synthetic(exe: bytes) -> None:
    tpage = {"count": 1, "cmd": 0xE1, "tpage": 31}
    font_a = {
        "count": 4, "cmd": 0x65, "u": 4, "v": 224,
        "clut": build.v171.v166.FONT_CLUT_MIN, "width": 12, "height": 12,
    }
    font_b = dict(font_a, v=128)
    marker = dict(font_a, v=v216.parent.MARKER_V)
    game_a = dict(font_a, u=0, v=160, clut=0x79C0, width=128, height=96)
    game_b = dict(font_a, v=128, clut=0x0010)
    wrong_width = dict(font_a, width=13)
    wrong_height = dict(font_a, height=13)
    both = dict(font_a, u=0, v=120, clut=0x79C0, width=128, height=128)
    cases = [
        ("real 12x12 A", [tpage, font_a], (224, [0, 255])),
        ("real 12x12 B", [tpage, font_b], (224, [0, 255])),
        ("persistent marker", [tpage, marker], (224, [0, 255])),
        ("A conflict chooses B", [tpage, font_a, game_a], (128, [0, 255, 160])),
        ("B conflict chooses A", [tpage, game_b, font_a], (224, [0, 128, 255])),
        ("simultaneous fallback A", [tpage, both, font_a], (224, [0, 120, 255])),
        ("wrong width unmarked", [tpage, wrong_width], (128, [0, 224])),
        ("wrong height unmarked", [tpage, wrong_height], (128, [0, 224])),
    ]
    for name, specs, expected in cases:
        actual = synthetic_case(exe, specs)
        if actual != expected:
            raise SystemExit(f"{name}: expected {expected}, got {actual}")
        print(f"PASS synthetic {name}: {actual}")


def configure_runtime() -> None:
    runtime.CACHE_SLOTS = 28
    runtime.CACHE_CELLS = 7
    runtime.CACHE_U = (4, 16, 28, 40, 52, 64, 76)
    runtime.CACHE_U_END = 88
    runtime.CACHE_V = 224
    runtime.CACHE_V_END = 236


def state_rows(ram: bytes) -> tuple[int, list[dict[str, object]]]:
    context, _parity, rows = runtime.trace_active_text_ot(ram)
    return 0x80000000 | (ram_at(context) + 0x70), rows


def selector_memory(ram: bytes, a0: int,
                    rows: list[dict[str, object]]) -> tuple[dict[int, int], list[int]]:
    memory: dict[int, int] = {}
    put(memory, a0, ram[ram_at(a0):ram_at(a0) + 4])
    addresses: list[int] = []
    for row in rows:
        address = int(row["address"])
        addresses.append(address)
        put(memory, address, ram[ram_at(address):ram_at(address) + 52])
    return memory, addresses


def slot_number(path: Path) -> int:
    return int(path.stem.rsplit("_", 1)[1])


def run_actual_ot_and_frame(exe: bytes) -> None:
    states = sorted(
        (path for path in SAVE_DIR.glob(f"{ACTUAL_PREFIX}_*.sav")
         if path.stem.rsplit("_", 1)[-1].isdigit()),
        key=slot_number,
    )
    if not states:
        raise SystemExit("v214/v215 actual-OT regression states are missing")

    layout, _blobs, _code = build.v190.resident_layout()
    resident_source = old_source = build.old.file_at(build.v171.SOURCE_BASE)
    resident_blob = exe[resident_source:resident_source + build.v171.COPY_N]
    active_at = layout["active_mask"][0]
    rect_at = layout["upload_rect"][0]
    checkpoint_n = ((build.v190.plan.SOURCE_N + build.v190.plan.CHECKPOINT_GROUP - 1)
                    // build.v190.plan.CHECKPOINT_GROUP) * 2

    for state in states:
        ram, _vram = load(state)
        a0, rows = state_rows(ram)
        memory, addresses = selector_memory(ram, a0, rows)
        selector_cpu, _visited = selector_to_frame(exe, memory, a0)
        condition = selector_cpu.r[build.A1]
        selected_v, selected_y = selected(condition)

        cache_addresses = [int(row["address"]) for row in rows if row["text_cache"]]
        marked = {
            address for address in addresses
            if selector_cpu.load(address + 13, 1) == v216.parent.MARKER_V
        }
        if marked != set(cache_addresses):
            raise SystemExit(f"slot{slot_number(state)} marker coverage differs")

        expected_mask = 0
        for row in rows:
            if row["text_cache"]:
                expected_mask |= 1 << int(row["slot"])

        frame_memory = cpu_tools.Memory()
        frame_memory.write(build.v171.RESIDENT_BASE, resident_blob)
        frame_memory.write(
            build.v171.HUFFMAN_CHECKPOINTS_RAM,
            ram[ram_at(build.v171.HUFFMAN_CHECKPOINTS_RAM):
                ram_at(build.v171.HUFFMAN_CHECKPOINTS_RAM) + checkpoint_n],
        )
        frame_memory.write(
            layout["owners"][0],
            ram[ram_at(layout["owners"][0]):ram_at(layout["owners"][0]) + 56],
        )
        frame_memory.store32(active_at, 0)
        frame_memory.write(a0, bytes(selector_cpu.load(a0 + i, 1) for i in range(4)))
        for address in addresses:
            frame_memory.write(
                address, bytes(selector_cpu.load(address + i, 1) for i in range(52))
            )
        frame_memory.write(cpu_tools.STACK_TOP - 0x200, bytes(0x400))

        frame_cpu = cpu_tools.R3000(frame_memory, FRAME)
        frame_cpu.reg[build.SP] = cpu_tools.STACK_TOP
        frame_cpu.reg[build.RA] = cpu_tools.SENTINEL
        frame_cpu.reg[build.A0] = a0
        frame_cpu.reg[build.A1] = condition
        frame_cpu.run()

        actual_mask = frame_memory.load32(active_at)
        wrong_v = [address for address in cache_addresses
                   if frame_memory.load8(address + 13) != selected_v]
        actual_y = frame_memory.load16(rect_at + 2)
        draws = [call for call in frame_cpu.calls if call.target == build.old.DRAWOT]
        print(
            f"PASS actual slot{slot_number(state)}: cache={len(cache_addresses)} "
            f"V={selected_v} Y={actual_y} mask=0x{actual_mask:08X} "
            f"DrawOT={len(draws)}"
        )
        if (actual_mask != expected_mask or wrong_v or actual_y != selected_y
                or len(draws) != 1):
            raise SystemExit(f"slot{slot_number(state)} selector/frame handoff differs")


def run_worldmap_regression(exe: bytes, base_exe: bytes) -> None:
    if not WORLD_FREEZE.exists() or not V215_ARCHIVE.exists():
        raise SystemExit("v215 world-map freeze fixture is missing")
    ram, _vram = load(WORLD_FREEZE)
    with ZipFile(V215_ARCHIVE) as archive:
        v215_exe = archive.read(build.PSX)

    entry_at = build.ENTRY - 0x8011A800
    classify_at = build.CLASSIFY - 0x8011A800
    if ram[ram_at(build.ENTRY):ram_at(build.ENTRY) + build.ENTRY_N] != \
            v215_exe[entry_at:entry_at + build.ENTRY_N]:
        raise SystemExit("freeze state does not contain the v215 selector entry")
    if ram[ram_at(build.CLASSIFY):ram_at(build.CLASSIFY) + build.CLASSIFY_N] != \
            v215_exe[classify_at:classify_at + build.CLASSIFY_N]:
        raise SystemExit("freeze state does not contain the v215 classifier")

    finish_at = build.FINISH - 0x8011A800
    v215_finish = v215_exe[finish_at:finish_at + OLD_FINISH_N]
    runtime_finish = ram[ram_at(build.FINISH):ram_at(build.FINISH) + OLD_FINISH_N]
    if runtime_finish[:20] != v215_finish[:20] or runtime_finish[20:] == v215_finish[20:]:
        raise SystemExit("freeze fixture no longer proves the v215 finish overwrite boundary")
    if exe[finish_at:finish_at + OLD_FINISH_N] != \
            base_exe[finish_at:finish_at + OLD_FINISH_N]:
        raise SystemExit("v216 changed the game-owned old finish range")

    a0, rows = state_rows(ram)
    memory, addresses = selector_memory(ram, a0, rows)
    before = {
        address: bytes(memory.get(address + i, 0) for i in range(52))
        for address in addresses
    }
    selector_cpu, visited = selector_to_frame(exe, memory, a0)
    after = {
        address: bytes(selector_cpu.load(address + i, 1) for i in range(52))
        for address in addresses
    }
    changed = [address for address in addresses if before[address] != after[address]]
    selected_v, _selected_y = selected(selector_cpu.r[build.A1])
    if changed or selected_v != build.CACHE_B_V:
        raise SystemExit(
            f"world-map selector differs: changed={len(changed)} selected_V={selected_v}"
        )
    if any(OLD_FINISH <= address < OLD_FINISH + OLD_FINISH_N for address in visited):
        raise SystemExit("world-map selector visited old finish")
    print(
        f"PASS world-map freeze regression: packets={len(addresses)} "
        f"changed=0 selected_V={selected_v} old_finish_visited=0"
    )


def main() -> None:
    archives = sorted((ROOT / "03_output").glob(
        "arc1_v216_relocate_selector_handoff_TEST_ONLY_????????.zip"
    ))
    if len(archives) != 1:
        raise SystemExit(f"expected one v216 archive, found {archives}")
    with ZipFile(archives[0]) as archive:
        exe = archive.read(build.PSX)
    with ZipFile(build.BASE) as archive:
        base_exe = archive.read(build.PSX)

    configure_runtime()
    run_synthetic(exe)
    run_actual_ot_and_frame(exe)
    run_worldmap_regression(exe, base_exe)
    print(f"archive={archives[0].name}")
    print("v216_runtime_regressions=PASS")


if __name__ == "__main__":
    main()
