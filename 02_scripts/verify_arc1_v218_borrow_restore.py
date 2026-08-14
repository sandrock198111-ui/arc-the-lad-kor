#!/usr/bin/env python3
"""Independent MIPS/runtime-fixture checks for the v218 borrow/restore frame."""
from __future__ import annotations

import struct
from pathlib import Path
from zipfile import ZipFile

import analyze_arc1_v214_runtime as ownership
import build_arc1_v190_dynamic_owner_repair as v190
import build_arc1_v218_borrow_restore_selected_cache as v218
import verify_arc1_v165c_failclosed_cache as cpu_tools
import verify_arc1_v216_runtime_regressions as v216_tests
from extract_savestate_vram import load
from verify_arc1_v214_selector_execution import CONTEXT, PACKET0, put
from verify_arc1_v215_selector_execution import packet


ROOT = Path(__file__).resolve().parents[1]
SAVE_DIR = Path(r"C:\Users\Administrator\AppData\Local\DuckStation\savestates")
LATEST_PREFIX = "HASH-101175C83D552C3"
BACKUP_PATTERN = bytes((index * 37 + 11) & 0xFF for index in range(v218.BACKUP_BYTES))


def ram_at(address: int) -> int:
    return address & 0x1FFFFF


def slot_number(path: Path) -> int:
    return int(path.stem.rsplit("_", 1)[1])


def output_zip() -> Path:
    matches = sorted((ROOT / "03_output").glob(f"{v218.OUT_STEM}_????????.zip"))
    if len(matches) != 1:
        raise SystemExit(f"expected one v218 archive, found: {matches}")
    return matches[0]


class BorrowCPU(cpu_tools.R3000):
    """Model the two extra library calls and deterministic VRAM readback."""

    def external(self) -> bool:
        if self.pc not in (v218.STOREIMAGE, v218.GPU_SYNC):
            return super().external()
        if self.pending_load is not None or self.pending_branch is not None:
            raise RuntimeError("v218 external reached with a pending CPU delay")
        if self.pc == v218.STOREIMAGE:
            rect = struct.unpack("<4H", self.memory.read(self.reg[v218.A0], 8))
            size = rect[2] * rect[3] * 2
            if size != v218.BACKUP_BYTES:
                raise RuntimeError(f"StoreImage size differs: {rect}")
            self.memory.write(self.reg[v218.A1], BACKUP_PATTERN)
            self.calls.append(cpu_tools.ExternalCall(
                self.pc, self.reg[v218.A0], self.reg[v218.A1], rect, BACKUP_PATTERN
            ))
        else:
            self.calls.append(cpu_tools.ExternalCall(
                self.pc, self.reg[v218.A0], self.reg[v218.A1]
            ))
        self.pc = self.reg[v218.RA]
        return False


def resident_memory(exe: bytes, ram: bytes, a0: int,
                    selector_cpu: object, addresses: list[int], active: int,
                    layout: dict[str, tuple[int, int]]) -> cpu_tools.Memory:
    source_at = v218.old.file_at(v218.build.v171.SOURCE_BASE)
    resident = exe[source_at:source_at + v218.build.v171.COPY_N]
    memory = cpu_tools.Memory()
    memory.write(v218.build.v171.RESIDENT_BASE, resident)

    checkpoint_n = (
        (v190.plan.SOURCE_N + v190.plan.CHECKPOINT_GROUP - 1)
        // v190.plan.CHECKPOINT_GROUP
    ) * 2
    checkpoints = v218.build.v171.HUFFMAN_CHECKPOINTS_RAM
    memory.write(
        checkpoints,
        ram[ram_at(checkpoints):ram_at(checkpoints) + checkpoint_n],
    )
    owners_at, owners_n = layout["owners"]
    memory.write(owners_at, ram[ram_at(owners_at):ram_at(owners_at) + owners_n])
    memory.store32(layout["active_mask"][0], active)
    memory.write(a0, bytes(selector_cpu.load(a0 + offset, 1) for offset in range(4)))
    for address in addresses:
        memory.write(
            address,
            bytes(selector_cpu.load(address + offset, 1) for offset in range(52)),
        )
    memory.write(cpu_tools.STACK_TOP - 0x400, bytes(0x800))
    return memory


def run_frame(exe: bytes, memory: cpu_tools.Memory, a0: int,
              condition: int) -> BorrowCPU:
    cpu = BorrowCPU(memory, v218.FRAME)
    cpu.reg[v218.SP] = cpu_tools.STACK_TOP
    cpu.reg[v218.RA] = cpu_tools.SENTINEL
    cpu.reg[v218.A0] = a0
    cpu.reg[v218.A1] = condition
    preserved: dict[int, int] = {}
    for register in range(v218.S0, v218.S7 + 1):
        value = 0x51510000 + register
        cpu.reg[register] = value
        preserved[register] = value
    cpu.run()
    if cpu.reg[v218.SP] != cpu_tools.STACK_TOP:
        raise SystemExit("v218 did not restore SP")
    for register, value in preserved.items():
        if cpu.reg[register] != value:
            raise SystemExit(f"v218 did not preserve r{register}")
    return cpu


def synthetic_active(exe: bytes, ram: bytes,
                     layout: dict[str, tuple[int, int]]) -> None:
    specs = [
        {"count": 1, "cmd": 0xE1, "tpage": 31},
        {
            "count": 4, "cmd": 0x65, "u": 4, "v": 224,
            "clut": v218.build.v171.v166.FONT_CLUT_MIN,
            "width": 12, "height": 12,
        },
        {
            "count": 4, "cmd": 0x65, "u": 0, "v": 160,
            "clut": 0x79C0, "width": 128, "height": 96,
        },
    ]
    addresses = [PACKET0 + index * 0x100 for index in range(len(specs))]
    selector_memory: dict[int, int] = {}
    put(selector_memory, CONTEXT, struct.pack("<I", addresses[0] & 0xFFFFFF))
    for index, spec in enumerate(specs):
        link = addresses[index + 1] & 0xFFFFFF if index + 1 < len(specs) else 0
        put(selector_memory, addresses[index], packet(link, **spec))
    selector_cpu, _visited = v216_tests.selector_to_frame(exe, selector_memory, CONTEXT)
    condition = selector_cpu.r[v218.build.A1]
    selected_v, selected_y = v216_tests.selected(condition)
    if (selected_v, selected_y) != (128, 384):
        raise SystemExit("synthetic A conflict did not select B")

    memory = resident_memory(
        exe, ram, CONTEXT, selector_cpu, addresses, 0xFFFFFFFF, layout
    )
    cpu = run_frame(exe, memory, CONTEXT, condition)
    targets = [call.target for call in cpu.calls]
    expected = (
        [v218.STOREIMAGE, v218.GPU_SYNC]
        + [v218.old.LOADIMAGE] * 7
        + [v218.old.DRAWOT, v218.GPU_SYNC, v218.old.LOADIMAGE]
    )
    if targets != expected:
        raise SystemExit(f"v218 active call order differs: {[hex(x) for x in targets]}")

    store = cpu.calls[0]
    restore = cpu.calls[-1]
    full_rect = (v218.build.v171.CACHE_X, selected_y, 21, v218.old.CELL)
    if store.rect != full_rect or restore.rect != full_rect:
        raise SystemExit(f"v218 borrow/restore rectangle differs: {store.rect}/{restore.rect}")
    if restore.payload != BACKUP_PATTERN or restore.a1 != store.a1:
        raise SystemExit("v218 did not restore the exact StoreImage payload")

    cache_uploads = cpu.calls[2:9]
    if [call.rect for call in cache_uploads] != [
        (v218.build.v171.CACHE_X + cell * 3, selected_y, 3, v218.old.CELL)
        for cell in range(7)
    ]:
        raise SystemExit("v218 seven cache upload rectangles differ")
    if memory.load8(addresses[1] + 13) != selected_v:
        raise SystemExit("v218 did not rewrite the strict marker to selected V")
    if memory.load32(layout["active_mask"][0]) != 0xFFFFFFFF:
        raise SystemExit("v218 persistent marker did not retain full next-frame mask")
    print("PASS synthetic active: borrow B -> 7 uploads -> DrawOT -> exact B restore")


def latest_inactive(exe: bytes, layout: dict[str, tuple[int, int]]) -> None:
    states = sorted(
        (path for path in SAVE_DIR.glob(f"{LATEST_PREFIX}_*.sav")
         if path.stem.rsplit("_", 1)[-1].isdigit()),
        key=slot_number,
    )
    if len(states) != 3:
        raise SystemExit(f"expected three latest v217 states, found: {states}")
    for state in states:
        ram, _vram = load(state)
        a0, rows = v216_tests.state_rows(ram)
        selector_memory, addresses = v216_tests.selector_memory(ram, a0, rows)
        selector_cpu, _visited = v216_tests.selector_to_frame(exe, selector_memory, a0)
        marked_before = sum(
            selector_cpu.load(address + 13, 1) == v218.v216.parent.MARKER_V
            for address in addresses
        )
        condition = selector_cpu.r[v218.build.A1]
        memory = resident_memory(exe, ram, a0, selector_cpu, addresses, 0, layout)
        cpu = run_frame(exe, memory, a0, condition)
        targets = [call.target for call in cpu.calls]
        if targets != [v218.old.DRAWOT]:
            raise SystemExit(
                f"slot{slot_number(state)} inactive path touched VRAM: "
                f"{[hex(target) for target in targets]}"
            )
        expected_next = 0xFFFFFFFF if marked_before else 0
        actual_next = memory.load32(layout["active_mask"][0])
        if actual_next != expected_next:
            raise SystemExit(
                f"slot{slot_number(state)} next mask {actual_next:#010x}, "
                f"expected {expected_next:#010x} from {marked_before} marker(s)"
            )
        selected_v, selected_y = v216_tests.selected(condition)
        print(
            f"PASS latest slot{slot_number(state)}: inactive DrawOT-only "
            f"selected_V={selected_v} selected_Y={selected_y} "
            f"markers={marked_before} next_mask={actual_next:#010x}"
        )


def main() -> None:
    archive = output_zip()
    with ZipFile(archive) as handle:
        exe = handle.read(v218.build.PSX)
    with ZipFile(v218.build.BASE) as handle:
        base_exe = handle.read(v218.build.PSX)

    v216_tests.configure_runtime()
    v216_tests.run_synthetic(exe)
    v216_tests.run_worldmap_regression(exe, base_exe)
    layout, _blobs, _code = v190.resident_layout()
    fixture = SAVE_DIR / f"{LATEST_PREFIX}_1.sav"
    ram, _vram = load(fixture)
    synthetic_active(exe, ram, layout)
    latest_inactive(exe, layout)
    print(f"archive={archive.name}")
    print("v218_borrow_restore_regressions=PASS")


if __name__ == "__main__":
    main()
