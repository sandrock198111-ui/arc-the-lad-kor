#!/usr/bin/env python3
"""Run v215 selector MIPS against the four copied v214 real OTs."""
from __future__ import annotations

import argparse
import struct
from pathlib import Path
from zipfile import ZipFile

import analyze_arc1_v163_runtime as runtime
import build_arc1_v215_correct_packet_layout_selector as v215
from extract_savestate_vram import load
from verify_arc1_v214_selector_execution import Machine, put


ROOT = Path(__file__).resolve().parents[1]
SAVE_DIR = Path(r"C:\Users\Administrator\AppData\Local\DuckStation\savestates")
DEFAULT_PREFIX = "HASH-DA2823B0BBB822CA"
FRAME = 0x801FF668


def ram_at(address: int) -> int:
    return address & 0x1FFFFF


def slot_number(path: Path) -> int:
    return int(path.stem.rsplit("_", 1)[1])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("prefix", nargs="?", default=DEFAULT_PREFIX)
    args = parser.parse_args()
    states = sorted(
        (path for path in SAVE_DIR.glob(f"{args.prefix}_*.sav")
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

    runtime.CACHE_SLOTS = 28
    runtime.CACHE_CELLS = 7
    runtime.CACHE_U = (4, 16, 28, 40, 52, 64, 76)
    runtime.CACHE_U_END = 88
    runtime.CACHE_V = 224
    runtime.CACHE_V_END = 236

    for state in states:
        ram, _vram = load(state)
        context, _parity, rows = runtime.trace_active_text_ot(ram)
        a0 = 0x80000000 | (ram_at(context) + 0x70)
        memory: dict[int, int] = {}
        put(memory, a0, ram[ram_at(a0):ram_at(a0) + 4])
        packet_addresses: list[int] = []
        cache_addresses: list[int] = []
        for row in rows:
            address = int(row["address"])
            packet_addresses.append(address)
            at = ram_at(address)
            put(memory, address, ram[at:at + 52])
            if row["text_cache"]:
                cache_addresses.append(address)

        machine = Machine(exe, memory)
        machine.r[v215.parent.build.A0] = a0
        while machine.pc != FRAME and machine.steps < 100000:
            machine.step()
        if machine.pc != FRAME:
            raise SystemExit(
                f"slot{slot_number(state)} selector did not reach frame: 0x{machine.pc:08X}"
            )
        marked = {
            address for address in packet_addresses
            if machine.load(address + 13, 1) == v215.parent.MARKER_V
        }
        marked_cache = set(cache_addresses) & marked
        false_positive = marked - set(cache_addresses)
        expected_mask = 0
        for row in rows:
            if row["text_cache"]:
                expected_mask |= 1 << int(row["slot"])
        print(
            f"slot{slot_number(state)}: cache_packets={len(cache_addresses)} "
            f"marked={len(marked_cache)} false_positive={len(false_positive)} "
            f"selected_V={machine.r[v215.parent.build.A1]} "
            f"expected_active=0x{expected_mask:08X} steps={machine.steps}"
        )
        if marked_cache != set(cache_addresses) or false_positive:
            raise SystemExit(f"slot{slot_number(state)} real OT marker coverage differs")
    print("v215_real_OT_marker_coverage=PASS")


if __name__ == "__main__":
    main()
