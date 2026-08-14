#!/usr/bin/env python3
"""Execute the archived v214 selector against a copied real save-state OT.

The save state is read-only.  OT packets are copied into the tiny instruction
emulator used by the synthetic selector tests, then execution stops exactly at
the resident frame entry so the transient V=255 markers can be counted.
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import analyze_arc1_v163_runtime as runtime  # noqa: E402
import build_arc1_v214_marked_ab_cache_selector as v214  # noqa: E402
from extract_savestate_vram import load  # noqa: E402
from verify_arc1_v214_selector_execution import Machine, put  # noqa: E402


SAVE_DIR = Path(r"C:\Users\Administrator\AppData\Local\DuckStation\savestates")
DEFAULT_PREFIX = "HASH-DA2823B0BBB822CA"


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
        "arc1_v214_marked_ab_cache_selector_TEST_ONLY_????????.zip"
    ))
    if len(archives) != 1:
        raise SystemExit(f"expected one v214 archive, found {archives}")
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
        before_v: dict[int, int] = {}
        for row in rows:
            address = int(row["address"])
            packet_addresses.append(address)
            at = ram_at(address)
            put(memory, address, ram[at:at + 52])
            before_v[address] = ram[at + 13]
            if row["text_cache"]:
                cache_addresses.append(address)

        machine = Machine(exe, memory)
        machine.r[v214.build.A0] = a0
        machine.run()
        marked = [address for address in packet_addresses
                  if machine.load(address + 13, 1) == v214.MARKER_V]
        marked_cache = [address for address in cache_addresses
                        if machine.load(address + 13, 1) == v214.MARKER_V]
        changed_noncache = [
            address for address in marked if address not in set(cache_addresses)
        ]
        print(
            f"slot{slot_number(state)}: packets={len(packet_addresses)} "
            f"cache={len(cache_addresses)} marked={len(marked)} "
            f"marked_cache={len(marked_cache)} noncache={len(changed_noncache)} "
            f"selected_V={machine.r[v214.build.A1]} steps={machine.steps}"
        )
        if len(marked_cache) != len(cache_addresses) or changed_noncache:
            print("  missed=" + ",".join(
                f"0x{address:08X}:V{before_v[address]}"
                for address in cache_addresses if address not in marked_cache
            ))
            print("  false_positive=" + ",".join(
                f"0x{address:08X}:V{before_v[address]}" for address in changed_noncache
            ))


if __name__ == "__main__":
    main()
