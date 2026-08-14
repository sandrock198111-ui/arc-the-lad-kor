#!/usr/bin/env python3
"""Read-only corpus audit for v219's paired transient cache marker.

The frame accepts a node only when its DMA count is four and its U/V bytes
sum to 255.  This script deliberately checks every node returned by the real
OT walk, including OTHER/link/control nodes; filtering to recognised GPU
primitives is what allowed v218's BIOS false positive to escape.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))

from analyze_arc1_v163_runtime import ram_at, trace_active_text_ot  # noqa: E402
from extract_savestate_vram import load  # noqa: E402


STATES = Path(r"C:\Users\Administrator\AppData\Local\DuckStation\savestates")
BIOS_FAILURE = STATES / "HASH-EB6915FE435E3501_1.sav"
BIOS_FALSE_NODE = 0x801AEA44
OUT_DIR = ROOT / "01_work/analysis/arc1_cache_marker_uv_complement"
CSV_OUT = OUT_DIR / "marker_candidates.csv"
REPORT = OUT_DIR / "report.txt"


def main() -> None:
    files = sorted(STATES.glob("*.sav"))
    if not files:
        raise SystemExit("no DuckStation save states found")

    candidates: list[dict[str, object]] = []
    failures: list[str] = []
    nodes = 0
    dma4 = 0
    bios_seen = 0
    bios_match = 0
    for index, path in enumerate(files, 1):
        try:
            ram, _vram = load(path)
            _context, _parity, rows = trace_active_text_ot(ram)
        except Exception as exc:
            failures.append(f"{path.name}: {type(exc).__name__}: {exc}")
            continue
        nodes += len(rows)
        for row in rows:
            address = int(row["address"])
            at = ram_at(address)
            count = int(row["dma_words"])
            u = ram[at + 12] if at + 13 < len(ram) else -1
            v = ram[at + 13] if at + 13 < len(ram) else -1
            if path == BIOS_FAILURE and address == BIOS_FALSE_NODE:
                bios_seen += 1
                bios_match += int(count == 4 and u + v == 0xFF)
            if count != 4:
                continue
            dma4 += 1
            if u + v != 0xFF:
                continue
            candidates.append({
                "state": path.name,
                "address": f"0x{address:08X}",
                "kind": row["kind"],
                "command": f"0x{int(row['command']):02X}",
                "dma_words": count,
                "u": u,
                "v": v,
            })
        if index % 50 == 0:
            print(f"scanned {index}/{len(files)}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fields = ["state", "address", "kind", "command", "dma_words", "u", "v"]
    with CSV_OUT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(candidates)

    lines = [
        f"savestates_total={len(files)}",
        f"savestates_decoded={len(files) - len(failures)}",
        f"savestates_failed={len(failures)}",
        f"ot_nodes_all_kinds={nodes}",
        f"ot_nodes_dma4={dma4}",
        f"existing_paired_marker_signature={len(candidates)}",
        f"bios_false_node_seen={bios_seen}",
        f"bios_false_node_signature={bios_match}",
        *[f"failure={item}" for item in failures],
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(CSV_OUT)


if __name__ == "__main__":
    main()
