#!/usr/bin/env python3
"""Re-audit COMM.IMG physical font cells against the FULL savestate set.

2026-08-15.  The 2026-08-09 audit (`audit_comm_physical_cell_safety.py`) used
289 states.  The static-promotion plan (05_docs/dynamic_cache_resolution_plan_
2026-08-15.md, section 3-2) needs the same per-cell text/nontext consumer
counts over every state available today, because promotion destinations must
be cells no non-text packet has ever been seen reading.

This script reuses the proven classifier verbatim (font tpage 0x005 mask,
SPRT kind, runtime font CLUT window) and only widens the sample.  It does not
decide anything; it writes counts for the planner to consume.

Cache-page states (v222..v229 experiments) are included on purpose: the cache
lives on page 15,1 while these cells live on the font page, so extra states
only add evidence.
"""
from __future__ import annotations

import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))

from analyze_arc1_v163_runtime import (  # noqa: E402
    FONT_CLUT_MAX, FONT_CLUT_MIN, RAM_SIZE, trace_active_text_ot,
)
from audit_comm_physical_cell_safety import (  # noqa: E402
    FONT_COLS, FONT_ROWS, is_font_tpage, touched_cells,
)
from extract_savestate_vram import inflate, locate_ram  # noqa: E402

STATES = Path.home() / "AppData/Local/DuckStation/savestates"
OUT = ROOT / "01_work/analysis/font_cell_audit_full"
OUT.mkdir(parents=True, exist_ok=True)


def main() -> None:
    text: Counter[tuple[int, int]] = Counter()
    nontext: Counter[tuple[int, int]] = Counter()
    nontext_states: dict[tuple[int, int], set[str]] = defaultdict(set)
    read = 0
    failures: list[str] = []
    paths = sorted(STATES.glob("*.sav"))
    for number, path in enumerate(paths, 1):
        try:
            blob = inflate(path)
            ram_base = locate_ram(blob)
            ram = blob[ram_base:ram_base + RAM_SIZE]
            _context, _parity, packets = trace_active_text_ot(ram)
        except BaseException as exc:  # noqa: BLE001 - keep scanning
            failures.append(f"{path.name}: {exc}")
            continue
        read += 1
        for packet in packets:
            if not is_font_tpage(packet.get("tpage")):
                continue
            try:
                u = int(packet["u"])
                v = int(packet["v"])
                width = int(packet["width"])
                height = int(packet["height"])
            except (KeyError, TypeError, ValueError):
                continue
            cells = touched_cells(u, v, width, height)
            if not cells:
                continue
            clut = packet.get("clut")
            looks_text = (
                packet.get("kind") in ("SPRT", "SPRT_8", "SPRT_16")
                and isinstance(clut, int)
                and FONT_CLUT_MIN <= clut <= FONT_CLUT_MAX
            )
            bucket = text if looks_text else nontext
            for cell in cells:
                bucket[cell] += 1
                if not looks_text:
                    nontext_states[cell].add(path.name)
        if number % 40 == 0:
            print(f"  consumer scan {number}/{len(paths)}", flush=True)

    with (OUT / "cell_consumers.csv").open("w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["row", "col", "text_reads", "nontext_reads", "nontext_state_count"])
        for row in range(FONT_ROWS):
            for col in range(FONT_COLS):
                cell = (row, col)
                w.writerow([row, col, text[cell], nontext[cell],
                            len(nontext_states[cell])])
    with (OUT / "nontext_states.csv").open("w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["row", "col", "state"])
        for (row, col), states in sorted(nontext_states.items()):
            for state in sorted(states):
                w.writerow([row, col, state])
    clean = sum(
        1
        for row in range(FONT_ROWS)
        for col in range(FONT_COLS)
        if nontext[(row, col)] == 0
    )
    report = [
        f"states_read={read}",
        f"states_failed={len(failures)}",
        f"cells_with_nontext_reads={sum(1 for c in nontext.values() if c)}",
        f"cells_without_nontext_reads={clean}",
    ]
    (OUT / "report.txt").write_text("\n".join(report + failures) + "\n", encoding="utf-8")
    print("\n".join(report))
    print(f"out={OUT}")


if __name__ == "__main__":
    main()
