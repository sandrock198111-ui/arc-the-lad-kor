#!/usr/bin/env python3
"""Build the D941 16px dialogue PoC with its code and table relocated.

This is a single-variable integration prerequisite.  It imports the accepted
D941 builder and changes only executable ownership:

* wrapper: ``0x8018FCD0`` -> ``0x801A2074``;
* coordinate table: ``0x801A7460`` -> ``0x801A2138``.

The 196-byte wrapper and 62-byte table are contiguous inside the pristine
656-byte zero run ``0x801A2074..0x801A2304``.  The old wrapper cave becomes
available for E2 lookup/completion, and the v0.41/v42 UI cave becomes entirely
available for later UI reconstruction.  Font pixels, diagnostic text, logical
codes, packet dimensions and advances are produced by the D941 builder without
forking its implementation.

The one apparent branch into the candidate run comes from data word
``0x1E1E1E1E`` in a monotonic table at ``0x8019A978``.  Its exact source, word
and calculated target are pinned; every other incoming edge fails the build.
"""
from __future__ import annotations

from pathlib import Path

import build_arc1_johab_font_16px_poc as build


ROOT = Path(__file__).resolve().parents[1]

build.ANALYSIS_DIR = ROOT / "01_work/analysis/johab_font_16px_relocated_poc"
build.OUTPUT_STEM = "arc1_johab_font_16px_relocated_pilgi_TEST_ONLY"

build.WRAPPER_ADDRESS = 0x801A2074
build.WRAPPER_CAVE_END = 0x801A2304
build.COORD_TABLE_ADDRESS = 0x801A2138
build.COORD_TABLE_CAPACITY = 128

build.KNOWN_WRAPPER_DATA_EDGES = (
    (0x8019A978, 0x801A21F4, "branch-op7", 0x1E1E1E1E),
)
build.KNOWN_TABLE_DATA_EDGES = ()


if __name__ == "__main__":
    build.main()
