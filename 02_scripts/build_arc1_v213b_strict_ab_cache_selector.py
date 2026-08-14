"""Run the v213 strict selector with its bgez assembly-site address supplied.

The parent builder's generic branch helper requires both current PC and target;
one bgez call omitted the PC.  This wrapper supplies the known classifier PC,
uses a new output stem, and otherwise executes the guarded v210-direct build.
"""
from __future__ import annotations

from pathlib import Path

import build_arc1_v213_strict_ab_cache_selector as build


original_branch = build.branch


def branch_with_bgez_pc(*args: int) -> int:
    if len(args) == 4:
        op, rs, rt, target = args
        return original_branch(op, rs, rt, build.CLASSIFY + 15 * 4, target)
    return original_branch(*args)


build.branch = branch_with_bgez_pc
build.OUT_STEM = "arc1_v213b_strict_ab_cache_selector_TEST_ONLY"
build.ANALYSIS = build.ROOT / "01_work/analysis" / build.OUT_STEM
build.REPORT = build.ANALYSIS / "build_report.txt"
build.DISASSEMBLY = build.ANALYSIS / "mips_disassembly.txt"


if __name__ == "__main__":
    build.main()
