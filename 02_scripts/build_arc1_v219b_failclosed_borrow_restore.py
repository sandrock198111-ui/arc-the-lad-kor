#!/usr/bin/env python3
"""Reproducibly emit the verified v219 payload under a unique v219b name.

The v219 ZIP was created before its independent interpreter learned the MIPS
NOR instruction, so it was not reused in place.  v219b has byte-identical game
content and a distinct artifact name; this wrapper preserves both histories.
"""
from __future__ import annotations

import build_arc1_v219_failclosed_borrow_restore as base


OUT_STEM = "arc1_v219b_failclosed_borrow_restore_TEST_ONLY"


def main() -> None:
    base.OUT_STEM = OUT_STEM
    base.main()
    report = base.build.REPORT
    text = report.read_text(encoding="utf-8")
    if text.startswith("v219 TEST ONLY"):
        text = "v219b TEST ONLY" + text[len("v219 TEST ONLY"):]
        report.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
