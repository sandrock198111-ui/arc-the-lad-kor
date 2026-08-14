#!/usr/bin/env python3
"""Run the v219 regressions against the uniquely named v219b artifact."""
from __future__ import annotations

import build_arc1_v219_failclosed_borrow_restore as build
import verify_arc1_v219_failclosed_borrow_restore as verify


def main() -> None:
    build.OUT_STEM = "arc1_v219b_failclosed_borrow_restore_TEST_ONLY"
    verify.main()


if __name__ == "__main__":
    main()
