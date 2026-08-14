#!/usr/bin/env python3
"""Run the real-OT v214 selector audit with a production-sized step limit."""
from __future__ import annotations

import verify_arc1_v214_actual_ot_selector as audit


def long_run(machine: audit.Machine) -> None:
    frame = 0x801FF668
    while machine.pc != frame and machine.steps < 100000:
        machine.step()
    if machine.pc != frame:
        raise AssertionError(
            f"selector did not reach frame: pc=0x{machine.pc:08X} steps={machine.steps}"
        )


def main() -> None:
    audit.Machine.run = long_run
    audit.main()


if __name__ == "__main__":
    main()
