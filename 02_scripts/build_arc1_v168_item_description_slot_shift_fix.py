"""Build v168: correct the v167 item-description slot-bit shift.

v167 calculated each cache slot correctly, but shifted the validity bit by
itself instead of by that slot.  This wrapper preserves the frozen v167 build
logic and replaces exactly that one MIPS instruction before producing a new,
uniquely named archive.
"""
from __future__ import annotations

import struct
from pathlib import Path

import build_arc1_v165_failclosed_cache as old
import build_arc1_v167_item_description_generation_guard as v167


ROOT = Path(__file__).resolve().parents[1]
BASE = v167.BASE
BASE_SHA256 = v167.BASE_SHA256
OUT_STEM = "arc1_v168_item_description_slot_shift_fix"
ANALYSIS = ROOT / "01_work/analysis/arc1_v168_item_description_slot_shift_fix"
REPORT = ANALYSIS / "build_report.txt"
DISASSEMBLY = ANALYSIS / "resident_disassembly.txt"
LAYOUT_CSV = ANALYSIS / "resident_layout.csv"
CHECKPOINT_GROUP = v167.CHECKPOINT_GROUP
ITEM_DESCRIPTION_HEADER = v167.ITEM_DESCRIPTION_HEADER
OT_WALK_LIMIT = v167.OT_WALK_LIMIT
FONT_CLUT_MIN = v167.FONT_CLUT_MIN
pack_layout = v167.pack_layout
build_frame = v167.build_frame

_v167_build_item_guard = v167.build_item_guard


def build_item_guard(address: int) -> bytes:
    blob = _v167_build_item_guard(address)
    wrong = struct.pack(
        "<I", old.r_type(old.T0, old.T0, old.T0, 0, 0x04)
    )
    fixed = struct.pack(
        "<I", old.r_type(old.T3, old.T0, old.T0, 0, 0x04)
    )
    if blob.count(wrong) != 1:
        raise SystemExit("v167 item-guard shift instruction is not unique")
    return blob.replace(wrong, fixed, 1)


def main() -> None:
    v167.OUT_STEM = OUT_STEM
    v167.ANALYSIS = ANALYSIS
    v167.REPORT = REPORT
    v167.DISASSEMBLY = DISASSEMBLY
    v167.LAYOUT_CSV = LAYOUT_CSV
    v167.build_item_guard = build_item_guard
    v167.main()

    report = REPORT.read_text(encoding="utf-8")
    report = report.replace(
        "v167 item-description generation guard",
        "v168 item-description slot-shift fix",
        1,
    )
    report += "v167_slot_shift_bug=fixed (sllv shift register T0 -> T3)\n"
    REPORT.write_text(report, encoding="utf-8")


if __name__ == "__main__":
    main()
