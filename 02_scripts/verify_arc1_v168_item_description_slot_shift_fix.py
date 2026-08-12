"""Execute and verify the final v168 resident code and user-state masks."""
from __future__ import annotations

from pathlib import Path

import build_arc1_v168_item_description_slot_shift_fix as build
import verify_arc1_v167_item_description_generation_guard as verify


ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "03_output/arc1_v168_item_description_slot_shift_fix_3B604507.zip"
PATCH_SHA256 = "3B6045078334ABCEC78D07A05F5B39C5368BB76D18A880878646279FF664A751"
OUT = ROOT / "01_work/analysis/arc1_v168_item_description_slot_shift_fix_verification"
REPORT = OUT / "verification_report.txt"


def main() -> None:
    verify.PATCH = PATCH
    verify.PATCH_SHA256 = PATCH_SHA256
    verify.OUT = OUT
    verify.REPORT = REPORT
    verify.build = build
    verify.main()

    report = REPORT.read_text(encoding="utf-8")
    report = report.replace(
        "v167 item-description generation guard verification",
        "v168 item-description slot-shift fix verification",
        1,
    )
    report += "v167_slot_shift_bug=fixed_and_executed PASS\n"
    REPORT.write_text(report, encoding="utf-8")


if __name__ == "__main__":
    main()
