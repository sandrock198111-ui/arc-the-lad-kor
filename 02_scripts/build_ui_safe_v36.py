#!/usr/bin/env python3
"""Build v0.36 by retaining v34 font data and repairing v35 acquisition text."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_ui_safe_v35 as base  # noqa: E402


OUTPUT = ROOT / "03_output" / "ui_safe_v36_cumulative_patch_only.zip"
MANIFEST = ROOT / "05_docs" / "ui_safe_v36.csv"
SKILL_REFERENCE = ROOT / "05_docs" / "ui_skill_guide_reference_v36.csv"
SYSTEM_MANIFEST = ROOT / "05_docs" / "ui_system_v36.csv"
BATTLE_MANIFEST = ROOT / "05_docs" / "ui_battle_choice_v36.csv"
WORLD_MANIFEST = ROOT / "05_docs" / "ui_world_name_v36.csv"
REVIEW_CSV = ROOT / "05_docs" / "ui_items_equipment_skills_v36_review.csv"
NONSTORY_MANIFEST = ROOT / "05_docs" / "ui_nonstory_system_v36.csv"
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_safe_v36"
REPORT = ANALYSIS / "build_report.txt"
READBACK = ANALYSIS / "readback.csv"
LOW_CODE_AUDIT = ANALYSIS / "low_6c_story_audit.csv"
PREVIEW = ANALYSIS / "lv_label_before_after.pbm"
TUTORIAL_AUDIT = ANALYSIS / "tutorial_e2_audit.csv"
SYSTEM_AUDIT = ANALYSIS / "system_text_audit.csv"
BATTLE_AUDIT = ANALYSIS / "battle_choice_audit.csv"


def preserve_v34_lv(_font: bytearray) -> tuple[int, int]:
    """Keep the runtime-accepted v34 compact LV plane byte-identical."""
    return 0, 0


def configure() -> None:
    for name, value in {
        "OUTPUT": OUTPUT,
        "MANIFEST": MANIFEST,
        "SKILL_REFERENCE": SKILL_REFERENCE,
        "SYSTEM_MANIFEST": SYSTEM_MANIFEST,
        "BATTLE_MANIFEST": BATTLE_MANIFEST,
        "WORLD_MANIFEST": WORLD_MANIFEST,
        "REVIEW_CSV": REVIEW_CSV,
        "NONSTORY_MANIFEST": NONSTORY_MANIFEST,
        "ANALYSIS": ANALYSIS,
        "REPORT": REPORT,
        "READBACK": READBACK,
        "LOW_CODE_AUDIT": LOW_CODE_AUDIT,
        "PREVIEW": PREVIEW,
        "TUTORIAL_AUDIT": TUTORIAL_AUDIT,
        "SYSTEM_AUDIT": SYSTEM_AUDIT,
        "BATTLE_AUDIT": BATTLE_AUDIT,
    }.items():
        setattr(base, name, value)

    # The item name is emitted separately. Avoid the broken opening-quote glyph
    # and produce, for example, "약초를 손에 넣었습니다." at runtime.
    base.SYSTEM_TRANSLATIONS[0x82474] = "를 손에 넣었습니다."
    base.patch_lv = preserve_v34_lv


def main() -> None:
    configure()
    base.main()

    report = REPORT.read_text(encoding="utf-8")
    report = report.replace(
        "UI safe v0.35 cumulative non-story bank repair",
        "UI safe v0.36 cumulative v35 regression repair",
    )
    report = report.replace("v35_", "v36_")
    report = report.replace(
        "v36_item_acquisition_suffix=」를 손에 넣었다.",
        "v36_item_acquisition_suffix=를 손에 넣었습니다.",
    )
    report += (
        "v36_font_source=v34_byte_identical\n"
        "v36_v35_thin_lv_patch_removed=true\n"
        "v36_button_icon_status=text_fallback_pending_glyph_relocation\n"
        "v36_deferred_level_wording=LV labels retained until safe glyph expansion\n"
    )
    report = report.replace(
        next(line for line in report.splitlines() if line.startswith("output_zip_sha256=")),
        f"output_zip_sha256={hashlib.sha256(OUTPUT.read_bytes()).hexdigest().upper()}",
    )
    REPORT.write_text(report, encoding="utf-8")
    print(report, end="")


if __name__ == "__main__":
    main()
