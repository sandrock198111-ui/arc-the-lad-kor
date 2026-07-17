#!/usr/bin/env python3
"""Build v0.34 with confirmation spacing and compact-LV presentation repairs."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_ui_safe_v33 as base  # noqa: E402


OUTPUT = ROOT / "03_output" / "ui_safe_v34_cumulative_patch_only.zip"
MANIFEST = ROOT / "05_docs" / "ui_safe_v34.csv"
SKILL_REFERENCE = ROOT / "05_docs" / "ui_skill_guide_reference_v34.csv"
SYSTEM_MANIFEST = ROOT / "05_docs" / "ui_system_v34.csv"
BATTLE_MANIFEST = ROOT / "05_docs" / "ui_battle_choice_v34.csv"
WORLD_MANIFEST = ROOT / "05_docs" / "ui_world_name_v34.csv"
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_safe_v34"
REPORT = ANALYSIS / "build_report.txt"
READBACK = ANALYSIS / "readback.csv"
LOW_CODE_AUDIT = ANALYSIS / "low_6c_story_audit.csv"
PREVIEW = ANALYSIS / "lv_label_before_after.pbm"
TUTORIAL_AUDIT = ANALYSIS / "tutorial_e2_audit.csv"
SYSTEM_AUDIT = ANALYSIS / "system_text_audit.csv"
BATTLE_AUDIT = ANALYSIS / "battle_choice_audit.csv"


HELP_TEXTS = tuple(
    (pointer, source, "결정 : 돌아가기" if pointer == 0x8235C else text)
    for pointer, source, text in base.HELP_TEXTS
)
HELP_POINTERS = {pointer for pointer, _source, _text in HELP_TEXTS}
SYSTEM_TEXTS = tuple(
    entry
    for entry in base.SYSTEM_TEXTS
    if entry[0] not in HELP_POINTERS and entry[0] != 0x82AC0
) + HELP_TEXTS + (
    (0x82AC0, 0x82A88, "예      아니요"),
)
RELOCATED_TEXTS = SYSTEM_TEXTS + base.WORLD_TEXTS + base.UI_FIXES


def label_bitmap() -> set[tuple[int, int]]:
    """Bold L and pointed V that remain distinct inside one 12-pixel cell."""
    rows = (
        "............",
        "............",
        ".##...#...#.",
        ".##...#...#.",
        ".##...#...#.",
        ".##...#...#.",
        ".##....#.#..",
        ".##....#.#..",
        ".#####...#..",
        "............",
        "............",
        "............",
    )
    return {
        (x, y)
        for y, row in enumerate(rows)
        for x, value in enumerate(row)
        if value == "#"
    }


def configure_base() -> None:
    path_values = {
        "OUTPUT": OUTPUT,
        "MANIFEST": MANIFEST,
        "SKILL_REFERENCE": SKILL_REFERENCE,
        "SYSTEM_MANIFEST": SYSTEM_MANIFEST,
        "BATTLE_MANIFEST": BATTLE_MANIFEST,
        "WORLD_MANIFEST": WORLD_MANIFEST,
        "ANALYSIS": ANALYSIS,
        "REPORT": REPORT,
        "READBACK": READBACK,
        "LOW_CODE_AUDIT": LOW_CODE_AUDIT,
        "PREVIEW": PREVIEW,
        "TUTORIAL_AUDIT": TUTORIAL_AUDIT,
        "SYSTEM_AUDIT": SYSTEM_AUDIT,
        "BATTLE_AUDIT": BATTLE_AUDIT,
    }
    for name, value in path_values.items():
        setattr(base, name, value)
    base.HELP_TEXTS = HELP_TEXTS
    base.HELP_POINTERS = HELP_POINTERS
    base.SYSTEM_TEXTS = SYSTEM_TEXTS
    base.RELOCATED_TEXTS = RELOCATED_TEXTS
    base.label_bitmap = label_bitmap


def main() -> None:
    configure_base()
    base.main()
    report = REPORT.read_text(encoding="utf-8")
    report = report.replace("v0.33", "v0.34").replace("v33_", "v34_")
    report += (
        "v34_confirmation_spacing=6_spaces\n"
        "v34_bottom_help=결정 : 돌아가기\n"
        "v34_button_icon_controls=0\n"
        f"v34_lv_bitmap_pixels={len(label_bitmap())}\n"
    )
    REPORT.write_text(report, encoding="utf-8")


if __name__ == "__main__":
    main()
