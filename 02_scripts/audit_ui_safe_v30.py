#!/usr/bin/env python3
"""Independently audit v0.30 UI wrapping and repeated tutorial E2 repairs."""

from __future__ import annotations

import csv
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from build_story_all_choices_v21 import encode as story_encode  # noqa: E402
from build_story_legacy_tone_e2_v18 import SLOT_BASE, SLOT_SIZE, disk_id  # noqa: E402
from build_ui_full_v26 import PSX_TARGET, TABLES, pointer_target, raw_string  # noqa: E402
from build_ui_safe_v27 import load_mapping  # noqa: E402
from build_ui_safe_v30 import (  # noqa: E402
    MANIFEST,
    OUTPUT,
    ROW_LAYOUT,
    ROW_TEXTS,
    TARGETS,
    TUTORIAL_AUDIT,
    encode,
)
from ui_safe_v30_overrides import OVERRIDES  # noqa: E402


V29 = ROOT / "03_output" / "ui_safe_v29_cumulative_patch_only.zip"
REPORT = ROOT / "01_work" / "analysis" / "ui_safe_v30" / "audit_report.txt"
FONT_TARGET = "COMM.IMG"


def csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def main() -> None:
    manifest = csv_rows(MANIFEST)
    keyed = {(row["table_key"], int(row["index"])): row for row in manifest}
    if len(manifest) != 503 or len(keyed) != 503:
        raise SystemExit("v0.30 manifest coverage differs")
    mapping = load_mapping()

    with ZipFile(V29) as before, ZipFile(OUTPUT) as after:
        if after.namelist() != before.namelist():
            raise SystemExit("ZIP member order differs from v0.29")
        before_files = {name: before.read(name) for name in before.namelist()}
        after_files = {name: after.read(name) for name in after.namelist()}
    changed = {name for name in before_files if before_files[name] != after_files[name]}
    expected_changed = {PSX_TARGET, *TARGETS}
    if changed != expected_changed:
        raise SystemExit(f"unexpected v0.30 changed members: {sorted(changed ^ expected_changed)}")
    if before_files[FONT_TARGET] != after_files[FONT_TARGET]:
        raise SystemExit("v0.30 changed the accepted v0.29 LV/font texture")

    executable = after_files[PSX_TARGET]
    for key, (count, _, pointer_table) in TABLES.items():
        for index in range(count):
            row = keyed[(key, index)]
            payload = raw_string(executable, pointer_target(executable, pointer_table, index))
            if payload.hex(" ").upper() != row["encoded_hex"]:
                raise SystemExit(f"pointer payload differs: {key}[{index}]")
            if row["status"] != "preserved_v25_missing_glyph":
                if payload != encode(row["korean_target"], mapping):
                    raise SystemExit(f"Korean payload differs: {key}[{index}]")

    for index, expected in ((8, "던지기 LV +1"), (20, "점프 LV +1"), (22, "받기 LV +1")):
        row = keyed[("equipment_description", index)]
        if row["korean_target"] != expected or "6C" not in row["encoded_hex"].split():
            raise SystemExit(f"LV level description differs: equipment_description[{index}]")

    balanced = 0
    for (kind, _), text in OVERRIDES.items():
        if kind != "skill_description":
            continue
        visual_rows = [text[pos : pos + 13].rstrip() for pos in range(0, len(text), 13)]
        if any(len(row) == 1 for row in visual_rows):
            raise SystemExit(f"orphan skill-help row remains: {text!r}")
        if len(visual_rows) == 2:
            balanced += 1
    if balanced != 12:
        raise SystemExit(f"balanced skill-help count differs: {balanced}")

    tutorial_rows = csv_rows(TUTORIAL_AUDIT)
    if len(tutorial_rows) != 24:
        raise SystemExit("tutorial audit row count differs")
    by_file: dict[str, list[dict[str, str]]] = {}
    for row in tutorial_rows:
        by_file.setdefault(row["file"], []).append(row)
    for name, offset in TARGETS.items():
        old = before_files[name]
        new = after_files[name]
        allowed: set[int] = set()
        for relative, _capacity in ROW_LAYOUT:
            allowed.update(range(offset + relative, offset + relative + 2))
        for row, ((relative, capacity), text) in zip(
            sorted(by_file[name], key=lambda item: int(item["row"])), zip(ROW_LAYOUT, ROW_TEXTS)
        ):
            slot = int(row["slot"])
            slot_offset = SLOT_BASE + slot * SLOT_SIZE
            allowed.update(range(slot_offset, slot_offset + SLOT_SIZE))
            payload = story_encode(text, mapping)
            if new[offset + relative : offset + relative + 2] != bytes((0xE2, disk_id(slot))):
                raise SystemExit(f"tutorial E2 command differs: {name} row {row['row']}")
            if new[slot_offset : slot_offset + len(payload)] != payload:
                raise SystemExit(f"tutorial E2 payload differs: {name} row {row['row']}")
            if new[slot_offset + SLOT_SIZE - 1] != capacity - 2:
                raise SystemExit(f"tutorial E2 skip differs: {name} row {row['row']}")
        for relative in (5, 21, 35):
            if new[offset + relative : offset + relative + 2] != b"\xE6\x01":
                raise SystemExit(f"tutorial E6 differs: {name} +0x{relative:X}")
        actual_diff = {index for index, (a, b) in enumerate(zip(old, new)) if a != b}
        if not actual_diff <= allowed:
            raise SystemExit(f"tutorial changed outside declared ranges: {name}")

    lines = [
        "UI safe v0.30 independent audit",
        "pointer_payload_readback=503/503",
        "equipment_LV_descriptions=3/3",
        "balanced_skill_help=12/12",
        "tutorial_duplicate_files=6/6",
        "tutorial_E2_rows=24/24",
        "tutorial_E6_controls=18/18",
        "comm_img_byte_identical_to_v29=true",
        "changes_outside_declared_ranges=false",
        "result=PASS",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
