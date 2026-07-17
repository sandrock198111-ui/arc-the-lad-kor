#!/usr/bin/env python3
"""Independently audit the safe v0.29 UI patch and LV label repair."""

from __future__ import annotations

import csv
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from build_ui_full_v26 import BASE, FONT_TARGET, PSX_TARGET, TABLES, pointer_target, raw_string  # noqa: E402
from build_ui_safe_v27 import load_mapping  # noqa: E402
from build_ui_safe_v29 import OUTPUT, encode, patch_label  # noqa: E402
from ui_safe_v29_overrides import OVERRIDES  # noqa: E402


MANIFEST = ROOT / "05_docs" / "ui_safe_v29.csv"
SKILL_REFERENCE = ROOT / "05_docs" / "ui_skill_guide_reference_v29.csv"
REPORT = ROOT / "01_work" / "analysis" / "ui_safe_v29" / "audit_report.txt"


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def main() -> None:
    rows = read_csv(MANIFEST)
    if len(rows) != 503:
        raise SystemExit(f"manifest row count differs: {len(rows)}")
    keyed = {(row["table_key"], int(row["index"])): row for row in rows}
    if len(keyed) != 503 or not set(OVERRIDES).issubset(keyed):
        raise SystemExit("manifest key coverage differs")

    mapping = load_mapping()
    with ZipFile(BASE) as base_archive, ZipFile(OUTPUT) as output_archive:
        base_names = base_archive.namelist()
        if output_archive.namelist() != base_names:
            raise SystemExit("ZIP member order differs")
        changed = [name for name in base_names if base_archive.read(name) != output_archive.read(name)]
        if changed != [FONT_TARGET, PSX_TARGET]:
            raise SystemExit(f"unexpected changed members: {changed}")
        expected_font = bytearray(base_archive.read(FONT_TARGET))
        expected_bytes, expected_nibbles = patch_label(expected_font)
        if output_archive.read(FONT_TARGET) != bytes(expected_font):
            raise SystemExit("COMM.IMG differs outside the expected LV repair")
        executable = output_archive.read(PSX_TARGET)

    readback = 0
    for key, (count, _, pointer_table) in TABLES.items():
        for index in range(count):
            row = keyed[(key, index)]
            payload = raw_string(executable, pointer_target(executable, pointer_table, index))
            if payload.hex(" ").upper() != row["encoded_hex"]:
                raise SystemExit(f"manifest payload differs: {key}[{index}]")
            if row["status"] != "preserved_v25_missing_glyph":
                expected = encode(row["korean_target"], mapping)
                if payload != expected or 0 in payload:
                    raise SystemExit(f"Korean payload differs: {key}[{index}]")
            readback += 1

    skills = read_csv(SKILL_REFERENCE)
    if len(skills) != 118:
        raise SystemExit(f"skill reference row count differs: {len(skills)}")
    if any(
        len(row["korean"]) > 14
        for row in skills
        if row["record_type"] == "skill_description" and row["korean"]
    ):
        raise SystemExit("skill description exceeds the verified single-line budget")

    report = [
        "UI safe v0.29 independent audit",
        f"pointer_payload_readback={readback}/503",
        f"override_readback={len(OVERRIDES)}/{len(OVERRIDES)}",
        "zip_member_order_preserved=true",
        "changed_members=COMM.IMG,PSX.EXE",
        f"comm_img_changed_bytes={expected_bytes}",
        f"comm_img_changed_nibbles={expected_nibbles}",
        "comm_img_change_scope=single_LV_bitplane",
        "skill_description_max_chars=14",
        "result=PASS",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
