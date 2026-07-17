#!/usr/bin/env python3
"""Independently audit the safe v0.28 UI patch and its manifests."""

from __future__ import annotations

import csv
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from build_ui_full_v26 import BASE, FONT_TARGET, PSX_TARGET, TABLES, pointer_target, raw_string  # noqa: E402
from build_ui_safe_v27 import encode, load_mapping  # noqa: E402
from build_ui_safe_v28 import OUTPUT  # noqa: E402
from ui_safe_v28_overrides import OVERRIDES  # noqa: E402


MANIFEST = ROOT / "05_docs" / "ui_safe_v28.csv"
SKILL_REFERENCE = ROOT / "05_docs" / "ui_skill_guide_reference_v28.csv"
REPORT = ROOT / "01_work" / "analysis" / "ui_safe_v28" / "audit_report.txt"


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def main() -> None:
    rows = read_csv(MANIFEST)
    if len(rows) != 503:
        raise SystemExit(f"manifest row count differs: {len(rows)}")
    keyed = {(row["table_key"], int(row["index"])): row for row in rows}
    if len(keyed) != 503:
        raise SystemExit("manifest has duplicate table/index keys")
    if not set(OVERRIDES).issubset(keyed):
        raise SystemExit("an override key is absent from the manifest")

    mapping = load_mapping()
    with ZipFile(BASE) as base_archive, ZipFile(OUTPUT) as output_archive:
        base_names = base_archive.namelist()
        if output_archive.namelist() != base_names:
            raise SystemExit("ZIP member order differs")
        changed = [
            name
            for name in base_names
            if base_archive.read(name) != output_archive.read(name)
        ]
        if changed != [PSX_TARGET]:
            raise SystemExit(f"unexpected changed members: {changed}")
        if base_archive.read(FONT_TARGET) != output_archive.read(FONT_TARGET):
            raise SystemExit("COMM.IMG differs")
        executable = output_archive.read(PSX_TARGET)

    readback = 0
    for key, (count, _, pointer_table) in TABLES.items():
        for index in range(count):
            row = keyed[(key, index)]
            pointer = pointer_target(executable, pointer_table, index)
            payload = raw_string(executable, pointer)
            if payload.hex(" ").upper() != row["encoded_hex"]:
                raise SystemExit(f"manifest payload differs: {key}[{index}]")
            if row["status"] != "preserved_v25_missing_glyph":
                expected = encode(row["korean_target"], mapping)
                if payload != expected:
                    raise SystemExit(f"Korean payload differs: {key}[{index}]")
                if 0 in payload:
                    raise SystemExit(f"zero inside translated payload: {key}[{index}]")
                for char in row["korean_target"]:
                    if char == " " or (char.isascii() and char.isdigit()):
                        continue
                    code = mapping[char]
                    if len(code) == 2 and not 0xDD <= code[0] <= 0xE0:
                        raise SystemExit(f"unsafe translated prefix: {key}[{index}]")
                    if len(code) == 1 and 0xE1 <= code[0] <= 0xE8:
                        raise SystemExit(f"unsafe one-byte control: {key}[{index}]")
            readback += 1

    skills = read_csv(SKILL_REFERENCE)
    if len(skills) != 118:
        raise SystemExit(f"skill reference row count differs: {len(skills)}")
    guide_rows = [
        row
        for row in skills
        if 1 <= int(row["index"]) <= 45
        and row["record_type"] in {"skill_name", "skill_description"}
    ]
    if len(guide_rows) != 90 or any("Game Magazine" not in row["reference"] for row in guide_rows):
        raise SystemExit("guide provenance is incomplete for player skills")

    translated = sum(row["status"] != "preserved_v25_missing_glyph" for row in rows)
    preserved = len(rows) - translated
    report = [
        "UI safe v0.28 independent audit",
        f"pointer_payload_readback={readback}/503",
        f"translated_existing_bank={translated}",
        f"preserved_v25_missing_glyph={preserved}",
        f"guide_player_skill_rows={len(guide_rows)}/90",
        "zip_member_order_preserved=true",
        "changed_members=PSX.EXE",
        "comm_img_byte_identical_to_v25=true",
        "translated_payload_zero_bytes=false",
        "translated_payload_e1_e8_prefixes=false",
        "result=PASS",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
