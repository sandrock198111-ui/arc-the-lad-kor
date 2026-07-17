#!/usr/bin/env python3
"""Independently audit the v0.31 system and battle-choice patch."""

from __future__ import annotations

import csv
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from build_story_all_choices_v21 import encode as story_encode  # noqa: E402
from build_story_dialogue_choice_structure_v22 import control_positions  # noqa: E402
from build_story_legacy_tone_e2_v18 import SLOT_BASE, SLOT_SIZE, disk_id  # noqa: E402
from build_ui_full_v26 import (  # noqa: E402
    PSX_LOAD_BASE,
    TABLES,
    pointer_target,
    raw_string,
)
from build_ui_safe_v27 import load_mapping  # noqa: E402
from build_ui_safe_v31 import (  # noqa: E402
    BATTLE_ACCEPT,
    BATTLE_AUDIT,
    BATTLE_DECLINE,
    BATTLE_FILES,
    BATTLE_PROMPT,
    MANIFEST,
    OUTPUT,
    SYSTEM_AUDIT,
    SYSTEM_POOLS,
    SYSTEM_TEXTS,
)
from build_ui_safe_v30 import encode  # noqa: E402
from ui_safe_v31_overrides import OVERRIDES  # noqa: E402


V30 = ROOT / "03_output" / "ui_safe_v30_cumulative_patch_only.zip"
REPORT = ROOT / "01_work" / "analysis" / "ui_safe_v31" / "audit_report.txt"
ONE_LINE_SKILLS = (1, 6, 12, 21, 23, 24, 25, 26, 27, 28, 43, 47)


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def main() -> None:
    mapping = load_mapping()
    manifest = rows(MANIFEST)
    keyed = {(row["table_key"], int(row["index"])): row for row in manifest}
    if len(manifest) != 503 or len(keyed) != 503:
        raise SystemExit("v0.31 UI manifest coverage differs")

    with ZipFile(V30) as before, ZipFile(OUTPUT) as after:
        if after.namelist() != before.namelist():
            raise SystemExit("v0.31 ZIP member order differs")
        old_files = {name: before.read(name) for name in before.namelist()}
        new_files = {name: after.read(name) for name in after.namelist()}
    changed = {name for name in new_files if new_files[name] != old_files[name]}
    expected_changed = {"PSX.EXE", *BATTLE_FILES}
    if changed != expected_changed:
        raise SystemExit(f"v0.31 changed-member set differs: {sorted(changed ^ expected_changed)}")
    if new_files["COMM.IMG"] != old_files["COMM.IMG"]:
        raise SystemExit("v0.31 changed the accepted font texture")

    executable = new_files["PSX.EXE"]
    for key, (count, _segment, pointer_table) in TABLES.items():
        for index in range(count):
            row = keyed[(key, index)]
            payload = raw_string(executable, pointer_target(executable, pointer_table, index))
            if payload.hex(" ").upper() != row["encoded_hex"]:
                raise SystemExit(f"UI pointer payload differs: {key}[{index}]")

    for index in ONE_LINE_SKILLS:
        text = OVERRIDES[("skill_description", index)]
        row = keyed[("skill_description", index)]
        if len(text) > 13 or "  " in text:
            raise SystemExit(f"skill help is not a clean single line: {index} {text!r}")
        if raw_string(
            executable,
            pointer_target(executable, TABLES["skill_description"][2], index),
        ) != encode(text, mapping):
            raise SystemExit(f"single-line skill payload differs: {index}")
        if row["korean_target"] != text:
            raise SystemExit(f"single-line skill manifest differs: {index}")

    system_rows = rows(SYSTEM_AUDIT)
    if len(system_rows) != 21 or len(SYSTEM_TEXTS) != 21:
        raise SystemExit("system text audit coverage differs")
    by_pointer = {int(row["pointer_offset"], 0): row for row in system_rows}
    for pointer_offset, source_offset, text in SYSTEM_TEXTS:
        row = by_pointer[pointer_offset]
        target = struct.unpack_from("<I", executable, pointer_offset)[0] - PSX_LOAD_BASE
        if target != int(row["new_offset"], 0):
            raise SystemExit(f"system pointer readback differs: 0x{pointer_offset:X}")
        if int(row["source_offset"], 0) != source_offset or row["korean"] != text:
            raise SystemExit(f"system audit source differs: 0x{pointer_offset:X}")
        if raw_string(executable, target) != encode(text, mapping):
            raise SystemExit(f"system payload differs: {text!r}")
    bottom_target = struct.unpack_from("<I", executable, 0x8235C)[0] - PSX_LOAD_BASE
    bottom_payload = raw_string(executable, bottom_target)
    if b"\xE7" in bottom_payload:
        raise SystemExit("controller-icon control remains in bottom help")

    allowed = bytearray(len(executable))
    for count, (start, end), pointer_table in TABLES.values():
        allowed[start:end] = b"\x01" * (end - start)
        allowed[pointer_table:pointer_table + count * 4] = b"\x01" * (count * 4)
    for start, end in SYSTEM_POOLS:
        allowed[start:end] = b"\x01" * (end - start)
    for pointer_offset, _source_offset, _text in SYSTEM_TEXTS:
        allowed[pointer_offset:pointer_offset + 4] = b"\x01" * 4
    for offset, (old, new) in enumerate(zip(old_files["PSX.EXE"], executable)):
        if old != new and not allowed[offset]:
            raise SystemExit(f"PSX delta is outside declared ranges: 0x{offset:X}")

    battle_rows = rows(BATTLE_AUDIT)
    if len(battle_rows) != 63:
        raise SystemExit("battle choice audit coverage differs")
    by_file: dict[str, list[dict[str, str]]] = {}
    for row in battle_rows:
        by_file.setdefault(row["file"], []).append(row)
    prompt_payload = story_encode(BATTLE_PROMPT, mapping)
    accept_payload = story_encode(BATTLE_ACCEPT, mapping)
    decline_payload = story_encode(BATTLE_DECLINE, mapping)
    for name in BATTLE_FILES:
        if len(by_file.get(name, [])) != 7:
            raise SystemExit(f"battle choice file coverage differs: {name}")
        accept_slots = {int(row["accept_slot"]) for row in by_file[name]}
        decline_slots = {int(row["decline_slot"]) for row in by_file[name]}
        if len(accept_slots) != 1 or len(decline_slots) != 1:
            raise SystemExit(f"battle shared options differ: {name}")
        data = new_files[name]
        original_file = (ROOT / "01_work" / name).read_bytes()
        for row in by_file[name]:
            offset = int(row["offset"], 0)
            capacity = int(row["capacity"])
            body = data[offset:offset + capacity]
            original = original_file[offset:offset + capacity]
            if control_positions(body, 0xE5) != control_positions(original, 0xE5):
                raise SystemExit(f"battle E5 geometry differs: {name} {row['offset']}")
            if control_positions(body, 0xE6) != control_positions(original, 0xE6):
                raise SystemExit(f"battle E6 geometry differs: {name} {row['offset']}")
            e5 = [position for position, _arg in control_positions(original, 0xE5)]
            e6 = [position for position, _arg in control_positions(original, 0xE6)]
            prompt_end = max(position for position in e6 if position < e5[0])
            option1 = e5[0] + 2
            option2 = e5[1] + 2
            prompt_slot = int(row["prompt_slot"])
            accept_slot = int(row["accept_slot"])
            decline_slot = int(row["decline_slot"])
            if body[:2] != bytes((0xE2, disk_id(prompt_slot))):
                raise SystemExit(f"battle prompt redirect differs: {name} {row['offset']}")
            if body[option1:option1 + 2] != bytes((0xE2, disk_id(accept_slot))):
                raise SystemExit(f"battle accept redirect differs: {name} {row['offset']}")
            if body[option2:option2 + 2] != bytes((0xE2, disk_id(decline_slot))):
                raise SystemExit(f"battle decline redirect differs: {name} {row['offset']}")
            checks = (
                (prompt_slot, prompt_payload, prompt_end - 2),
                (accept_slot, accept_payload, 0),
                (decline_slot, decline_payload, 5),
            )
            for slot, payload, skip in checks:
                slot_offset = SLOT_BASE + slot * SLOT_SIZE
                if data[slot_offset:slot_offset + len(payload)] != payload:
                    raise SystemExit(f"battle slot payload differs: {name} slot={slot}")
                if data[slot_offset + SLOT_SIZE - 1] != skip:
                    raise SystemExit(f"battle slot skip differs: {name} slot={slot}")

    lines = [
        "UI safe v0.31 independent audit",
        "pointer_payload_readback=503/503",
        "single_line_skill_help=12/12",
        "system_text_pointer_readback=21/21",
        "bottom_icon_controls_removed=true",
        "battle_choice_bodies=63/63",
        "battle_choice_files=9/9",
        "battle_E5_geometry_preserved=true",
        "battle_E6_geometry_preserved=true",
        "comm_img_byte_identical_to_v30=true",
        "changes_outside_declared_ranges=false",
        "result=PASS",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
