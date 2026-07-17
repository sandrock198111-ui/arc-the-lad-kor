#!/usr/bin/env python3
"""Build v0.30 with balanced skill help and six repeated tutorial repairs."""

from __future__ import annotations

import csv
import hashlib
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_ui_safe_v29 as base  # noqa: E402
from build_story_all_choices_v21 import encode as story_encode  # noqa: E402
from build_story_legacy_tone_e2_v18 import SLOT_BASE, SLOT_COUNT, SLOT_SIZE, disk_id  # noqa: E402
from build_ui_safe_v27 import load_mapping  # noqa: E402
from ui_safe_v30_overrides import OVERRIDES  # noqa: E402


V29_MISSING_CHARS = base.missing_chars


OUTPUT = ROOT / "03_output" / "ui_safe_v30_cumulative_patch_only.zip"
MANIFEST = ROOT / "05_docs" / "ui_safe_v30.csv"
SKILL_REFERENCE = ROOT / "05_docs" / "ui_skill_guide_reference_v30.csv"
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_safe_v30"
REPORT = ANALYSIS / "build_report.txt"
READBACK = ANALYSIS / "readback.csv"
LOW_CODE_AUDIT = ANALYSIS / "low_6c_story_audit.csv"
PREVIEW = ANALYSIS / "lv_label_before_after.pbm"
TUTORIAL_AUDIT = ANALYSIS / "tutorial_e2_audit.csv"

TARGETS = {
    "21/S2045.DAT": 0x4922E,
    "31/S3014.DAT": 0x48252,
    "5/S5013.DAT": 0x4921A,
    "6/S6014.DAT": 0x491C6,
    "7/S7012.DAT": 0x48CBE,
    "8/S8013.DAT": 0x47CAC,
}
ROW_LAYOUT = ((0, 5), (7, 14), (23, 12), (37, 13))
ROW_TEXTS = ("초핀", "전투 중 자기 차례에", "시작 버튼을 누르면", "상태를 확인해요")
SOURCE_BODY = bytes.fromhex(
    "6C 69 72 34 25 E6 01 AF 5C 53 DD 64 23 24 A4 B2 1C 62 31 34 30 "
    "E6 01 47 62 31 5C DD A1 62 34 2F 3B 2B 36 E6 01 "
    "47 DB 31 62 47 2F A0 32 27 2B 3D 4C 37"
)


def missing_chars(text: str, mapping: dict[str, bytes]) -> str:
    return V29_MISSING_CHARS(text.replace("LV", ""), mapping)


def encode(text: str, mapping: dict[str, bytes]) -> bytes:
    output = bytearray()
    index = 0
    while index < len(text):
        if text.startswith("LV", index):
            output.append(0x6C)
            index += 2
            continue
        char = text[index]
        if char == " ":
            output.append(0x9C)
        elif char.isascii() and char.isdigit():
            output.append(0x11 + int(char))
        elif char in base.SINGLE_BYTE:
            output.append(base.SINGLE_BYTE[char])
        else:
            output.extend(mapping[char])
        index += 1
    return bytes(output)


def patch_tutorials(files: dict[str, bytes]) -> list[dict[str, str | int]]:
    mapping = load_mapping()
    payloads = [story_encode(text, mapping) for text in ROW_TEXTS]
    audit: list[dict[str, str | int]] = []
    for name, offset in TARGETS.items():
        data = bytearray(files[name])
        if data[offset : offset + len(SOURCE_BODY)] != SOURCE_BODY:
            raise SystemExit(f"tutorial source body differs: {name} 0x{offset:X}")
        free = [
            slot
            for slot in range(SLOT_COUNT)
            if not any(data[SLOT_BASE + slot * SLOT_SIZE : SLOT_BASE + (slot + 1) * SLOT_SIZE])
        ]
        if len(free) < len(ROW_TEXTS):
            raise SystemExit(f"not enough E2 slots for tutorial: {name}")
        for row_index, ((relative, capacity), text, payload) in enumerate(
            zip(ROW_LAYOUT, ROW_TEXTS, payloads), start=1
        ):
            if len(payload) > SLOT_SIZE - 1:
                raise SystemExit(f"tutorial E2 payload overflow: {name} row {row_index}")
            slot = free.pop(0)
            slot_offset = SLOT_BASE + slot * SLOT_SIZE
            data[slot_offset : slot_offset + SLOT_SIZE] = b"\x00" * SLOT_SIZE
            data[slot_offset : slot_offset + len(payload)] = payload
            data[slot_offset + SLOT_SIZE - 1] = capacity - 2
            data[offset + relative : offset + relative + 2] = bytes((0xE2, disk_id(slot)))
            audit.append(
                {
                    "file": name,
                    "body_offset": f"0x{offset:X}",
                    "row": row_index,
                    "row_offset": relative,
                    "capacity": capacity,
                    "slot": slot,
                    "disk_id": f"0x{disk_id(slot):02X}",
                    "skip": capacity - 2,
                    "encoded_bytes": len(payload),
                    "text": text,
                }
            )
        for relative in (5, 21, 35):
            if data[offset + relative : offset + relative + 2] != b"\xE6\x01":
                raise SystemExit(f"tutorial E6 changed: {name} +0x{relative:X}")
        files[name] = bytes(data)
    return audit


def write_audit(rows: list[dict[str, str | int]]) -> None:
    TUTORIAL_AUDIT.parent.mkdir(parents=True, exist_ok=True)
    with TUTORIAL_AUDIT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def rewrite_report() -> None:
    lines = REPORT.read_text(encoding="utf-8").splitlines()
    lines = [
        "UI safe v0.30 cumulative balanced-help and tutorial repair"
        if line.startswith("UI safe v0.29")
        else line
        for line in lines
    ]
    lines = [
        f"output_zip_sha256={hashlib.sha256(OUTPUT.read_bytes()).hexdigest().upper()}"
        if line.startswith("output_zip_sha256=")
        else line
        for line in lines
    ]
    lines = [
        "changed_members=COMM.IMG,PSX.EXE," + ",".join(TARGETS)
        if line.startswith("changed_members=")
        else line
        for line in lines
    ]
    lines.extend(
        [
            "balanced_skill_help_rows=12",
            "equipment_level_labels=던지기 LV +1|점프 LV +1|받기 LV +1",
            "tutorial_duplicate_files=6",
            "tutorial_e2_rows=24",
            "tutorial_e6_controls_preserved=18/18",
        ]
    )
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    base.OUTPUT = OUTPUT
    base.MANIFEST = MANIFEST
    base.SKILL_REFERENCE = SKILL_REFERENCE
    base.ANALYSIS = ANALYSIS
    base.REPORT = REPORT
    base.READBACK = READBACK
    base.LOW_CODE_AUDIT = LOW_CODE_AUDIT
    base.PREVIEW = PREVIEW
    base.OVERRIDES = OVERRIDES
    base.missing_chars = missing_chars
    base.encode = encode
    base.main()

    with ZipFile(OUTPUT) as archive:
        infos = archive.infolist()
        files = {info.filename: archive.read(info.filename) for info in infos}
    audit = patch_tutorials(files)
    write_audit(audit)

    temporary = OUTPUT.with_suffix(".tmp.zip")
    with ZipFile(temporary, "w", ZIP_DEFLATED, compresslevel=9) as archive:
        for info in infos:
            archive.writestr(info, files[info.filename])
    temporary.replace(OUTPUT)
    with ZipFile(OUTPUT) as archive:
        if any(archive.read(name) != payload for name, payload in files.items()):
            raise SystemExit("v0.30 ZIP readback differs")
    rewrite_report()
    print(REPORT.read_text(encoding="utf-8"), end="")


if __name__ == "__main__":
    main()
