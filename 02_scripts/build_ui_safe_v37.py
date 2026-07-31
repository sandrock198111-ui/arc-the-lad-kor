#!/usr/bin/env python3
"""Build v0.37 by changing only shared confirmation-box geometry in v0.36."""

from __future__ import annotations

import hashlib
import shutil
import struct
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output" / "ui_safe_v36_cumulative_patch_only.zip"
OUTPUT = ROOT / "03_output" / "ui_safe_v37_cumulative_patch_only.zip"
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_safe_v37"
REPORT = ANALYSIS / "build_report.txt"

BASE_ZIP_HASH = "B88FCA6C706E59F779197F23B4DCE45C1C0C87AF1274E9B4B316B3D4751276D3"
BASE_PSX_HASH = "A3AF6C2E3C6D720AC70DFC9E7FD8252A4E2D595D1AB7095BEF655ABE41F13E8B"
BASE_COMM_HASH = "FB6D4027023C6A75A1561D72507C52656472B4F31E1EB92B73965CA3B51543EA"

PSX_TARGET = "PSX.EXE"
FONT_TARGET = "COMM.IMG"
BOX_WIDTH_INSN = 0x463D8
PROMPT_X_INSN = 0x46428
EXPECTED_BOX_WIDTH = 0x24750010  # addiu s5, v1, 0x10
WIDER_BOX_WIDTH = 0x24750028    # addiu s5, v1, 0x28
EXPECTED_PROMPT_X = 0x26440008  # addiu a0, s2, 8
CENTERED_PROMPT_X = 0x26440014  # addiu a0, s2, 20

MANIFESTS = (
    ("ui_safe_v36.csv", "ui_safe_v37.csv"),
    ("ui_skill_guide_reference_v36.csv", "ui_skill_guide_reference_v37.csv"),
    ("ui_system_v36.csv", "ui_system_v37.csv"),
    ("ui_battle_choice_v36.csv", "ui_battle_choice_v37.csv"),
    ("ui_world_name_v36.csv", "ui_world_name_v37.csv"),
    ("ui_items_equipment_skills_v36_review.csv", "ui_items_equipment_skills_v37_review.csv"),
    ("ui_nonstory_system_v36.csv", "ui_nonstory_system_v37.csv"),
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_ZIP_HASH:
        raise SystemExit("v0.36 base ZIP hash differs")

    with ZipFile(BASE) as archive:
        infos = {item.filename: item for item in archive.infolist()}
        before_files = {name: archive.read(name) for name in infos}
    if digest(before_files[PSX_TARGET]) != BASE_PSX_HASH:
        raise SystemExit("v0.36 PSX.EXE hash differs")
    if digest(before_files[FONT_TARGET]) != BASE_COMM_HASH:
        raise SystemExit("v0.36 COMM.IMG hash differs")

    files = dict(before_files)
    executable = bytearray(files[PSX_TARGET])
    old_box = struct.unpack_from("<I", executable, BOX_WIDTH_INSN)[0]
    old_prompt = struct.unpack_from("<I", executable, PROMPT_X_INSN)[0]
    if old_box != EXPECTED_BOX_WIDTH:
        raise SystemExit(f"confirmation box instruction differs: 0x{old_box:08X}")
    if old_prompt != EXPECTED_PROMPT_X:
        raise SystemExit(f"confirmation prompt instruction differs: 0x{old_prompt:08X}")

    before_psx = bytes(executable)
    struct.pack_into("<I", executable, BOX_WIDTH_INSN, WIDER_BOX_WIDTH)
    struct.pack_into("<I", executable, PROMPT_X_INSN, CENTERED_PROMPT_X)
    files[PSX_TARGET] = bytes(executable)

    changed_offsets = [
        offset
        for offset, (old, new) in enumerate(zip(before_psx, executable))
        if old != new
    ]
    if changed_offsets != [BOX_WIDTH_INSN, PROMPT_X_INSN]:
        raise SystemExit(f"unexpected PSX delta offsets: {changed_offsets}")

    temporary = OUTPUT.with_suffix(".tmp")
    with ZipFile(temporary, "w", ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            archive.writestr(infos[name], files[name])
    temporary.replace(OUTPUT)

    with ZipFile(OUTPUT) as archive:
        after_files = {name: archive.read(name) for name in archive.namelist()}
    if set(before_files) != set(after_files):
        raise SystemExit("v0.37 member list differs from v0.36")
    changed_members = [
        name for name in sorted(before_files) if before_files[name] != after_files[name]
    ]
    if changed_members != [PSX_TARGET]:
        raise SystemExit(f"unexpected changed members: {changed_members}")
    if after_files[FONT_TARGET] != before_files[FONT_TARGET]:
        raise SystemExit("v0.37 COMM.IMG differs from v0.36")

    for source_name, target_name in MANIFESTS:
        source = ROOT / "05_docs" / source_name
        target = ROOT / "05_docs" / target_name
        shutil.copy2(source, target)

    # 18 characters * 12 pixels plus the new 40-pixel horizontal margin.
    maximum_width = 18 * 12 + 0x28
    if maximum_width >= 320:
        raise SystemExit(f"confirmation box exceeds screen: {maximum_width}px")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    report = (
        "UI safe v0.37 cumulative confirmation geometry repair\n"
        "base=v0.36 byte-stable cumulative ZIP\n"
        f"base_zip_sha256={BASE_ZIP_HASH}\n"
        "changed_members=PSX.EXE\n"
        f"changed_psx_offsets=0x{BOX_WIDTH_INSN:X},0x{PROMPT_X_INSN:X}\n"
        "changed_psx_bytes=2\n"
        "confirmation_box_extra_width=24px\n"
        "confirmation_box_left_extension=12px\n"
        "confirmation_box_right_extension=12px\n"
        "confirmation_text_absolute_position=unchanged\n"
        "confirmation_cursor_absolute_position=unchanged\n"
        f"confirmation_maximum_width={maximum_width}px\n"
        "font_source=v34 byte-identical\n"
        f"comm_img_sha256={digest(after_files[FONT_TARGET])}\n"
        f"psx_exe_sha256={digest(after_files[PSX_TARGET])}\n"
        f"output_zip_sha256={digest(OUTPUT.read_bytes())}\n"
    )
    REPORT.write_text(report, encoding="utf-8")
    print(report, end="")


if __name__ == "__main__":
    main()
