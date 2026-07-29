#!/usr/bin/env python3
"""Build v89 by replacing the UI-only book glyph in one story E2 payload.

v88 encoded "책" as UI virtual code EA 6F. The story parser only accepts
normal and DD-E0 glyph codes, so slot 3 stopped as soon as that code was read.
This build reuses an otherwise unused story glyph cell (E0 2D) for "책" and
changes only that code in the affected S3032 E2 payload.
"""

from __future__ import annotations

import csv
import hashlib
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_story_sf0b1_return_full as story_font  # noqa: E402
import build_ui_hud_e7_v86_p6_repack_slots_1_to_6 as v86  # noqa: E402
import build_ui_hud_e7_v88_p6_state_persistence_slots_3_to_6 as v88  # noqa: E402


BASE = (
    ROOT
    / "03_output"
    / "ui_hud_e7_v88_p6_state_persistence_slots_3_to_6_patch_only.zip"
)
OUTPUT = (
    ROOT
    / "03_output"
    / "ui_hud_e7_v89_story_safe_book_glyph_patch_only.zip"
)
ANALYSIS = (
    ROOT
    / "01_work"
    / "analysis"
    / "ui_hud_e7_v89_story_safe_book_glyph"
)
REPORT = ANALYSIS / "build_report.txt"

BASE_SHA256 = "CB89BF7A66CE1C176D44FD8E49772F4D94A8A4A688C11A95E207F3F89D802FAC"
BASE_COMM_SHA256 = "2B59950A5EB8BEF30FAEC4E519F39F9E41A1521B58B18C803478625A2F9FD221"
BASE_S3032_SHA256 = "53832FFDDD3A3DD63F79DCE5FA635E65CA1F8F58C0251D4A0721DFE6FB2E62CF"

COMM_MEMBER = "COMM.IMG"
S3032_MEMBER = "31/S3032.DAT"
PSX_MEMBER = "PSX.EXE"

TARGET_SLOT = 2
TARGET_SLOT_OFFSET = v86.SLOT_BASE + TARGET_SLOT * v86.SLOT_SIZE
BAD_UI_CODE = bytes.fromhex("EA 6F")
BOOK_STORY_CODE = bytes.fromhex("E0 2D")
EXPECTED_PAYLOAD = bytes.fromhex(
    "E0 DA E0 C5 E6 01 "
    "E0 49 E0 6B 9C E0 E7 E0 EA 9C E0 6B E0 BD 9C E0 04 E0 16 E0 A7 E6 01 "
    "E0 CB DF E5 E0 C2 9C EA 6F DF F6 DF A7 9C DF B7 9C "
    "E0 F1 E0 5F E0 35 E0 C1 E0 60"
)
EXPECTED_TEXT = "야군 / 만일 무슨 일이 생겨도 / 저희는 책임질 수 없습니다."


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def story_code_owner(code: bytes) -> str:
    paths = (
        ROOT / "05_docs" / "korean_charmap.csv",
        ROOT / "05_docs" / "korean_charmap_extended.csv",
    )
    owners: list[str] = []
    for path in paths:
        with path.open(encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                if bytes.fromhex(row["code_hex"]) == code:
                    owners.append(row["char"])
    if owners != ["듯"]:
        raise SystemExit(f"E0 2D owner changed: {owners}")
    return owners[0]


def ensure_story_code_unused(members: dict[str, bytes], code: bytes) -> None:
    occurrences: list[str] = []
    for name, data in members.items():
        if not name.upper().endswith(".DAT"):
            continue
        count = data[0x45000:].count(code)
        if count:
            occurrences.append(f"{name}:{count}")
    if occurrences:
        raise SystemExit(
            "replacement story code is already used: " + ", ".join(occurrences)
        )


def allowed_glyph_offsets(code: bytes) -> tuple[set[int], int, int, int]:
    index = story_font.glyph_index(code)
    row, remainder = divmod(index, 84)
    column, plane = divmod(remainder, 4)
    if (row, column) in story_font.CURSOR_RESERVED_CELLS:
        raise SystemExit("replacement glyph overlaps a reserved cursor cell")
    offsets = {
        y * story_font.ROW_BYTES + x // 2
        for y in range(row * 12, row * 12 + 12)
        for x in range(column * 12, column * 12 + 12)
    }
    return offsets, row, column, plane


def main() -> None:
    if sha256(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v88 base ZIP hash differs")

    with ZipFile(BASE, "r") as source:
        infos = source.infolist()
        members = {info.filename: source.read(info.filename) for info in infos}
    original = dict(members)

    if sha256(members[COMM_MEMBER]) != BASE_COMM_SHA256:
        raise SystemExit("v88 COMM.IMG hash differs")
    if sha256(members[S3032_MEMBER]) != BASE_S3032_SHA256:
        raise SystemExit("v88 S3032.DAT hash differs")

    old_owner = story_code_owner(BOOK_STORY_CODE)
    ensure_story_code_unused(members, BOOK_STORY_CODE)

    comm = bytearray(members[COMM_MEMBER])
    allowed_offsets, glyph_row, glyph_column, glyph_plane = allowed_glyph_offsets(
        BOOK_STORY_CODE
    )
    story_font.write_glyph_plane(comm, BOOK_STORY_CODE, "책")
    members[COMM_MEMBER] = bytes(comm)

    comm_diffs = {
        index
        for index, (before, after) in enumerate(
            zip(original[COMM_MEMBER], members[COMM_MEMBER])
        )
        if before != after
    }
    if not comm_diffs or not comm_diffs <= allowed_offsets:
        raise SystemExit("COMM.IMG changed outside the dedicated glyph cell")

    s3032 = bytearray(members[S3032_MEMBER])
    payload_end = TARGET_SLOT_OFFSET + len(EXPECTED_PAYLOAD)
    if s3032[TARGET_SLOT_OFFSET:payload_end] != EXPECTED_PAYLOAD:
        raise SystemExit("v88 slot 2 payload differs")
    if EXPECTED_PAYLOAD.count(BAD_UI_CODE) != 1:
        raise SystemExit("expected UI-only code count differs")

    bad_offset = s3032.find(BAD_UI_CODE, TARGET_SLOT_OFFSET, payload_end)
    if bad_offset < 0:
        raise SystemExit("UI-only book code was not found")
    s3032[bad_offset : bad_offset + 2] = BOOK_STORY_CODE
    members[S3032_MEMBER] = bytes(s3032)

    s3032_diffs = {
        index
        for index, (before, after) in enumerate(
            zip(original[S3032_MEMBER], members[S3032_MEMBER])
        )
        if before != after
    }
    if s3032_diffs != {bad_offset, bad_offset + 1}:
        raise SystemExit(f"unexpected S3032 changes: {sorted(s3032_diffs)}")

    safe_payload = members[S3032_MEMBER][TARGET_SLOT_OFFSET:payload_end]
    if BAD_UI_CODE in safe_payload:
        raise SystemExit("UI-only code remains in the repaired payload")
    if safe_payload.count(BOOK_STORY_CODE) != 1:
        raise SystemExit("story-safe book code count differs")

    changed_members = [
        name for name in members if members[name] != original[name]
    ]
    if changed_members != [COMM_MEMBER, S3032_MEMBER]:
        raise SystemExit(f"unexpected changed members: {changed_members}")
    if members[PSX_MEMBER] != original[PSX_MEMBER]:
        raise SystemExit("PSX.EXE changed")

    # Preserve the two already successful slots and the second new dialogue.
    for slot in (0, 1, 3):
        start = v86.SLOT_BASE + slot * v86.SLOT_SIZE
        end = start + v86.SLOT_SIZE
        if members[S3032_MEMBER][start:end] != original[S3032_MEMBER][start:end]:
            raise SystemExit(f"preserved S3032 slot {slot} changed")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w", compression=ZIP_DEFLATED, compresslevel=9) as target:
        for info in infos:
            target.writestr(v88.clone_info(info), members[info.filename])

    with ZipFile(OUTPUT, "r") as built:
        readback_infos = built.infolist()
        readback = {
            info.filename: built.read(info.filename) for info in readback_infos
        }
    if [info.filename for info in readback_infos] != [
        info.filename for info in infos
    ]:
        raise SystemExit("ZIP member order changed")
    if readback != members:
        raise SystemExit("ZIP readback differs")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    report = [
        "ui_hud_e7_v89 story-safe book glyph repair",
        f"base={BASE}",
        f"base_zip_sha256={BASE_SHA256}",
        f"output={OUTPUT}",
        f"output_zip_sha256={sha256(OUTPUT.read_bytes())}",
        f"output_comm_sha256={sha256(members[COMM_MEMBER])}",
        f"output_s3032_sha256={sha256(members[S3032_MEMBER])}",
        f"target_member={S3032_MEMBER}",
        f"target_slot={TARGET_SLOT}",
        f"target_slot_offset=0x{TARGET_SLOT_OFFSET:X}",
        f"bad_ui_code={BAD_UI_CODE.hex(' ').upper()}",
        f"book_story_code={BOOK_STORY_CODE.hex(' ').upper()}",
        f"reassigned_from={old_owner}",
        f"glyph_row={glyph_row}",
        f"glyph_column={glyph_column}",
        f"glyph_plane={glyph_plane}",
        f"comm_changed_bytes={len(comm_diffs)}",
        f"s3032_changed_offsets={','.join(f'0x{x:X}' for x in sorted(s3032_diffs))}",
        f"dialogue={EXPECTED_TEXT}",
        "preserved_s3032_slots=0,1,3",
        "psx_exe_changed=NO",
        "changed_members=COMM.IMG,31/S3032.DAT",
        "iso_built=NO",
        "runtime_status=PENDING_USER_TEST",
    ]
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")

    print(f"OUTPUT={OUTPUT}")
    print(f"SHA256={sha256(OUTPUT.read_bytes())}")
    print(f"COMM_SHA256={sha256(members[COMM_MEMBER])}")
    print(f"S3032_SHA256={sha256(members[S3032_MEMBER])}")
    print(f"COMM_CHANGED_BYTES={len(comm_diffs)}")
    print(
        "S3032_CHANGED_OFFSETS="
        + ",".join(f"0x{x:X}" for x in sorted(s3032_diffs))
    )
    print(f"REPORT={REPORT}")


if __name__ == "__main__":
    main()
