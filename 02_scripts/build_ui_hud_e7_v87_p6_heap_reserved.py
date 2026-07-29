#!/usr/bin/env python3
"""Reserve the relocated P6 helper image from the PS1 heap.

v85/v86 copy a 0x114-byte helper image to the original BSS end at
0x801FE3C4. The untouched startup code then initializes the heap at
0x801FE3C8, overwriting the helper's second instruction. This build advances
the heap boundary by exactly 0x114 bytes. The existing size calculation uses
the same boundary, so the heap upper end stays unchanged.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
BASE = (
    ROOT
    / "03_output"
    / "ui_hud_e7_v86_p6_glyph_repack_slots_1_to_6_patch_only.zip"
)
OUTPUT = (
    ROOT
    / "03_output"
    / "ui_hud_e7_v87_p6_heap_reserved_patch_only.zip"
)
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_hud_e7_v87_p6_heap_reserved"
REPORT = ANALYSIS / "build_report.txt"

BASE_SHA256 = "41D7A246196D5D985B60C93A84E6D6D11E154F0C0D34EE2AED5BFD11C995678F"
BASE_PSX_SHA256 = "F7FB3A63023E3923395445A42AFA467F44E33416BE2E70A0CFD6EE0C3FD340D8"
PSX_MEMBER = "PSX.EXE"
PSX_LOAD_BASE = 0x8011A800

HELPER_START = 0x801FE3C4
HELPER_SIZE = 0x114
HELPER_END = HELPER_START + HELPER_SIZE
OLD_HEAP_START = HELPER_START + 4
NEW_HEAP_START = HELPER_END + 4

HEAP_BOUNDARY_INSTRUCTION = 0x80175810
EXPECTED_OLD_WORD = 0x2484E3C4  # addiu a0,a0,-0x1c3c
NEW_WORD = 0x2484E4D8  # addiu a0,a0,-0x1b28

SOURCE_HELPER_SECOND_WORD = 0x801A86F0
EXPECTED_HELPER_SECOND_WORD = 0x2463E4CC


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def file_offset(address: int) -> int:
    offset = address - PSX_LOAD_BASE
    if offset < 0:
        raise ValueError(f"address before PSX load base: 0x{address:08X}")
    return offset


def clone_info(info: ZipInfo) -> ZipInfo:
    copied = ZipInfo(info.filename, info.date_time)
    copied.compress_type = ZIP_DEFLATED
    copied.comment = info.comment
    copied.extra = info.extra
    copied.internal_attr = info.internal_attr
    copied.external_attr = info.external_attr
    copied.create_system = info.create_system
    copied.flag_bits = info.flag_bits
    return copied


def main() -> None:
    base_bytes = BASE.read_bytes()
    if sha256(base_bytes) != BASE_SHA256:
        raise SystemExit("v86 base ZIP hash differs")

    with ZipFile(BASE, "r") as source:
        infos = source.infolist()
        members = {info.filename: source.read(info.filename) for info in infos}

    original_members = dict(members)
    original_psx = members[PSX_MEMBER]
    if sha256(original_psx) != BASE_PSX_SHA256:
        raise SystemExit("v86 PSX.EXE hash differs")

    psx = bytearray(original_psx)
    patch_offset = file_offset(HEAP_BOUNDARY_INSTRUCTION)
    old_word = struct.unpack_from("<I", psx, patch_offset)[0]
    if old_word != EXPECTED_OLD_WORD:
        raise SystemExit(
            f"heap boundary instruction differs: 0x{old_word:08X}"
        )

    helper_word = struct.unpack_from(
        "<I", psx, file_offset(SOURCE_HELPER_SECOND_WORD)
    )[0]
    if helper_word != EXPECTED_HELPER_SECOND_WORD:
        raise SystemExit(
            f"source helper word differs: 0x{helper_word:08X}"
        )

    struct.pack_into("<I", psx, patch_offset, NEW_WORD)
    members[PSX_MEMBER] = bytes(psx)

    changed_members = [
        name for name in members if members[name] != original_members[name]
    ]
    if changed_members != [PSX_MEMBER]:
        raise SystemExit(f"unexpected changed members: {changed_members}")
    if len(psx) != len(original_psx):
        raise SystemExit("PSX.EXE size changed")

    byte_diffs = [
        index
        for index, (before, after) in enumerate(zip(original_psx, psx))
        if before != after
    ]
    expected_diffs = [patch_offset, patch_offset + 1]
    if byte_diffs != expected_diffs:
        raise SystemExit(
            f"unexpected PSX.EXE byte diffs: {byte_diffs}"
        )

    if NEW_HEAP_START <= HELPER_END:
        raise SystemExit("new heap still overlaps the helper image")
    if NEW_HEAP_START - OLD_HEAP_START != HELPER_SIZE:
        raise SystemExit("heap reservation size differs from helper size")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as target:
        for info in infos:
            target.writestr(clone_info(info), members[info.filename])

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
    report_lines = [
        "ui_hud_e7_v87 P6 heap reservation",
        f"base={BASE}",
        f"base_zip_sha256={BASE_SHA256}",
        f"base_psx_sha256={BASE_PSX_SHA256}",
        f"output={OUTPUT}",
        f"output_zip_sha256={sha256(OUTPUT.read_bytes())}",
        f"output_psx_sha256={sha256(members[PSX_MEMBER])}",
        f"helper_image=0x{HELPER_START:08X}-0x{HELPER_END - 1:08X}",
        f"helper_size=0x{HELPER_SIZE:X}",
        f"old_heap_start=0x{OLD_HEAP_START:08X}",
        f"new_heap_start=0x{NEW_HEAP_START:08X}",
        f"patched_instruction=0x{HEAP_BOUNDARY_INSTRUCTION:08X}",
        f"old_word=0x{EXPECTED_OLD_WORD:08X}",
        f"new_word=0x{NEW_WORD:08X}",
        f"psx_byte_diffs={','.join(f'0x{x:X}' for x in byte_diffs)}",
        "changed_members=PSX.EXE",
        "heap_upper_boundary_preserved=YES",
        "story_dat_changed=NO",
        "comm_img_changed=NO",
        "runtime_status=PENDING",
    ]
    REPORT.write_text("\n".join(report_lines) + "\n", encoding="utf-8")

    print(f"OUTPUT={OUTPUT}")
    print(f"SHA256={sha256(OUTPUT.read_bytes())}")
    print(f"PSX_SHA256={sha256(members[PSX_MEMBER])}")
    print(f"REPORT={REPORT}")
    print(f"DIFF_OFFSETS={','.join(f'0x{x:X}' for x in byte_diffs)}")


if __name__ == "__main__":
    main()
