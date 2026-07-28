"""Build v84 by preserving the v83 P6 sidecar code across startup BSS clear.

v83 placed its helper routines and 12-byte sidecar in the original zero tail
at 0x801A86E8-0x801A87FF. The executable startup loop clears that exact range,
so the helpers become NOPs before the first dialogue is rendered. This build
moves only the BSS clear start to 0x801A8800, immediately after the reserved
tail. All v83 renderer, font, story, and test-data bytes remain unchanged.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from build_ui_hud_e7_v83_p6_sidecar_renderer import (
    SIDECAR_ADDRESS,
    TAIL_CAVE_END,
    TAIL_CAVE_START,
    build_glyph_helper,
    build_marker_helper,
)


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output" / "ui_hud_e7_v83_p6_sidecar_renderer_test_patch_only.zip"
OUTPUT = (
    ROOT
    / "03_output"
    / "ui_hud_e7_v84_p6_sidecar_bss_boundary_fix_patch_only.zip"
)
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_hud_e7_v84"
REPORT = ANALYSIS / "build_report.txt"

BASE_SHA256 = "CFC4B7791E3A4341D6DD39B7BE3EC8A1BBC471E31C62AD08F80CF8D0EA51D84D"
BASE_PSX_SHA256 = "BE241B18DAD853D3970C0877760E9FCFA1EADBEC125349EFE3391A637E289968"
PSX_MEMBER = "PSX.EXE"
PSX_LOAD_BASE = 0x8011A800

STARTUP_CLEAR_INSTRUCTION = 0x801757C0
OLD_CLEAR_START = 0x801A86E8
NEW_CLEAR_START = TAIL_CAVE_END
EXPECTED_OLD_WORD = 0x244286E8  # addiu v0,v0,-0x7918
NEW_WORD = 0x24428800           # addiu v0,v0,-0x7800


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def file_offset(address: int) -> int:
    offset = address - PSX_LOAD_BASE
    if not 0 <= offset < 0x8E000:
        raise ValueError(f"address outside PSX.EXE: 0x{address:08X}")
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
    if sha256(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v83 base archive hash differs")

    with ZipFile(BASE, "r") as source:
        infos = source.infolist()
        members = {info.filename: source.read(info.filename) for info in infos}

    original_psx = members[PSX_MEMBER]
    if sha256(original_psx) != BASE_PSX_SHA256:
        raise SystemExit("v83 PSX.EXE hash differs")

    psx = bytearray(original_psx)
    clear_offset = file_offset(STARTUP_CLEAR_INSTRUCTION)
    old_word = struct.unpack_from("<I", psx, clear_offset)[0]
    if old_word != EXPECTED_OLD_WORD:
        raise SystemExit(
            f"startup clear instruction differs: 0x{old_word:08X}"
        )

    glyph_helper = build_glyph_helper(TAIL_CAVE_START)
    marker_address = (TAIL_CAVE_START + len(glyph_helper) + 3) & ~3
    marker_helper = build_marker_helper(marker_address)
    marker_end = marker_address + len(marker_helper)
    if marker_end > SIDECAR_ADDRESS:
        raise SystemExit("v83 helper layout exceeds the sidecar")
    if SIDECAR_ADDRESS + 12 > NEW_CLEAR_START:
        raise SystemExit("v83 sidecar exceeds the new BSS boundary")

    glyph_slice = psx[
        file_offset(TAIL_CAVE_START) :
        file_offset(TAIL_CAVE_START) + len(glyph_helper)
    ]
    marker_slice = psx[
        file_offset(marker_address) :
        file_offset(marker_address) + len(marker_helper)
    ]
    sidecar_slice = psx[
        file_offset(SIDECAR_ADDRESS) : file_offset(SIDECAR_ADDRESS) + 12
    ]
    if glyph_slice != glyph_helper:
        raise SystemExit("v83 glyph helper differs")
    if marker_slice != marker_helper:
        raise SystemExit("v83 marker helper differs")
    if any(sidecar_slice):
        raise SystemExit("v83 sidecar initializer is not zero")

    struct.pack_into("<I", psx, clear_offset, NEW_WORD)
    members[PSX_MEMBER] = bytes(psx)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as target:
        for info in infos:
            target.writestr(clone_info(info), members[info.filename])

    with ZipFile(OUTPUT, "r") as built:
        readback_infos = built.infolist()
        readback = {
            info.filename: built.read(info.filename) for info in readback_infos
        }
    if readback != members:
        raise SystemExit("ZIP readback differs")
    if [info.filename for info in readback_infos] != [
        info.filename for info in infos
    ]:
        raise SystemExit("ZIP member order differs")

    changed_members = [
        name for name in members if members[name] != (
            original_psx if name == PSX_MEMBER else readback[name]
        )
    ]
    if changed_members != [PSX_MEMBER]:
        raise SystemExit(f"unexpected changed members: {changed_members}")

    changed_offsets = [
        index for index, (before, after) in enumerate(zip(original_psx, psx))
        if before != after
    ]
    expected_offsets = [
        clear_offset + index
        for index, (before, after) in enumerate(
            zip(
                struct.pack("<I", EXPECTED_OLD_WORD),
                struct.pack("<I", NEW_WORD),
            )
        )
        if before != after
    ]
    if changed_offsets != expected_offsets:
        raise SystemExit(
            f"unexpected PSX.EXE changes: {changed_offsets}"
        )

    # Model the startup clear loop and prove that it starts after all v83 data.
    if not (
        OLD_CLEAR_START <= TAIL_CAVE_START
        and marker_end <= SIDECAR_ADDRESS
        and SIDECAR_ADDRESS + 12 == NEW_CLEAR_START
    ):
        raise SystemExit("BSS-boundary proof failed")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        "\n".join(
            [
                "ui_hud_e7_v84 P6 sidecar BSS-boundary fix",
                f"base={BASE}",
                f"base_sha256={BASE_SHA256}",
                f"base_psx_sha256={BASE_PSX_SHA256}",
                f"output={OUTPUT}",
                f"output_sha256={sha256(OUTPUT.read_bytes())}",
                f"startup_instruction=0x{STARTUP_CLEAR_INSTRUCTION:08X}",
                f"old_clear_start=0x{OLD_CLEAR_START:08X}",
                f"new_clear_start=0x{NEW_CLEAR_START:08X}",
                f"glyph_helper=0x{TAIL_CAVE_START:08X}",
                f"marker_helper=0x{marker_address:08X}",
                f"marker_end=0x{marker_end:08X}",
                f"sidecar=0x{SIDECAR_ADDRESS:08X}-0x{SIDECAR_ADDRESS + 12:08X}",
                f"changed_psx_offsets={','.join(f'0x{x:X}' for x in changed_offsets)}",
                "changed_members=PSX.EXE",
                "all_other_v83_members_byte_identical=YES",
                "v83_helpers_readback=PASS",
                "bss_boundary_proof=PASS",
                "zip_readback=PASS",
                "runtime_verification=PENDING",
                "",
            ]
        ),
        encoding="utf-8",
    )

    print(OUTPUT)
    print(f"SHA256 {sha256(OUTPUT.read_bytes())}")
    print(f"PSX.EXE SHA256 {sha256(bytes(psx))}")
    print(
        f"clear_start 0x{OLD_CLEAR_START:08X} -> 0x{NEW_CLEAR_START:08X}"
    )
    print(f"changed_psx_bytes={len(changed_offsets)}")
    print("all_other_v83_members_byte_identical=YES")
    print("static_readback=PASS")


if __name__ == "__main__":
    main()
