"""Build v74 by fixing the v73 leaf-function return-address loop.

The glyph flag hook was installed with JAL inside a leaf function that does not
save RA.  That replaced the caller's return address with 0x8016B5E0, so the
function repeatedly returned to its own middle.  Keep the v73 dual-page work
unchanged and replace only that call/return pair with a non-linking trampoline.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output" / "ui_hud_e7_v73_dual_tpage_renderer_patch_only.zip"
OUTPUT = ROOT / "03_output" / "ui_hud_e7_v74_leaf_ra_trampoline_fix_patch_only.zip"
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_hud_e7_v74"
REPORT = ANALYSIS / "build_report.txt"

BASE_SHA256 = "70C3CA41D994589DFFD41859C198F0EF371F7A93E71C8196932297A67A4CAA23"
PSX_MEMBER = "PSX.EXE"
COMM_MEMBER = "COMM.IMG"
PSX_LOAD_BASE = 0x8011A800

GLYPH_FLAG_HOOK = 0x8016B5D8
GLYPH_FLAG_HELPER = 0x801A2094
GLYPH_FLAG_HELPER_RETURN = 0x801A20A8
GLYPH_FLAG_CONTINUE = 0x8016B5E0

# Slot 1 evidence from HASH-DF8E4CEB26B8ECFB_1.sav.
SLOT1_PC = 0x8016B60C
SLOT1_RA = 0x8016B5E0


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


def j(address: int) -> int:
    return 0x08000000 | ((address >> 2) & 0x03FFFFFF)


def jal(address: int) -> int:
    return 0x0C000000 | ((address >> 2) & 0x03FFFFFF)


def main() -> None:
    base_data = BASE.read_bytes()
    if sha256(base_data) != BASE_SHA256:
        raise SystemExit("v73 base archive hash differs")

    with ZipFile(BASE, "r") as source:
        infos = source.infolist()
        original = {info.filename: source.read(info.filename) for info in infos}

    psx = bytearray(original[PSX_MEMBER])
    hook_offset = file_offset(GLYPH_FLAG_HOOK)
    return_offset = file_offset(GLYPH_FLAG_HELPER_RETURN)

    expected_hook = struct.pack("<II", jal(GLYPH_FLAG_HELPER), 0)
    expected_return = struct.pack("<II", 0x03E00008, 0)  # jr ra; nop
    if psx[hook_offset : hook_offset + 8] != expected_hook:
        raise SystemExit("v73 glyph flag hook differs")
    if psx[return_offset : return_offset + 8] != expected_return:
        raise SystemExit("v73 glyph flag helper return differs")

    # A plain J does not modify RA.  The helper then jumps directly to the two
    # displaced-instruction continuation, leaving the caller's RA intact.
    struct.pack_into("<I", psx, hook_offset, j(GLYPH_FLAG_HELPER))
    struct.pack_into("<I", psx, return_offset, j(GLYPH_FLAG_CONTINUE))

    members = dict(original)
    members[PSX_MEMBER] = bytes(psx)
    changed_members = [name for name in members if members[name] != original[name]]
    if changed_members != [PSX_MEMBER]:
        raise SystemExit(f"unexpected changed members: {changed_members}")
    if members[COMM_MEMBER] != original[COMM_MEMBER]:
        raise SystemExit("COMM.IMG changed")

    changed_offsets = [
        index
        for index, (before, after) in enumerate(zip(original[PSX_MEMBER], psx))
        if before != after
    ]
    allowed_ranges = {
        *range(hook_offset, hook_offset + 4),
        *range(return_offset, return_offset + 4),
    }
    if any(offset not in allowed_ranges for offset in changed_offsets):
        raise SystemExit("PSX.EXE changed outside the two trampoline words")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as target:
        for info in infos:
            target.writestr(clone_info(info), members[info.filename])

    with ZipFile(OUTPUT, "r") as built:
        readback = {info.filename: built.read(info.filename) for info in built.infolist()}
    if readback != members:
        raise SystemExit("ZIP readback differs")

    built_psx = readback[PSX_MEMBER]
    expected_fixed_hook = struct.pack("<II", j(GLYPH_FLAG_HELPER), 0)
    expected_fixed_return = struct.pack("<II", j(GLYPH_FLAG_CONTINUE), 0)
    if built_psx[hook_offset : hook_offset + 8] != expected_fixed_hook:
        raise SystemExit("fixed hook readback differs")
    if built_psx[return_offset : return_offset + 8] != expected_fixed_return:
        raise SystemExit("fixed helper return readback differs")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        "\n".join(
            [
                "ui_hud_e7_v74 leaf RA trampoline fix build report",
                f"base={BASE}",
                f"base_sha256={BASE_SHA256}",
                f"output={OUTPUT}",
                f"output_sha256={sha256(OUTPUT.read_bytes())}",
                "changed_members=PSX.EXE",
                "unchanged_members=COMM.IMG and all DAT members",
                f"slot1_pc=0x{SLOT1_PC:08X}",
                f"slot1_ra=0x{SLOT1_RA:08X}",
                "diagnosis=JAL overwrote RA in a leaf glyph-builder function",
                f"hook=J 0x{GLYPH_FLAG_HELPER:08X}",
                f"helper_return=J 0x{GLYPH_FLAG_CONTINUE:08X}",
                f"changed_psx_bytes={len(changed_offsets)}",
                "change_scope=two MIPS instruction words only",
                "static_readback=PASS",
                "runtime_verification=PENDING",
                "v73_status=REJECTED_INFINITE_RETURN_LOOP",
                "",
            ]
        ),
        encoding="utf-8",
    )

    print(OUTPUT)
    print(f"SHA256 {sha256(OUTPUT.read_bytes())}")
    print(f"Changed PSX.EXE bytes {len(changed_offsets)}")
    print("COMM.IMG and all DAT members unchanged")


if __name__ == "__main__":
    main()
