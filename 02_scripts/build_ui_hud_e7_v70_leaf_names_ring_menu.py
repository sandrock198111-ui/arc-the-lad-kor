"""Build the v70 patch from the verified v69 patch-only archive.

This is intentionally narrow:
- point the two item-name occurrences of "잎" at v69's dedicated leaf glyph;
- replace the malformed battle help label with "명령 링 열기";
- preserve COMM.IMG and every DAT file byte-for-byte.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
BASE = (
    ROOT
    / "ex"
    / "코덱스"
    / "ui_hud_e7_v69_leaf_glyph_manual_pixel_fix_patch_only.zip"
)
OUTPUT = ROOT / "03_output" / "ui_hud_e7_v70_leaf_names_ring_menu_patch_only.zip"
REPORT = ROOT / "01_work" / "analysis" / "ui_hud_e7_v70" / "build_report.txt"

BASE_SHA256 = "1EF230C7DD36717B0EC6C42F172C98F35D6093C5B417B2041821A07590D8DDE4"
PSX_MEMBER = "PSX.EXE"
PSX_LOAD_BASE = 0x8011A800

LEAF_NAME_OFFSETS = (0x80A81, 0x80A91)
OLD_LEAF_CODE = bytes.fromhex("EA 66")
DEDICATED_LEAF_CODE = bytes.fromhex("E9 75")

HELP_POINTER_OFFSET = 0x8234C
HELP_OFFSET = 0x82780
HELP_SLOT_END = 0x827A0
OLD_HELP = bytes.fromhex(
    "E7 02 E0 C6 E0 40 DF E2 9C E7 05 E9 51 9C E0 B2 E0 AC"
)
# ○공격, □명령 링 열기.  The known-good icon, punctuation, and legacy
# "열기" bytes are retained; only the malformed label is replaced.
NEW_HELP = bytes.fromhex(
    "E7 02 E0 C6 E0 40 DF E2 9C E7 05 "
    "E9 5E E9 48 9C EA 3C 9C E0 B2 E0 AC"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


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
        raise SystemExit("v69 base archive hash differs")

    with ZipFile(BASE, "r") as source:
        infos = source.infolist()
        members = {info.filename: source.read(info.filename) for info in infos}

    if PSX_MEMBER not in members:
        raise SystemExit("PSX.EXE is missing from v69 archive")

    original = members[PSX_MEMBER]
    psx = bytearray(original)

    for offset in LEAF_NAME_OFFSETS:
        if psx[offset : offset + 2] != OLD_LEAF_CODE:
            raise SystemExit(f"unexpected leaf code at 0x{offset:X}")
        psx[offset : offset + 2] = DEDICATED_LEAF_CODE

    pointer_target = struct.unpack_from("<I", psx, HELP_POINTER_OFFSET)[0]
    expected_target = PSX_LOAD_BASE + HELP_OFFSET
    if pointer_target != expected_target:
        raise SystemExit(
            f"help pointer differs: 0x{pointer_target:08X} != 0x{expected_target:08X}"
        )
    if psx[HELP_OFFSET : HELP_OFFSET + len(OLD_HELP)] != OLD_HELP:
        raise SystemExit("battle help source bytes differ")
    if psx[HELP_OFFSET + len(OLD_HELP)] != 0:
        raise SystemExit("battle help source is not NUL-terminated")

    slot_size = HELP_SLOT_END - HELP_OFFSET
    if len(NEW_HELP) + 1 > slot_size:
        raise SystemExit("new battle help does not fit its reserved slot")
    psx[HELP_OFFSET:HELP_SLOT_END] = NEW_HELP + bytes(slot_size - len(NEW_HELP))
    members[PSX_MEMBER] = bytes(psx)

    changed_members = [
        name for name, data in members.items() if data != (
            original if name == PSX_MEMBER else data
        )
    ]
    if changed_members != [PSX_MEMBER]:
        raise SystemExit(f"unexpected changed members: {changed_members}")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as target:
        for info in infos:
            target.writestr(clone_info(info), members[info.filename])

    # Independent readback from the completed archive.
    with ZipFile(OUTPUT, "r") as built:
        built_members = {info.filename: built.read(info.filename) for info in built.infolist()}
    built_psx = built_members[PSX_MEMBER]
    for offset in LEAF_NAME_OFFSETS:
        if built_psx[offset : offset + 2] != DEDICATED_LEAF_CODE:
            raise SystemExit(f"leaf readback failed at 0x{offset:X}")
    if built_psx[HELP_OFFSET : HELP_OFFSET + len(NEW_HELP)] != NEW_HELP:
        raise SystemExit("battle help readback failed")
    if built_psx[HELP_OFFSET + len(NEW_HELP)] != 0:
        raise SystemExit("battle help terminator readback failed")

    unchanged = [name for name in members if name != PSX_MEMBER]
    for name in unchanged:
        if built_members[name] != members[name]:
            raise SystemExit(f"non-PSX member changed: {name}")

    diff_offsets = [
        index
        for index, (before, after) in enumerate(zip(original, built_psx))
        if before != after
    ]
    expected_leaf_diffs = {
        offset + delta for offset in LEAF_NAME_OFFSETS for delta in range(2)
    }
    help_diffs = {
        index
        for index in range(HELP_OFFSET, HELP_SLOT_END)
        if original[index] != built_psx[index]
    }
    expected_diffs = expected_leaf_diffs | help_diffs
    if set(diff_offsets) != expected_diffs:
        raise SystemExit("PSX.EXE changed outside the approved offsets")

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        "\n".join(
            [
                "ui_hud_e7_v70 build report",
                f"base={BASE}",
                f"base_sha256={BASE_SHA256}",
                f"output={OUTPUT}",
                f"output_sha256={sha256(OUTPUT.read_bytes())}",
                f"psx_before_sha256={sha256(original)}",
                f"psx_after_sha256={sha256(built_psx)}",
                "changed_members=PSX.EXE",
                "unchanged_members=" + ",".join(unchanged),
                "leaf_offsets=" + ",".join(f"0x{x:X}" for x in LEAF_NAME_OFFSETS),
                "leaf_code=EA 66 -> E9 75",
                f"help_pointer_offset=0x{HELP_POINTER_OFFSET:X}",
                f"help_string_offset=0x{HELP_OFFSET:X}",
                f"help_payload_bytes={len(NEW_HELP)}",
                f"help_slot_bytes={slot_size}",
                f"help_free_bytes={slot_size - len(NEW_HELP) - 1}",
                f"psx_diff_byte_count={len(diff_offsets)}",
                "static_readback=PASS",
                "runtime_verification=PENDING",
                "",
            ]
        ),
        encoding="utf-8",
    )

    print(OUTPUT)
    print(f"SHA256 {sha256(OUTPUT.read_bytes())}")
    print(f"PSX diff bytes {len(diff_offsets)}")
    print(f"Help slot free bytes {slot_size - len(NEW_HELP) - 1}")


if __name__ == "__main__":
    main()
