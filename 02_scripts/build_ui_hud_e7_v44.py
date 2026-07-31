#!/usr/bin/env python3
"""Build the focused v0.44 HUD-LV and E7 button-icon repair.

The immutable v0.43 cumulative ZIP is the rollback base.  This builder changes
only the PSX.EXE bytes proven by runtime save-state packet inspection.
"""

from __future__ import annotations

import copy
import csv
import hashlib
import io
import struct
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE_ZIP = ROOT / "03_output" / "ui_runtime_repairs_v43_cumulative_patch_only.zip"
OUTPUT_ZIP = ROOT / "03_output" / "ui_hud_e7_v44_cumulative_patch_only.zip"
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_hud_e7_v44"
REPORT = ANALYSIS / "build_report.txt"
DIFF_AUDIT = ANALYSIS / "psx_diff_audit.csv"

BASE_ZIP_SHA256 = "ACA90EA9529C4D0000D68DC1563F5290DF8C1ABA68AB5E881FBCA103047CAF56"
BASE_PSX_SHA256 = "58382528E240E97DC92FE20AFB6BFF69C85F05FEC4AE8FB130CCA154B88CFE9C"
BASE_COMM_SHA256 = "AEFEE1EDD4FB2B00DF1533C745C0E8AE3A78A96D5CD0C7302F65B2456E8626F6"

PSX_NAME = "PSX.EXE"
COMM_NAME = "COMM.IMG"
PSX_LOAD_BASE = 0x8011A800

ICON_TABLE = 0x80210
ICON_INDEX_1_U = ICON_TABLE + 2  # E7 02: decision/confirm
ICON_INDEX_2_U = ICON_TABLE + 4  # E7 03: cancel/back
ICON_INDEX_3_U = ICON_TABLE + 6  # unrelated next icon
ICON_STUB = 0x82134

HUD_LV_SOURCE = 0x82154
HUD_EMPTY_SOURCE = 0x82168
HUD_POINTER_1 = 0x823AC
HUD_POINTER_2 = 0x823B0

EXPECTED_ICON_TABLE = bytes.fromhex(
    "62 0C 72 0C B4 0C C0 0C A2 0C B2 0C C2 0C D2 14"
)
EXPECTED_ICON_STUB = bytes.fromhex(
    "FC FF 68 24 03 00 08 2D 02 00 00 15 E4 00 02 34 "
    "82 00 02 34 29 00 02 A2 B4 AD 05 08 00 00 00 00"
)
EXPECTED_HUD_RESERVE = bytes.fromhex(
    "6C 00 00 00 00 00 00 00 DD B2 00 00 01 DE 4F 00 "
    "DD 90 00 00 00 00 00 00"
)
EXPECTED_HUD_POINTERS = bytes.fromhex(
    "54 C9 19 80 58 C9 19 80 5C C9 19 80 60 C9 19 80 64 C9 19 80"
)

# v0.42/v0.43 already contain these two clean 12x12 images in COMM.IMG.
# Runtime proves x=180 is the working X/back icon.  The other clean icon is at
# x=192; v0.44 corrects the table index so E7 02 actually selects it.
ICON_V = 228
DECISION_DESTINATION = (192, ICON_V)
BACK_DESTINATION = (180, ICON_V)
DECISION_CLEAN_SOURCE = (162, 354)
BACK_CLEAN_SOURCE = (114, 354)
ICON_WIDTH = 12
ICON_HEIGHT = 12
COMM_ROW_BYTES = 0x380

ALLOWED_DIFF_OFFSETS = {
    ICON_INDEX_1_U,
    ICON_INDEX_3_U,
    ICON_STUB,
    HUD_LV_SOURCE,
    HUD_LV_SOURCE + 1,
    HUD_LV_SOURCE + 2,
    HUD_LV_SOURCE + 3,
    HUD_POINTER_2,
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def physical_code_for(char: str) -> bytes:
    with (ROOT / "05_docs" / "ui_glyph_store_v42_map.csv").open(
        encoding="utf-8-sig", newline=""
    ) as handle:
        for row in csv.DictReader(handle):
            if row["char"] == char:
                return bytes.fromhex(row["virtual_code_hex"])
    raise SystemExit(f"v0.42 virtual code missing for {char!r}")


def rectangle(data: bytes, x: int, y: int, width: int, height: int) -> bytes:
    pixels = bytearray()
    for dy in range(height):
        row = (y + dy) * COMM_ROW_BYTES
        for dx in range(width):
            value = data[row + (x + dx) // 2]
            pixels.append((value >> (4 * ((x + dx) & 1))) & 0x0F)
    return bytes(pixels)


def clone_entries(base_bytes: bytes) -> list[tuple[zipfile.ZipInfo, bytes]]:
    with zipfile.ZipFile(io.BytesIO(base_bytes), "r") as archive:
        return [(copy.copy(info), archive.read(info.filename)) for info in archive.infolist()]


def zip_bytes(entries: list[tuple[zipfile.ZipInfo, bytes]]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", allowZip64=True) as archive:
        for info, data in entries:
            archive.writestr(copy.copy(info), data)
    return output.getvalue()


def expect(data: bytes, offset: int, expected: bytes, label: str) -> None:
    actual = data[offset : offset + len(expected)]
    if actual != expected:
        raise SystemExit(
            f"{label} differs at 0x{offset:X}: "
            f"expected {expected.hex(' ')}, got {actual.hex(' ')}"
        )


def main() -> None:
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    base_zip_bytes = BASE_ZIP.read_bytes()
    if sha256(base_zip_bytes) != BASE_ZIP_SHA256:
        raise SystemExit("v0.43 rollback-base ZIP hash differs")

    entries = clone_entries(base_zip_bytes)
    by_name = {info.filename: data for info, data in entries}
    if sha256(by_name[PSX_NAME]) != BASE_PSX_SHA256:
        raise SystemExit("v0.43 PSX.EXE hash differs")
    if sha256(by_name[COMM_NAME]) != BASE_COMM_SHA256:
        raise SystemExit("v0.43 COMM.IMG hash differs")

    base_psx = by_name[PSX_NAME]
    base_comm = by_name[COMM_NAME]
    expect(base_psx, ICON_TABLE, EXPECTED_ICON_TABLE, "E7 icon table")
    expect(base_psx, ICON_STUB, EXPECTED_ICON_STUB, "E7 V-coordinate stub")
    expect(base_psx, HUD_LV_SOURCE, EXPECTED_HUD_RESERVE, "HUD reserve")
    expect(base_psx, HUD_POINTER_1, EXPECTED_HUD_POINTERS, "HUD pointers")

    if rectangle(base_comm, *DECISION_DESTINATION, ICON_WIDTH, ICON_HEIGHT) != rectangle(
        base_comm, *DECISION_CLEAN_SOURCE, ICON_WIDTH, ICON_HEIGHT
    ):
        raise SystemExit("decision icon destination differs from its clean source")
    if rectangle(base_comm, *BACK_DESTINATION, ICON_WIDTH, ICON_HEIGHT) != rectangle(
        base_comm, *BACK_CLEAN_SOURCE, ICON_WIDTH, ICON_HEIGHT
    ):
        raise SystemExit("back icon destination differs from its clean source")

    executable = bytearray(base_psx)

    # E7 02/03 arrive at table indices 1/2, not 2/3.  Preserve the accepted
    # index-2 X icon, route index 1 to the existing decision image, and restore
    # unrelated index 3 to its original U coordinate.
    executable[ICON_INDEX_1_U] = DECISION_DESTINATION[0]
    executable[ICON_INDEX_3_U] = 0x0C
    executable[ICON_STUB] = 0xFE  # addiu t0,v1,-2; even v1 values 2 and 4 match

    lv = physical_code_for("L") + physical_code_for("V") + b"\x00"
    if lv != bytes.fromhex("EA 9A EA 9B 00"):
        raise SystemExit(f"unexpected virtual LV payload: {lv.hex(' ')}")
    executable[HUD_LV_SOURCE : HUD_LV_SOURCE + 8] = lv + b"\x00" * 3
    struct.pack_into("<I", executable, HUD_POINTER_2, PSX_LOAD_BASE + HUD_EMPTY_SOURCE)

    # The active skill HUD reads pointer 1 as one string.  Pointer 2 remains an
    # empty auxiliary string at the zero-filled reserve tail.
    if executable[HUD_LV_SOURCE : HUD_LV_SOURCE + 5] != lv:
        raise SystemExit("HUD LV readback differs")
    if executable[HUD_EMPTY_SOURCE] != 0:
        raise SystemExit("relocated empty HUD string is not empty")
    if struct.unpack_from("<I", executable, HUD_POINTER_1)[0] != PSX_LOAD_BASE + HUD_LV_SOURCE:
        raise SystemExit("HUD pointer 1 changed unexpectedly")
    if struct.unpack_from("<I", executable, HUD_POINTER_2)[0] != PSX_LOAD_BASE + HUD_EMPTY_SOURCE:
        raise SystemExit("HUD pointer 2 readback differs")

    # Simulate the corrected E7 table/stub contract.
    icon_contract = {
        "E7 02 decision": (executable[ICON_INDEX_1_U], ICON_V),
        "E7 03 back": (executable[ICON_INDEX_2_U], ICON_V),
        "next icon": (executable[ICON_INDEX_3_U], 130),
    }
    expected_contract = {
        "E7 02 decision": DECISION_DESTINATION,
        "E7 03 back": BACK_DESTINATION,
        "next icon": (12, 130),
    }
    if icon_contract != expected_contract:
        raise SystemExit(f"E7 icon contract differs: {icon_contract!r}")

    diff_rows: list[dict[str, object]] = []
    for offset, (before, after) in enumerate(zip(base_psx, executable)):
        if before == after:
            continue
        if offset not in ALLOWED_DIFF_OFFSETS:
            raise SystemExit(f"PSX.EXE changed outside v0.44 declaration at 0x{offset:X}")
        diff_rows.append(
            {
                "offset": f"0x{offset:X}",
                "before": f"{before:02X}",
                "after": f"{after:02X}",
            }
        )
    if {int(row["offset"], 16) for row in diff_rows} != ALLOWED_DIFF_OFFSETS:
        raise SystemExit("v0.44 did not change exactly the declared PSX.EXE bytes")

    changed_entries: list[tuple[zipfile.ZipInfo, bytes]] = []
    for info, data in entries:
        changed_entries.append((info, bytes(executable) if info.filename == PSX_NAME else data))
    built_once = zip_bytes(changed_entries)
    built_twice = zip_bytes(changed_entries)
    if built_once != built_twice:
        raise SystemExit("ZIP build is not deterministic")
    OUTPUT_ZIP.write_bytes(built_once)

    with DIFF_AUDIT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=("offset", "before", "after"))
        writer.writeheader()
        writer.writerows(diff_rows)

    output_hash = sha256(built_once)
    output_psx_hash = sha256(bytes(executable))
    report_lines = [
        "version=v0.44",
        f"base_zip={BASE_ZIP}",
        f"base_zip_sha256={BASE_ZIP_SHA256}",
        f"output_zip={OUTPUT_ZIP}",
        f"output_zip_sha256={output_hash}",
        f"output_psx_sha256={output_psx_hash}",
        f"comm_sha256={sha256(base_comm)}",
        "changed_members=PSX.EXE",
        f"changed_psx_bytes={len(diff_rows)}",
        "hud_lv=EA 9A EA 9B 00 via pointer 1",
        "hud_pointer_2=relocated empty string at 0x82168",
        "e7_02=U192,V228 decision icon",
        "e7_03=U180,V228 back icon",
        "e7_next=U12,V130 restored",
        "comm_img=byte-identical to v0.43",
        "deterministic_build=PASS",
        "runtime_status=PENDING_USER_PACKAGE_TEST",
    ]
    REPORT.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    print("\n".join(report_lines))


if __name__ == "__main__":
    main()
