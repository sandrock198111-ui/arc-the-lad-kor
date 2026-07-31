#!/usr/bin/env python3
"""Build v0.39 with a safe circle icon and repaired battle HUD labels."""

from __future__ import annotations

import csv
import hashlib
import shutil
import struct
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output" / "ui_safe_v38_cumulative_patch_only.zip"
V37 = ROOT / "03_output" / "ui_safe_v37_cumulative_patch_only.zip"
OUTPUT = ROOT / "03_output" / "ui_safe_v39_cumulative_patch_only.zip"
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_safe_v39"
REPORT = ANALYSIS / "build_report.txt"
ICON_AUDIT = ANALYSIS / "icon_relocation_audit.csv"
HUD_AUDIT = ANALYSIS / "battle_hud_label_audit.csv"

BASE_ZIP_HASH = "D66E6F4F780E3096B604C7699E3E7EB00392EE7C0C4FA457AEDE3F61EEFD45D9"
BASE_PSX_HASH = "2FCBA5A1737A59FAA570F04B05668945FA67508B1A61EB549C755BCB9EF131C9"
BASE_COMM_HASH = "882B2C4A900AAA4D1D92143C7187D4E99C9A40F76FE910486CC105FA6EBE1FAC"
V37_COMM_HASH = "FB6D4027023C6A75A1561D72507C52656472B4F31E1EB92B73965CA3B51543EA"

PSX_TARGET = "PSX.EXE"
FONT_TARGET = "COMM.IMG"
ORIGINAL_EXE = ROOT / "01_work" / "PSX.EXE"
ORIGINAL_FONT = ROOT / "01_work" / "COMM.IMG"
PSX_LOAD_BASE = 0x8011A800
ROW_BYTES = 0x380

ICON_U_OFFSET = 0x80214
EXPECTED_ICON_U = 0x00
NEW_ICON_U = 0x18
ICON_SOURCE = (114, 354)
FAILED_DESTINATION = (0, 130)
WORKING_X_DESTINATION = (12, 130)
NEW_DESTINATION = (24, 130)
ICON_WIDTH = 12
ICON_HEIGHT = 12

HUD_POINTERS = (0x823AC, 0x823B0, 0x823B4, 0x823B8, 0x823BC)
HUD_OLD_SOURCES = (0x82390, 0x82394, 0x82398, 0x8239C, 0x823A0)
HUD_NEW_SOURCES = (0x820A8, 0x820AC, 0x820B0, 0x820B4, 0x820B8)
HUD_PAYLOADS = (
    bytes.fromhex("6C 00 00 00"),       # compact LV; V pointer is intentionally empty
    bytes.fromhex("00 00 00 00"),
    bytes.fromhex("DD B2 00 00"),      # original auxiliary HUD label
    bytes.fromhex("01 DE 4F 00"),      # original M label
    bytes.fromhex("DD 90 00 00"),      # original P label
)
HUD_LABELS = ("LV", "empty V tail", "original auxiliary", "M", "P")
EXPECTED_ORIGINAL_HUD = (
    bytes.fromhex("01 DF 60 00"),
    bytes.fromhex("90 70 00 00"),
    bytes.fromhex("DD B2 00 00"),
    bytes.fromhex("01 DE 4F 00"),
    bytes.fromhex("DD 90 00 00"),
)

MANIFESTS = (
    ("ui_safe_v38.csv", "ui_safe_v39.csv"),
    ("ui_skill_guide_reference_v38.csv", "ui_skill_guide_reference_v39.csv"),
    ("ui_system_v38.csv", "ui_system_v39.csv"),
    ("ui_battle_choice_v38.csv", "ui_battle_choice_v39.csv"),
    ("ui_world_name_v38.csv", "ui_world_name_v39.csv"),
    ("ui_items_equipment_skills_v38_review.csv", "ui_items_equipment_skills_v39_review.csv"),
    ("ui_nonstory_system_v38.csv", "ui_nonstory_system_v39.csv"),
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def get_pixel(data: bytes | bytearray, x: int, y: int) -> int:
    value = data[y * ROW_BYTES + x // 2]
    return value & 0x0F if x % 2 == 0 else value >> 4


def set_pixel(data: bytearray, x: int, y: int, value: int) -> None:
    offset = y * ROW_BYTES + x // 2
    if x % 2 == 0:
        data[offset] = (data[offset] & 0xF0) | (value & 0x0F)
    else:
        data[offset] = (data[offset] & 0x0F) | ((value & 0x0F) << 4)


def rectangle(data: bytes | bytearray, x: int, y: int) -> tuple[int, ...]:
    return tuple(
        get_pixel(data, x + dx, y + dy)
        for dy in range(ICON_HEIGHT)
        for dx in range(ICON_WIDTH)
    )


def write_rectangle(data: bytearray, destination: tuple[int, int], pixels: tuple[int, ...]) -> None:
    for dy in range(ICON_HEIGHT):
        for dx in range(ICON_WIDTH):
            set_pixel(
                data,
                destination[0] + dx,
                destination[1] + dy,
                pixels[dy * ICON_WIDTH + dx],
            )


def code_for(row: int, column: int, plane: int) -> bytes:
    index = row * 84 + column * 4 + plane
    number = index - 0xDB
    return bytes((0xDD + number // 255, number % 255))


def assert_icon_destination_unassigned() -> str:
    assigned: set[bytes] = set()
    for name in ("korean_charmap.csv", "korean_charmap_extended.csv"):
        with (ROOT / "05_docs" / name).open(encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                if row["code_hex"]:
                    assigned.add(bytes.fromhex(row["code_hex"]))
    codes = [
        code_for(font_row, NEW_DESTINATION[0] // 12, plane)
        for font_row in (10, 11)
        for plane in range(4)
    ]
    overlap = assigned.intersection(codes)
    if overlap:
        raise SystemExit("new circle icon destination overlaps assigned glyphs")
    return " ".join(code.hex().upper() for code in codes)


def glyph_index(code: bytes) -> int:
    if len(code) == 1:
        return code[0] - 1
    return 0xDB + (code[0] - 0xDD) * 255 + code[1]


def plane(data: bytes, code: bytes) -> bytes:
    index = glyph_index(code)
    row, remainder = divmod(index, 84)
    column, bitplane = divmod(remainder, 4)
    bit = 1 << bitplane
    return bytes(
        1 if get_pixel(data, column * 12 + x, row * 12 + y) & bit else 0
        for y in range(12)
        for x in range(12)
    )


def copy_manifests() -> None:
    for source_name, target_name in MANIFESTS:
        source = ROOT / "05_docs" / source_name
        target = ROOT / "05_docs" / target_name
        shutil.copyfile(source, target)

    manifest = ROOT / "05_docs" / "ui_nonstory_system_v39.csv"
    with manifest.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
        fields = list(rows[0])
    additions = [
        {
            "pointer_offset": f"0x{pointer:X}",
            "source_offset": f"0x{old:X}",
            "new_offset": f"0x{new:X}",
            "japanese": label,
            "korean": label,
            "status": "battle_hud_pointer_repaired",
            "encoded_bytes": str(len(payload.rstrip(b"\x00"))),
            "encoded_hex": payload.rstrip(b"\x00").hex(" ").upper(),
        }
        for pointer, old, new, payload, label in zip(
            HUD_POINTERS, HUD_OLD_SOURCES, HUD_NEW_SOURCES, HUD_PAYLOADS, HUD_LABELS
        )
    ]
    rows.extend(additions)
    with manifest.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_ZIP_HASH:
        raise SystemExit("v0.38 base ZIP hash differs")

    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        files = {info.filename: archive.read(info.filename) for info in infos}
    with ZipFile(V37) as archive:
        v37_font = archive.read(FONT_TARGET)

    if digest(files[PSX_TARGET]) != BASE_PSX_HASH:
        raise SystemExit("v0.38 PSX.EXE hash differs")
    if digest(files[FONT_TARGET]) != BASE_COMM_HASH:
        raise SystemExit("v0.38 COMM.IMG hash differs")
    if digest(v37_font) != V37_COMM_HASH:
        raise SystemExit("v0.37 COMM.IMG hash differs")

    executable = bytearray(files[PSX_TARGET])
    font = bytearray(files[FONT_TARGET])
    original_exe = ORIGINAL_EXE.read_bytes()
    original_font = ORIGINAL_FONT.read_bytes()
    before_exe = bytes(executable)
    before_font = bytes(font)

    if executable[ICON_U_OFFSET] != EXPECTED_ICON_U:
        raise SystemExit("v0.38 circle icon U differs")
    if rectangle(font, *WORKING_X_DESTINATION) != rectangle(font, 162, 354):
        raise SystemExit("working X icon changed before v0.39")

    destination_codes = assert_icon_destination_unassigned()
    write_rectangle(font, FAILED_DESTINATION, rectangle(v37_font, *FAILED_DESTINATION))
    circle_pixels = rectangle(font, *ICON_SOURCE)
    if circle_pixels != rectangle(original_font, 130, 130):
        raise SystemExit("verified circle duplicate differs from original")
    write_rectangle(font, NEW_DESTINATION, circle_pixels)
    executable[ICON_U_OFFSET] = NEW_ICON_U

    if rectangle(font, *NEW_DESTINATION) != circle_pixels:
        raise SystemExit("new circle icon destination readback differs")
    if rectangle(font, *FAILED_DESTINATION) != rectangle(v37_font, *FAILED_DESTINATION):
        raise SystemExit("failed U=0 destination was not restored")
    if rectangle(font, *WORKING_X_DESTINATION) != rectangle(before_font, *WORKING_X_DESTINATION):
        raise SystemExit("working X icon regressed")

    for source, expected in zip(HUD_OLD_SOURCES, EXPECTED_ORIGINAL_HUD):
        if original_exe[source : source + 4] != expected:
            raise SystemExit(f"original HUD label differs at 0x{source:X}")
    for code in (bytes.fromhex("DE4F"), bytes.fromhex("DD90"), bytes.fromhex("DDB2")):
        if plane(original_font, code) != plane(bytes(font), code):
            raise SystemExit(f"preserved original HUD glyph changed: {code.hex().upper()}")

    pool_start = min(HUD_NEW_SOURCES)
    pool_end = max(source + len(payload) for source, payload in zip(HUD_NEW_SOURCES, HUD_PAYLOADS))
    if any(executable[pool_start:pool_end]):
        raise SystemExit("v0.39 HUD allocation is not empty")

    hud_rows: list[dict[str, object]] = []
    for pointer, old_source, new_source, payload, label in zip(
        HUD_POINTERS, HUD_OLD_SOURCES, HUD_NEW_SOURCES, HUD_PAYLOADS, HUD_LABELS
    ):
        expected_pointer = PSX_LOAD_BASE + old_source
        if struct.unpack_from("<I", executable, pointer)[0] != expected_pointer:
            raise SystemExit(f"HUD pointer differs at 0x{pointer:X}")
        executable[new_source : new_source + len(payload)] = payload
        struct.pack_into("<I", executable, pointer, PSX_LOAD_BASE + new_source)
        if executable[new_source : new_source + len(payload)] != payload:
            raise SystemExit(f"HUD payload readback differs at 0x{new_source:X}")
        hud_rows.append(
            {
                "pointer_offset": f"0x{pointer:X}",
                "old_source": f"0x{old_source:X}",
                "new_source": f"0x{new_source:X}",
                "label": label,
                "payload_hex": payload.hex(" ").upper(),
                "status": "repointed_safe_pool",
            }
        )

    files[PSX_TARGET] = bytes(executable)
    files[FONT_TARGET] = bytes(font)

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    with ICON_AUDIT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "icon_id", "old_u", "new_u", "destination", "unassigned_codes",
                "working_x_preserved", "status",
            ),
        )
        writer.writeheader()
        writer.writerow(
            {
                "icon_id": "E7_02",
                "old_u": "0x00",
                "new_u": "0x18",
                "destination": "24,130",
                "unassigned_codes": destination_codes,
                "working_x_preserved": "yes",
                "status": "relocated_away_from_u_zero_boundary",
            }
        )
    with HUD_AUDIT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=tuple(hud_rows[0]))
        writer.writeheader()
        writer.writerows(hud_rows)

    copy_manifests()
    with ZipFile(OUTPUT, "w", ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(info, files[info.filename])

    # The member comparison is explicit to avoid trusting generated metadata.
    with ZipFile(BASE) as archive:
        changed_members = [name for name in files if files[name] != archive.read(name)]
    if changed_members != [FONT_TARGET, PSX_TARGET]:
        raise SystemExit(f"unexpected changed members: {changed_members}")

    psx_changed = [i for i, (a, b) in enumerate(zip(before_exe, executable)) if a != b]
    font_changed = [i for i, (a, b) in enumerate(zip(before_font, font)) if a != b]
    REPORT.write_text(
        "UI safe v0.39 cumulative circle-icon and battle-HUD repair\n"
        f"base_zip_sha256={BASE_ZIP_HASH}\n"
        f"output_zip_sha256={digest(OUTPUT.read_bytes())}\n"
        f"psx_sha256={digest(bytes(executable))}\n"
        f"comm_sha256={digest(bytes(font))}\n"
        f"changed_members={','.join(changed_members)}\n"
        f"psx_changed_bytes={len(psx_changed)}\n"
        f"comm_changed_bytes={len(font_changed)}\n"
        "circle_icon=E7_02 U=0x18 destination=(24,130)\n"
        "cross_icon=E7_03 preserved byte-identical\n"
        "battle_hud=LV combined label plus original M/P labels\n"
        "v38_help_payload=preserved\n"
        "v38_lv_plane=preserved\n",
        encoding="utf-8",
    )
    print(f"wrote {OUTPUT}")
    print(f"sha256 {digest(OUTPUT.read_bytes())}")
    print(f"changed members: {', '.join(changed_members)}")


if __name__ == "__main__":
    main()
