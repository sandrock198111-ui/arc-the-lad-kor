#!/usr/bin/env python3
"""Build v0.38 with an isolated LV plane and relocated E7 button icons."""

from __future__ import annotations

import csv
import hashlib
import shutil
import struct
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output" / "ui_safe_v37_cumulative_patch_only.zip"
OUTPUT = ROOT / "03_output" / "ui_safe_v38_cumulative_patch_only.zip"
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_safe_v38"
REPORT = ANALYSIS / "build_report.txt"
ICON_AUDIT = ANALYSIS / "icon_relocation_audit.csv"
FONT_AUDIT = ANALYSIS / "font_plane_audit.csv"

BASE_ZIP_HASH = "0583FEED2266C883B413260114F331D73FAC12AE1C9A17EB123D559D9EB29AA1"
BASE_PSX_HASH = "80781088D34FFD41095C19C32A450DBFE96EEE4A313AE1884A1251B57EDE77CB"
BASE_COMM_HASH = "FB6D4027023C6A75A1561D72507C52656472B4F31E1EB92B73965CA3B51543EA"

PSX_TARGET = "PSX.EXE"
FONT_TARGET = "COMM.IMG"
ORIGINAL_FONT = ROOT / "01_work" / "COMM.IMG"
PSX_LOAD_BASE = 0x8011A800
ROW_BYTES = 0x380

# The E7 renderer samples 12x12 sprites from V=0x82 in this texture page.
ICON_TABLE = 0x80210
ICON_WIDTH = 12
ICON_HEIGHT = 12
ICON_Y = 0x82
ICON_SOURCES = {
    2: (114, 354),
    3: (162, 354),
}
ORIGINAL_ICON_POSITIONS = {
    2: (130, 130),
    3: (146, 130),
}
# Rows 10/11, columns 0/1 are unassigned in both Korean charmaps and unused by
# every current story/UI payload. Keeping V=0x82 avoids changing draw state.
ICON_DESTINATIONS = {
    2: (0, ICON_Y),
    3: (12, ICON_Y),
}

HELP_POINTER = 0x8235C
EXPECTED_HELP_TARGET = 0x82014
NEW_HELP_TARGET = 0x82094
EXPECTED_HELP_PAYLOAD = bytes.fromhex(
    "DF 86 E0 EB 9C DF 80 9C E0 D5 E0 9C E0 C0 E0 AC"
)
# [circle]결정 [cross]돌아가기. The icon primitive advances by its own width,
# so no extra blank is needed immediately after each E7 control.
NEW_HELP_PAYLOAD = bytes.fromhex(
    "E7 02 DF 86 E0 EB 9C E7 03 E0 D5 E0 9C E0 C0 E0 AC"
)

LV_CODE = 0x6C
LV_BITMAP = (
    "............",
    "............",
    ".#....#...#.",
    ".#....#...#.",
    ".#....#...#.",
    ".#....#...#.",
    ".#.....#.#..",
    ".#.....#.#..",
    ".####...#...",
    "............",
    "............",
    "............",
)

MANIFESTS = (
    ("ui_safe_v37.csv", "ui_safe_v38.csv"),
    ("ui_skill_guide_reference_v37.csv", "ui_skill_guide_reference_v38.csv"),
    ("ui_system_v37.csv", "ui_system_v38.csv"),
    ("ui_battle_choice_v37.csv", "ui_battle_choice_v38.csv"),
    ("ui_world_name_v37.csv", "ui_world_name_v38.csv"),
    ("ui_items_equipment_skills_v37_review.csv", "ui_items_equipment_skills_v38_review.csv"),
    ("ui_nonstory_system_v37.csv", "ui_nonstory_system_v38.csv"),
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


def code_for(row: int, column: int, plane: int) -> bytes:
    index = row * 84 + column * 4 + plane
    number = index - 0xDB
    return bytes((0xDD + number // 255, number % 255))


def assert_destinations_unassigned() -> list[dict[str, object]]:
    assigned: set[bytes] = set()
    for name in ("korean_charmap.csv", "korean_charmap_extended.csv"):
        with (ROOT / "05_docs" / name).open(encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                if row["code_hex"]:
                    assigned.add(bytes.fromhex(row["code_hex"]))

    rows: list[dict[str, object]] = []
    for icon_id, (x, _y) in ICON_DESTINATIONS.items():
        column = x // 12
        codes = [
            code_for(font_row, column, plane)
            for font_row in (10, 11)
            for plane in range(4)
        ]
        overlap = assigned.intersection(codes)
        if overlap:
            raise SystemExit(
                f"icon {icon_id} destination overlaps assigned glyphs: "
                + ",".join(code.hex().upper() for code in sorted(overlap))
            )
        rows.append(
            {
                "icon_id": icon_id,
                "destination_x": x,
                "destination_y": ICON_Y,
                "font_rows": "10,11",
                "font_column": column,
                "overlapped_codes": " ".join(code.hex().upper() for code in codes),
                "assigned_codes": 0,
                "status": "safe_unassigned_glyph_planes",
            }
        )
    return rows


def patch_lv(font: bytearray) -> tuple[int, int]:
    before = bytes(font)
    index = LV_CODE - 1
    row, remainder = divmod(index, 84)
    column, plane = divmod(remainder, 4)
    bit = 1 << plane
    glyph = {
        (x, y)
        for y, line in enumerate(LV_BITMAP)
        for x, value in enumerate(line)
        if value == "#"
    }
    for y in range(12):
        for x in range(12):
            px = column * 12 + x
            py = row * 12 + y
            old = get_pixel(font, px, py)
            new = old | bit if (x, y) in glyph else old & ~bit
            if (new & ~bit) != (old & ~bit):
                raise SystemExit("LV writer changed a neighboring plane")
            set_pixel(font, px, py, new)

    changed_bytes = 0
    changed_pixels = 0
    for offset, (old_byte, new_byte) in enumerate(zip(before, font)):
        if old_byte != new_byte:
            changed_bytes += 1
    for y in range(12):
        for x in range(12):
            px = column * 12 + x
            py = row * 12 + y
            if get_pixel(before, px, py) != get_pixel(font, px, py):
                changed_pixels += 1
    return changed_bytes, changed_pixels


def patch_icons(font: bytearray) -> list[dict[str, object]]:
    original = ORIGINAL_FONT.read_bytes()
    rows: list[dict[str, object]] = []
    for icon_id in (2, 3):
        source = ICON_SOURCES[icon_id]
        original_position = ORIGINAL_ICON_POSITIONS[icon_id]
        destination = ICON_DESTINATIONS[icon_id]
        pixels = rectangle(font, *source)
        if pixels != rectangle(original, *original_position):
            raise SystemExit(f"icon {icon_id} duplicate no longer matches original")
        for dy in range(ICON_HEIGHT):
            for dx in range(ICON_WIDTH):
                set_pixel(
                    font,
                    destination[0] + dx,
                    destination[1] + dy,
                    pixels[dy * ICON_WIDTH + dx],
                )
        if rectangle(font, *destination) != pixels:
            raise SystemExit(f"icon {icon_id} relocation readback differs")
        rows.append(
            {
                "icon_id": icon_id,
                "source_x": source[0],
                "source_y": source[1],
                "destination_x": destination[0],
                "destination_y": destination[1],
                "width": ICON_WIDTH,
                "height": ICON_HEIGHT,
                "pixel_sha256": digest(bytes(pixels)),
                "status": "relocated_same_texture_page",
            }
        )
    return rows


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields: list[str] = []
    for row in rows:
        for field in row:
            if field not in fields:
                fields.append(field)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def copy_manifests() -> None:
    for source_name, target_name in MANIFESTS:
        shutil.copy2(ROOT / "05_docs" / source_name, ROOT / "05_docs" / target_name)

    path = ROOT / "05_docs" / "ui_system_v38.csv"
    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
        fields = list(rows[0])
    matches = [row for row in rows if int(row["pointer_offset"], 0) == HELP_POINTER]
    if len(matches) != 1:
        raise SystemExit("v38 system manifest help row count differs")
    row = matches[0]
    row["new_offset"] = f"0x{NEW_HELP_TARGET:X}"
    row["encoded_bytes"] = str(len(NEW_HELP_PAYLOAD))
    row["korean"] = "{결정버튼}결정 {취소버튼}돌아가기"
    row["encoded_hex"] = NEW_HELP_PAYLOAD.hex(" ").upper()
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_ZIP_HASH:
        raise SystemExit("v0.37 base ZIP hash differs")
    with ZipFile(BASE) as archive:
        infos = {item.filename: item for item in archive.infolist()}
        before_files = {name: archive.read(name) for name in infos}
    if digest(before_files[PSX_TARGET]) != BASE_PSX_HASH:
        raise SystemExit("v0.37 PSX.EXE hash differs")
    if digest(before_files[FONT_TARGET]) != BASE_COMM_HASH:
        raise SystemExit("v0.37 COMM.IMG hash differs")

    destination_audit = assert_destinations_unassigned()
    files = dict(before_files)
    executable = bytearray(files[PSX_TARGET])
    font = bytearray(files[FONT_TARGET])
    before_executable = bytes(executable)
    before_font = bytes(font)

    lv_changed_bytes, lv_changed_pixels = patch_lv(font)
    icon_rows = patch_icons(font)

    expected_u = {2: 0x82, 3: 0x92}
    for icon_id in (2, 3):
        table_offset = ICON_TABLE + icon_id * 2
        if executable[table_offset] != expected_u[icon_id]:
            raise SystemExit(f"icon {icon_id} source U differs")
        if executable[table_offset + 1] != ICON_WIDTH:
            raise SystemExit(f"icon {icon_id} width differs")
        executable[table_offset] = ICON_DESTINATIONS[icon_id][0]

    old_pointer = struct.unpack_from("<I", executable, HELP_POINTER)[0]
    if old_pointer != PSX_LOAD_BASE + EXPECTED_HELP_TARGET:
        raise SystemExit("v0.37 help pointer differs")
    if executable[EXPECTED_HELP_TARGET:EXPECTED_HELP_TARGET + len(EXPECTED_HELP_PAYLOAD)] != EXPECTED_HELP_PAYLOAD:
        raise SystemExit("v0.37 help payload differs")
    if any(executable[NEW_HELP_TARGET:NEW_HELP_TARGET + len(NEW_HELP_PAYLOAD) + 1]):
        raise SystemExit("v0.38 help allocation is not empty")
    executable[NEW_HELP_TARGET:NEW_HELP_TARGET + len(NEW_HELP_PAYLOAD)] = NEW_HELP_PAYLOAD
    executable[NEW_HELP_TARGET + len(NEW_HELP_PAYLOAD)] = 0
    struct.pack_into("<I", executable, HELP_POINTER, PSX_LOAD_BASE + NEW_HELP_TARGET)

    if executable[NEW_HELP_TARGET:NEW_HELP_TARGET + len(NEW_HELP_PAYLOAD)] != NEW_HELP_PAYLOAD:
        raise SystemExit("v0.38 help payload readback differs")
    if NEW_HELP_PAYLOAD.count(b"\xE7\x02") != 1 or NEW_HELP_PAYLOAD.count(b"\xE7\x03") != 1:
        raise SystemExit("v0.38 help icon control count differs")

    allowed_psx = {ICON_TABLE + 4, ICON_TABLE + 6}
    allowed_psx.update(range(HELP_POINTER, HELP_POINTER + 4))
    allowed_psx.update(range(NEW_HELP_TARGET, NEW_HELP_TARGET + len(NEW_HELP_PAYLOAD)))
    psx_diffs = [
        offset
        for offset, (old, new) in enumerate(zip(before_executable, executable))
        if old != new
    ]
    unexpected_psx = [offset for offset in psx_diffs if offset not in allowed_psx]
    if unexpected_psx:
        raise SystemExit(f"unexpected PSX delta at 0x{unexpected_psx[0]:X}")

    lv_index = LV_CODE - 1
    lv_row, lv_remainder = divmod(lv_index, 84)
    lv_column, lv_plane = divmod(lv_remainder, 4)
    lv_bit = 1 << lv_plane
    changed_comm_pixels = 0
    for y in range(len(font) // ROW_BYTES):
        for x in range(ROW_BYTES * 2):
            old = get_pixel(before_font, x, y)
            new = get_pixel(font, x, y)
            if old == new:
                continue
            changed_comm_pixels += 1
            in_lv = (
                lv_column * 12 <= x < lv_column * 12 + 12
                and lv_row * 12 <= y < lv_row * 12 + 12
                and not ((old ^ new) & ~lv_bit)
            )
            in_icon = any(
                dx <= x < dx + ICON_WIDTH and dy <= y < dy + ICON_HEIGHT
                for dx, dy in ICON_DESTINATIONS.values()
            )
            if not in_lv and not in_icon:
                raise SystemExit(f"unexpected COMM delta at ({x},{y})")

    files[PSX_TARGET] = bytes(executable)
    files[FONT_TARGET] = bytes(font)
    temporary = OUTPUT.with_suffix(".tmp")
    with ZipFile(temporary, "w", ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            archive.writestr(infos[name], files[name])
    temporary.replace(OUTPUT)

    with ZipFile(OUTPUT) as archive:
        after_files = {name: archive.read(name) for name in archive.namelist()}
    changed_members = [
        name for name in sorted(before_files) if before_files[name] != after_files[name]
    ]
    if changed_members != [FONT_TARGET, PSX_TARGET]:
        raise SystemExit(f"unexpected changed members: {changed_members}")

    copy_manifests()
    write_csv(ICON_AUDIT, destination_audit + icon_rows)
    write_csv(
        FONT_AUDIT,
        [
            {
                "code": "0x6C",
                "display": "LV",
                "bitmap_pixels": sum(line.count("#") for line in LV_BITMAP),
                "changed_bytes": lv_changed_bytes,
                "changed_pixels": lv_changed_pixels,
                "neighbor_planes_changed": 0,
                "status": "v35_thin_pointed_lv_restored",
            }
        ],
    )

    report = (
        "UI safe v0.38 cumulative LV and button-icon repair\n"
        "base=v0.37 hash-locked cumulative ZIP\n"
        f"base_zip_sha256={BASE_ZIP_HASH}\n"
        "changed_members=COMM.IMG,PSX.EXE\n"
        f"lv_bitmap_pixels={sum(line.count('#') for line in LV_BITMAP)}\n"
        f"lv_changed_bytes={lv_changed_bytes}\n"
        f"lv_changed_pixels={lv_changed_pixels}\n"
        "lv_neighbor_planes_changed=0\n"
        "button_icon_ids=E7_02,E7_03\n"
        "button_icon_destination_u=0x00,0x0C\n"
        "button_icon_destination_v=0x82\n"
        "button_icon_destination_assigned_glyphs=0\n"
        "button_help={결정버튼}결정 {취소버튼}돌아가기\n"
        f"button_help_pointer=0x{HELP_POINTER:X}->0x{NEW_HELP_TARGET:X}\n"
        f"psx_changed_bytes={len(psx_diffs)}\n"
        f"comm_changed_pixels={changed_comm_pixels}\n"
        f"comm_img_sha256={digest(after_files[FONT_TARGET])}\n"
        f"psx_exe_sha256={digest(after_files[PSX_TARGET])}\n"
        f"output_zip_sha256={digest(OUTPUT.read_bytes())}\n"
    )
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(report, encoding="utf-8")
    print(report, end="")


if __name__ == "__main__":
    main()
