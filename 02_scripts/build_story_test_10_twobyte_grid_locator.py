from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "99_backup" / "story_test_07_stable.zip"
WORK = ROOT / "01_work" / "story_test_10_twobyte_grid_locator"
WORK_FONT = WORK / "COMM.IMG"
WORK_DAT = WORK / "1" / "S1071.DAT"
OUTPUT = ROOT / "03_output" / "story_test_10_twobyte_grid_locator_patch_only.zip"
EXPECTED_SOURCE_HASH = "2A09829F936BD6BF6D4EB8D9A614656B3E993ECE93B7F86B71D8637488E63125"
FONT_PATH = Path(r"C:\Windows\Fonts\gulim.ttc")
ROW_BYTES = 0x380
FILLER = 0x9C

CODES = {
    "여": 0x68, "기": 0x6C, "까": 0x70, "지": 0x74, "다": 0x78,
    "이": 0x7C, "뒤": 0x80, "는": 0x84, "혼": 0x88, "자": 0x8C,
    "가": 0x90, "라": 0x94, " ": FILLER,
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def render_glyph(char: str) -> Image.Image:
    font = ImageFont.truetype(str(FONT_PATH), size=12)
    canvas = Image.new("L", (24, 24), 0)
    draw = ImageDraw.Draw(canvas)
    bbox = draw.textbbox((0, 0), char, font=font)
    width = bbox[2] - bbox[0]
    height = bbox[3] - bbox[1]
    x = (24 - width) // 2 - bbox[0]
    y = (24 - height) // 2 - bbox[1]
    draw.text((x, y), char, fill=255, font=font)
    glyph = canvas.crop((6, 6, 18, 18))
    return glyph.point(lambda value: 255 if value >= 192 else 0, mode="1")


def set_pixel(data: bytearray, x: int, y: int, value: int) -> None:
    offset = y * ROW_BYTES + x // 2
    if x % 2 == 0:
        data[offset] = (data[offset] & 0xF0) | value
    else:
        data[offset] = (data[offset] & 0x0F) | (value << 4)


def write_glyph(font: bytearray, position: tuple[int, int], char: str) -> None:
    glyph = render_glyph(char)
    x0, y0 = position
    for y in range(12):
        for x in range(12):
            set_pixel(font, x0 + x, y0 + y, 15 if glyph.getpixel((x, y)) else 0)


def grid_position(first: int, second: int, row_adjust: int, column_adjust: int) -> tuple[int, int]:
    row = (first >> 2) + row_adjust
    column = (second >> 2) + column_adjust
    if not (0 <= row <= 62 and 0 <= column <= 62):
        raise ValueError("Adjusted grid coordinate is out of range")
    page = (row // 42) * 3 + (column // 21)
    return page * 256 + (column % 21) * 12, (row % 42) * 12


def encode(line: str) -> bytes:
    return bytes(CODES[char] for char in line)


def main() -> None:
    if digest(SOURCE) != EXPECTED_SOURCE_HASH:
        raise SystemExit("story_test_07 stable artifact hash mismatch")
    if WORK_FONT.exists() or WORK_DAT.exists() or OUTPUT.exists():
        raise SystemExit("Story test 10 already exists; refusing to overwrite it.")

    WORK_DAT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(SOURCE) as archive:
        font = bytearray(archive.read("COMM.IMG"))
        dat = bytearray(archive.read("1/S1071.DAT"))

    variants = [
        (0, 0, "가", "나", "no adjustment"),
        (-1, -1, "촌", "장", "row -1, column -1"),
        (-1, 0, "아", "크", "row -1"),
        (0, -1, "여", "기", "column -1"),
    ]
    for row_adjust, column_adjust, first_marker, second_marker, label in variants:
        first_position = grid_position(0xDD, 0x0B, row_adjust, column_adjust)
        second_position = grid_position(0xD4, 0x25, row_adjust, column_adjust)
        write_glyph(font, first_position, first_marker)
        write_glyph(font, second_position, second_marker)
        print(label, first_position, second_position, first_marker + second_marker)

    start, length, terminator = 0x478D6, 39, 0x478FD
    if dat[terminator] != 0:
        raise SystemExit("First block terminator is not 0x00")
    payload = bytearray((0xDD, 0x0B, 0xD4, 0x25, 0xE6, 0x01))
    payload.extend(encode("여기까지다"))
    payload.extend((0xE6, 0x01))
    payload.extend(encode("이 뒤는 혼자 가라"))
    dat[start : start + length] = bytes([FILLER]) * length
    dat[start : start + len(payload)] = payload

    WORK_FONT.write_bytes(font)
    WORK_DAT.write_bytes(dat)

    with zipfile.ZipFile(OUTPUT, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.write(WORK_FONT, "COMM.IMG")
        archive.write(WORK_DAT, "1/S1071.DAT")
        archive.write(WORK / "TEST_INFO.txt", "TEST_INFO.txt")

    print(digest(OUTPUT), OUTPUT)


if __name__ == "__main__":
    main()
