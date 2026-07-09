from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "99_backup" / "story_test_07_stable.zip"
WORK = ROOT / "01_work" / "story_test_11_remaining_slots_probe"
WORK_FONT = WORK / "COMM.IMG"
WORK_DAT = WORK / "1" / "S1071.DAT"
OUTPUT = ROOT / "03_output" / "story_test_11_remaining_slots_probe_patch_only.zip"
EXPECTED_SOURCE_HASH = "2A09829F936BD6BF6D4EB8D9A614656B3E993ECE93B7F86B71D8637488E63125"
FONT_PATH = Path(r"C:\Windows\Fonts\gulim.ttc")
FONT_SIZE = 12
THRESHOLD = 192
ROW_BYTES = 0x380
FILLER = 0x9C

CODES = {
    "여": 0x68, "기": 0x6C, "까": 0x70, "지": 0x74, "다": 0x78,
    "이": 0x7C, "뒤": 0x80, "는": 0x84, "혼": 0x88, "자": 0x8C,
    "가": 0x90, "라": 0x94, "아": 0x98, " ": FILLER,
    "크": 0xA0, "조": 0xA4, "심": 0xA8, "하": 0xAC, "거": 0xB0,
    "돌": 0xB4, "올": 0xB8, "때": 0xBC, "리": 0xC0, "겠": 0xC4,
    "예": 0xC8, "촌": 0xCC, "장": 0xD0,
    "마": 0xD4, "을": 0xD8, "로": 0xDC,
}

NEW_GLYPHS = {
    52: "마",
    53: "을",
    54: "로",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def render_glyph(char: str) -> Image.Image:
    font = ImageFont.truetype(str(FONT_PATH), size=FONT_SIZE)
    canvas = Image.new("L", (24, 24), 0)
    draw = ImageDraw.Draw(canvas)
    bbox = draw.textbbox((0, 0), char, font=font)
    width = bbox[2] - bbox[0]
    height = bbox[3] - bbox[1]
    x = (24 - width) // 2 - bbox[0]
    y = (24 - height) // 2 - bbox[1]
    draw.text((x, y), char, fill=255, font=font)
    glyph = canvas.crop((6, 6, 18, 18))
    return glyph.point(lambda value: 255 if value >= THRESHOLD else 0, mode="1")


def set_pixel(data: bytearray, x: int, y: int, value: int) -> None:
    offset = y * ROW_BYTES + x // 2
    if x % 2 == 0:
        data[offset] = (data[offset] & 0xF0) | (value & 0x0F)
    else:
        data[offset] = (data[offset] & 0x0F) | ((value & 0x0F) << 4)


def write_cell(font: bytearray, cell: int, glyph: Image.Image) -> None:
    x0 = (cell % 21) * 12
    y0 = (cell // 21) * 12
    for y in range(12):
        for x in range(12):
            set_pixel(font, x0 + x, y0 + y, 15 if glyph.getpixel((x, y)) else 0)


def encode(lines: list[str]) -> bytes:
    output = bytearray()
    for line_number, line in enumerate(lines):
        if line_number:
            output.extend((0xE6, 0x01))
        output.extend(CODES[char] for char in line)
    return bytes(output)


def write_text_files() -> None:
    charmap = """Story test 11 remaining 1-byte slot probe

Base: story_test_07 stable

Existing map:
68=여 6C=기 70=까 74=지 78=다 7C=이
80=뒤 84=는 88=혼 8C=자 90=가 94=라 98=아
9C=blank filler and in-sentence space
A0=크 A4=조 A8=심 AC=하 B0=거 B4=돌
B8=올 BC=때 C0=리 C4=겠 C8=예 CC=촌 D0=장

New probe map:
D4=마 D8=을 DC=로

E6 01=line break
"""
    test_info = """Arc the Lad 1 JP Korean Patch - Story Test 11 remaining slot probe

Purpose:
- Verify whether 0xD4/0xD8/0xDC can be used as additional safe 1-byte Korean codes.
- Keep story_test_07 stable first/third/fourth dialogue behavior intact.

Change:
- Add glyphs 마/을/로 to COMM.IMG cells 52-54.
- Replace only the second S1071 dialogue block with:
  마을로
  가라

Expected DuckStation check:
- Title screen/logo must be normal.
- First dialogue should still be the story_test_07 stable text.
- Second dialogue should display 마을로 / 가라 and continue.
- Third/fourth dialogue and next scene progression should remain normal.
"""
    (WORK / "CHARMAP.txt").write_text(charmap, encoding="utf-8")
    (WORK / "TEST_INFO.txt").write_text(test_info, encoding="utf-8")


def main() -> None:
    if digest(SOURCE) != EXPECTED_SOURCE_HASH:
        raise SystemExit("story_test_07 stable artifact hash mismatch")
    if WORK_FONT.exists() or WORK_DAT.exists() or OUTPUT.exists():
        raise SystemExit("Story test 11 already exists; refusing to overwrite it.")

    WORK_DAT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(SOURCE) as archive:
        font = bytearray(archive.read("COMM.IMG"))
        dat = bytearray(archive.read("1/S1071.DAT"))

    for cell, char in NEW_GLYPHS.items():
        write_cell(font, cell, render_glyph(char))

    start, length, terminator = 0x47932, 41, 0x4795B
    if dat[terminator] != 0:
        raise SystemExit("Second block terminator is not 0x00")
    payload = encode(["마을로", "가라"])
    if len(payload) > length:
        raise SystemExit("Text exceeds second block")
    dat[start : start + length] = bytes([FILLER]) * length
    dat[start : start + len(payload)] = payload

    WORK_FONT.write_bytes(font)
    WORK_DAT.write_bytes(dat)
    write_text_files()

    with zipfile.ZipFile(OUTPUT, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.write(WORK_FONT, "COMM.IMG")
        archive.write(WORK_DAT, "1/S1071.DAT")
        archive.write(WORK / "CHARMAP.txt", "CHARMAP.txt")
        archive.write(WORK / "TEST_INFO.txt", "TEST_INFO.txt")

    print(digest(WORK_FONT), WORK_FONT)
    print(digest(WORK_DAT), WORK_DAT)
    print(digest(OUTPUT), OUTPUT)


if __name__ == "__main__":
    main()
