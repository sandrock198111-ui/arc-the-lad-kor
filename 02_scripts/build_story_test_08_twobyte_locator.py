from __future__ import annotations

import hashlib
import shutil
import zipfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "03_output" / "story_test_07_spacing_patch_only.zip"
BACKUP = ROOT / "99_backup" / "story_test_07_stable.zip"
WORK = ROOT / "01_work" / "story_test_08_twobyte_locator"
WORK_FONT = WORK / "COMM.IMG"
WORK_DAT = WORK / "1" / "S1071.DAT"
OUTPUT = ROOT / "03_output" / "story_test_08_twobyte_locator_patch_only.zip"
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


def write_glyph(font: bytearray, x0: int, y0: int, char: str) -> None:
    glyph = render_glyph(char)
    for y in range(12):
        for x in range(12):
            set_pixel(font, x0 + x, y0 + y, 15 if glyph.getpixel((x, y)) else 0)


def glyph_index(code_word: int) -> int:
    return (code_word >> 2) - 1


def map_a(index: int) -> tuple[int, int]:
    # Seven 256x512 vertical texture strips; 21x42 glyphs per strip.
    page, local = divmod(index, 21 * 42)
    return page * 256 + (local % 21) * 12, (local // 21) * 12


def map_b(index: int) -> tuple[int, int]:
    # Fourteen 256x256 texture pages; seven across and two down.
    page, local = divmod(index, 21 * 21)
    return (page % 7) * 256 + (local % 21) * 12, (page // 7) * 256 + (local // 21) * 12


def encode(line: str) -> bytes:
    return bytes(CODES[char] for char in line)


def main() -> None:
    if digest(SOURCE) != EXPECTED_SOURCE_HASH:
        raise SystemExit("story_test_07 artifact hash mismatch")

    BACKUP.parent.mkdir(parents=True, exist_ok=True)
    if not BACKUP.exists():
        shutil.copy2(SOURCE, BACKUP)
    elif digest(BACKUP) != EXPECTED_SOURCE_HASH:
        raise SystemExit("story_test_07 backup hash mismatch")

    if WORK_FONT.exists() or WORK_DAT.exists() or OUTPUT.exists():
        raise SystemExit("Story test 08 already exists; refusing to overwrite it.")

    WORK_DAT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(SOURCE) as archive:
        font = bytearray(archive.read("COMM.IMG"))
        dat = bytearray(archive.read("1/S1071.DAT"))

    village_code = 0x0BDD  # bytes DD 0B
    elder_code = 0x25D4    # bytes D4 25

    for code, char in ((village_code, "가"), (elder_code, "나")):
        write_glyph(font, *map_a(glyph_index(code)), char)
    for code, char in ((village_code, "촌"), (elder_code, "장")):
        write_glyph(font, *map_b(glyph_index(code)), char)

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

    print("Village index/positions:", glyph_index(village_code), map_a(glyph_index(village_code)), map_b(glyph_index(village_code)))
    print("Elder index/positions:", glyph_index(elder_code), map_a(glyph_index(elder_code)), map_b(glyph_index(elder_code)))
    print(digest(BACKUP), BACKUP)
    print(digest(OUTPUT), OUTPUT)


if __name__ == "__main__":
    main()
