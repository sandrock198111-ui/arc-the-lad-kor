from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
BASE_PATCH = ROOT / "99_backup" / "story_test_18_s1011_nine_blocks_fix_block8_success.zip"
ORIGINAL_S1072 = ROOT / "01_work" / "1" / "S1072.DAT"
WORK = ROOT / "01_work" / "story_test_20_s1072_first_blocks"
WORK_FONT = WORK / "COMM.IMG"
WORK_S1071 = WORK / "1" / "S1071.DAT"
WORK_S1011 = WORK / "1" / "S1011.DAT"
WORK_S1072 = WORK / "1" / "S1072.DAT"
OUTPUT = ROOT / "03_output" / "story_test_20_s1072_first_blocks_patch_only.zip"
EXPECTED_BASE_HASH = "492C1F206F91532EFA7DFC5E9E39A5F4902B745043C979475B9AA3894BCE5204"

FONT_PATH = Path(r"C:\Windows\Fonts\gulim.ttc")
FONT_SIZE = 12
THRESHOLD = 192
ROW_BYTES = 0x380
FILLER = 0x9C

CODES = {
    # New low-slot glyphs for the first S1072 screen.
    "신": 0x08,
    "의": 0x0C,
    "피": 0x10,
    "를": 0x14,
    "잇": 0x18,
    "킨": 0x1C,
    "땅": 0x20,
    "말": 0x24,
    "괄": 0x28,
    "량": 0x2C,
    "덕": 0x30,
    "에": 0x34,
    "드": 0x38,
    "디": 0x3C,
    "어": 0x40,
    "사": 0x44,
    "나": 0x48,
    # Existing stable glyphs.
    "여": 0x68,
    "기": 0x6C,
    "까": 0x70,
    "지": 0x74,
    "다": 0x78,
    "이": 0x7C,
    "뒤": 0x80,
    "는": 0x84,
    "혼": 0x88,
    "자": 0x8C,
    "가": 0x90,
    "라": 0x94,
    "아": 0x98,
    " ": FILLER,
    "크": 0xA0,
    "조": 0xA4,
    "심": 0xA8,
    "하": 0xAC,
    "거": 0xB0,
    "돌": 0xB4,
    "올": 0xB8,
    "때": 0xBC,
    "리": 0xC0,
    "겠": 0xC4,
    "예": 0xC8,
    "촌": 0xCC,
    "장": 0xD0,
    "마": 0xD4,
    "을": 0xD8,
    "로": 0xDC,
}

NEW_GLYPHS = {
    1: "신",
    2: "의",
    3: "피",
    4: "를",
    5: "잇",
    6: "킨",
    7: "땅",
    8: "말",
    9: "괄",
    10: "량",
    11: "덕",
    12: "에",
    13: "드",
    14: "디",
    15: "어",
    16: "사",
    17: "나",
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


def patch_block(dat: bytearray, start: int, length: int, terminator: int, lines: list[str]) -> None:
    if dat[terminator] != 0:
        raise SystemExit(f"Terminator at 0x{terminator:X} is not 0x00")
    payload = encode(lines)
    if len(payload) > length:
        raise SystemExit(f"Text exceeds block at 0x{start:X}: {len(payload)} > {length}")
    dat[start : start + length] = bytes([FILLER]) * length
    dat[start : start + len(payload)] = payload


def write_text_files() -> None:
    test_info = """Arc the Lad 1 JP Korean Patch - Story Test 20 S1072 first visible blocks

Purpose:
- Correct the actual next screen reported after story_test_18.
- story_test_19 targeted S1013, but the reported screen is S1072.
- Use story_test_18 success as the base, not story_test_19.

Patched visible text:
- Block 1: 촌장 / 신의피를 / 잇는자가 / 지킨땅
- Block 2: 촌장 / 말괄량덕에 / 드디어사라지나

Expected DuckStation check:
- Title/logo normal.
- Existing S1011/S1071 success areas do not regress.
- The reported next screen should no longer show mostly Japanese text.
- Some later unpatched Japanese blocks may still show mixed glyphs because low slots are now Korean glyphs.
"""
    charmap = """Story test 20 charmap extension

New low-slot glyphs:
08=신 0C=의 10=피 14=를 18=잇 1C=킨 20=땅 24=말 28=괄 2C=량 30=덕 34=에 38=드 3C=디 40=어 44=사 48=나

Existing stable map:
68=여 6C=기 70=까 74=지 78=다 7C=이 80=뒤 84=는 88=혼 8C=자 90=가 94=라 98=아
9C=blank filler and in-sentence space
A0=크 A4=조 A8=심 AC=하 B0=거 B4=돌 B8=올 BC=때 C0=리 C4=겠 C8=예 CC=촌 D0=장
D4=마 D8=을 DC=로
E6 01=line break
E0-FF remains forbidden except E6 01 line break.
"""
    (WORK / "TEST_INFO.txt").write_text(test_info, encoding="utf-8")
    (WORK / "CHARMAP.txt").write_text(charmap, encoding="utf-8")


def main() -> None:
    if digest(BASE_PATCH) != EXPECTED_BASE_HASH:
        raise SystemExit("story_test_18 success artifact hash mismatch")
    if not ORIGINAL_S1072.exists():
        raise SystemExit("Original extracted S1072.DAT is missing")
    if WORK_FONT.exists() or WORK_S1072.exists() or OUTPUT.exists():
        raise SystemExit("Story test 20 already exists; refusing to overwrite it.")

    WORK_S1072.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(BASE_PATCH) as archive:
        font = bytearray(archive.read("COMM.IMG"))
        s1071 = archive.read("1/S1071.DAT")
        s1011 = archive.read("1/S1011.DAT")
    s1072 = bytearray(ORIGINAL_S1072.read_bytes())

    for cell, char in NEW_GLYPHS.items():
        write_cell(font, cell, render_glyph(char))

    patch_block(s1072, 0x47996, 0x19, 0x479AF, ["촌장", "신의피를", "잇는자가", "지킨땅"])
    patch_block(s1072, 0x479F4, 0x19, 0x47A0D, ["촌장", "말괄량덕에", "드디어사라지나"])

    WORK_FONT.write_bytes(font)
    WORK_S1071.write_bytes(s1071)
    WORK_S1011.write_bytes(s1011)
    WORK_S1072.write_bytes(s1072)
    write_text_files()

    with zipfile.ZipFile(OUTPUT, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.write(WORK_FONT, "COMM.IMG")
        archive.write(WORK_S1071, "1/S1071.DAT")
        archive.write(WORK_S1011, "1/S1011.DAT")
        archive.write(WORK_S1072, "1/S1072.DAT")
        archive.write(WORK / "CHARMAP.txt", "CHARMAP.txt")
        archive.write(WORK / "TEST_INFO.txt", "TEST_INFO.txt")

    print(digest(WORK_FONT), WORK_FONT)
    print(digest(WORK_S1071), WORK_S1071)
    print(digest(WORK_S1011), WORK_S1011)
    print(digest(WORK_S1072), WORK_S1072)
    print(digest(OUTPUT), OUTPUT)


if __name__ == "__main__":
    main()
