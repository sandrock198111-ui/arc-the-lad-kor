from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_ZIP = ROOT / "00_original" / "arc.zip"
TEST02_DAT = ROOT / "01_work" / "story_test_02" / "1" / "S1071.DAT"
WORK = ROOT / "01_work" / "story_test_03"
WORK_FONT = WORK / "COMM.IMG"
WORK_DAT = WORK / "1" / "S1071.DAT"
OUTPUT = ROOT / "03_output" / "story_test_03_gulim1bit_patch_only.zip"
FONT_PATH = Path(r"C:\Windows\Fonts\gulim.ttc")
FONT_SIZE = 12
THRESHOLD = 192
ROW_BYTES = 0x380

CHARACTERS = "여기까지다이뒤는혼자가라아크조심하거돌올때리겠예"


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


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def main() -> None:
    if WORK_FONT.exists() or WORK_DAT.exists() or OUTPUT.exists():
        raise SystemExit("Story test 03 already exists; refusing to overwrite it.")

    WORK_DAT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(ORIGINAL_ZIP) as archive:
        font = bytearray(archive.read("COMM.IMG"))

    dat = TEST02_DAT.read_bytes()
    expected_dat_hash = "9A48353BF78D634333EBAC49A42EB1644C6C32571B88FA1053F3D151BD884833"
    if hashlib.sha256(dat).hexdigest().upper() != expected_dat_hash:
        raise SystemExit("story_test_02 S1071.DAT hash mismatch")

    # code 0x04 -> blank cell 0.
    for y in range(12):
        for x in range(12):
            set_pixel(font, x, y, 0)

    # code 0x08 begins at cell 1; subsequent codes and cells advance together.
    for index, char in enumerate(CHARACTERS):
        glyph = render_glyph(char)
        cell = index + 1
        destination_x = (cell % 21) * 12
        destination_y = (cell // 21) * 12
        for y in range(12):
            for x in range(12):
                set_pixel(font, destination_x + x, destination_y + y, 15 if glyph.getpixel((x, y)) else 0)

    WORK_FONT.write_bytes(font)
    WORK_DAT.write_bytes(dat)

    with zipfile.ZipFile(OUTPUT, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.write(WORK_FONT, "COMM.IMG")
        archive.write(WORK_DAT, "1/S1071.DAT")
        archive.write(WORK / "CHARMAP.txt", "CHARMAP.txt")
        archive.write(WORK / "TEST_INFO.txt", "TEST_INFO.txt")

    print(sha256(WORK_FONT), WORK_FONT)
    print(sha256(WORK_DAT), WORK_DAT)
    print(sha256(OUTPUT), OUTPUT)


if __name__ == "__main__":
    main()
