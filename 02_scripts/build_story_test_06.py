from __future__ import annotations

import hashlib
import shutil
import zipfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_ZIP = ROOT / "00_original" / "arc.zip"
TEST05_ZIP = ROOT / "03_output" / "story_test_05_mixedslots_patch_only.zip"
TEST05_BACKUP = ROOT / "99_backup" / "story_test_05_progress_success.zip"
WORK = ROOT / "01_work" / "story_test_06"
WORK_FONT = WORK / "COMM.IMG"
WORK_DAT = WORK / "1" / "S1071.DAT"
OUTPUT = ROOT / "03_output" / "story_test_06_speaker_names_patch_only.zip"
FONT_PATH = Path(r"C:\Windows\Fonts\gulim.ttc")
FONT_SIZE = 12
THRESHOLD = 192
ROW_BYTES = 0x380
EXPECTED_TEST05_HASH = "72FAD387151F6D6F8D788AB25424B9AF4E8546707CC42D2F65C47D08E4DD0073"

CHARACTERS = "여기까지다이뒤는혼자가라아크조심하거돌올때리겠예촌장"
FILLER_CODE = 0x9C
CHARACTER_CELLS = list(range(25, 38)) + list(range(39, 52))


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def code_for_cell(cell: int) -> int:
    return (cell + 1) * 4


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


def write_cell(font: bytearray, cell: int, glyph: Image.Image | None) -> None:
    x0 = (cell % 21) * 12
    y0 = (cell // 21) * 12
    for y in range(12):
        for x in range(12):
            value = 0 if glyph is None else (15 if glyph.getpixel((x, y)) else 0)
            set_pixel(font, x0 + x, y0 + y, value)


def encode(lines: list[str], mapping: dict[str, int]) -> bytes:
    output = bytearray()
    for line_number, line in enumerate(lines):
        if line_number:
            output.extend((0xE6, 0x01))
        output.extend(mapping[char] for char in line)
    return bytes(output)


def main() -> None:
    if file_digest(TEST05_ZIP) != EXPECTED_TEST05_HASH:
        raise SystemExit("story_test_05 artifact hash mismatch")
    TEST05_BACKUP.parent.mkdir(parents=True, exist_ok=True)
    if not TEST05_BACKUP.exists():
        shutil.copy2(TEST05_ZIP, TEST05_BACKUP)
    elif file_digest(TEST05_BACKUP) != EXPECTED_TEST05_HASH:
        raise SystemExit("story_test_05 backup hash mismatch")

    if len(CHARACTER_CELLS) != len(CHARACTERS):
        raise SystemExit("Character/cell count mismatch")
    if WORK_FONT.exists() or WORK_DAT.exists() or OUTPUT.exists():
        raise SystemExit("Story test 06 already exists; refusing to overwrite it.")

    WORK_DAT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(ORIGINAL_ZIP) as archive:
        font = bytearray(archive.read("COMM.IMG"))
        dat = bytearray(archive.read("1/S1071.DAT"))

    mapping = {
        char: code_for_cell(cell)
        for char, cell in zip(CHARACTERS, CHARACTER_CELLS, strict=True)
    }
    if mapping["촌"] != 0xCC or mapping["장"] != 0xD0:
        raise SystemExit("Unexpected speaker-name codes")

    write_cell(font, 38, None)
    for char, cell in zip(CHARACTERS, CHARACTER_CELLS, strict=True):
        write_cell(font, cell, render_glyph(char))

    patches = [
        (0x478D6, 39, ["촌장", "여기까지다", "이뒤는혼자가라"], 0x478FD),
        (0x47932, 41, ["아크여", "조심하거라"], 0x4795B),
        (0x4798E, 55, ["촌장", "돌아올때까지", "기다리겠다"], 0x479C5),
        (0x479FA, 6, ["예"], 0x47A00),
    ]

    for start, length, lines, terminator in patches:
        if dat[terminator] != 0:
            raise SystemExit(f"Expected 0x00 terminator at 0x{terminator:X}")
        payload = encode(lines, mapping)
        if len(payload) > length:
            raise SystemExit(f"Text exceeds block at 0x{start:X}")
        dat[start : start + length] = bytes([FILLER_CODE]) * length
        dat[start : start + len(payload)] = payload

    WORK_FONT.write_bytes(font)
    WORK_DAT.write_bytes(dat)

    with zipfile.ZipFile(OUTPUT, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.write(WORK_FONT, "COMM.IMG")
        archive.write(WORK_DAT, "1/S1071.DAT")
        archive.write(WORK / "CHARMAP.txt", "CHARMAP.txt")
        archive.write(WORK / "TEST_INFO.txt", "TEST_INFO.txt")

    print(file_digest(TEST05_BACKUP), TEST05_BACKUP)
    print(file_digest(WORK_FONT), WORK_FONT)
    print(file_digest(WORK_DAT), WORK_DAT)
    print(file_digest(OUTPUT), OUTPUT)


if __name__ == "__main__":
    main()
