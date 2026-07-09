from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE_PATCH = ROOT / "99_backup" / "story_test_16_s1011_four_blocks_success.zip"
WORK = ROOT / "01_work" / "story_test_18_s1011_nine_blocks_fix_block8"
WORK_FONT = WORK / "COMM.IMG"
WORK_S1071 = WORK / "1" / "S1071.DAT"
WORK_S1011 = WORK / "1" / "S1011.DAT"
OUTPUT = ROOT / "03_output" / "story_test_18_s1011_nine_blocks_fix_block8_patch_only.zip"
EXPECTED_BASE_HASH = "814A872839B7F7D6B16E4537595742C1BA9F585290003526533534B4B11E5994"
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


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


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
        raise SystemExit(f"Text exceeds block at 0x{start:X}")
    dat[start : start + length] = bytes([FILLER]) * length
    dat[start : start + len(payload)] = payload


def write_text_files() -> None:
    test_info = """Arc the Lad 1 JP Korean Patch - Story Test 18 S1011 nine blocks, block 8 fix

Purpose:
- Fix story_test_17 block 8, where original Japanese bytes before 0x47B40 remained visible as よく.
- Keep the file-range batch approach.

Change:
- Base is story_test_16 success.
- Reapply blocks 5-9.
- Block 8 is corrected from 0x47B40 length 47 to 0x47B3E length 49.

Expected DuckStation check:
- Blocks before the mixed line should remain OK.
- Block 8 should show 촌장 / 아크여 / 돌아올 때까지 without leading Japanese text.
- Last block should show 예.
- No freeze after the last changed block.
"""
    charmap = """Story test 18 S1011 nine-block map

Same character map as story_test_17.
68=여 6C=기 70=까 74=지 78=다 7C=이
80=뒤 84=는 88=혼 8C=자 90=가 94=라 98=아
9C=blank filler and in-sentence space
A0=크 A4=조 A8=심 AC=하 B0=거 B4=돌
B8=올 BC=때 C0=리 C4=겠 C8=예 CC=촌 D0=장
D4=마 D8=을 DC=로
E6 01=line break
"""
    (WORK / "TEST_INFO.txt").write_text(test_info, encoding="utf-8")
    (WORK / "CHARMAP.txt").write_text(charmap, encoding="utf-8")


def main() -> None:
    if digest(BASE_PATCH) != EXPECTED_BASE_HASH:
        raise SystemExit("story_test_16 success artifact hash mismatch")
    if WORK_FONT.exists() or WORK_S1071.exists() or WORK_S1011.exists() or OUTPUT.exists():
        raise SystemExit("Story test 18 already exists; refusing to overwrite it.")

    WORK_S1011.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(BASE_PATCH) as archive:
        font = archive.read("COMM.IMG")
        s1071 = archive.read("1/S1071.DAT")
        s1011 = bytearray(archive.read("1/S1011.DAT"))

    patches = [
        (0x479FC, 36, 0x47A20, ["아크", "조심하라", "기다리겠다"]),
        (0x47A54, 12, 0x47A60, ["가라"]),
        (0x47AD2, 26, 0x47AEC, ["마을로", "돌아가라"]),
        (0x47B3E, 49, 0x47B6F, ["촌장", "아크여", "돌아올 때까지"]),
        (0x47BB2, 5, 0x47BB7, ["예"]),
    ]
    for start, length, terminator, lines in patches:
        patch_block(s1011, start, length, terminator, lines)

    WORK_FONT.write_bytes(font)
    WORK_S1071.write_bytes(s1071)
    WORK_S1011.write_bytes(s1011)
    write_text_files()

    with zipfile.ZipFile(OUTPUT, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.write(WORK_FONT, "COMM.IMG")
        archive.write(WORK_S1071, "1/S1071.DAT")
        archive.write(WORK_S1011, "1/S1011.DAT")
        archive.write(WORK / "CHARMAP.txt", "CHARMAP.txt")
        archive.write(WORK / "TEST_INFO.txt", "TEST_INFO.txt")

    print(digest(WORK_FONT), WORK_FONT)
    print(digest(WORK_S1071), WORK_S1071)
    print(digest(WORK_S1011), WORK_S1011)
    print(digest(OUTPUT), OUTPUT)


if __name__ == "__main__":
    main()
