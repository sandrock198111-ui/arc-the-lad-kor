from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE_PATCH = ROOT / "99_backup" / "story_test_13_s1011_first_block_success.zip"
WORK = ROOT / "01_work" / "story_test_14_s1011_two_blocks"
WORK_FONT = WORK / "COMM.IMG"
WORK_S1071 = WORK / "1" / "S1071.DAT"
WORK_S1011 = WORK / "1" / "S1011.DAT"
OUTPUT = ROOT / "03_output" / "story_test_14_s1011_two_blocks_patch_only.zip"
EXPECTED_BASE_HASH = "2518D065D106CDD43FCD3900242EB1DA4D1552BB67D0624E573D938C65CD30EF"
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
    test_info = """Arc the Lad 1 JP Korean Patch - Story Test 14 S1011 two blocks

Purpose:
- Extend S1011 from one translated block to two translated blocks.
- Keep COMM.IMG and S1071.DAT unchanged from story_test_13.

Change:
- First S1011 block remains:
  아크여
  마을로 가라
- Second S1011 block at 0x47902 becomes:
  이 뒤로
  가라

Expected DuckStation check:
- First S1011 block should remain 아크여 / 마을로 가라.
- Next S1011 block should display 이 뒤로 / 가라.
- No freeze after either block.
"""
    charmap = """Story test 14 S1011 two-block map

Same character map as story_test_13.
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
        raise SystemExit("story_test_13 success artifact hash mismatch")
    if WORK_FONT.exists() or WORK_S1071.exists() or WORK_S1011.exists() or OUTPUT.exists():
        raise SystemExit("Story test 14 already exists; refusing to overwrite it.")

    WORK_S1011.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(BASE_PATCH) as archive:
        font = archive.read("COMM.IMG")
        s1071 = archive.read("1/S1071.DAT")
        s1011 = bytearray(archive.read("1/S1011.DAT"))

    patch_block(s1011, 0x47902, 23, 0x47919, ["이 뒤로", "가라"])

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
