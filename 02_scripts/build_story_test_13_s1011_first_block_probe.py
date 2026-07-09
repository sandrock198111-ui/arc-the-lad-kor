from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE_PATCH = ROOT / "99_backup" / "story_test_12_stable_extra_font_success.zip"
ORIGINAL_ZIP = ROOT / "00_original" / "arc.zip"
WORK = ROOT / "01_work" / "story_test_13_s1011_first_block_probe"
WORK_FONT = WORK / "COMM.IMG"
WORK_S1071 = WORK / "1" / "S1071.DAT"
WORK_S1011 = WORK / "1" / "S1011.DAT"
OUTPUT = ROOT / "03_output" / "story_test_13_s1011_first_block_probe_patch_only.zip"
EXPECTED_BASE_HASH = "A746D25902C235C107B65E9B7FBAE673F3F73205F0DD95A0EAD8B73775F5B370"
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


def write_text_files() -> None:
    charmap = """Story test 13 S1011 first block probe

Base: story_test_12 success

68=여 6C=기 70=까 74=지 78=다 7C=이
80=뒤 84=는 88=혼 8C=자 90=가 94=라 98=아
9C=blank filler and in-sentence space
A0=크 A4=조 A8=심 AC=하 B0=거 B4=돌
B8=올 BC=때 C0=리 C4=겠 C8=예 CC=촌 D0=장
D4=마 D8=을 DC=로

E6 01=line break
"""
    test_info = """Arc the Lad 1 JP Korean Patch - Story Test 13 S1011 first block probe

Purpose:
- Verify that the story_test_12 text/font method can be applied to S1011.
- Touch only one S1011 dialogue block before any larger scene expansion.

Change:
- Keep COMM.IMG and S1071.DAT from story_test_12.
- Modify original 1/S1011.DAT text block at 0x478AA only.
- New first-block text:
  아크여
  마을로 가라

Expected DuckStation check:
- S1071 intro scene should remain same as story_test_12 if reached.
- When S1011 first block appears, it should show 아크여 / 마을로 가라.
- No title/logo corruption.
- No freeze after the S1011 block.
"""
    (WORK / "CHARMAP.txt").write_text(charmap, encoding="utf-8")
    (WORK / "TEST_INFO.txt").write_text(test_info, encoding="utf-8")


def main() -> None:
    if digest(BASE_PATCH) != EXPECTED_BASE_HASH:
        raise SystemExit("story_test_12 base artifact hash mismatch")
    if WORK_FONT.exists() or WORK_S1071.exists() or WORK_S1011.exists() or OUTPUT.exists():
        raise SystemExit("Story test 13 already exists; refusing to overwrite it.")

    WORK_S1011.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(BASE_PATCH) as archive:
        font = archive.read("COMM.IMG")
        s1071 = archive.read("1/S1071.DAT")

    with zipfile.ZipFile(ORIGINAL_ZIP) as archive:
        s1011 = bytearray(archive.read("1/S1011.DAT"))

    start, length, terminator = 0x478AA, 35, 0x478CD
    if s1011[terminator] != 0:
        raise SystemExit("S1011 first block terminator is not 0x00")
    payload = encode(["아크여", "마을로 가라"])
    if len(payload) > length:
        raise SystemExit("S1011 first block text exceeds available space")
    s1011[start : start + length] = bytes([FILLER]) * length
    s1011[start : start + len(payload)] = payload

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
