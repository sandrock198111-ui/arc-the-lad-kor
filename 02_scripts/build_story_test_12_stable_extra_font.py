from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "99_backup" / "story_test_11_remaining_slots_success.zip"
WORK = ROOT / "01_work" / "story_test_12_stable_extra_font"
WORK_FONT = WORK / "COMM.IMG"
WORK_DAT = WORK / "1" / "S1071.DAT"
OUTPUT = ROOT / "03_output" / "story_test_12_stable_extra_font_patch_only.zip"
EXPECTED_SOURCE_HASH = "88BCDE15A1803B569BDE3130525DE9F62BD24B03AB1C2F13F40BC85B24BF4A60"
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
    charmap = """Story test 12 stable extra font map

Base: story_test_11 success

68=여 6C=기 70=까 74=지 78=다 7C=이
80=뒤 84=는 88=혼 8C=자 90=가 94=라 98=아
9C=blank filler and in-sentence space
A0=크 A4=조 A8=심 AC=하 B0=거 B4=돌
B8=올 BC=때 C0=리 C4=겠 C8=예 CC=촌 D0=장
D4=마 D8=을 DC=로

E6 01=line break
"""
    test_info = """Arc the Lad 1 JP Korean Patch - Story Test 12 stable extra font

Purpose:
- Keep the successful D4/D8/DC glyphs from story_test_11.
- Restore the second S1071 dialogue to the story_test_07 stable wording.
- Establish a cleaner base for future translation expansion.

Visible dialogue:
- 촌장 / 여기까지다 / 이 뒤는 혼자 가라
- 아크여 / 조심하거라
- 촌장 / 돌아올 때까지 / 기다리겠다
- 예

Expected DuckStation check:
- Same visible behavior as story_test_07.
- Title screen/logo remains normal.
- New glyphs 마/을/로 remain available for future blocks.
"""
    (WORK / "CHARMAP.txt").write_text(charmap, encoding="utf-8")
    (WORK / "TEST_INFO.txt").write_text(test_info, encoding="utf-8")


def main() -> None:
    if digest(SOURCE) != EXPECTED_SOURCE_HASH:
        raise SystemExit("story_test_11 success artifact hash mismatch")
    if WORK_FONT.exists() or WORK_DAT.exists() or OUTPUT.exists():
        raise SystemExit("Story test 12 already exists; refusing to overwrite it.")

    WORK_DAT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(SOURCE) as archive:
        font = archive.read("COMM.IMG")
        dat = bytearray(archive.read("1/S1071.DAT"))

    start, length, terminator = 0x47932, 41, 0x4795B
    if dat[terminator] != 0:
        raise SystemExit("Second block terminator is not 0x00")
    payload = encode(["아크여", "조심하거라"])
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
