from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE_PATCH = ROOT / "03_output" / "story_test_21_s1072_visible_batch_patch_only.zip"
WORK = ROOT / "01_work" / "story_test_22_s1072_add_kukuru_block"
WORK_FONT = WORK / "COMM.IMG"
WORK_S1071 = WORK / "1" / "S1071.DAT"
WORK_S1011 = WORK / "1" / "S1011.DAT"
WORK_S1072 = WORK / "1" / "S1072.DAT"
OUTPUT = ROOT / "03_output" / "story_test_22_s1072_add_kukuru_block_patch_only.zip"
EXPECTED_BASE_HASH = "8AF42D0C093E08DE5860F51A1E92A9A694028571488D4330A09B16538DB87EE5"
FILLER = 0x9C

CODES = {
    "신": 0x08,
    "의": 0x0C,
    "피": 0x10,
    "를": 0x14,
    "은": 0x18,
    "결": 0x1C,
    "계": 0x20,
    "킨": 0x24,
    "진": 0x28,
    "땅": 0x2C,
    "도": 0x30,
    "사": 0x34,
    "말": 0x38,
    "괄": 0x3C,
    "량": 0x40,
    "덕": 0x44,
    "분": 0x48,
    "에": 0x4C,
    "드": 0x50,
    "디": 0x54,
    "어": 0x58,
    "나": 0x5C,
    "제": 0x60,
    "끝": 0x64,
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
        raise SystemExit(f"Text exceeds block at 0x{start:X}: {len(payload)} > {length}")
    dat[start : start + length] = bytes([FILLER]) * length
    dat[start : start + len(payload)] = payload


def write_text_files() -> None:
    test_info = """Arc the Lad 1 JP Korean Patch - Story Test 22 S1072 add remaining portrait block

Purpose:
- Keep story_test_21 S1072 batch.
- Add the remaining mixed portrait block around 0x47C24.
- No new glyphs are added; use the story_test_21 font as-is.

Patched block:
- 1/S1072.DAT 0x47C24-0x47C5A, terminator 0x47C5B

Temporary visible text:
- 아크 / 조심하라 / 마을로가라

Expected DuckStation check:
- The temple descent sequence should no longer show the remaining mixed portrait block.
- House/interior mixed text is a separate file/sequence and is not fixed by this test.
"""
    (WORK / "TEST_INFO.txt").write_text(test_info, encoding="utf-8")


def main() -> None:
    if digest(BASE_PATCH) != EXPECTED_BASE_HASH:
        raise SystemExit("story_test_21 artifact hash mismatch")
    if WORK_FONT.exists() or WORK_S1072.exists() or OUTPUT.exists():
        raise SystemExit("Story test 22 already exists; refusing to overwrite it.")

    WORK_S1072.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(BASE_PATCH) as archive:
        font = archive.read("COMM.IMG")
        s1071 = archive.read("1/S1071.DAT")
        s1011 = archive.read("1/S1011.DAT")
        s1072 = bytearray(archive.read("1/S1072.DAT"))

    patch_block(s1072, 0x47C24, 0x37, 0x47C5B, ["아크", "조심하라", "마을로가라"])

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
        archive.write(WORK / "TEST_INFO.txt", "TEST_INFO.txt")

    print(digest(WORK_FONT), WORK_FONT)
    print(digest(WORK_S1071), WORK_S1071)
    print(digest(WORK_S1011), WORK_S1011)
    print(digest(WORK_S1072), WORK_S1072)
    print(digest(OUTPUT), OUTPUT)


if __name__ == "__main__":
    main()
