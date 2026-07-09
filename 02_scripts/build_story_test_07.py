from __future__ import annotations

import hashlib
import shutil
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "03_output" / "story_test_06_speaker_names_patch_only.zip"
BACKUP = ROOT / "99_backup" / "story_test_06_names_success.zip"
WORK = ROOT / "01_work" / "story_test_07"
WORK_FONT = WORK / "COMM.IMG"
WORK_DAT = WORK / "1" / "S1071.DAT"
OUTPUT = ROOT / "03_output" / "story_test_07_spacing_patch_only.zip"
EXPECTED_SOURCE_HASH = "EAC88E54C9AD9054AC5D825900C9AD1D9DC97D5C585EBED371A73EC67BB332FC"
FILLER = 0x9C

CODES = {
    "여": 0x68, "기": 0x6C, "까": 0x70, "지": 0x74, "다": 0x78,
    "이": 0x7C, "뒤": 0x80, "는": 0x84, "혼": 0x88, "자": 0x8C,
    "가": 0x90, "라": 0x94, "아": 0x98, " ": FILLER,
    "크": 0xA0, "조": 0xA4, "심": 0xA8, "하": 0xAC, "거": 0xB0,
    "돌": 0xB4, "올": 0xB8, "때": 0xBC, "리": 0xC0, "겠": 0xC4,
    "예": 0xC8, "촌": 0xCC, "장": 0xD0,
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def encode(lines: list[str]) -> bytes:
    output = bytearray()
    for index, line in enumerate(lines):
        if index:
            output.extend((0xE6, 0x01))
        output.extend(CODES[char] for char in line)
    return bytes(output)


def main() -> None:
    if digest(SOURCE) != EXPECTED_SOURCE_HASH:
        raise SystemExit("story_test_06 artifact hash mismatch")

    BACKUP.parent.mkdir(parents=True, exist_ok=True)
    if not BACKUP.exists():
        shutil.copy2(SOURCE, BACKUP)
    elif digest(BACKUP) != EXPECTED_SOURCE_HASH:
        raise SystemExit("story_test_06 backup hash mismatch")

    if WORK_FONT.exists() or WORK_DAT.exists() or OUTPUT.exists():
        raise SystemExit("Story test 07 already exists; refusing to overwrite it.")

    WORK_DAT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(SOURCE) as archive:
        font = archive.read("COMM.IMG")
        dat = bytearray(archive.read("1/S1071.DAT"))

    patches = [
        (0x478D6, 39, ["촌장", "여기까지다", "이 뒤는 혼자 가라"], 0x478FD),
        (0x4798E, 55, ["촌장", "돌아올 때까지", "기다리겠다"], 0x479C5),
    ]

    for start, length, lines, terminator in patches:
        if dat[terminator] != 0:
            raise SystemExit(f"Expected 0x00 terminator at 0x{terminator:X}")
        payload = encode(lines)
        if len(payload) > length:
            raise SystemExit(f"Text exceeds block at 0x{start:X}")
        dat[start : start + length] = bytes([FILLER]) * length
        dat[start : start + len(payload)] = payload

    WORK_FONT.write_bytes(font)
    WORK_DAT.write_bytes(dat)

    with zipfile.ZipFile(OUTPUT, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.write(WORK_FONT, "COMM.IMG")
        archive.write(WORK_DAT, "1/S1071.DAT")
        archive.write(WORK / "CHARMAP.txt", "CHARMAP.txt")
        archive.write(WORK / "TEST_INFO.txt", "TEST_INFO.txt")

    print(digest(BACKUP), BACKUP)
    print(digest(WORK_FONT), WORK_FONT)
    print(digest(WORK_DAT), WORK_DAT)
    print(digest(OUTPUT), OUTPUT)


if __name__ == "__main__":
    main()
