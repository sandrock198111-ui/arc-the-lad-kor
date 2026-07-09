from __future__ import annotations

import hashlib
import shutil
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE_PATCH = ROOT / "99_backup" / "story_test_18_s1011_nine_blocks_fix_block8_success.zip"
ORIGINAL_S1072 = ROOT / "01_work" / "1" / "S1072.DAT"
WORK = ROOT / "01_work" / "story_test_24_s1072_first_block_stable_only"
WORK_FONT = WORK / "COMM.IMG"
WORK_S1071 = WORK / "1" / "S1071.DAT"
WORK_S1011 = WORK / "1" / "S1011.DAT"
WORK_S1072 = WORK / "1" / "S1072.DAT"
OUTPUT = ROOT / "03_output" / "story_test_24_s1072_first_block_stable_only_patch_only.zip"
FILES_ONLY = ROOT / "03_output" / "story_test_24_s1072_first_block_stable_only_files"
EXPECTED_BASE_HASH = "492C1F206F91532EFA7DFC5E9E39A5F4902B745043C979475B9AA3894BCE5204"

# Verified story_test_18 S1011 first-block payload:
# speaker/name line + line break + short instruction, using stable high-slot bytes only.
STABLE_PAYLOAD = bytes.fromhex("98 A0 68 E6 01 D4 D8 DC 9C 90 94")
FILLER = 0x9C


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def patch_text_until_double_zero(dat: bytearray, start: int, double_zero: int, payload: bytes) -> None:
    if dat[double_zero:double_zero + 2] != b"\x00\x00":
        raise SystemExit(f"Double-zero boundary at 0x{double_zero:X} is not 00 00")
    length = double_zero - start
    if len(payload) > length:
        raise SystemExit(f"Text exceeds block at 0x{start:X}: {len(payload)} > {length}")
    dat[start:double_zero] = bytes([FILLER]) * length
    dat[start:start + len(payload)] = payload
    if dat[double_zero:double_zero + 2] != b"\x00\x00":
        raise SystemExit(f"Patch corrupted double-zero boundary at 0x{double_zero:X}")


def write_text_files() -> None:
    (WORK / "TEST_INFO.txt").write_text(
        "\n".join(
            [
                "Story test 24: S1072 first-block minimal probe.",
                "Base: story_test_18 stable success.",
                "COMM.IMG, S1071.DAT, S1011.DAT are copied unchanged from story_test_18.",
                "S1072.DAT is rebuilt from original and only 0x478CC-0x478FE is patched.",
                "The first 00 00 boundary at 0x478FF is preserved.",
                "No low-slot 0x08-0x64 glyphs are used. No new font glyphs are rendered.",
                "Payload is copied from a story_test_18 verified S1011 block.",
                "Expected check: if this block appears as stable Korean and advances, the first S1072 boundary is usable.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> None:
    if digest(BASE_PATCH) != EXPECTED_BASE_HASH:
        raise SystemExit("story_test_18 success artifact hash mismatch")
    if not ORIGINAL_S1072.exists():
        raise SystemExit("Original extracted S1072.DAT is missing")
    if WORK.exists() or OUTPUT.exists() or FILES_ONLY.exists():
        raise SystemExit("story_test_24 output already exists; refusing to overwrite it.")

    WORK_S1072.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(BASE_PATCH) as archive:
        font = archive.read("COMM.IMG")
        s1071 = archive.read("1/S1071.DAT")
        s1011 = archive.read("1/S1011.DAT")
    s1072 = bytearray(ORIGINAL_S1072.read_bytes())

    patch_text_until_double_zero(s1072, 0x478CC, 0x478FF, STABLE_PAYLOAD)

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

    FILES_ONLY.mkdir(parents=True)
    shutil.copy2(WORK_FONT, FILES_ONLY / "COMM.IMG")
    (FILES_ONLY / "1").mkdir()
    shutil.copy2(WORK_S1071, FILES_ONLY / "1" / "S1071.DAT")
    shutil.copy2(WORK_S1011, FILES_ONLY / "1" / "S1011.DAT")
    shutil.copy2(WORK_S1072, FILES_ONLY / "1" / "S1072.DAT")

    print(digest(WORK_FONT), WORK_FONT)
    print(digest(WORK_S1071), WORK_S1071)
    print(digest(WORK_S1011), WORK_S1011)
    print(digest(WORK_S1072), WORK_S1072)
    print(digest(OUTPUT), OUTPUT)
    print(FILES_ONLY)


if __name__ == "__main__":
    main()
