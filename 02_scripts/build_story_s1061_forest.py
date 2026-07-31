from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output" / "story_s2011_city_dialogue_patch_only.zip"
SOURCE = Path(r"E:\arc\out\1\S1061.DAT")
OUTPUT = ROOT / "03_output" / "story_s1061_forest_dialogue_patch_only.zip"
TARGET = "1/S1061.DAT"
FILLER = 0x9C

# Confirmed from the eight saved forest screens.  The 0x47E44 body is the
# three-byte question form; every first 00 00 boundary remains untouched.
PATCHES = (
    (0x478A4, "38 26 24 2e 2e 30 1b 1b 3d 37", "98 a0"),
    (0x47B40, "6e 35 20 24 2b 79 1b b0 30 1e 73 37", "98 a0 e6 01 90 8c"),
    (0x47B94, "41 26 91 46 58 24 3f 1c de 25 7b 29 1f 4d 4f 38 52 2a dd 40 99 22 36 20 e6 01 ad 1c dd 37 cc 36 20 91 29 21 1f 49 54 24", "98 a0 e6 01 a4 a8"),
    (0x47BF0, "df 61 df 61 41 2d 1d 7a 3d 39 24 ad e6 01 b7 3a 2d 23 7b 1b 1f 1b 2d 35 37", "98 a0 e6 01 68 6c"),
    (0x47C3E, "36 23 20 3e ad 28 dd 0b 2f 56 21 74 3e 37 e4 1f e6 01 a3 6f 34 60 42 dd 17 23 74 49 58 e6 01 6e 20 b2 20 22 20 38 1e 32 1d 1b 37", "98 a0 e6 01 90 8c"),
    (0x47D52, "4e 4e 53 df 61 df 61 37", "98 a0"),
    (0x47E44, "dd 52 3c", "98 a0 3c"),
    (0x48076, "df 61 df 61 43 20 29 1f 37 e4 3d e6 01 4a 48 74 3e 20 33 df 61 df 61 37", "98 a0 e6 01 90 8c"),
)


def main() -> None:
    data = bytearray(SOURCE.read_bytes())
    for offset, expected_hex, replacement_hex in PATCHES:
        expected = bytes.fromhex(expected_hex)
        replacement = bytes.fromhex(replacement_hex)
        if data[offset : offset + len(expected)] != expected:
            raise SystemExit(f"{TARGET} 0x{offset:X}: unexpected source bytes")
        boundary = offset + len(expected)
        if data[boundary : boundary + 2] != b"\x00\x00":
            raise SystemExit(f"{TARGET} 0x{offset:X}: boundary missing")
        data[offset:boundary] = bytes([FILLER]) * len(expected)
        data[offset : offset + len(replacement)] = replacement
        if data[boundary : boundary + 2] != b"\x00\x00":
            raise SystemExit(f"{TARGET} 0x{offset:X}: boundary changed")

    with zipfile.ZipFile(BASE) as base_zip, zipfile.ZipFile(
        OUTPUT, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as result:
        for info in base_zip.infolist():
            if info.filename not in {"BUILD_REPORT.txt", TARGET}:
                result.writestr(info, base_zip.read(info.filename))
        result.writestr(TARGET, data)

    with zipfile.ZipFile(OUTPUT) as result:
        if len(result.namelist()) != 17 or "BUILD_REPORT.txt" in result.namelist():
            raise SystemExit("unexpected ZIP contents")
        if result.namelist().count(TARGET) != 1:
            raise SystemExit(f"{TARGET} must occur exactly once")
        output = result.read(TARGET)
        for offset, expected_hex, replacement_hex in PATCHES:
            expected = bytes.fromhex(expected_hex)
            replacement = bytes.fromhex(replacement_hex)
            boundary = offset + len(expected)
            if output[offset : offset + len(replacement)] != replacement:
                raise SystemExit(f"output mismatch at 0x{offset:X}")
            if output[boundary : boundary + 2] != b"\x00\x00":
                raise SystemExit(f"output boundary mismatch at 0x{offset:X}")

    print(f"wrote {OUTPUT}")
    print(f"files=18 sha256={hashlib.sha256(OUTPUT.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
