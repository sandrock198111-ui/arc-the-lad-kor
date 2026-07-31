from __future__ import annotations

import csv
import hashlib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output" / "story_s2051_throne_full_patch_only.zip"
ORIGINAL = ROOT / "00_original" / "arc.zip"
OUTPUT = ROOT / "03_output" / "story_s2055_throne_after_full_patch_only.zip"
TARGET = "22/S2055.DAT"
FILLER = 0x9C
LINEBREAK = b"\xE6\x01"

# Slots 1-10 plus the live screen immediately after slot 10. The changing
# runtime field at PS1 RAM 0x1FA59C resolves to this ordered S2055 range.
PATCHES = (
    (0x478F0, "5e 5d 25 e6 01 41 32 30 28 24 dd 4b 2a 3b ae 1c b7 35 36 e6 01 4d 4f 2a 91 29 1f 1c 35 1d 3c", "이말이다"),
    (0x4794A, "28 1b 37", "예?"),
    (0x47980, "50 8b 25 e6 01 6e 2f 91 26 20 02 e6 01 3b 27 46 1c 3d 26 1d 7e 2a e6 01 5d dd 5e 1c de 76 2f 7d 3e 1d 54 36 df 61 37", "아크|조심하라"),
    (0x479E0, "50 8b 25 e6 01 5d 3d 24 2e 1c 7e 28 5d dd 5e dd 43 29 dd 29 39 2f 38 3e 55 2d 30 3b 22 40 38 37", "아크|덕분이다"),
    (0x47A38, "5e 5d 25 e6 01 dd 43 29 dd 29 39 36 1d 37 e4 3d e6 01 2e 1c 3d 26 1d 96 dd 0d 2a 41 1c 3d 26 1d df 61 37", "조사하라"),
    (0x47A94, "5e 5d 25 e6 01 42 31 4e 36 40 33 24 e6 01 6e 20 41 1c b0 2a 27 2e 36 30 3f 22 36 e6 01 de 6f 2b 38 1c 28 3f 22 1c 20 3c", "조사하라"),
    (0x47AFC, "4d 4f 2a 24 2e 32 2f b7 20 33 3f 8c 20 29 1f 36 df 61 df 61 37", "나도|가겠다"),
    (0x47B58, "5e 5d 25 e6 01 2e 32 28 27 3a 1e 3e 24 e6 01 47 78 6b 42 5d dd 5e 23 dd 07 43 22 5b dd 47 7e 1c de 0c 1e 5a 37", "?"),
    (0x47BC4, "5e 5d 25 e6 01 41 26 20 24 e4 3d e6 01 dd 4b 2a dd 1c 44 21 1b 22 20 38 1e 32 2d 1c 20 df 61 df 61 37", "나도|가겠다"),
    (0x47C24, "5e 5d 25 e6 01 5b cd dd 1a 5a 09 59 1b 7d 45 0a 36 4d 4f 36 dd 4b 36 1c 88 23 54 2d 1d dd b1 de 78 2a 3f 22 36 1b 26 1c 35 3c", "예?"),
    (0x47C88, "43 20 39 27 59 2d 37 e4 3d e6 01 4d 4f 28 24 b7 3a 2d 36 24 52 1c dd 93 9a 2f e6 01 20 49 1f dd 7e dd 87 2f 1e 1f 36 91 29 21 1b 27 1e 1f 37", "신의|말이다"),
)


def load_charmap() -> dict[str, int]:
    with (ROOT / "05_docs" / "korean_charmap.csv").open(
        encoding="utf-8-sig", newline=""
    ) as handle:
        return {
            row["char"]: int(row["code_hex"], 16)
            for row in csv.DictReader(handle)
        }


def encode(text: str, charmap: dict[str, int]) -> bytes:
    payload = bytearray()
    for line_number, line in enumerate(text.split("|")):
        if line_number:
            payload.extend(LINEBREAK)
        for char in line:
            payload.append(0x3C if char == "?" else charmap[char])
    return bytes(payload)


def main() -> None:
    charmap = load_charmap()
    with zipfile.ZipFile(BASE) as base:
        files = {
            info.filename: base.read(info.filename)
            for info in base.infolist()
            if info.filename != "BUILD_REPORT.txt"
        }
    with zipfile.ZipFile(ORIGINAL) as original:
        data = bytearray(original.read(TARGET))

    report: list[str] = []
    for offset, expected_hex, text in PATCHES:
        expected = bytes.fromhex(expected_hex)
        end = offset + len(expected)
        payload = encode(text, charmap)
        if data[offset:end] != expected:
            raise SystemExit(f"{TARGET} 0x{offset:X}: unexpected original bytes")
        if data[end:end + 2] != b"\x00\x00":
            raise SystemExit(f"{TARGET} 0x{offset:X}: missing 00 00 boundary")
        if len(payload) > len(expected):
            raise SystemExit(f"{TARGET} 0x{offset:X}: replacement exceeds capacity")
        data[offset:end] = bytes([FILLER]) * len(expected)
        data[offset:offset + len(payload)] = payload
        if data[end:end + 2] != b"\x00\x00":
            raise SystemExit(f"{TARGET} 0x{offset:X}: boundary changed")
        report.append(f"0x{offset:X}: {text} ({len(payload)}/{len(expected)})")

    files[TARGET] = bytes(data)
    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        for name in sorted(files):
            output.writestr(name, files[name])

    with zipfile.ZipFile(OUTPUT) as output:
        names = output.namelist()
        if len(names) != 30 or len(names) != len(set(names)):
            raise SystemExit("unexpected cumulative ZIP entry count")
        if "BUILD_REPORT.txt" in names or output.read(TARGET) != data:
            raise SystemExit("cumulative ZIP verification failed")

    print("\n".join(report))
    print(f"wrote {OUTPUT}")
    print(f"sha256={hashlib.sha256(OUTPUT.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
