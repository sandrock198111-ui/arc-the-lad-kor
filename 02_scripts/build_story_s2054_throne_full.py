from __future__ import annotations

import csv
import hashlib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output" / "story_s2051_throne_full_patch_only.zip"
ORIGINAL = ROOT / "00_original" / "arc.zip"
OUTPUT = ROOT / "03_output" / "story_throne_s2054_full_patch_only.zip"
TARGET = "22/S2054.DAT"
FILLER = 0x9C
LINEBREAK = b"\xE6\x01"

# The latest DuckStation states load S2054 for the current throne-room set.
# Every target is a bounded visible-dialogue payload in the original file.
PATCHES = (
    (0x4792E, "dd 3a 53 64 31 7c 1c dd ca dd 8a 23 44 27 1e 1f", "아크|예?"),
    (0x47970, "50 8b 25 e6 01 79 dd f3 de 50 e6 01 35 2a 3f 1b 23 3e 5e 5d 28 dd b7 3f 1b 2a dd 6c 1b 3d 26 35 e6 01 dd a8 43 29 21 85 2a b0 2f d3 2e 26", "아크|여기까지|가자"),
    (0x479DE, "66 68 25 e6 01 50 8b 23 dd ca dd 8a 1b 1f 1e 27 2b e6 01 de 8d de 02 52 09 b5 dd 05 2d 23 2d 0a 5c 82 60 ab 2f e6 01 90 70 de 21 23 de 91 33 46 27 1e 1f", "아크|조심|뒤로가자"),
    (0x47A44, "50 8b 25 e6 01 41 26 20 24 3d 1e 43 20 29 1f", "아크|기다"),
    (0x47A86, "50 8b 25 e6 01 dd 8e dd 3e 2a 30 44 1f 3d 26 35 e6 01 b0 28 c3 dd 05 54 d3 3e 36 1e 3d 26", "아크|혼자|가지마"),
    (0x47AD6, "50 8b 25 e6 01 70 2a 22 2a 3d 1b", "아크|나가자"),
)


def encode(text: str) -> bytes:
    with (ROOT / "05_docs" / "korean_charmap.csv").open(
        encoding="utf-8-sig", newline=""
    ) as handle:
        charmap = {row["char"]: int(row["code_hex"], 16) for row in csv.DictReader(handle)}
    payload = bytearray()
    for line_number, line in enumerate(text.split("|")):
        if line_number:
            payload.extend(LINEBREAK)
        for char in line:
            payload.append(0x3C if char == "?" else charmap[char])
    return bytes(payload)


def main() -> None:
    with zipfile.ZipFile(BASE) as base:
        files = {info.filename: base.read(info.filename) for info in base.infolist()}
    with zipfile.ZipFile(ORIGINAL) as original:
        data = bytearray(original.read(TARGET))

    for offset, expected_hex, text in PATCHES:
        expected = bytes.fromhex(expected_hex)
        end = offset + len(expected)
        payload = encode(text)
        if data[offset:end] != expected:
            raise SystemExit(f"{TARGET} 0x{offset:X}: unexpected original bytes")
        if data[end:end + 2] != b"\x00\x00" or len(payload) > len(expected):
            raise SystemExit(f"{TARGET} 0x{offset:X}: invalid boundary or capacity")
        data[offset:end] = bytes([FILLER]) * len(expected)
        data[offset:offset + len(payload)] = payload
        if data[end:end + 2] != b"\x00\x00":
            raise SystemExit(f"{TARGET} 0x{offset:X}: boundary changed")

    files[TARGET] = bytes(data)
    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        for name in sorted(files):
            output.writestr(name, files[name])
    with zipfile.ZipFile(OUTPUT) as output:
        names = output.namelist()
        if len(names) != 30 or len(names) != len(set(names)) or "BUILD_REPORT.txt" in names:
            raise SystemExit("unexpected ZIP structure")
        if output.read(TARGET) != files[TARGET]:
            raise SystemExit("S2054 verification failed")
    print(f"wrote {OUTPUT}")
    print(f"sha256={hashlib.sha256(OUTPUT.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
