from __future__ import annotations

import csv
import hashlib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRIOR_PATCH = ROOT / "03_output" / "story_slots_1_to_10_dialogue_patch_only.zip"
ADDITIONAL_PATCH = ROOT / "03_output" / "story_reed_king_flashback_underground_patch_only.zip"
OUTPUT = ROOT / "03_output" / "story_s2051_throne_full_patch_only.zip"
TARGET = "22/S2051.DAT"
FILLER = 0x9C
LINEBREAK = b"\xE6\x01"

# Ten ordered throne-room dialogue bodies recorded in DuckStation states 1-10.
# Each tuple preserves the original body and its immediate 00 00 control boundary.
PATCHES = (
    (0x478A6, "5e 5d 25 e6 01 3b 27 46 2a 24 42 31 4e 20 3c", "아크|조심"),
    (0x4792C, "5e 5d 25 e6 01 60 8f 34 9b 30 1c de 49 40 3e e6 01 43 1e 1c de a6 23 38 86 29 21 3b 22 37 e4 1f e6 01 dd 15 43 29 1f 61 2f dd 09 29 21 1b 22 41 26 4a 48 1d 3c", "아크|여기까지|가자"),
    (0x4799C, "9b 30 4d 4f 09 59 1b 32 1b 0a 20 33 61 2f e6 01 38 33 1b 27 1e 1f 37", "아크|여기다"),
    (0x479EC, "5e 5d 25 e6 01 4d 4f 36 1d 3c", "아크|기다"),
    (0x47A28, "5e 5d 25 e6 01 41 32 30 24 4d 4f 28 3b 27 46 23 e6 01 1d 2d 36 91 29 1f 3c", "아크|혼자|가지마"),
    (0x47A7C, "28 1b e4 0b e6 01 4d 4f 28 01 52 2a dd 40 99 22 36 e6 01 91 29 21 1b 27 1e 1f 37", "아크|예?"),
    (0x47AD0, "5e 5d 25 e6 01 52 dd a3 2a dd 40 99 22 36 1d 37 e6 01 41 32 28 df 61 df 61 37", "아크|돌아가"),
    (0x47B22, "50 8b 25 e6 01 42 31 4e 36 de d8 1e 1f 1d 37 e6 01 51 29 1f 1d 7a 2f de 13 23 2b 22 38 1c 30 28 1d 1b 37", "아크|이거|다"),
    (0x47B7E, "50 8b 25 e6 01 5d 3d 24 2e 1c 3d 26 1d 96 dd 0d 1c b0 1d 54 df 61 df 61 df 61 37", "아크|나가자"),
    (0x47BD2, "5e 5d 25 e6 01 ce dd 12 2a dd 40 99 22 df 61 df 61 de e7 dd a9 96 30 3f 29 1f dd 4b 2a e6 01 de 39 2f dd 28 1e 1f cf 23 38 41 2d 1d 7a 2f df 61 df 61 37", "아크|조심|뒤로가자"),
)


def load_charmap() -> dict[str, int]:
    with (ROOT / "05_docs" / "korean_charmap.csv").open(
        encoding="utf-8-sig", newline=""
    ) as handle:
        return {row["char"]: int(row["code_hex"], 16) for row in csv.DictReader(handle)}


def encode(text: str, charmap: dict[str, int]) -> bytes:
    result = bytearray()
    for line_number, line in enumerate(text.split("|")):
        if line_number:
            result.extend(LINEBREAK)
        for char in line:
            # The dialogue-path question glyph is a verified one-byte code,
            # but is intentionally absent from the Korean font CSV.
            result.append(0x3C if char == "?" else charmap[char])
    return bytes(result)


def main() -> None:
    charmap = load_charmap()
    # Start from the latest cumulative payload, not the original archive.
    # This preserves all accepted S2051 replacements outside the new range.
    with zipfile.ZipFile(PRIOR_PATCH) as prior:
        files = {
            info.filename: prior.read(info.filename)
            for info in prior.infolist()
            if info.filename != "BUILD_REPORT.txt"
        }
    with zipfile.ZipFile(ADDITIONAL_PATCH) as additional:
        # This later delivery branched before PRIOR_PATCH. Only add the five
        # scene files absent from the cumulative base.
        for info in additional.infolist():
            if info.filename != "BUILD_REPORT.txt" and info.filename not in files:
                files[info.filename] = additional.read(info.filename)

    data = bytearray(files[TARGET])

    report: list[str] = []
    for offset, expected_hex, text in PATCHES:
        expected = bytes.fromhex(expected_hex)
        end = offset + len(expected)
        payload = encode(text, charmap)
        # A prior replacement may already occupy this body.  The immutable
        # control boundary is the structural guard for this overlay build.
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
        if len(names) != len(set(names)) or "BUILD_REPORT.txt" in names:
            raise SystemExit("ZIP has duplicate or report entries")
        if len(names) != len(files) or output.read(TARGET) != data:
            raise SystemExit("ZIP verification failed")

    print("\n".join(report))
    print(f"wrote {OUTPUT}")
    print(f"sha256={hashlib.sha256(OUTPUT.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
