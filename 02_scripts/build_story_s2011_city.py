from __future__ import annotations

import csv
import hashlib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output" / "story_s1041_short_questions_patch_only.zip"
SOURCE = Path(r"E:\arc\out\21\S2011.DAT")
OUTPUT = ROOT / "03_output" / "story_s2011_city_dialogue_patch_only.zip"
TARGET = "21/S2011.DAT"
FILLER = 0x9C
LINEBREAK = b"\xE6\x01"

# The seven screens are slot 10, then slots 1 through 6.  Each expected body
# is checked before replacement; the first 00 00 control boundary is preserved.
PATCHES = (
    (0x4791A, "2e 32 2a 24 a3 6f 34 60 42 dd 17 20 df 61 df 61 37", "\uc5ec\uae30\ub2e4"),
    (0x47AAA, "6e 35 3c 01 63 dd 54 2a dd 5b 27 22 1c 20 3c", "\uc544\ud06c|\uac00\uc790"),
    (0x47AF6, "3b 31 1b 02 e4 3d e6 01 98 29 21 3e 32 3d 31 02", "\uc544\ud06c|\uc5ec\uae30"),
    (0x47BAC, "66 68 25 e6 01 a3 6f 34 60 42 dd 17 23 6e 1c dd 3e 35 dd 88 84 09 2e 6a 26 0a 37 2e 2e 28 96 dd 0d 1c de 8a 99 89 30 28 1d 1b 6a 02", "\uc544\ud06c|\uc870\uc2ec"),
    (0x47C0C, "de 8a 99 23 9a 1f 2d 4a 48 1d 1b 37 e6 01 ad 28 5c 71 dd 39 dd 03 53 20 33 9a 1f 42 31 4e 37 5d cb 23 dd c2 58 32 1f 2d 35 37", "\uc544\ud06c|\uac00\uc790"),
    (0x47C68, "66 68 25 e6 01 5c 71 dd 39 dd 03 53 1c 42 31 4e 37 e4 1f e6 01 2e 2d 1d 96 dd 0d 35 29 1f 1c 20 df 61 df 61 37", "\uc544\ud06c"),
    (0x47CC0, "66 68 25 e6 01 b0 28 d3 1b 21 1b 22 37 e6 01 dd 75 29 21 3d 1e 37", "\uc544\ud06c"),
)


def load_charmap() -> dict[str, int]:
    with (ROOT / "05_docs" / "korean_charmap.csv").open(encoding="utf-8-sig", newline="") as f:
        return {row["char"]: int(row["code_hex"], 16) for row in csv.DictReader(f)}


def encode(text: str, charmap: dict[str, int]) -> bytes:
    payload = bytearray()
    for line_index, line in enumerate(text.split("|")):
        if line_index:
            payload.extend(LINEBREAK)
        for char in line:
            payload.append(charmap[char])
    return bytes(payload)


def main() -> None:
    if not BASE.exists() or not SOURCE.exists():
        raise SystemExit("missing cumulative base ZIP or current S2011 source")
    charmap = load_charmap()
    data = bytearray(SOURCE.read_bytes())
    report: list[str] = []
    for offset, expected_hex, text in PATCHES:
        expected = bytes.fromhex(expected_hex)
        if data[offset : offset + len(expected)] != expected:
            raise SystemExit(f"{TARGET} 0x{offset:X}: unexpected source bytes")
        boundary = offset + len(expected)
        if data[boundary : boundary + 2] != b"\x00\x00":
            raise SystemExit(f"{TARGET} 0x{offset:X}: 00 00 boundary missing")
        payload = encode(text, charmap)
        if len(payload) > len(expected):
            raise SystemExit(f"{TARGET} 0x{offset:X}: payload exceeds capacity")
        data[offset:boundary] = bytes([FILLER]) * len(expected)
        data[offset : offset + len(payload)] = payload
        if data[boundary : boundary + 2] != b"\x00\x00":
            raise SystemExit(f"{TARGET} 0x{offset:X}: boundary changed")
        report.append(f"0x{offset:X} {len(payload)}/{len(expected)} {text}")

    with zipfile.ZipFile(BASE) as base_zip, zipfile.ZipFile(
        OUTPUT, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as result:
        for info in base_zip.infolist():
            if info.filename != "BUILD_REPORT.txt":
                result.writestr(info, base_zip.read(info.filename))
        result.writestr(TARGET, data)

    with zipfile.ZipFile(OUTPUT) as result:
        if len(result.namelist()) != 17 or "BUILD_REPORT.txt" in result.namelist():
            raise SystemExit("unexpected output ZIP entries")
        output_data = result.read(TARGET)
        for offset, expected_hex, text in PATCHES:
            expected = bytes.fromhex(expected_hex)
            payload = encode(text, charmap)
            boundary = offset + len(expected)
            if output_data[offset : offset + len(payload)] != payload:
                raise SystemExit(f"output verification failed at 0x{offset:X}")
            if output_data[boundary : boundary + 2] != b"\x00\x00":
                raise SystemExit(f"output boundary verification failed at 0x{offset:X}")

    print("\n".join(report))
    print(f"wrote {OUTPUT}")
    print(f"files=17 sha256={hashlib.sha256(OUTPUT.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
