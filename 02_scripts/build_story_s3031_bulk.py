from __future__ import annotations

import csv
import hashlib
import sys
import zipfile
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from build_story_sf0b1_return_full import (  # noqa: E402
    CURSOR_RESERVED_CELLS,
    FILLER,
    FONT_TARGET,
    PAGEBREAK,
    glyph_index,
    load_charmap,
    write_glyph_plane,
)


BASE = ROOT / "03_output" / "story_bulk_s4041_cursor_fixed_full_patch_only.zip"
SOURCE = ROOT / "01_work" / "31" / "S3031.DAT"
MANIFEST = ROOT / "05_docs" / "story_s3031_bulk_translation.csv"
EXTENDED_CHARMAP = ROOT / "05_docs" / "korean_charmap_extended.csv"
OUTPUT = ROOT / "03_output" / "story_bulk_s3031_s4041_cursor_fixed_full_patch_only.zip"
TARGET = "31/S3031.DAT"
LINEBREAK = b"\xE6\x01"
REASSIGNED_CODES = tuple(bytes.fromhex(code) for code in ("E0C5", "E039", "E08F"))
BASELINE_DIRS = (
    "1", "21", "22", "23", "31", "32", "4", "5", "6", "7", "8", "9",
    "B", "C1", "C2", "D", "E1", "E2", "E3", "E4", "E5", "F",
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def encode_verified(text: str, charmap: dict[str, bytes], verified: set[str]) -> bytes:
    output = bytearray()
    for char in text:
        if char == "|":
            output.extend(LINEBREAK)
        elif char == "^":
            output.extend(PAGEBREAK)
        elif char == " ":
            output.append(FILLER)
        else:
            if char not in verified:
                raise SystemExit(f"translation uses unverified glyph: {char}")
            output.extend(charmap[char])
    return bytes(output)


def verify_codes_unused(rows: list[dict[str, str]], base_files: dict[str, bytes]) -> None:
    codes = {bytes.fromhex(row["code_hex"]): row["char"] for row in rows}
    counts: Counter[bytes] = Counter()
    for directory in BASELINE_DIRS:
        for path in (ROOT / "01_work" / directory).glob("*.DAT"):
            data = path.read_bytes()[0x45000:]
            for offset in range(len(data) - 1):
                pair = data[offset : offset + 2]
                if pair in codes:
                    counts[pair] += 1
    for code, char in codes.items():
        if counts[code]:
            raise SystemExit(f"extended code {code.hex()} for {char} occurs in original story data")
        index = glyph_index(code)
        row, remainder = divmod(index, 84)
        column, _ = divmod(remainder, 4)
        if (row, column) in CURSOR_RESERVED_CELLS:
            raise SystemExit(f"extended code {code.hex()} for {char} overlaps cursor")
    patched_dat = [data for name, data in base_files.items() if name.upper().endswith(".DAT")]
    for code in REASSIGNED_CODES:
        if any(code in data for data in patched_dat):
            raise SystemExit(f"reassigned code {code.hex()} occurs in cumulative DAT data")


def cursor_bytes(font: bytes) -> bytes:
    row_bytes = 0x380
    return b"".join(font[y * row_bytes : y * row_bytes + 16] for y in range(128, 160))


def main() -> None:
    translations = load_csv(MANIFEST)
    if len(translations) != 27:
        raise SystemExit("S3031 manifest must contain 27 dialogues")
    extended_rows = load_csv(EXTENDED_CHARMAP)
    verified = {row["char"] for row in extended_rows}
    charmap = load_charmap()

    with zipfile.ZipFile(BASE) as archive:
        files = {info.filename: archive.read(info.filename) for info in archive.infolist()}
    if len(files) != 31 or FONT_TARGET not in files or TARGET in files:
        raise SystemExit("unexpected cumulative base")
    verify_codes_unused(extended_rows, files)

    original = SOURCE.read_bytes()
    target = bytearray(original)
    base_font = files[FONT_TARGET]
    font = bytearray(base_font)
    for row in extended_rows:
        write_glyph_plane(font, bytes.fromhex(row["code_hex"]), row["char"])
    if cursor_bytes(font) != cursor_bytes(base_font):
        raise SystemExit("font update changed the confirmed battle cursor rectangle")

    report: list[str] = []
    for row in translations:
        offset = int(row["offset"], 0)
        expected = bytes.fromhex(row["expected_hex"])
        end = offset + len(expected)
        if original[offset:end] != expected:
            raise SystemExit(f"{TARGET} 0x{offset:X}: source bytes differ")
        if original[end : end + 2] != b"\x00\x00":
            raise SystemExit(f"{TARGET} 0x{offset:X}: missing boundary")
        payload = encode_verified(row["text"], charmap, verified)
        if len(payload) > len(expected):
            raise SystemExit(
                f"{TARGET} 0x{offset:X}: translation too long "
                f"{len(payload)} > {len(expected)}"
            )
        target[offset:end] = bytes([FILLER]) * len(expected)
        target[offset : offset + len(payload)] = payload
        if target[end : end + 2] != b"\x00\x00":
            raise SystemExit(f"{TARGET} 0x{offset:X}: boundary changed")
        report.append(f"0x{offset:X} {len(payload)}/{len(expected)} {row['text']}")

    files[FONT_TARGET] = bytes(font)
    files[TARGET] = bytes(target)
    if OUTPUT.exists():
        OUTPUT.unlink()
    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            archive.writestr(name, files[name])

    with zipfile.ZipFile(BASE) as base, zipfile.ZipFile(OUTPUT) as output:
        names = output.namelist()
        if len(names) != 32 or len(names) != len(set(names)):
            raise SystemExit("output must contain 32 unique game files")
        for name in base.namelist():
            if name != FONT_TARGET and output.read(name) != base.read(name):
                raise SystemExit(f"cumulative regression: {name}")
        if output.read(TARGET) != target or output.read(FONT_TARGET) != font:
            raise SystemExit("output payload verification failed")

    print("\n".join(report))
    print(f"entries=32 font_changed_bytes={sum(a != b for a, b in zip(base_font, font))}")
    print(f"wrote {OUTPUT}")
    print(f"sha256={digest(OUTPUT.read_bytes())}")


if __name__ == "__main__":
    main()
