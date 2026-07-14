from __future__ import annotations

import csv
import hashlib
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from build_story_sf0b1_return_full import (  # noqa: E402
    CURSOR_RESERVED_CELLS,
    FILLER,
    FONT_TARGET,
    glyph_index,
    load_charmap,
    write_glyph_plane,
)


BASE = ROOT / "03_output" / "story_bulk_s3031_s4041_cursor_fixed_full_patch_only.zip"
SOURCE = ROOT / "01_work" / "21" / "S2041.DAT"
MANIFEST = ROOT / "05_docs" / "story_s2041_bulk_translation.csv"
CHARMAP = ROOT / "05_docs" / "korean_charmap_extended.csv"
CORPUS = ROOT / "01_work" / "analysis" / "story_corpus" / "story_corpus.csv"
OUTPUT = ROOT / "03_output" / "story_bulk_s2041_s3031_s4041_cursor_fixed_full_patch_only.zip"
TARGET = "21/S2041.DAT"
SOURCE_SHA256 = "C8F263D6A13A50EE1513D2F47E662A54415155FEC9A734925D9060FBFA27ACBF"
LINEBREAK = b"\xE6\x01"
CHOICE = b"\xE5\x04"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def encode(text: str, charmap: dict[str, bytes], verified: set[str]) -> bytes:
    output = bytearray()
    for char in text:
        if char == "|":
            output.extend(LINEBREAK)
        elif char == "@":
            output.extend(CHOICE)
        elif char == " ":
            output.append(FILLER)
        else:
            if char not in verified:
                raise SystemExit(f"translation uses unverified glyph: {char}")
            output.extend(charmap[char])
    return bytes(output)


def verify_new_codes_unused(rows: list[dict[str, str]]) -> None:
    new_codes = {
        bytes.fromhex(row["code_hex"]): row["char"]
        for row in rows
        if "bulk batch S2041" in row["slot_note"]
    }
    if len(new_codes) != 32:
        raise SystemExit("expected exactly 32 S2041 glyph codes")
    for corpus_row in load_csv(CORPUS):
        body = bytes.fromhex(corpus_row["original_hex"])
        offset = 0
        while offset < len(body):
            if 0xDD <= body[offset] <= 0xE0 and offset + 1 < len(body):
                code = body[offset : offset + 2]
                if code in new_codes:
                    raise SystemExit(
                        f"new code {code.hex()} for {new_codes[code]} occurs in parsed dialogue"
                    )
                offset += 2
            else:
                offset += 1
    for code, char in new_codes.items():
        index = glyph_index(code)
        row, remainder = divmod(index, 84)
        column, _ = divmod(remainder, 4)
        if (row, column) in CURSOR_RESERVED_CELLS:
            raise SystemExit(f"new code {code.hex()} for {char} overlaps cursor")


def cursor_bytes(font: bytes) -> bytes:
    return b"".join(font[y * 0x380 : y * 0x380 + 16] for y in range(128, 160))


def main() -> None:
    translations = load_csv(MANIFEST)
    if len(translations) != 21:
        raise SystemExit("S2041 manifest must contain 21 blocks")
    rows = load_csv(CHARMAP)
    verified = {row["char"] for row in rows}
    charmap = load_charmap()
    verify_new_codes_unused(rows)

    with zipfile.ZipFile(BASE) as archive:
        files = {info.filename: archive.read(info.filename) for info in archive.infolist()}
    if len(files) != 32 or FONT_TARGET not in files or TARGET in files:
        raise SystemExit("unexpected cumulative base")

    original = SOURCE.read_bytes()
    if digest(original) != SOURCE_SHA256:
        raise SystemExit("S2041 source hash differs")
    target = bytearray(original)
    base_font = files[FONT_TARGET]
    font = bytearray(base_font)
    for row in rows:
        write_glyph_plane(font, bytes.fromhex(row["code_hex"]), row["char"])
    if cursor_bytes(font) != cursor_bytes(base_font):
        raise SystemExit("font update changed the confirmed cursor rectangle")

    report: list[str] = []
    for row in translations:
        offset = int(row["offset"], 0)
        capacity = int(row["capacity"])
        end = offset + capacity
        if original[end : end + 2] != b"\x00\x00":
            raise SystemExit(f"{TARGET} 0x{offset:X}: missing boundary")
        payload = encode(row["text"], charmap, verified)
        if len(payload) > capacity:
            raise SystemExit(
                f"{TARGET} 0x{offset:X}: translation too long {len(payload)} > {capacity}"
            )
        target[offset:end] = bytes([FILLER]) * capacity
        target[offset : offset + len(payload)] = payload
        if target[end : end + 2] != b"\x00\x00":
            raise SystemExit(f"{TARGET} 0x{offset:X}: boundary changed")
        if "@" in row["text"] and target[offset : offset + 2] != CHOICE:
            raise SystemExit(f"{TARGET} 0x{offset:X}: choice marker missing")
        report.append(f"0x{offset:X} {len(payload)}/{capacity} {row['text']}")

    files[FONT_TARGET] = bytes(font)
    files[TARGET] = bytes(target)
    if OUTPUT.exists():
        OUTPUT.unlink()
    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            archive.writestr(name, files[name])

    with zipfile.ZipFile(BASE) as base, zipfile.ZipFile(OUTPUT) as output:
        names = output.namelist()
        if len(names) != 33 or len(names) != len(set(names)):
            raise SystemExit("output must contain 33 unique game files")
        for name in base.namelist():
            if name != FONT_TARGET and output.read(name) != base.read(name):
                raise SystemExit(f"cumulative regression: {name}")
        if output.read(TARGET) != target or output.read(FONT_TARGET) != font:
            raise SystemExit("output payload verification failed")

    print("\n".join(report))
    print(f"entries=33 font_changed_bytes={sum(a != b for a, b in zip(base_font, font))}")
    print(f"wrote {OUTPUT}")
    print(f"sha256={digest(OUTPUT.read_bytes())}")


if __name__ == "__main__":
    main()
