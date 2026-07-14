from __future__ import annotations

import csv
import hashlib
import zipfile
from pathlib import Path

from build_story_s3011_s3022_sc011_bulk import (
    BASE,
    BATCH_NOTE,
    CHOICE,
    CORPUS,
    EXTENDED_CHARMAP,
    FONT_TARGET,
    MANIFEST,
    OUTPUT,
    REPORT,
    SOURCES,
    cursor_bytes,
    encode,
    load_csv,
    load_maps,
    parsed_dialogue_codes,
)
from build_story_sf0b1_return_full import FILLER, write_glyph_plane


VERIFY_REPORT = REPORT.with_name("verification_report.txt")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def main() -> None:
    translations = load_csv(MANIFEST)
    mapping, extended = load_maps()
    chars = [row["char"] for row in extended]
    codes = [row["code_hex"].upper() for row in extended]
    if len(chars) != len(set(chars)):
        raise SystemExit("duplicate character in extended charmap")
    if len(codes) != len(set(codes)):
        raise SystemExit("duplicate code in extended charmap")

    corpus_codes = parsed_dialogue_codes()
    batch_rows = [row for row in extended if row["slot_note"] == BATCH_NOTE]
    if not batch_rows:
        raise SystemExit("current batch glyph rows missing")
    for row in batch_rows:
        if bytes.fromhex(row["code_hex"]) in corpus_codes:
            raise SystemExit(f"batch code occurs in parsed dialogue: {row}")

    with zipfile.ZipFile(BASE) as base, zipfile.ZipFile(OUTPUT) as output:
        base_files = {info.filename: base.read(info.filename) for info in base.infolist()}
        output_files = {info.filename: output.read(info.filename) for info in output.infolist()}
    if len(base_files) != 33 or len(output_files) != 36:
        raise SystemExit("unexpected archive entry count")
    if len(output_files) != len(set(output_files)):
        raise SystemExit("duplicate output archive entry")
    for name, body in base_files.items():
        if name != FONT_TARGET and output_files[name] != body:
            raise SystemExit(f"base regression: {name}")

    by_file: dict[str, list[dict[str, str]]] = {name: [] for name in SOURCES}
    for row in translations:
        by_file[row["file"]].append(row)
    changed_counts: dict[str, int] = {}
    for name, (path, expected_hash) in SOURCES.items():
        original = path.read_bytes()
        if digest(original) != expected_hash:
            raise SystemExit(f"source hash differs: {name}")
        expected = bytearray(original)
        allowed: set[int] = set()
        for row in by_file[name]:
            offset = int(row["offset"], 0)
            capacity = int(row["capacity"])
            end = offset + capacity
            payload = encode(row["text"], mapping)
            expected[offset:end] = bytes([FILLER]) * capacity
            expected[offset : offset + len(payload)] = payload
            allowed.update(range(offset, end))
            if expected[end : end + 2] != b"\x00\x00":
                raise SystemExit(f"boundary changed: {name} 0x{offset:X}")
            if payload.count(CHOICE) != row["text"].count("@"):
                raise SystemExit(f"choice count differs: {name} 0x{offset:X}")
        actual = output_files[name]
        if actual != expected:
            raise SystemExit(f"full target reconstruction differs: {name}")
        changed = {index for index, (a, b) in enumerate(zip(original, actual)) if a != b}
        if not changed <= allowed:
            raise SystemExit(f"out-of-range target changes: {name}")
        changed_counts[name] = len(changed)

    reconstructed_font = bytearray(base_files[FONT_TARGET])
    for row in extended:
        write_glyph_plane(reconstructed_font, bytes.fromhex(row["code_hex"]), row["char"])
    if bytes(reconstructed_font) != output_files[FONT_TARGET]:
        raise SystemExit("font reconstruction differs")
    if cursor_bytes(reconstructed_font) != cursor_bytes(base_files[FONT_TARGET]):
        raise SystemExit("cursor rectangle differs")

    lines = [
        "PASS",
        f"output={OUTPUT}",
        f"sha256={digest(OUTPUT.read_bytes())}",
        "entries=36",
        f"manifest_blocks={len(translations)}",
        f"batch_glyphs={len(batch_rows)}",
        f"extended_glyphs={len(extended)}",
        "cursor_rectangle=unchanged",
        "base_nonfont_files=unchanged",
    ]
    lines.extend(f"changed_bytes[{name}]={count}" for name, count in changed_counts.items())
    VERIFY_REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
