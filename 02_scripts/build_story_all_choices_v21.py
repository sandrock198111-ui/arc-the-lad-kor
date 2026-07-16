from __future__ import annotations

import csv
import hashlib
import sys
import zipfile
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))
sys.path.insert(0, str(ROOT / "02_scripts"))

from build_story_legacy_tone_e2_v18 import (  # noqa: E402
    FONT_TARGET,
    cursor,
    cursor_code,
    glyph_index,
    write_glyph_plane,
)


BASE = ROOT / "03_output/story_choice_layout_v20_cumulative_patch_only.zip"
BASE_HASH = "213717051809418251E5765D3BC72983990ADEE7A147F004FE4E7F2276C14AF4"
MANIFEST = ROOT / "05_docs/story_all_choices_v21_translation.csv"
CHARMAP = ROOT / "05_docs/korean_charmap_extended.csv"
CORPUS = ROOT / "01_work/analysis/story_corpus/story_corpus.csv"
OUTPUT = ROOT / "03_output/story_all_choices_v21_cumulative_patch_only.zip"
REPORT = ROOT / "01_work/analysis/all_choices_v21/build_report.txt"

FILLER = 0x9C
LINEBREAK = b"\xE6\x01"
BATCH_NOTE = "all choice bodies v0.21"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def digit_code(char: str) -> bytes:
    return bytes((0x11 + int(char),))


def encode(text: str, mapping: dict[str, bytes]) -> bytes:
    payload = bytearray()
    for char in text:
        if char == " ":
            payload.append(FILLER)
        elif char.isascii() and char.isdigit():
            payload.extend(digit_code(char))
        elif char not in mapping:
            raise SystemExit(f"missing glyph mapping: {char!r}")
        else:
            payload.extend(mapping[char])
    return bytes(payload)


def markers(body: bytes) -> list[bytes]:
    return [
        body[position:position + 2]
        for position in range(len(body) - 1)
        if body[position] == 0xE5
    ]


def first_marker(body: bytes) -> int:
    positions = [position for position in range(len(body) - 1) if body[position] == 0xE5]
    if not positions:
        raise SystemExit("choice body has no E5 marker")
    return positions[0]


def original_dynamic_e2(prompt: bytes) -> bytes:
    positions = [position for position in range(len(prompt) - 1) if prompt[position] == 0xE2]
    if len(positions) != 1:
        raise SystemExit(f"dynamic choice requires exactly one E2 command: {positions}")
    position = positions[0]
    return prompt[position:position + 2]


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("v0.20 base hash differs")

    manifest = rows(MANIFEST)
    keys = [(item["file"], item["offset"]) for item in manifest]
    modes = Counter(item["mode"] for item in manifest)
    target_files = sorted({item["file"] for item in manifest})
    if len(manifest) != 265 or len(keys) != len(set(keys)) or len(target_files) != 42:
        raise SystemExit(
            f"unexpected manifest scope: rows={len(manifest)} unique={len(set(keys))} "
            f"files={len(target_files)}"
        )
    if modes != {"vertical_inline": 257, "preserve_current": 8}:
        raise SystemExit(f"unexpected manifest modes: {modes}")
    if any(int(item["overflow"] or 0) for item in manifest):
        raise SystemExit("translation plan still contains overflows")

    corpus = rows(CORPUS)
    corpus_by_key = {
        (item["file"], item["payload_start"]): item
        for item in corpus
        if item["confidence"] == "high" and "<CTRL:E5>" in item["decoded_jp"]
    }
    if set(keys) != set(corpus_by_key):
        raise SystemExit("manifest does not exactly cover all high-confidence E5 bodies")

    with zipfile.ZipFile(BASE) as archive:
        infos = {info.filename: info for info in archive.infolist()}
        base_files = {name: archive.read(name) for name in infos}
    files = dict(base_files)
    for name in target_files:
        if name not in files:
            files[name] = (ROOT / "01_work" / name).read_bytes()

    extended = rows(CHARMAP)
    mapping = {item["char"]: bytes.fromhex(item["code_hex"]) for item in extended}
    needed = {
        char
        for item in manifest
        for char in item["text"]
        if char not in {" ", "|"} and not (char.isascii() and char.isdigit())
    }
    missing = sorted(needed - mapping.keys())
    occupied = set(mapping.values())
    occupied_indices = {glyph_index(code) for code in occupied}
    parsed_codes: set[bytes] = set()
    for item in corpus:
        source = ROOT / "01_work" / item["file"]
        if not source.exists():
            continue
        data = source.read_bytes()
        offset = int(item["payload_start"], 0)
        capacity = int(item["capacity"])
        body = data[offset:offset + capacity]
        position = 0
        while position < len(body):
            if 0xDD <= body[position] <= 0xE0 and position + 1 < len(body):
                parsed_codes.add(body[position:position + 2])
                position += 2
            else:
                position += 1

    candidates: list[bytes] = []
    candidate_indices: set[int] = set()
    for first in range(0xE0, 0xDC, -1):
        for second in range(0xFF, -1, -1):
            code = bytes((first, second))
            index = glyph_index(code)
            if (
                code not in occupied
                and code not in parsed_codes
                and index not in occupied_indices
                and index not in candidate_indices
                and not cursor_code(code)
            ):
                candidates.append(code)
                candidate_indices.add(index)
    if len(candidates) < len(missing):
        raise SystemExit(f"not enough safe glyph codes: {len(missing)} > {len(candidates)}")

    additions: list[dict[str, str]] = []
    for char, code in zip(missing, candidates):
        mapping[char] = code
        additions.append(
            {"char": char, "code_hex": code.hex().upper(), "slot_note": BATCH_NOTE}
        )
    batch_chars = sorted(
        {item["char"] for item in extended if item["slot_note"] == BATCH_NOTE} | set(missing)
    )

    font_before = files[FONT_TARGET]
    font = bytearray(font_before)
    for char in batch_chars:
        write_glyph_plane(font, mapping[char], char)
    if cursor(font) != cursor(font_before):
        raise SystemExit("battle cursor texture regression")
    files[FONT_TARGET] = bytes(font)

    before_targets = {name: files[name] for name in target_files}
    changed_ranges: dict[str, list[tuple[int, int]]] = {name: [] for name in target_files}
    report_lines: list[str] = []
    for item in manifest:
        name = item["file"]
        offset = int(item["offset"], 0)
        capacity = int(item["capacity"])
        original_file = (ROOT / "01_work" / name).read_bytes()
        original = original_file[offset:offset + capacity]
        current = files[name][offset:offset + capacity]
        if original_file[offset + capacity:offset + capacity + 2] != b"\x00\x00":
            raise SystemExit(f"original boundary differs: {name} 0x{offset:X}")
        original_markers = markers(original)
        expected_markers = [bytes.fromhex(value) for value in item["marker_types"].split("|")]
        if original_markers != expected_markers:
            raise SystemExit(f"manifest marker types differ: {name} 0x{offset:X}")

        if item["mode"] == "preserve_current":
            if current == original or markers(current) != original_markers:
                raise SystemExit(f"preserved choice is not verified: {name} 0x{offset:X}")
            report_lines.append(
                f"{name} 0x{offset:X} mode=preserve_current markers={len(original_markers)}"
            )
            continue

        parts = item["text"].split("|")
        prompt, options = parts[0], parts[1:]
        if len(options) != len(original_markers):
            raise SystemExit(f"option count differs: {name} 0x{offset:X}")
        payload = bytearray()
        if int(item["dynamic_e2"]):
            payload.extend(original_dynamic_e2(original[:first_marker(original)]))
        payload.extend(encode(prompt, mapping))
        if prompt:
            payload.extend(LINEBREAK)
        for index, (marker, option) in enumerate(zip(original_markers, options)):
            payload.extend(marker)
            payload.extend(encode(option, mapping))
            if index + 1 < len(options):
                payload.extend(LINEBREAK)
        if len(payload) > capacity:
            raise SystemExit(f"choice overflow: {name} 0x{offset:X} {len(payload)}/{capacity}")
        data = bytearray(files[name])
        data[offset:offset + capacity] = bytes(payload) + bytes((FILLER,)) * (
            capacity - len(payload)
        )
        result = bytes(data[offset:offset + capacity])
        if markers(result) != original_markers:
            raise SystemExit(f"choice marker regression: {name} 0x{offset:X}")
        files[name] = bytes(data)
        changed_ranges[name].append((offset, offset + capacity))
        report_lines.append(
            f"{name} 0x{offset:X} mode=vertical_inline markers={len(original_markers)} "
            f"bytes={len(payload)}/{capacity} text={item['text']}"
        )

    for name in target_files:
        before = before_targets[name]
        after = files[name]
        allowed = bytearray(len(after))
        for start, end in changed_ranges[name]:
            allowed[start:end] = b"\x01" * (end - start)
        outside = [
            index
            for index, (old, new) in enumerate(zip(before, after))
            if old != new and not allowed[index]
        ]
        if outside:
            raise SystemExit(
                f"{name} changed outside choice ranges: 0x{outside[0]:X} ({len(outside)} bytes)"
            )

    sorted_names = sorted(files)
    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted_names:
            if name in infos:
                archive.writestr(infos[name], files[name])
            else:
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o600 << 16
                archive.writestr(info, files[name])

    with zipfile.ZipFile(OUTPUT) as archive:
        names = archive.namelist()
        if names != sorted_names or len(names) != len(set(names)):
            raise SystemExit("output ZIP names/order differ")
        for name in sorted_names:
            if archive.read(name) != files[name]:
                raise SystemExit(f"ZIP readback differs: {name}")

        translated = 0
        mismatches = 0
        for item in manifest:
            name = item["file"]
            offset = int(item["offset"], 0)
            capacity = int(item["capacity"])
            original = (ROOT / "01_work" / name).read_bytes()[offset:offset + capacity]
            result = archive.read(name)[offset:offset + capacity]
            translated += int(result != original)
            mismatches += int(markers(result) != markers(original))
        if translated != 265 or mismatches:
            raise SystemExit(
                f"choice coverage differs: translated={translated} marker_mismatches={mismatches}"
            )

    if additions:
        with CHARMAP.open("a", encoding="utf-8", newline="") as handle:
            csv.DictWriter(handle, fieldnames=["char", "code_hex", "slot_note"]).writerows(additions)

    report_lines.extend(
        [
            f"choice_bodies=265",
            f"choice_files=42",
            f"rewritten=257",
            f"preserved_verified=8",
            "original_marker_sequences_preserved=265",
            "marker_mismatches=0",
            "overflows=0",
            f"batch_glyphs={len(batch_chars)}",
            f"zip_entries={len(sorted_names)}",
            "battle_cursor_preserved=true",
            f"sha256={digest(OUTPUT.read_bytes())}",
        ]
    )
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    print(f"choices=265 rewritten=257 preserved=8 files=42")
    print(f"batch_glyphs={len(batch_chars)} zip_entries={len(sorted_names)}")
    print(f"sha256={digest(OUTPUT.read_bytes())}")
    print(OUTPUT)


if __name__ == "__main__":
    main()
