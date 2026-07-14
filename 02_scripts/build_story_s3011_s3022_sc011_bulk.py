from __future__ import annotations

import csv
import hashlib
import zipfile
from collections import defaultdict
from pathlib import Path

from build_story_sf0b1_return_full import (
    BASE_CHARMAP,
    CURSOR_RESERVED_CELLS,
    FILLER,
    FONT_TARGET,
    glyph_index,
    write_glyph_plane,
)


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output" / "story_bulk_s2041_s3031_s4041_cursor_fixed_full_patch_only.zip"
MANIFEST = ROOT / "05_docs" / "story_s3011_s3022_sc011_bulk_translation.csv"
EXTENDED_CHARMAP = ROOT / "05_docs" / "korean_charmap_extended.csv"
CORPUS = ROOT / "01_work" / "analysis" / "story_corpus" / "story_corpus.csv"
OUTPUT = ROOT / "03_output" / "story_bulk_s3011_s3022_sc011_s2041_s3031_s4041_cursor_fixed_full_patch_only.zip"
REPORT = ROOT / "01_work" / "analysis" / "next_bulk_latest_states" / "build_report.txt"
LINEBREAK = b"\xE6\x01"
CHOICE = b"\xE5\x04"
BATCH_NOTE = "unused parsed-dialogue code; bulk batch S3011 S3022 SC011"
SOURCES = {
    "31/S3011.DAT": (
        ROOT / "01_work" / "31" / "S3011.DAT",
        "3EAFBAC0D769573D04AFC2BBC7CA95BD3F3667C6E6C2337F299AB265B57B7196",
    ),
    "31/S3022.DAT": (
        ROOT / "01_work" / "31" / "S3022.DAT",
        "A8D9618E652C081303F5B815B77A774CF2A8AE0705AF7FF479F5346F209B7A37",
    ),
    "C1/SC011.DAT": (
        ROOT / "01_work" / "C1" / "SC011.DAT",
        "91A039FB8805923765E953FE4D1ECAD0A9E5496332F3A2F5BC80D4C792B0304B",
    ),
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def load_maps() -> tuple[dict[str, bytes], list[dict[str, str]]]:
    mapping: dict[str, bytes] = {}
    for path in (BASE_CHARMAP, EXTENDED_CHARMAP):
        for row in load_csv(path):
            mapping[row["char"]] = bytes.fromhex(row["code_hex"])
    return mapping, load_csv(EXTENDED_CHARMAP)


def parsed_dialogue_codes() -> set[bytes]:
    used: set[bytes] = set()
    for row in load_csv(CORPUS):
        body = bytes.fromhex(row["original_hex"])
        offset = 0
        while offset < len(body):
            if 0xDD <= body[offset] <= 0xE0 and offset + 1 < len(body):
                used.add(body[offset : offset + 2])
                offset += 2
            else:
                offset += 1
    return used


def is_cursor_code(code: bytes) -> bool:
    index = glyph_index(code)
    row, remainder = divmod(index, 84)
    column, _ = divmod(remainder, 4)
    return (row, column) in CURSOR_RESERVED_CELLS


def allocate_missing(
    translations: list[dict[str, str]], mapping: dict[str, bytes], extended: list[dict[str, str]]
) -> list[dict[str, str]]:
    special = {"|", "@", " "}
    missing = sorted({char for row in translations for char in row["text"] if char not in mapping and char not in special})
    occupied = set(mapping.values())
    corpus_used = parsed_dialogue_codes()
    candidates = []
    for first in range(0xE0, 0xDC, -1):
        for second in range(0xFF, -1, -1):
            code = bytes((first, second))
            if code not in occupied and code not in corpus_used and not is_cursor_code(code):
                candidates.append(code)
    if len(candidates) < len(missing):
        raise SystemExit(f"not enough safe glyph codes: need {len(missing)}, have {len(candidates)}")
    new_rows = []
    for char, code in zip(missing, candidates):
        mapping[char] = code
        new_rows.append({"char": char, "code_hex": code.hex().upper(), "slot_note": BATCH_NOTE})
    if {bytes.fromhex(row["code_hex"]) for row in new_rows} & corpus_used:
        raise SystemExit("new glyph allocation overlaps parsed dialogue")
    return new_rows


def encode(text: str, mapping: dict[str, bytes]) -> bytes:
    output = bytearray()
    for char in text:
        if char == "|":
            output.extend(LINEBREAK)
        elif char == "@":
            output.extend(CHOICE)
        elif char == " ":
            output.append(FILLER)
        else:
            output.extend(mapping[char])
    return bytes(output)


def cursor_bytes(font: bytes) -> bytes:
    return b"".join(font[y * 0x380 : y * 0x380 + 16] for y in range(128, 160))


def main() -> None:
    translations = load_csv(MANIFEST)
    if len(translations) != 45:
        raise SystemExit("manifest must contain exactly 45 verified blocks")
    counts = defaultdict(int)
    for row in translations:
        counts[row["file"]] += 1
    if dict(counts) != {"31/S3011.DAT": 1, "31/S3022.DAT": 36, "C1/SC011.DAT": 8}:
        raise SystemExit(f"unexpected manifest distribution: {dict(counts)}")

    mapping, extended = load_maps()
    new_rows = allocate_missing(translations, mapping, extended)
    with zipfile.ZipFile(BASE) as archive:
        files = {info.filename: archive.read(info.filename) for info in archive.infolist()}
    if len(files) != 33 or FONT_TARGET not in files or any(name in files for name in SOURCES):
        raise SystemExit("unexpected cumulative base")

    originals: dict[str, bytes] = {}
    targets: dict[str, bytearray] = {}
    for name, (path, expected_hash) in SOURCES.items():
        original = path.read_bytes()
        if digest(original) != expected_hash:
            raise SystemExit(f"source hash differs: {name}")
        originals[name] = original
        targets[name] = bytearray(original)

    base_font = files[FONT_TARGET]
    font = bytearray(base_font)
    for row in extended + new_rows:
        write_glyph_plane(font, bytes.fromhex(row["code_hex"]), row["char"])
    if cursor_bytes(font) != cursor_bytes(base_font):
        raise SystemExit("font update changed the confirmed battle cursor rectangle")

    report = []
    for row in translations:
        name = row["file"]
        offset = int(row["offset"], 0)
        capacity = int(row["capacity"])
        end = offset + capacity
        original = originals[name]
        target = targets[name]
        if original[end : end + 2] != b"\x00\x00":
            raise SystemExit(f"{name} 0x{offset:X}: missing boundary")
        payload = encode(row["text"], mapping)
        if len(payload) > capacity:
            raise SystemExit(f"{name} 0x{offset:X}: {len(payload)} > {capacity}: {row['text']}")
        target[offset:end] = bytes([FILLER]) * capacity
        target[offset : offset + len(payload)] = payload
        if target[end : end + 2] != b"\x00\x00":
            raise SystemExit(f"{name} 0x{offset:X}: boundary changed")
        if row["text"].count("@") != payload.count(CHOICE):
            raise SystemExit(f"{name} 0x{offset:X}: choice marker count changed")
        report.append(f"{name} 0x{offset:X} {len(payload)}/{capacity} {row['text']}")

    files[FONT_TARGET] = bytes(font)
    for name, target in targets.items():
        files[name] = bytes(target)
    if OUTPUT.exists():
        OUTPUT.unlink()
    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            archive.writestr(name, files[name])

    with zipfile.ZipFile(BASE) as base, zipfile.ZipFile(OUTPUT) as output:
        names = output.namelist()
        if len(names) != 36 or len(names) != len(set(names)):
            raise SystemExit("output must contain 36 unique game files")
        for name in base.namelist():
            if name != FONT_TARGET and output.read(name) != base.read(name):
                raise SystemExit(f"cumulative regression: {name}")
        for name, target in targets.items():
            if output.read(name) != target:
                raise SystemExit(f"output payload differs: {name}")
        if output.read(FONT_TARGET) != font:
            raise SystemExit("output font differs")

    if new_rows:
        with EXTENDED_CHARMAP.open("a", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=["char", "code_hex", "slot_note"])
            writer.writerows(new_rows)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        "\n".join(report)
        + f"\nnew_glyphs={len(new_rows)}\nentries=36\nsha256={digest(OUTPUT.read_bytes())}\n",
        encoding="utf-8",
    )
    print("\n".join(report))
    print(f"new_glyphs={len(new_rows)} entries=36")
    print(f"wrote {OUTPUT}")
    print(f"sha256={digest(OUTPUT.read_bytes())}")


if __name__ == "__main__":
    main()
