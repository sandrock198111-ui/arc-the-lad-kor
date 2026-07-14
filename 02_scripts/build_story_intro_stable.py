from __future__ import annotations

import csv
import hashlib
import zipfile
from pathlib import Path

from build_story_sf0b1_return_full import (
    BASE_CHARMAP, CURSOR_RESERVED_CELLS, FILLER, FONT_TARGET,
    glyph_index, write_glyph_plane,
)

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/story_bulk_s3011_s3022_s3023_s3024_sc011_s2041_s3031_s4041_cursor_fixed_full_patch_only.zip"
MANIFEST = ROOT / "05_docs/story_intro_s1071_s1011_stable_translation.csv"
EXTENDED = ROOT / "05_docs/korean_charmap_extended.csv"
CORPUS = ROOT / "01_work/analysis/story_corpus/story_corpus.csv"
OUTPUT = ROOT / "03_output/story_intro_stable_v01_cumulative_patch_only.zip"
LINEBREAK = b"\xE6\x01"


def load(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def is_cursor(code: bytes) -> bool:
    row, rem = divmod(glyph_index(code), 84)
    column, _ = divmod(rem, 4)
    return (row, column) in CURSOR_RESERVED_CELLS


def encode(text: str, mapping: dict[str, bytes]) -> bytes:
    out = bytearray()
    for char in text:
        out.extend(LINEBREAK if char == "|" else bytes((FILLER,)) if char == " " else mapping[char])
    return bytes(out)


def main() -> None:
    manifest = load(MANIFEST)
    if len(manifest) != 13:
        raise SystemExit("intro manifest must contain 13 rows")
    mapping: dict[str, bytes] = {}
    for path in (BASE_CHARMAP, EXTENDED):
        for row in load(path):
            mapping[row["char"]] = bytes.fromhex(row["code_hex"])
    extended = load(EXTENDED)
    occupied = set(mapping.values())
    parsed: set[bytes] = set()
    for row in load(CORPUS):
        body = bytes.fromhex(row["original_hex"])
        pos = 0
        while pos < len(body):
            if 0xDD <= body[pos] <= 0xE0 and pos + 1 < len(body):
                parsed.add(body[pos:pos + 2])
                pos += 2
            else:
                pos += 1
    missing = sorted({c for row in manifest for c in row["text"] if c not in mapping and c not in "| "})
    candidates = [bytes((a, b)) for a in range(0xE0, 0xDC, -1) for b in range(0xFF, -1, -1)
                  if bytes((a, b)) not in occupied and bytes((a, b)) not in parsed and not is_cursor(bytes((a, b)))]
    if len(candidates) < len(missing):
        raise SystemExit(f"not enough safe codes: {len(missing)} > {len(candidates)}")
    added = []
    for char, code in zip(missing, candidates):
        mapping[char] = code
        added.append({"char": char, "code_hex": code.hex().upper(), "slot_note": "intro stable v0.1"})

    with zipfile.ZipFile(BASE) as archive:
        files = {item.filename: archive.read(item.filename) for item in archive.infolist()}
    if len(files) != 38:
        raise SystemExit("unexpected cumulative base")
    targets = {name: bytearray(files[name]) for name in {row["file"] for row in manifest}}
    report = []
    overflow = []
    for row in manifest:
        name, offset, capacity = row["file"], int(row["offset"], 0), int(row["capacity"])
        end = offset + capacity
        if files[name][end:end + 2] != b"\x00\x00":
            raise SystemExit(f"missing boundary: {name} 0x{offset:X}")
        payload = encode(row["text"], mapping)
        if len(payload) > capacity:
            overflow.append(f"{name} 0x{offset:X} {len(payload)}/{capacity} {row['text']}")
            continue
        targets[name][offset:end] = bytes((FILLER,)) * capacity
        targets[name][offset:offset + len(payload)] = payload
        report.append(f"{name} 0x{offset:X} {len(payload)}/{capacity} {row['text']}")
    if overflow:
        raise SystemExit("too long:\n" + "\n".join(overflow))

    base_font = files[FONT_TARGET]
    font = bytearray(base_font)
    for row in extended + added:
        write_glyph_plane(font, bytes.fromhex(row["code_hex"]), row["char"])
    cursor = lambda data: b"".join(data[y * 0x380:y * 0x380 + 16] for y in range(128, 160))
    if cursor(font) != cursor(base_font):
        raise SystemExit("battle cursor regression")
    files[FONT_TARGET] = bytes(font)
    files.update({name: bytes(data) for name, data in targets.items()})
    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            archive.writestr(name, files[name])
    with zipfile.ZipFile(BASE) as before, zipfile.ZipFile(OUTPUT) as after:
        if len(after.namelist()) != 38 or len(set(after.namelist())) != 38:
            raise SystemExit("output entry count differs")
        for name in before.namelist():
            if name not in targets and name != FONT_TARGET and after.read(name) != before.read(name):
                raise SystemExit(f"cumulative regression: {name}")
    if added:
        with EXTENDED.open("a", encoding="utf-8", newline="") as handle:
            csv.DictWriter(handle, fieldnames=["char", "code_hex", "slot_note"]).writerows(added)
    report_path = ROOT / "01_work/analysis/story_intro_stable_v01_build_report.txt"
    report_path.write_text("\n".join(report) + f"\nnew_glyphs={len(added)}\nsha256={digest(OUTPUT.read_bytes())}\n", encoding="utf-8")
    print(f"entries={len(manifest)} new_glyphs={len(added)} files={len(files)}")
    print(OUTPUT)
    print(digest(OUTPUT.read_bytes()))


if __name__ == "__main__":
    main()
