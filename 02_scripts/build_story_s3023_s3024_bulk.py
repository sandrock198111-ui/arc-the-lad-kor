from __future__ import annotations

import csv
import hashlib
import zipfile
from collections import defaultdict
from pathlib import Path

from build_story_sf0b1_return_full import (
    BASE_CHARMAP, CURSOR_RESERVED_CELLS, FILLER, FONT_TARGET,
    glyph_index, write_glyph_plane,
)

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/story_bulk_s3011_s3022_sc011_s2041_s3031_s4041_cursor_fixed_full_patch_only.zip"
MANIFEST = ROOT / "05_docs/story_s3023_s3024_bulk_translation.csv"
EXTENDED = ROOT / "05_docs/korean_charmap_extended.csv"
CORPUS = ROOT / "01_work/analysis/story_corpus/story_corpus.csv"
OUTPUT = ROOT / "03_output/story_bulk_s3011_s3022_s3023_s3024_sc011_s2041_s3031_s4041_cursor_fixed_full_patch_only.zip"
LINEBREAK = b"\xE6\x01"
SOURCES = {
    "31/S3023.DAT": (ROOT / "01_work/31/S3023.DAT", "0880627052315C938F21E6191BB39FFE98CFBBB30ACB220B15131B554DEC6970"),
    "31/S3024.DAT": (ROOT / "01_work/31/S3024.DAT", "975FB3B4D9EB3F7CA4AC8AD98607F7C6AC3383F8D05DC2D1A10D51D7CCB9CD2F"),
}


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def cursor_code(code: bytes) -> bool:
    row, rem = divmod(glyph_index(code), 84)
    column, _ = divmod(rem, 4)
    return (row, column) in CURSOR_RESERVED_CELLS


def compact(text: str) -> str:
    for before, after in (
        ("괴물 출몰 뒤론", "괴물 뒤론"),
        ("군에서 식량을 사야 해.", "군 식량을 사야 해."),
        ("그게 결코 싸지 않다네.", "싸진 않다네."),
        ("아이|앗! ", ""),
        ("앗! ", ""),
        (" 버스터 형이다.", " 버스터다."),
        (" 버스터 형이다", " 버스터다"),
        ("남자|이젠 괴물 소굴이 됐습니다.", "남자|이젠 괴물 소굴입니다."),
        ("남자|이제 제멋대로입니다.|히히히히!", "남자|이젠 제멋대로죠.|히히히!"),
        ("병사|들어가십시오.", "병사|들어가시오."),
    ):
        text = text.replace(before, after)
    return text


def main() -> None:
    manifest = rows(MANIFEST)
    counts = defaultdict(int)
    for item in manifest:
        counts[item["file"]] += 1
    if dict(counts) != {"31/S3023.DAT": 17, "31/S3024.DAT": 57}:
        raise SystemExit(f"unexpected manifest: {dict(counts)}")

    mapping: dict[str, bytes] = {}
    for path in (BASE_CHARMAP, EXTENDED):
        for item in rows(path):
            mapping[item["char"]] = bytes.fromhex(item["code_hex"])
    extended = rows(EXTENDED)
    occupied = set(mapping.values())
    parsed: set[bytes] = set()
    for item in rows(CORPUS):
        body = bytes.fromhex(item["original_hex"])
        pos = 0
        while pos < len(body):
            if 0xDD <= body[pos] <= 0xE0 and pos + 1 < len(body):
                parsed.add(body[pos:pos + 2])
                pos += 2
            else:
                pos += 1
    missing = sorted({c for item in manifest for c in item["text"] if c not in mapping and c not in "| "})
    candidates = [bytes((a, b)) for a in range(0xE0, 0xDC, -1) for b in range(0xFF, -1, -1)
                  if bytes((a, b)) not in occupied and bytes((a, b)) not in parsed and not cursor_code(bytes((a, b)))]
    if len(candidates) < len(missing):
        raise SystemExit(f"not enough glyph codes: {len(missing)} > {len(candidates)}")
    new_rows = []
    for char, code in zip(missing, candidates):
        mapping[char] = code
        new_rows.append({"char": char, "code_hex": code.hex().upper(), "slot_note": "unused parsed-dialogue code; bulk S3023 S3024"})

    with zipfile.ZipFile(BASE) as archive:
        files = {i.filename: archive.read(i.filename) for i in archive.infolist()}
    if len(files) != 36 or any(name in files for name in SOURCES):
        raise SystemExit("unexpected cumulative base")
    base_font = files[FONT_TARGET]
    font = bytearray(base_font)
    for item in extended + new_rows:
        write_glyph_plane(font, bytes.fromhex(item["code_hex"]), item["char"])
    cursor = lambda data: b"".join(data[y * 0x380:y * 0x380 + 16] for y in range(128, 160))
    if cursor(font) != cursor(base_font):
        raise SystemExit("battle cursor regression")

    originals, targets = {}, {}
    for name, (path, expected) in SOURCES.items():
        data = path.read_bytes()
        if digest(data) != expected:
            raise SystemExit(f"source hash differs: {name}")
        originals[name] = data
        targets[name] = bytearray(data)
    report = []
    overflow = []
    for item in manifest:
        name, offset, capacity = item["file"], int(item["offset"], 0), int(item["capacity"])
        end = offset + capacity
        if originals[name][end:end + 2] != b"\x00\x00":
            raise SystemExit(f"missing boundary: {name} 0x{offset:X}")
        actual = compact(item["text"])
        payload = bytearray()
        for char in actual:
            payload.extend(LINEBREAK if char == "|" else bytes((FILLER,)) if char == " " else mapping[char])
        if len(payload) > capacity and "|" in actual and actual.split("|", 1)[0] in {"병사", "노인", "아이", "남자"}:
            actual = actual.split("|", 1)[1]
            payload = bytearray()
            for char in actual:
                payload.extend(LINEBREAK if char == "|" else bytes((FILLER,)) if char == " " else mapping[char])
        if len(payload) > capacity:
            overflow.append(f"{name} 0x{offset:X} {len(payload)}/{capacity} {actual}")
            continue
        targets[name][offset:end] = bytes((FILLER,)) * capacity
        targets[name][offset:offset + len(payload)] = payload
        report.append(f"{name} 0x{offset:X} {len(payload)}/{capacity} {actual}")

    if overflow:
        raise SystemExit("too long:\n" + "\n".join(overflow))
    files[FONT_TARGET] = bytes(font)
    files.update({name: bytes(data) for name, data in targets.items()})
    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            archive.writestr(name, files[name])
    with zipfile.ZipFile(BASE) as before, zipfile.ZipFile(OUTPUT) as after:
        if len(after.namelist()) != 38 or len(set(after.namelist())) != 38:
            raise SystemExit("output file count differs")
        for name in before.namelist():
            if name != FONT_TARGET and after.read(name) != before.read(name):
                raise SystemExit(f"cumulative regression: {name}")
    if new_rows:
        with EXTENDED.open("a", encoding="utf-8", newline="") as handle:
            csv.DictWriter(handle, fieldnames=["char", "code_hex", "slot_note"]).writerows(new_rows)
    report_path = ROOT / "01_work/analysis/story_s3023_s3024_bulk_build_report.txt"
    report_path.write_text("\n".join(report) + f"\nnew_glyphs={len(new_rows)}\nsha256={digest(OUTPUT.read_bytes())}\n", encoding="utf-8")
    print(f"entries={len(manifest)} new_glyphs={len(new_rows)} files={len(files)}")
    print(OUTPUT)
    print(digest(OUTPUT.read_bytes()))


if __name__ == "__main__":
    main()
