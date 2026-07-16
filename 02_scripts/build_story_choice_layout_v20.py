from __future__ import annotations

import csv
import hashlib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/story_minister_s3022_s3031_e2_v19_cumulative_patch_only.zip"
BASE_HASH = "5558DAE42D6EBD0CED2DA238512F30EE451007E731F7E9B4A5CC5E591A77A171"
MANIFEST = ROOT / "05_docs/story_choice_layout_v20_translation.csv"
CHARMAP = ROOT / "05_docs/korean_charmap_extended.csv"
OUTPUT = ROOT / "03_output/story_choice_layout_v20_cumulative_patch_only.zip"
REPORT = ROOT / "01_work/analysis/story_choice_layout_v20_report.txt"

SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
FILLER = 0x9C
CHOICE = b"\xE5\x03"
LINEBREAK = b"\xE6\x01"
CHOICE_LAYOUTS = {
    ("1/S1023.DAT", 0x47AB0): ({0, 1, 2, 3}, {0, 1, 2}),
    ("1/S1023.DAT", 0x47B30): ({0, 1, 2}, {0, 1}),
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def encode(text: str, mapping: dict[str, bytes]) -> bytes:
    payload = bytearray()
    for char in text:
        if char == " ":
            payload.append(FILLER)
        elif char not in mapping:
            raise SystemExit(f"missing glyph mapping: {char!r}")
        else:
            payload.extend(mapping[char])
    return bytes(payload)


def encode_choice(
    name: str,
    offset: int,
    text: str,
    mapping: dict[str, bytes],
) -> bytes:
    marker_before, linebreak_after = CHOICE_LAYOUTS[(name, offset)]
    parts = text.split("|")
    if len(parts) != len(marker_before):
        raise SystemExit(f"choice segment mismatch: {name} 0x{offset:X}")
    payload = bytearray()
    for index, part in enumerate(parts):
        if index in marker_before:
            payload.extend(CHOICE)
        payload.extend(encode(part, mapping))
        if index in linebreak_after:
            payload.extend(LINEBREAK)
    return bytes(payload)


def slot_from_disk_id(value: int) -> int:
    if 0x81 <= value <= 0xA8:
        return value - 0x81
    if 0xAA <= value <= 0xD0:
        return value - 0x82
    raise SystemExit(f"invalid E2 disk id: 0x{value:02X}")


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("v0.19 base hash differs")

    manifest = rows(MANIFEST)
    expected = [
        ("1/S1023.DAT", "0x47AB0", "choice_vertical"),
        ("1/S1023.DAT", "0x47B30", "choice_vertical"),
        ("31/S3012.DAT", "0x47FF0", "hybrid_prompt"),
    ]
    actual = [(item["file"], item["offset"], item["mode"]) for item in manifest]
    if actual != expected:
        raise SystemExit(f"unexpected manifest rows: {actual}")

    mapping = {item["char"]: bytes.fromhex(item["code_hex"]) for item in rows(CHARMAP)}
    with zipfile.ZipFile(BASE) as archive:
        infos = archive.infolist()
        files = {info.filename: archive.read(info.filename) for info in infos}
    if len(files) != 41 or len(files) != len(infos):
        raise SystemExit("unexpected v0.19 entry count")

    before = dict(files)
    report_lines: list[str] = []
    for item in manifest:
        name = item["file"]
        offset = int(item["offset"], 0)
        capacity = int(item["capacity"])
        data = bytearray(files[name])
        if data[offset + capacity:offset + capacity + 2] != b"\x00\x00":
            raise SystemExit(f"dialogue boundary differs: {name} 0x{offset:X}")

        if item["mode"] == "choice_vertical":
            payload = encode_choice(name, offset, item["text"], mapping)
            if len(payload) > capacity:
                raise SystemExit(f"choice overflow: {name} 0x{offset:X} {len(payload)}/{capacity}")
            data[offset:offset + capacity] = payload + bytes((FILLER,)) * (capacity - len(payload))
            markers = len(CHOICE_LAYOUTS[(name, offset)][0])
            breaks = len(CHOICE_LAYOUTS[(name, offset)][1])
            body = data[offset:offset + capacity]
            if body.count(CHOICE) != markers or body.count(LINEBREAK) != breaks:
                raise SystemExit(f"choice controls differ: {name} 0x{offset:X}")
            report_lines.append(
                f"{name} 0x{offset:X} vertical markers={markers} breaks={breaks} "
                f"bytes={len(payload)}/{capacity} text={item['text']}"
            )
        else:
            if data[offset] != 0xE2:
                raise SystemExit("S3012 hybrid prompt is not E2")
            slot = slot_from_disk_id(data[offset + 1])
            slot_offset = SLOT_BASE + slot * SLOT_SIZE
            skip = data[slot_offset + SLOT_SIZE - 1]
            if skip != 25:
                raise SystemExit(f"S3012 hybrid skip differs: {skip}")
            payload = encode(item["text"], mapping)
            if len(payload) > SLOT_SIZE - 1:
                raise SystemExit(f"hybrid prompt overflow: {len(payload)}/{SLOT_SIZE - 1}")
            options_before = bytes(data[offset + 27:offset + capacity])
            data[slot_offset:slot_offset + SLOT_SIZE] = b"\x00" * SLOT_SIZE
            data[slot_offset:slot_offset + len(payload)] = payload
            data[slot_offset + SLOT_SIZE - 1] = skip
            if bytes(data[offset + 27:offset + capacity]) != options_before:
                raise SystemExit("S3012 option bytes changed")
            report_lines.append(
                f"{name} 0x{offset:X} hybrid slot={slot} skip={skip} "
                f"bytes={len(payload)}/{SLOT_SIZE - 1} text={item['text']}"
            )
        files[name] = bytes(data)

    changed = {name for name in files if files[name] != before[name]}
    if changed != {"1/S1023.DAT", "31/S3012.DAT"}:
        raise SystemExit(f"unexpected changed files: {sorted(changed)}")

    with zipfile.ZipFile(OUTPUT, "w") as archive:
        for info in infos:
            archive.writestr(info, files[info.filename])

    with zipfile.ZipFile(OUTPUT) as archive:
        if archive.namelist() != [info.filename for info in infos]:
            raise SystemExit("ZIP entry order differs")
        if len(archive.namelist()) != 41 or len(set(archive.namelist())) != 41:
            raise SystemExit("output must contain 41 unique entries")
        for name in files:
            if archive.read(name) != files[name]:
                raise SystemExit(f"ZIP readback differs: {name}")

    report_lines.extend(
        [
            "base_entries_preserved=41",
            "changed_files=1/S1023.DAT,31/S3012.DAT",
            "choice_marker_order_preserved=true",
            "s3012_option_bytes_preserved=true",
            f"sha256={digest(OUTPUT.read_bytes())}",
        ]
    )
    REPORT.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    print(f"sha256={digest(OUTPUT.read_bytes())}")
    print(OUTPUT)


if __name__ == "__main__":
    main()
