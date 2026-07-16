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

from build_story_sf0b1_return_full import FONT_TARGET, glyph_index, write_glyph_plane  # noqa: E402
from build_story_verified_returns_e2_v17 import cursor, cursor_code, disk_id  # noqa: E402


BASE = ROOT / "03_output/story_verified_returns_e2_v17_cumulative_patch_only.zip"
BASE_HASH = "0CC3244DDE10CD8267248E984151DFA89BA788FCDE7C7A39C38B82E9A5E5CCDD"
MANIFEST = ROOT / "05_docs/story_legacy_tone_e2_v18_translation.csv"
EXTENDED = ROOT / "05_docs/korean_charmap_extended.csv"
CORPUS = ROOT / "01_work/analysis/story_corpus/story_corpus.csv"
OUTPUT = ROOT / "03_output/story_legacy_tone_e2_v18_cumulative_patch_only.zip"
REPORT = ROOT / "01_work/analysis/story_legacy_tone_e2_v18_report.txt"

SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT_COUNT = 79
FILLER = 0x9C
LINEBREAK = b"\xE6\x01"
BATCH_NOTE = "legacy tone E2 v0.18"

CHOICE_LAYOUTS = {
    ("21/S2041.DAT", 0x47EFE): (b"\xE5\x03", {0, 1, 2}, {0, 1, 2}),
    ("21/S2041.DAT", 0x48160): (b"\xE5\x04", {0, 1, 2}, {0, 1}),
    ("21/S2041.DAT", 0x48488): (b"\xE5\x04", {0, 1, 2}, {0, 1}),
    ("31/S3012.DAT", 0x4811E): (b"\xE5\x04", {0, 1, 2}, {0, 1}),
}

HYBRID = ("31/S3012.DAT", 0x47FF0)
HYBRID_PROMPT_END = 27
HYBRID_OPTION_RANGES = ((29, 36), (40, 53))
HYBRID_MARKER = b"\xE5\x03"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def encode(text: str, mapping: dict[str, bytes]) -> bytes:
    payload = bytearray()
    for char in text:
        payload.extend(bytes((FILLER,)) if char == " " else mapping[char])
    return bytes(payload)


def encode_choice(
    name: str,
    offset: int,
    text: str,
    mapping: dict[str, bytes],
) -> bytes:
    marker, marker_before, linebreak_after = CHOICE_LAYOUTS[(name, offset)]
    parts = text.split("|")
    if len(parts) != 3:
        raise SystemExit(f"choice must have three segments: {name} 0x{offset:X}")
    payload = bytearray()
    for index, part in enumerate(parts):
        if index in marker_before:
            payload.extend(marker)
        payload.extend(encode(part, mapping))
        if index in linebreak_after:
            payload.extend(LINEBREAK)
    return bytes(payload)


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("v0.17 base hash differs")

    manifest = rows(MANIFEST)
    counts = Counter(item["file"] for item in manifest)
    modes = Counter(item["mode"] for item in manifest)
    if len(manifest) != 53 or counts != {
        "F/SF0B1.DAT": 17,
        "21/S2041.DAT": 22,
        "31/S3012.DAT": 14,
    } or modes != {"e2": 48, "choice": 4, "hybrid_choice": 1}:
        raise SystemExit(f"unexpected manifest: rows={len(manifest)} files={counts} modes={modes}")

    corpus = rows(CORPUS)
    corpus_keys = {
        (item["file"], item["payload_start"])
        for item in corpus
        if item["file"] in counts and item["confidence"] == "high"
    }
    manifest_keys = {(item["file"], item["offset"]) for item in manifest}
    if corpus_keys != manifest_keys:
        raise SystemExit(f"manifest/corpus mismatch: {sorted(corpus_keys ^ manifest_keys)}")

    with zipfile.ZipFile(BASE) as archive:
        infos = {item.filename: item for item in archive.infolist()}
        files = {name: archive.read(name) for name in infos}
    if len(files) != 39:
        raise SystemExit("unexpected v0.17 file count")
    for name in counts:
        if name not in files:
            files[name] = (ROOT / "01_work" / name).read_bytes()

    extended = rows(EXTENDED)
    mapping = {item["char"]: bytes.fromhex(item["code_hex"]) for item in extended}
    occupied = set(mapping.values())
    occupied_indices = {glyph_index(code) for code in occupied}
    replaced = {(item["file"], item["offset"]) for item in manifest}
    parsed_codes: set[bytes] = set()
    for item in corpus:
        key = (item["file"], item["payload_start"])
        if key in replaced:
            continue
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

    needed = {
        char
        for item in manifest
        for char in item["text"]
        if char not in {" ", "|"}
    }
    missing = sorted(needed - mapping.keys())
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

    additions = []
    for char, code in zip(missing, candidates):
        mapping[char] = code
        additions.append({"char": char, "code_hex": code.hex().upper(), "slot_note": BATCH_NOTE})
    batch_glyphs = [item for item in extended if item["slot_note"] == BATCH_NOTE] + additions

    base_font = files[FONT_TARGET]
    font = bytearray(base_font)
    for char in sorted(needed):
        write_glyph_plane(font, mapping[char], char)
    if cursor(font) != cursor(base_font):
        raise SystemExit("battle cursor texture regression")
    files[FONT_TARGET] = bytes(font)

    targets = {name: bytearray(files[name]) for name in counts}
    e2_counts = Counter(
        item["file"] for item in manifest if item["mode"] in {"e2", "hybrid_choice"}
    )
    free_slots = {
        name: [
            slot
            for slot in range(SLOT_COUNT)
            if not any(data[SLOT_BASE + slot * SLOT_SIZE:SLOT_BASE + (slot + 1) * SLOT_SIZE])
        ]
        for name, data in targets.items()
    }
    for name, count in e2_counts.items():
        if len(free_slots[name]) < count:
            raise SystemExit(f"not enough empty slots in {name}: {len(free_slots[name])} < {count}")

    report_lines: list[str] = []
    for item in manifest:
        name = item["file"]
        data = targets[name]
        original = (ROOT / "01_work" / name).read_bytes()
        offset = int(item["offset"], 0)
        capacity = int(item["capacity"])
        mode = item["mode"]
        if original[offset + capacity:offset + capacity + 2] != b"\x00\x00":
            raise SystemExit(f"original boundary differs: {name} 0x{offset:X}")
        if data[offset + capacity:offset + capacity + 2] != b"\x00\x00":
            raise SystemExit(f"current boundary differs: {name} 0x{offset:X}")

        if mode == "choice":
            marker, marker_before, linebreak_after = CHOICE_LAYOUTS[(name, offset)]
            original_body = original[offset:offset + capacity]
            if original_body.count(marker) != len(marker_before):
                raise SystemExit(f"original choice markers differ: {name} 0x{offset:X}")
            if original_body.count(LINEBREAK) != len(linebreak_after):
                raise SystemExit(f"original choice line breaks differ: {name} 0x{offset:X}")
            payload = encode_choice(name, offset, item["text"], mapping)
            if len(payload) > capacity:
                raise SystemExit(f"choice overflow: {name} 0x{offset:X} {len(payload)}/{capacity}")
            data[offset:offset + capacity] = payload + bytes((FILLER,)) * (capacity - len(payload))
            report_lines.append(
                f"{name} 0x{offset:X} mode=choice bytes={len(payload)}/{capacity} text={item['text']}"
            )
            continue

        parts = item["text"].split("|")
        visible = parts[0]
        payload = encode(visible, mapping)
        if len(payload) > SLOT_SIZE - 1:
            raise SystemExit(f"E2 overflow: {name} 0x{offset:X} {len(payload)}/{SLOT_SIZE - 1}")
        slot = free_slots[name].pop(0)
        slot_offset = SLOT_BASE + slot * SLOT_SIZE
        data[slot_offset:slot_offset + SLOT_SIZE] = b"\x00" * SLOT_SIZE
        data[slot_offset:slot_offset + len(payload)] = payload

        if mode == "hybrid_choice":
            if (name, offset) != HYBRID or len(parts) != 3:
                raise SystemExit(f"unexpected hybrid choice: {name} 0x{offset:X}")
            original_body = original[offset:offset + capacity]
            if original_body[HYBRID_PROMPT_END:HYBRID_PROMPT_END + 2] != HYBRID_MARKER:
                raise SystemExit("hybrid first marker differs")
            if original_body[38:40] != HYBRID_MARKER:
                raise SystemExit("hybrid second marker differs")
            data[offset:offset + capacity] = original_body
            data[offset:offset + 2] = bytes((0xE2, disk_id(slot)))
            for option, (start, end) in zip(parts[1:], HYBRID_OPTION_RANGES):
                option_payload = encode(option, mapping)
                if len(option_payload) > end - start:
                    raise SystemExit(f"hybrid option overflow: {option} {len(option_payload)}/{end - start}")
                data[offset + start:offset + end] = option_payload + bytes((FILLER,)) * (
                    end - start - len(option_payload)
                )
            skip = HYBRID_PROMPT_END - 2
        else:
            skip = capacity - 2

        data[slot_offset + SLOT_SIZE - 1] = skip
        data[offset:offset + 2] = bytes((0xE2, disk_id(slot)))
        report_lines.append(
            f"{name} 0x{offset:X} mode={mode} slot={slot} command=E2 {disk_id(slot):02X} "
            f"skip={skip} bytes={len(payload)}/{SLOT_SIZE - 1} text={item['text']}"
        )

    files.update({name: bytes(data) for name, data in targets.items()})
    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            if name in infos:
                archive.writestr(infos[name], files[name])
            else:
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o600 << 16
                archive.writestr(info, files[name])

    with zipfile.ZipFile(BASE) as before, zipfile.ZipFile(OUTPUT) as after:
        if len(after.namelist()) != 40 or len(set(after.namelist())) != 40:
            raise SystemExit("output must contain 40 unique files")
        common_changed = {
            name for name in before.namelist() if before.read(name) != after.read(name)
        }
        expected_common = {"F/SF0B1.DAT", "21/S2041.DAT", FONT_TARGET}
        if common_changed != expected_common:
            raise SystemExit(f"unexpected common changes: {sorted(common_changed ^ expected_common)}")
        if "31/S3012.DAT" not in after.namelist():
            raise SystemExit("S3012 missing from output")

    if additions:
        with EXTENDED.open("a", encoding="utf-8", newline="") as handle:
            csv.DictWriter(handle, fieldnames=["char", "code_hex", "slot_note"]).writerows(additions)

    report = "\n".join(report_lines) + "\n"
    report += f"dialogues={len(manifest)}\ne2={modes['e2']}\nchoice={modes['choice']}\n"
    report += f"hybrid_choice={modes['hybrid_choice']}\nnew_glyphs={len(batch_glyphs)}\n"
    report += "sf0b1_naturalized=true\ns2041_complete=true\ns3012_complete=true\n"
    report += "battle_cursor_preserved=true\nother_files_preserved=true\n"
    report += f"sha256={digest(OUTPUT.read_bytes())}\n"
    REPORT.write_text(report, encoding="utf-8")
    print(f"dialogues={len(manifest)} e2={modes['e2']} choice={modes['choice']} hybrid=1")
    print(f"new_glyphs={len(batch_glyphs)}")
    print(f"sha256={digest(OUTPUT.read_bytes())}")
    print(OUTPUT)


if __name__ == "__main__":
    main()
