from __future__ import annotations

import csv
import hashlib
import zipfile
from collections import Counter
from pathlib import Path

from build_story_all_choices_v21 import encode
from build_story_dialogue_choice_structure_v22 import (
    control_positions,
    disk_id,
    slot_from_disk_id,
)
from build_story_legacy_tone_e2_v18 import SLOT_BASE, SLOT_COUNT, SLOT_SIZE


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/story_dialogue_choice_structure_v22_cumulative_patch_only.zip"
BASE_HASH = "C5005057BF77F51912A93E5FB4C4EA3F1368BD2CDA6C5A02BF32E55F531254C4"
CHOICES = ROOT / "05_docs/story_all_choices_v21_translation.csv"
OVERRIDES = ROOT / "05_docs/story_v23_choice_prompt_lines.csv"
CHARMAP = ROOT / "05_docs/korean_charmap_extended.csv"
OUTPUT = ROOT / "03_output/story_choice_row_alignment_v23_cumulative_patch_only.zip"
REPORT = ROOT / "01_work/analysis/story_choice_row_alignment_v23_report.txt"
AUDIT = ROOT / "01_work/analysis/story_choice_row_alignment_v23_audit.csv"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def prompt_spans(original: bytes) -> tuple[int, list[tuple[int, int]]]:
    markers = control_positions(original, 0xE5)
    if not markers:
        raise ValueError("choice body has no E5 control")
    first_marker = markers[0][0]
    breaks = control_positions(original[:first_marker], 0xE6)
    spans: list[tuple[int, int]] = []
    start = 0
    for position, _ in breaks:
        if position > start:
            spans.append((start, position))
        start = position + 2
    if start < first_marker:
        spans.append((start, first_marker))
    return first_marker, spans


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("v0.22 base hash differs")

    choice_rows = rows(CHOICES)
    override_rows = rows(OVERRIDES)
    if len(choice_rows) != 265 or len(override_rows) != 15:
        raise SystemExit("unexpected v0.23 manifest scope")

    override_map = {
        (item["file"], item["offset"]): item["lines"].split("|")
        for item in override_rows
    }
    mapping = {
        item["char"]: bytes.fromhex(item["code_hex"])
        for item in rows(CHARMAP)
    }

    with zipfile.ZipFile(BASE) as archive:
        infos = {info.filename: info for info in archive.infolist()}
        files = {name: archive.read(name) for name in infos}
    base_files = dict(files)

    free_slots: dict[str, list[int]] = {}
    for name, data in files.items():
        if len(data) < SLOT_BASE + SLOT_COUNT * SLOT_SIZE:
            continue
        free_slots[name] = [
            slot
            for slot in range(SLOT_COUNT)
            if not any(
                data[
                    SLOT_BASE + slot * SLOT_SIZE:
                    SLOT_BASE + (slot + 1) * SLOT_SIZE
                ]
            )
        ]

    targets: list[tuple[dict[str, str], bytes, int, list[tuple[int, int]], int]] = []
    old_slot_keys: list[tuple[str, int]] = []
    for item in choice_rows:
        name = item["file"]
        offset = int(item["offset"], 0)
        capacity = int(item["capacity"])
        current = files[name][offset:offset + capacity]
        original = (ROOT / "01_work" / name).read_bytes()[offset:offset + capacity]
        if len(current) < 2 or current[0] != 0xE2:
            continue
        try:
            old_slot = slot_from_disk_id(current[1])
        except ValueError:
            continue
        first_marker, spans = prompt_spans(original)
        if not control_positions(original[:first_marker], 0xE6):
            continue
        targets.append((item, original, first_marker, spans, old_slot))
        old_slot_keys.append((name, old_slot))

    if len(targets) != 133:
        raise SystemExit(f"unexpected external choice prompts: {len(targets)}/133")
    duplicate_slots = [key for key, count in Counter(old_slot_keys).items() if count != 1]
    if duplicate_slots:
        raise SystemExit(f"shared old prompt slots: {duplicate_slots}")

    used_ranges: dict[str, list[tuple[int, int]]] = {}
    audit_rows: list[dict[str, object]] = []
    used_slots: list[tuple[str, int, int, int]] = []

    def allow(name: str, start: int, end: int) -> None:
        used_ranges.setdefault(name, []).append((start, end))

    def write_slot(
        name: str,
        data: bytearray,
        slot: int,
        text: str,
        skip: int,
    ) -> None:
        payload = encode(text, mapping)
        if len(payload) > SLOT_SIZE - 2:
            raise SystemExit(f"v0.23 E2 overflow: {name} slot={slot} bytes={len(payload)}")
        slot_offset = SLOT_BASE + slot * SLOT_SIZE
        data[slot_offset:slot_offset + SLOT_SIZE] = b"\x00" * SLOT_SIZE
        data[slot_offset:slot_offset + len(payload)] = payload
        data[slot_offset + SLOT_SIZE - 1] = skip
        allow(name, slot_offset, slot_offset + SLOT_SIZE)
        used_slots.append((name, slot, len(payload), skip))

    for item, original, first_marker, spans, old_slot in targets:
        name = item["file"]
        offset = int(item["offset"], 0)
        capacity = int(item["capacity"])
        old_body = files[name][offset:offset + capacity]
        prompt = item["text"].split("|")[0]
        line_texts = override_map.get((name, item["offset"]), [prompt])
        if len(line_texts) != len(spans):
            raise SystemExit(
                f"prompt line count differs: {name} {item['offset']} "
                f"text={len(line_texts)} source={len(spans)}"
            )

        data = bytearray(files[name])
        body = bytearray(old_body)
        body[:first_marker] = original[:first_marker]
        slots = [old_slot]
        for _ in range(1, len(spans)):
            if not free_slots.get(name):
                raise SystemExit(f"no free v0.23 prompt slot: {name} {item['offset']}")
            slots.append(free_slots[name].pop(0))

        for (start, end), text, slot in zip(spans, line_texts, slots):
            if end - start < 2:
                raise SystemExit(f"prompt span too short: {name} {item['offset']} {start}:{end}")
            skip = end - start - 2
            write_slot(name, data, slot, text, skip)
            body[start:start + 2] = bytes((0xE2, disk_id(slot)))

        data[offset:offset + capacity] = body
        if body[first_marker:] != old_body[first_marker:]:
            raise SystemExit(f"option bytes changed: {name} {item['offset']}")
        if control_positions(body, 0xE5) != control_positions(original, 0xE5):
            raise SystemExit(f"E5 geometry changed: {name} {item['offset']}")
        if control_positions(body, 0xE6) != control_positions(original, 0xE6):
            raise SystemExit(f"E6 geometry changed: {name} {item['offset']}")
        files[name] = bytes(data)
        allow(name, offset, offset + first_marker)
        audit_rows.append(
            {
                "file": name,
                "offset": item["offset"],
                "line_count": len(spans),
                "slots": "|".join(map(str, slots)),
                "line_texts": "|".join(line_texts),
                "e6_positions": "|".join(
                    str(position)
                    for position, _ in control_positions(original[:first_marker], 0xE6)
                ),
                "first_e5": first_marker,
            }
        )

    if set(override_map) != {
        (item["file"], item["offset"])
        for item in audit_rows
        if int(item["line_count"]) > 1
    }:
        raise SystemExit("two-line override keys differ from source prompt geometry")

    outside: list[tuple[str, int]] = []
    for name, result in files.items():
        before = base_files[name]
        for position, (old, new) in enumerate(zip(before, result)):
            if old == new:
                continue
            if not any(start <= position < end for start, end in used_ranges.get(name, [])):
                outside.append((name, position))
                break
    if outside:
        raise SystemExit(f"changes outside declared v0.23 ranges: {outside}")

    slot_errors: list[tuple[str, int]] = []
    for name, slot, payload_bytes, skip in used_slots:
        start = SLOT_BASE + slot * SLOT_SIZE
        payload = files[name][start:start + SLOT_SIZE]
        if any(payload[payload_bytes:SLOT_SIZE - 1]) or payload[-1] != skip:
            slot_errors.append((name, slot))
    if slot_errors:
        raise SystemExit(f"invalid v0.23 slots: {slot_errors}")

    sorted_names = sorted(files)
    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted_names:
            archive.writestr(infos[name], files[name])
    with zipfile.ZipFile(OUTPUT) as archive:
        if archive.namelist() != sorted_names:
            raise SystemExit("v0.23 ZIP order differs")
        for name in sorted_names:
            if archive.read(name) != files[name]:
                raise SystemExit(f"v0.23 ZIP readback differs: {name}")

    AUDIT.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "file", "offset", "line_count", "slots", "line_texts",
                "e6_positions", "first_e5",
            ],
        )
        writer.writeheader()
        writer.writerows(audit_rows)

    report = [
        "Story choice row alignment v0.23",
        f"base_sha256={BASE_HASH}",
        f"external_choice_prompts={len(targets)}",
        f"single_text_rows={sum(int(item['line_count']) == 1 for item in audit_rows)}",
        f"two_text_rows={sum(int(item['line_count']) == 2 for item in audit_rows)}",
        f"e2_slots_written={len(used_slots)}",
        "option_regions_byte_identical=true",
        "source_e5_geometry_preserved=true",
        "source_e6_geometry_preserved=true",
        "outside_declared_changes=0",
        f"zip_entries={len(sorted_names)}",
        f"sha256={digest(OUTPUT.read_bytes())}",
    ]
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print(" ".join(report[2:]))


if __name__ == "__main__":
    main()
