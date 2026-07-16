from __future__ import annotations

import csv
import hashlib
import zipfile
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "01_work"
DOCS = ROOT / "05_docs"
CORPUS = WORK / "analysis/story_corpus/story_corpus.csv"
PATCH = ROOT / "03_output/story_minister_s3022_s3031_e2_v19_cumulative_patch_only.zip"
OUTPUT = WORK / "analysis/full_audit_v20"

SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT_COUNT = 79

OFFSET_ONLY_MANIFEST_FILES = {
    "story_s2041_bulk_translation.csv": "21/S2041.DAT",
    "story_s3031_bulk_translation.csv": "31/S3031.DAT",
    "story_s4041_bulk_translation.csv": "4/S4041.DAT",
    "story_sf0b1_return_translation.csv": "F/SF0B1.DAT",
}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, object]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def custom_slot(disk_id: int) -> int | None:
    if 0x81 <= disk_id <= 0xA8:
        return disk_id - 0x81
    if 0xAA <= disk_id <= 0xD0:
        return disk_id - 0x82
    return None


def nearest_offset(offsets: list[int], target: int) -> tuple[int | None, int | None]:
    if not offsets:
        return None, None
    nearest = min(offsets, key=lambda value: (abs(value - target), value))
    return nearest, nearest - target


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)

    corpus = read_csv(CORPUS)
    corpus_by_file: dict[str, list[dict[str, str]]] = defaultdict(list)
    corpus_by_key: dict[tuple[str, int], dict[str, str]] = {}
    for row in corpus:
        name = row["file"].replace("\\", "/")
        offset = int(row["payload_start"], 0)
        corpus_by_file[name].append(row)
        corpus_by_key[(name, offset)] = row

    with zipfile.ZipFile(PATCH) as archive:
        patch_names = archive.namelist()
        if len(patch_names) != len(set(patch_names)):
            raise SystemExit("patch ZIP contains duplicate names")
        patched = {name: archive.read(name) for name in patch_names}

    dat_paths = sorted(WORK.rglob("*.DAT"))
    dat_files: dict[str, bytes] = {}
    for path in dat_paths:
        if "analysis" in path.parts:
            continue
        name = path.relative_to(WORK).as_posix()
        dat_files[name] = path.read_bytes()

    body_rows: list[dict[str, object]] = []
    body_counts: dict[str, Counter[str]] = defaultdict(Counter)
    for name, source_rows in sorted(corpus_by_file.items()):
        original = dat_files.get(name)
        if original is None:
            continue
        current = patched.get(name, original)
        for row in source_rows:
            offset = int(row["payload_start"], 0)
            capacity = int(row["capacity"])
            confidence = row["confidence"]
            status = "original"
            disk_id = ""
            slot_value: int | str = ""
            metadata: int | str = ""
            expected_metadata: int | str = ""
            terminator = ""

            original_body = original[offset : offset + capacity]
            current_body = current[offset : offset + capacity]
            if current_body != original_body:
                if len(current_body) >= 2 and current_body[0] == 0xE2:
                    disk_id = f"0x{current_body[1]:02X}"
                    slot = custom_slot(current_body[1])
                    if slot is None or not 0 <= slot < SLOT_COUNT:
                        status = "e2_invalid_id"
                    else:
                        slot_value = slot
                        slot_offset = SLOT_BASE + slot * SLOT_SIZE
                        external = current[slot_offset : slot_offset + SLOT_SIZE]
                        metadata = external[-1] if len(external) == SLOT_SIZE else ""
                        expected_metadata = capacity - 2
                        terminator = int(0 in external[:-1]) if len(external) == SLOT_SIZE else 0
                        if metadata == expected_metadata and terminator:
                            status = "e2_valid"
                        elif terminator:
                            status = "e2_hybrid_or_metadata_mismatch"
                        else:
                            status = "e2_missing_terminator"
                else:
                    status = "inline_changed"

            body_counts[name][confidence] += 1
            if confidence == "high":
                body_counts[name][status] += 1
            body_rows.append(
                {
                    "file": name,
                    "offset": f"0x{offset:X}",
                    "capacity": capacity,
                    "confidence": confidence,
                    "in_patch_zip": int(name in patched),
                    "status": status,
                    "disk_id": disk_id,
                    "slot": slot_value,
                    "metadata": metadata,
                    "expected_metadata": expected_metadata,
                    "external_has_terminator": terminator,
                    "decoded_jp": " / ".join(
                        line.rstrip()
                        for line in row["decoded_jp"].replace("\r", "").strip().split("\n")
                    ),
                }
            )

    file_rows: list[dict[str, object]] = []
    all_dat_names = sorted(set(dat_files) | set(corpus_by_file))
    for name in all_dat_names:
        original = dat_files.get(name, b"")
        current = patched.get(name, original)
        counts = body_counts[name]
        changed_bytes = sum(a != b for a, b in zip(original, current))
        changed_bytes += abs(len(original) - len(current))
        free_slots = 0
        occupied_slots = 0
        if len(current) >= SLOT_BASE + SLOT_COUNT * SLOT_SIZE:
            for slot in range(SLOT_COUNT):
                start = SLOT_BASE + slot * SLOT_SIZE
                block = current[start : start + SLOT_SIZE]
                if any(block):
                    occupied_slots += 1
                else:
                    free_slots += 1
        remaining = counts["original"] + counts["inline_changed"]
        if counts["high"] == 0:
            capacity_state = "no_high_confidence_dialogue"
        elif remaining == 0:
            capacity_state = "covered"
        elif remaining <= free_slots:
            capacity_state = "fits_current_e2_bank"
        else:
            capacity_state = "needs_choice_inline_or_bank_extension"
        file_rows.append(
            {
                "file": name,
                "size": len(original),
                "in_patch_zip": int(name in patched),
                "whole_file_changed": int(current != original),
                "changed_bytes": changed_bytes,
                "corpus_total": sum(counts[level] for level in ("high", "medium", "low")),
                "high": counts["high"],
                "medium": counts["medium"],
                "low": counts["low"],
                "e2_valid": counts["e2_valid"],
                "e2_other": (
                    counts["e2_invalid_id"]
                    + counts["e2_hybrid_or_metadata_mismatch"]
                    + counts["e2_missing_terminator"]
                ),
                "inline_changed": counts["inline_changed"],
                "original_high": counts["original"],
                "occupied_slots": occupied_slots,
                "free_slots": free_slots,
                "remaining_for_e2": remaining,
                "capacity_state": capacity_state,
            }
        )

    inventory_rows: list[dict[str, object]] = []
    for path in sorted(
        item
        for item in WORK.rglob("*")
        if item.is_file() and OUTPUT not in item.parents
    ):
        relative = path.relative_to(WORK).as_posix()
        is_analysis = int("analysis" in path.parts)
        is_game_candidate = int(not is_analysis and path.suffix.upper() in {
            ".DAT", ".IMG", ".XA", ".STR", ".EXE", ".SND", ".CNF"
        })
        patch_data = patched.get(relative)
        source_data = None
        if relative in patched:
            source_data = path.read_bytes()
        inventory_rows.append(
            {
                "file": relative,
                "extension": path.suffix.upper(),
                "size": path.stat().st_size,
                "is_analysis": is_analysis,
                "is_game_candidate": is_game_candidate,
                "in_patch_zip": int(relative in patched),
                "patch_size": "" if patch_data is None else len(patch_data),
                "patch_equals_work": "" if patch_data is None else int(patch_data == source_data),
            }
        )

    manifest_rows: list[dict[str, object]] = []
    translations_by_key: dict[tuple[str, int], set[str]] = defaultdict(set)
    manifest_candidates = sorted(DOCS.glob("story*translation*.csv"))
    for manifest in manifest_candidates:
        rows = read_csv(manifest)
        inferred_file = OFFSET_ONLY_MANIFEST_FILES.get(manifest.name)
        for index, row in enumerate(rows, start=2):
            name = (row.get("file") or inferred_file or "").replace("\\", "/")
            raw_offset = row.get("offset", "")
            if not name or not raw_offset:
                manifest_rows.append(
                    {
                        "manifest": manifest.name,
                        "row": index,
                        "file": name,
                        "offset": raw_offset,
                        "exact_corpus": 0,
                        "nearest_offset": "",
                        "nearest_delta": "",
                        "confidence": "",
                        "conflicting_texts": "",
                    }
                )
                continue
            offset = int(raw_offset, 0)
            text = row.get("text", "")
            translations_by_key[(name, offset)].add(text)
            corpus_row = corpus_by_key.get((name, offset))
            offsets = [int(item["payload_start"], 0) for item in corpus_by_file.get(name, [])]
            nearest, delta = nearest_offset(offsets, offset)
            manifest_rows.append(
                {
                    "manifest": manifest.name,
                    "row": index,
                    "file": name,
                    "offset": f"0x{offset:X}",
                    "exact_corpus": int(corpus_row is not None),
                    "nearest_offset": "" if nearest is None else f"0x{nearest:X}",
                    "nearest_delta": "" if delta is None else delta,
                    "confidence": "" if corpus_row is None else corpus_row["confidence"],
                    "conflicting_texts": "",
                }
            )
    for row in manifest_rows:
        if not row["file"] or not row["offset"]:
            continue
        key = (str(row["file"]), int(str(row["offset"]), 0))
        texts = translations_by_key[key]
        row["conflicting_texts"] = max(0, len(texts) - 1)

    body_fields = [
        "file", "offset", "capacity", "confidence", "in_patch_zip", "status",
        "disk_id", "slot", "metadata", "expected_metadata",
        "external_has_terminator", "decoded_jp",
    ]
    file_fields = [
        "file", "size", "in_patch_zip", "whole_file_changed", "changed_bytes",
        "corpus_total", "high", "medium", "low", "e2_valid", "e2_other",
        "inline_changed", "original_high", "occupied_slots", "free_slots",
        "remaining_for_e2", "capacity_state",
    ]
    inventory_fields = [
        "file", "extension", "size", "is_analysis", "is_game_candidate",
        "in_patch_zip", "patch_size", "patch_equals_work",
    ]
    manifest_fields = [
        "manifest", "row", "file", "offset", "exact_corpus", "nearest_offset",
        "nearest_delta", "confidence", "conflicting_texts",
    ]
    write_csv(OUTPUT / "story_body_audit.csv", body_rows, body_fields)
    write_csv(OUTPUT / "story_file_audit.csv", file_rows, file_fields)
    write_csv(OUTPUT / "all_files_inventory.csv", inventory_rows, inventory_fields)
    write_csv(OUTPUT / "manifest_offset_audit.csv", manifest_rows, manifest_fields)

    high_bodies = [row for row in body_rows if row["confidence"] == "high"]
    status_counts = Counter(str(row["status"]) for row in high_bodies)
    story_files = [row for row in file_rows if int(row["high"]) > 0]
    overflow_files = [
        row for row in story_files
        if row["capacity_state"] == "needs_choice_inline_or_bank_extension"
    ]
    stale_manifest_rows = [
        row for row in manifest_rows
        if not row["exact_corpus"] and row["file"] and row["offset"]
    ]
    conflicting_rows = [row for row in manifest_rows if int(row["conflicting_texts"] or 0) > 0]
    included_dat = [name for name in patch_names if name.upper().endswith(".DAT")]
    changed_dat = [row for row in file_rows if row["whole_file_changed"]]
    unchanged_included_dat = [
        row for row in file_rows if row["in_patch_zip"] and not row["whole_file_changed"]
    ]

    summary = [
        "Full story file audit v0.20",
        f"patch={PATCH.relative_to(ROOT).as_posix()}",
        f"patch_sha256={sha256(PATCH.read_bytes())}",
        f"work_files_inventory={len(inventory_rows)}",
        f"work_game_candidates={sum(int(row['is_game_candidate']) for row in inventory_rows)}",
        f"dat_files={len(dat_files)}",
        f"dat_files_with_corpus={len(corpus_by_file)}",
        f"dat_files_with_high_confidence={len(story_files)}",
        f"patch_entries={len(patch_names)}",
        f"patch_dat_entries={len(included_dat)}",
        f"changed_dat_files={len(changed_dat)}",
        f"unchanged_dat_entries_in_patch={len(unchanged_included_dat)}",
        f"corpus_bodies={len(body_rows)}",
        f"high_confidence_bodies={len(high_bodies)}",
    ]
    summary.extend(f"high_{key}={value}" for key, value in sorted(status_counts.items()))
    summary.extend(
        [
            f"files_fully_covered={sum(row['capacity_state'] == 'covered' for row in story_files)}",
            f"files_with_remaining_bodies={sum(int(row['remaining_for_e2']) > 0 for row in story_files)}",
            f"files_needing_bank_extension_or_inline_choices={len(overflow_files)}",
            f"translation_manifests={len(manifest_candidates)}",
            f"manifest_rows={len(manifest_rows)}",
            f"manifest_rows_without_exact_corpus={len(stale_manifest_rows)}",
            f"manifest_rows_with_conflicting_text={len(conflicting_rows)}",
            "",
            "Files needing bank extension or inline choices:",
        ]
    )
    summary.extend(
        f"{row['file']} remaining={row['remaining_for_e2']} free={row['free_slots']} high={row['high']}"
        for row in overflow_files
    )
    summary.extend(["", "Unchanged DAT entries carried in patch ZIP:"])
    summary.extend(str(row["file"]) for row in unchanged_included_dat)
    summary.extend(["", "Manifest rows without exact corpus offset:"])
    summary.extend(
        f"{row['manifest']}:{row['row']} {row['file']} {row['offset']} nearest={row['nearest_offset']} delta={row['nearest_delta']}"
        for row in stale_manifest_rows
    )
    (OUTPUT / "summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")
    print("\n".join(summary[:30]))
    print(OUTPUT)


if __name__ == "__main__":
    main()
