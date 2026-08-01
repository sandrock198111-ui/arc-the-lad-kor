"""Apply one manually reviewed Korean-script translation batch safely.

The canonical CSV is intentionally never edited by position.  Every batch row
must carry the exact source file, offset, and Japanese text observed at review
time.  This prevents an old batch from silently landing on a different string.
"""

from __future__ import annotations

import argparse
import collections
import csv
import hashlib
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "05_docs" / "script_translated_full.csv"
LOG = ROOT / "05_docs" / "translation_batch_log.csv"

CANONICAL_FIELDS = [
    "source file",
    "offset",
    "japanese",
    "korean",
    "source of the translation (existing / new)",
]
BATCH_FIELDS = ["source file", "offset", "japanese", "korean", "review_note"]
LOG_FIELDS = [
    "batch_id",
    "applied_at_utc",
    "rows_applied",
    "canonical_sha256_before",
    "canonical_sha256_after",
    "selection_basis",
    "new_proper_nouns",
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_csv(path: Path, required_fields: list[str]) -> tuple[list[dict[str, str]], list[str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError(f"{path}: missing CSV header")
        missing = [field for field in required_fields if field not in reader.fieldnames]
        if missing:
            raise ValueError(f"{path}: missing columns: {', '.join(missing)}")
        return list(reader), reader.fieldnames


def location_key(row: dict[str, str]) -> tuple[str, str]:
    return row["source file"], row["offset"].upper()


def batch_source_text(row: dict[str, str]) -> str:
    """Decode the review-file line-break notation without normalising source text."""
    encoded = row["japanese"]
    if "\r" in encoded or "\n" in encoded:
        raise ValueError("batch Japanese must use literal \\n for embedded line breaks")
    return encoded.replace("\\n", "\n")


def canonical_record_key(row: dict[str, str]) -> tuple[str, str, str]:
    return (*location_key(row), row["japanese"])


def batch_record_key(row: dict[str, str]) -> tuple[str, str, str]:
    return (*location_key(row), batch_source_text(row))


def validate_batch(
    canonical_rows: list[dict[str, str]], batch_rows: list[dict[str, str]]
) -> dict[tuple[str, str, str], dict[str, str]]:
    canonical_by_location: dict[tuple[str, str], list[dict[str, str]]] = collections.defaultdict(list)
    for row in canonical_rows:
        canonical_by_location[location_key(row)].append(row)

    batch_by_key: dict[tuple[str, str, str], dict[str, str]] = {}
    for row in batch_rows:
        current_location = location_key(row)
        source_text = batch_source_text(row)
        current_key = batch_record_key(row)
        if current_key in batch_by_key:
            raise ValueError(f"batch has duplicate key: {current_key[:2]}")
        batch_by_key[current_key] = row

        candidates = canonical_by_location.get(current_location, [])
        if not candidates:
            raise ValueError(f"batch key does not exist in canonical CSV: {current_location}")
        exact = [candidate for candidate in candidates if candidate["japanese"] == source_text]
        if len(exact) != 1:
            raise ValueError(
                f"batch source must identify exactly one canonical row: {current_location}; "
                f"matching rows={len(exact)}"
            )
        current = exact[0]
        if current["japanese"] != source_text:
            raise ValueError(f"source text changed since review: {current_location}")
        if not current["japanese"].strip():
            raise ValueError(f"blank Japanese source is not translatable: {current_location}")
        if "<G:" in current["japanese"]:
            raise ValueError(f"unresolved glyph source is not translatable: {current_location}")
        if current["korean"].strip():
            raise ValueError(f"existing Korean translation would be overwritten: {current_location}")
        if not row["korean"].strip():
            raise ValueError(f"empty Korean translation in batch: {current_location}")
    return batch_by_key


def append_log(
    batch_id: str,
    rows_applied: int,
    sha_before: str,
    sha_after: str,
    selection_basis: str,
    new_proper_nouns: str,
) -> None:
    existing: list[dict[str, str]] = []
    if LOG.exists():
        existing, fields = read_csv(LOG, LOG_FIELDS)
        if fields != LOG_FIELDS:
            raise ValueError(f"{LOG}: unexpected columns")
        if any(row["batch_id"] == batch_id for row in existing):
            raise ValueError(f"batch_id already recorded: {batch_id}")
    existing.append(
        {
            "batch_id": batch_id,
            "applied_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "rows_applied": str(rows_applied),
            "canonical_sha256_before": sha_before,
            "canonical_sha256_after": sha_after,
            "selection_basis": selection_basis,
            "new_proper_nouns": new_proper_nouns,
        }
    )
    with LOG.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LOG_FIELDS, lineterminator="\r\n")
        writer.writeheader()
        writer.writerows(existing)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("batch_csv", type=Path)
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--selection-basis", required=True)
    parser.add_argument("--new-proper-nouns", default="none")
    parser.add_argument("--apply", action="store_true", help="write the canonical CSV and batch log")
    args = parser.parse_args()

    canonical_rows, canonical_fields = read_csv(CANONICAL, CANONICAL_FIELDS)
    if canonical_fields != CANONICAL_FIELDS:
        raise ValueError(f"{CANONICAL}: unexpected column order")
    batch_rows, _ = read_csv(args.batch_csv, BATCH_FIELDS)
    if not batch_rows:
        raise ValueError("refusing to apply an empty batch")
    batch_by_key = validate_batch(canonical_rows, batch_rows)

    print(f"validated {len(batch_by_key)} rows; canonical SHA-256 {sha256(CANONICAL)}")
    if not args.apply:
        print("dry run only; pass --apply to write")
        return

    before_rows = [dict(row) for row in canonical_rows]
    sha_before = sha256(CANONICAL)
    for row in canonical_rows:
        planned = batch_by_key.get(canonical_record_key(row))
        if planned is not None:
            row["korean"] = planned["korean"]
            row["source of the translation (existing / new)"] = "new"

    for before, after in zip(before_rows, canonical_rows, strict=True):
        current_key = canonical_record_key(before)
        if current_key in batch_by_key:
            if before["japanese"] != after["japanese"]:
                raise AssertionError(f"source changed while applying: {current_key}")
            continue
        if before != after:
            raise AssertionError(f"unplanned canonical mutation: {current_key}")

    with CANONICAL.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CANONICAL_FIELDS, lineterminator="\r\n")
        writer.writeheader()
        writer.writerows(canonical_rows)

    sha_after = sha256(CANONICAL)
    append_log(
        args.batch_id,
        len(batch_by_key),
        sha_before,
        sha_after,
        args.selection_basis,
        args.new_proper_nouns,
    )
    print(f"applied {len(batch_by_key)} rows; canonical SHA-256 {sha_after}")


if __name__ == "__main__":
    main()
