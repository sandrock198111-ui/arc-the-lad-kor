#!/usr/bin/env python3
"""Generate the pinned V356 non-text exclusion ledger.

The 199 blank Korean rows in ``script_translated_full.csv`` are not dialogue.
The 2026-08-07 audit established that they are binary/external tables and false
positive control-looking records.  This generator turns that conclusion into a
machine-readable, raw-byte-pinned deny-write list; it never edits the canonical
translation CSV.
"""

from __future__ import annotations

import csv
import hashlib
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TRANSLATED = ROOT / "05_docs/script_translated_full.csv"
ORIGINAL = ROOT / "05_docs/script_original_full.csv"
OUTPUT = ROOT / "05_docs/v356_nontext_exclusions.csv"

TRANSLATED_SHA256 = "6AB19301CF92F51DCCAC5ADC7F4251F43A7032A0FDC8D7271BB5C75F2D856EBE"
ORIGINAL_SHA256 = "D20D44522A9ECDC9894BAB46D49BC0B9BB7E4573D19BA8627AFCEDA3C2BA1188"
EXPECTED_ROWS = 199
EXPECTED_FILES = 42
EXPECTED_PATTERNS = 44

FIELDS = (
    "row_number",
    "source file",
    "offset",
    "length",
    "raw_sha256",
    "raw_hex",
    "classification",
    "evidence",
    "write_policy",
)


class LedgerError(RuntimeError):
    pass


def sha(data: bytes | Path) -> str:
    raw = data.read_bytes() if isinstance(data, Path) else data
    return hashlib.sha256(raw).hexdigest().upper()


def classify(raw: bytes, frequency: int) -> str:
    if frequency == 23:
        return "repeated_external_table_record"
    if raw[:1] == b"\xE5":
        return "false_choice_marker_binary_record"
    if raw[:1] in (b"\xF6", b"\xF7", b"\xFD", b"\xFE"):
        return "control_or_sentinel_record"
    if raw == bytes.fromhex("19 64 39 03"):
        return "comm_binary_record"
    return "binary_or_external_table_false_positive"


def main() -> None:
    if sha(TRANSLATED) != TRANSLATED_SHA256:
        raise LedgerError("canonical translation CSV drifted; review the exclusion population")
    if sha(ORIGINAL) != ORIGINAL_SHA256:
        raise LedgerError("original dialogue extraction CSV drifted")

    with TRANSLATED.open(encoding="utf-8-sig", newline="") as handle:
        translated = list(csv.DictReader(handle))
    with ORIGINAL.open(encoding="utf-8-sig", newline="") as handle:
        original_rows = list(csv.DictReader(handle))

    if len(translated) != len(original_rows) or len(translated) != 2878:
        raise LedgerError("dialogue corpus population mismatch")

    originals: dict[tuple[str, str], dict[str, str]] = {}
    for row in original_rows:
        key = (row["source file"], str(int(row["byte offset"], 0)))
        if key in originals:
            raise LedgerError(f"duplicate original key: {key}")
        originals[key] = row

    pending: list[tuple[int, dict[str, str], dict[str, str], bytes]] = []
    for number, row in enumerate(translated, start=1):
        if (row.get("korean") or "").strip():
            continue
        key = (row["source file"], str(int(row["offset"], 0)))
        original = originals.get(key)
        if original is None:
            raise LedgerError(f"blank row has no protected original: {key}")
        raw = bytes.fromhex(original["raw bytes as hex"].replace(" ", ""))
        if row["japanese"].replace("\r\n", "\n") != original["decoded Japanese"].replace("\r\n", "\n"):
            raise LedgerError(f"decoded source mismatch: {key}")
        pending.append((number, row, original, raw))

    frequencies = Counter(raw for _n, _row, _original, raw in pending)
    if len(pending) != EXPECTED_ROWS:
        raise LedgerError(f"non-text population changed: {len(pending)} != {EXPECTED_ROWS}")
    if len({row["source file"] for _n, row, _original, _raw in pending}) != EXPECTED_FILES:
        raise LedgerError("non-text source-file population changed")
    if len(frequencies) != EXPECTED_PATTERNS:
        raise LedgerError("non-text raw-pattern population changed")
    if sorted(count for count in frequencies.values() if count == 23) != [23] * 6:
        raise LedgerError("six repeated 23-file external-table records were not reproduced")

    rows: list[dict[str, str]] = []
    for number, row, original, raw in pending:
        rows.append({
            "row_number": str(number),
            "source file": row["source file"],
            "offset": row["offset"],
            "length": str(len(raw)),
            "raw_sha256": sha(raw),
            "raw_hex": raw.hex(" ").upper(),
            "classification": classify(raw, frequencies[raw]),
            "evidence": (
                "05_docs/test_log.txt:2025; 05_docs/codex_notes.txt:1376-1378; "
                "2026-08-07 read audit: extractor false positive, not dialogue"
            ),
            "write_policy": "PROTECT_BYTE_EXACT_NEVER_TRANSLATE",
        })

    temporary = OUTPUT.with_suffix(".csv.tmp")
    with temporary.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(OUTPUT)
    print(
        f"V356 non-text ledger PASS: rows={len(rows)}, files={EXPECTED_FILES}, "
        f"unique_raw={len(frequencies)}, sha256={sha(OUTPUT)}"
    )


if __name__ == "__main__":
    main()
