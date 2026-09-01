#!/usr/bin/env python3
"""Generate the exact V356 dialogue reinsertion target ledger.

The human-editable canonical CSV remains the source of prose.  This script only
classifies the rows that V354 does not currently render as that prose.  The 199
binary/external-table false positives are supplied by the separate, hash-pinned
non-text exclusion ledger and can never enter this output.
"""
from __future__ import annotations

import csv
import hashlib
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from review_editor import Editor  # noqa: E402


OUTPUT = ROOT / "05_docs/v356_full_dialogue_targets.csv"
FIELDS = (
    "row_number", "source file", "offset", "classification", "target_korean",
    "raw_length", "raw_sha256", "raw_hex", "review_status",
)
TARGET_STATES = {"빌드대기", "선택지", "B검수필요"}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def main() -> None:
    editor = Editor.__new__(Editor)
    editor.load()
    states = Counter(editor.state_of(line) for line in editor.lines)
    expected = {
        "적용됨": 2336,
        "빌드대기": 162,
        "선택지": 134,
        "B검수필요": 47,
        "비텍스트보호": 199,
    }
    if states != expected:
        raise SystemExit(f"V356 target census drift: {dict(states)} != {expected}")
    if any(editor.measure(line, line.proposal)["missing"] for line in editor.lines):
        raise SystemExit("V356 target ledger refuses a missing glyph")

    rows: list[dict[str, object]] = []
    for line in editor.lines:
        state = editor.state_of(line)
        if state not in TARGET_STATES:
            continue
        if line.nontext_protected:
            raise SystemExit(f"non-text row entered target set: {line.file} {line.offset}")
        review_status = line.bank_status if line.bank_review else ""
        rows.append({
            "row_number": line.n,
            "source file": line.file,
            "offset": line.offset,
            "classification": state,
            "target_korean": line.proposal,
            "raw_length": len(line.raw),
            "raw_sha256": sha(line.raw),
            "raw_hex": line.raw.hex(" ").upper(),
            "review_status": review_status,
        })

    if len(rows) != 343 or len({(r["source file"], r["offset"]) for r in rows}) != 343:
        raise SystemExit(f"V356 target set must contain 343 unique rows, got {len(rows)}")
    if Counter(str(row["classification"]) for row in rows) != {
        "빌드대기": 162, "선택지": 134, "B검수필요": 47,
    }:
        raise SystemExit("V356 target classification drift")

    with OUTPUT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(
        f"V356 target ledger PASS: rows={len(rows)}, files={len({r['source file'] for r in rows})}, "
        f"sha256={sha(OUTPUT.read_bytes())}"
    )


if __name__ == "__main__":
    main()
