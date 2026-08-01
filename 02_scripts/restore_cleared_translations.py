"""Put back the 301 translations that were cleared for the wrong reason.

Rows whose Japanese still contains a <G:...> marker had their Korean cleared, because a
translation written against text nobody has decoded cannot be checked. That reasoning
holds for a machine translating around a gap. It does not hold for these rows: they
were not generated in that run, they came from this project's earlier translation work,
where a person had the game in front of them. Deleting them threw away real work over a
rule aimed at something else.

They are recoverable because the source CSVs are still here. Restore only rows whose
Japanese matches exactly, and mark them so the difference stays visible: their Japanese
is still partly unread, so any later edit to them needs the remaining glyph indices
resolved first.
"""
from __future__ import annotations

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "05_docs/script_translated_full.csv"
RECON = ROOT / "05_docs/script_translation_reconciliation.csv"


def col(fields, *names):
    for n in names:
        for f in fields:
            if n in f.lower():
                return f
    return None


def main() -> None:
    with TARGET.open(encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        fields = r.fieldnames
        rows = list(r)
    ja = col(fields, "japanese")
    ko = col(fields, "korean")
    src = col(fields, "source of")
    key = col(fields, "source file"), col(fields, "offset")

    with RECON.open(encoding="utf-8", newline="") as f:
        recon = list(csv.DictReader(f))
    rf = recon[0].keys()
    rja, rko = col(rf, "japanese"), col(rf, "korean")
    rkey = col(rf, "source file"), col(rf, "offset")

    bank = {}
    for x in recon:
        k = (x.get(rkey[0]), x.get(rkey[1]))
        v = (x.get(rko) or "").strip()
        if v:
            bank[k] = (v, (x.get(rja) or ""))

    restored = skipped = 0
    for row in rows:
        if (row[ko] or "").strip():
            continue
        if "<G:" not in (row[ja] or ""):
            continue
        k = (row.get(key[0]), row.get(key[1]))
        hit = bank.get(k)
        if not hit:
            continue
        text, ja_seen = hit
        if ja_seen and ja_seen != row[ja]:
            skipped += 1
            continue
        row[ko] = text
        if src:
            row[src] = "existing (japanese partly unread)"
        restored += 1

    with TARGET.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    filled = sum(1 for r in rows if (r[ko] or "").strip())
    print(f"restored : {restored}")
    print(f"skipped, Japanese did not match : {skipped}")
    print(f"translated rows now : {filled} of {len(rows)}")


if __name__ == "__main__":
    main()
