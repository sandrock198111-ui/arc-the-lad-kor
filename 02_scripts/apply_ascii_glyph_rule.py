"""Apply the *verified* ASCII subsection of the original font atlas.

The original COMM.IMG bitplanes were reviewed index by index on 2026-08-01.
Only indices 0..25 visibly equal ``chr(index + 32)``.  Index 0 is the blank
ASCII space glyph, and indices 26..94 are Japanese/non-ASCII glyphs.  Do not widen this
range from contextual samples: doing so changes source text, rather than merely
resolving it.
"""
from __future__ import annotations

import csv
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "05_docs/script_original_full.csv"
MAP = ROOT / "05_docs/japanese_font_index_map.csv"
ASCII_LO, ASCII_HI, OFFSET = 0, 25, 32
REJECTED = frozenset(range(26, 95))
COL = "decoded Japanese"


def resolve(text: str) -> str:
    return re.sub(r"<G:(\d+)>",
                  lambda m: (chr(int(m.group(1)) + OFFSET)
                             if ASCII_LO <= int(m.group(1)) <= ASCII_HI else m.group(0)),
                  text)


def main() -> None:
    with CORPUS.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fields = reader.fieldnames
        rows = list(reader)
    if COL not in fields:
        raise SystemExit(f"{CORPUS.name} has no '{COL}' column")

    before_clean = sum(1 for r in rows if "<G:" not in r[COL])
    for r in rows:
        r[COL] = resolve(r[COL])
    after_clean = sum(1 for r in rows if "<G:" not in r[COL])

    left = Counter()
    for r in rows:
        for m in re.finditer(r"<G:(\d+)>", r[COL]):
            left[int(m.group(1))] += 1

    with CORPUS.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    # record the rule in the index map so nothing re-derives it
    existing = []
    if MAP.exists():
        with MAP.open(encoding="utf-8-sig", newline="") as f:
            existing = list(csv.reader(f))
    header = existing[0] if existing else ["glyph index", "character", "how"]
    # Remove every old row that came from the rejected broad rule.  Retaining
    # those rows would silently reintroduce false source decodes on a later
    # corpus rebuild.
    # The font-map header names its provenance column ``how it was established``.
    # Replace every 0..94 row rather than checking a positional provenance cell:
    # the rejected broad rule already created duplicate entries in this range.
    body = [r for r in existing[1:]
            if not (r and r[0].isdigit() and 0 <= int(r[0]) <= 94)]
    for i in range(ASCII_LO, ASCII_HI + 1):
        row = [str(i)] + [""] * (len(header) - 1)
        row[1] = chr(i + OFFSET)
        if len(row) > 2:
            row[2] = "ascii rule: index = code - 32"
        body.append(row)
    for i in sorted(REJECTED):
        row = [str(i)] + [""] * (len(header) - 1)
        if len(row) > 2:
            row[2] = "original COMM.IMG audit: Japanese/non-ASCII; ASCII rule rejected"
        body.append(row)
    body.sort(key=lambda r: int(r[0]) if r and r[0].isdigit() else 1 << 30)
    with MAP.open("w", encoding="utf-8-sig", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(header)
        wr.writerows(body)

    print(f"fully decoded strings : {before_clean} -> {after_clean} of {len(rows)}")
    print(f"unresolved indices    : {len(left)}  ({sum(left.values())} occurrences)")
    print(f"most frequent left    : {[i for i, _ in left.most_common(15)]}")
    print(f"wrote {CORPUS.name} and {MAP.name}")


if __name__ == "__main__":
    main()
