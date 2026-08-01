"""The low end of the Japanese font atlas is plain ASCII: index = code - 32.

The map was being built one character at a time from context, which resolved 106
indices in twenty minutes. It was never a reasoning problem. Ten glyphs read off the
rendered font showed the pattern -- " at 2, # at 3, $ at 4, % at 5, & at 6, ' at 7,
* at 10, / at 15, 9 at 25 -- and nine of the ten land exactly on ASCII minus 32.

Applying it takes the corpus from 2,282 fully decoded strings to 5,368 of 5,795, and
drops the unresolved indices from 120 to 105. What remains is the kanji range, where
context now works well because the text around it reads.
"""
from __future__ import annotations

import csv
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "05_docs/script_original_full.csv"
MAP = ROOT / "05_docs/japanese_font_index_map.csv"
ASCII_LO, ASCII_HI, OFFSET = 0, 94, 32
COL = "decoded Japanese"


def resolve(text: str) -> str:
    return re.sub(r"<G:(\d+)>",
                  lambda m: (chr(int(m.group(1)) + OFFSET)
                             if ASCII_LO <= int(m.group(1)) <= ASCII_HI else m.group(0)),
                  text)


def main() -> None:
    with CORPUS.open(encoding="utf-8", newline="") as f:
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

    with CORPUS.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    # record the rule in the index map so nothing re-derives it
    existing = []
    if MAP.exists():
        with MAP.open(encoding="utf-8", newline="") as f:
            existing = list(csv.reader(f))
    header = existing[0] if existing else ["glyph index", "character", "how"]
    body = [r for r in existing[1:]
            if not (r and r[0].isdigit() and ASCII_LO <= int(r[0]) <= ASCII_HI)]
    for i in range(ASCII_LO, ASCII_HI + 1):
        row = [str(i)] + [""] * (len(header) - 1)
        row[1] = chr(i + OFFSET)
        if len(row) > 2:
            row[2] = "ascii rule: index = code - 32"
        body.append(row)
    body.sort(key=lambda r: int(r[0]) if r and r[0].isdigit() else 1 << 30)
    with MAP.open("w", encoding="utf-8", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(header)
        wr.writerows(body)

    print(f"fully decoded strings : {before_clean} -> {after_clean} of {len(rows)}")
    print(f"unresolved indices    : {len(left)}  ({sum(left.values())} occurrences)")
    print(f"most frequent left    : {[i for i, _ in left.most_common(15)]}")
    print(f"wrote {CORPUS.name} and {MAP.name}")


if __name__ == "__main__":
    main()
