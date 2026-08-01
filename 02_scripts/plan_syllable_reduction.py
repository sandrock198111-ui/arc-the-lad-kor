"""Which words to reword, and how many glyph slots each one buys back.

The projection says the finished script needs about 904 distinct syllables against 507
already placed and 28 free slots, so roughly 230 have to go. Cutting them at random
would damage the text; cutting the right ones barely touches it.

The leverage is in the tail. A syllable that appears once costs a full glyph slot and
carries almost no meaning on its own, so rewording the single word that contains it
removes the slot outright. A syllable appearing hundreds of times cannot be touched at
any price. This ranks every syllable by what removing it would cost.

Worked from the translated rows available now rather than the finished script, so the
counts are a sample: a syllable that looks unique here may appear again later. The
ranking is what matters, and that is stable.
"""
from __future__ import annotations

import csv
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSV = ROOT / "05_docs/script_translated_full.csv"
MAPS = ("korean_charmap.csv", "korean_charmap_extended.csv")
OUT = ROOT / "05_docs/syllable_reduction_plan.csv"
HANGUL = re.compile(r"[가-힣]+")


def main() -> None:
    with CSV.open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    ko = next(c for c in rows[0] if "korean" in c.lower())
    sf = next(c for c in rows[0] if "source file" in c.lower())
    lines = [(r[sf], r[ko]) for r in rows if (r[ko] or "").strip()]

    placed = set()
    for name in MAPS:
        with (ROOT / "05_docs" / name).open(encoding="utf-8-sig") as f:
            for r in csv.DictReader(f):
                placed.add(r["char"])

    freq = Counter()
    words = defaultdict(Counter)          # syllable -> the words that carry it
    where = defaultdict(set)              # syllable -> which files
    for src, text in lines:
        for word in HANGUL.findall(text):
            for ch in set(word):
                words[ch][word] += 1
                where[ch].add(src)
        for ch in text:
            if "가" <= ch <= "힣":
                freq[ch] += 1

    new = {c for c in freq if c not in placed}
    print(f"translated rows        : {len(lines)}")
    print(f"distinct syllables     : {len(freq)}")
    print(f"already have a glyph   : {len(freq) - len(new)}")
    print(f"need a new slot        : {len(new)}\n")

    # a syllable is cheap to remove when it is rare and lives in few distinct words
    ranked = sorted(new, key=lambda c: (freq[c], len(words[c])))
    rows_out = []
    for c in ranked:
        ws = words[c].most_common()
        rows_out.append({
            "syllable": c,
            "occurrences": freq[c],
            "distinct words": len(ws),
            "files": len(where[c]),
            "words": " ".join(f"{w}({n})" for w, n in ws[:6]),
        })
    with OUT.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows_out[0]))
        w.writeheader()
        w.writerows(rows_out)

    once = [r for r in rows_out if r["occurrences"] == 1]
    twice = [r for r in rows_out if r["occurrences"] == 2]
    few = [r for r in rows_out if r["occurrences"] <= 3]
    print("how much the tail is worth")
    print(f"  appear once   : {len(once):>4} syllables"
          f"  -> {len(once)} slots for {len(once)} reworded words")
    print(f"  appear twice  : {len(twice):>4}")
    print(f"  three or fewer: {len(few):>4}  <== the realistic target\n")

    print("cheapest to remove, most expensive last")
    print(f"  {'':2} {'uses':>4} {'words':>5}  the words that carry it")
    for r in rows_out[:30]:
        print(f"  {r['syllable']} {r['occurrences']:>4} {r['distinct words']:>5}  "
              f"{r['words'][:60]}")

    print("\nsyllables that cannot be touched, for contrast")
    for c, n in Counter({c: freq[c] for c in new}).most_common(8):
        print(f"  {c} {n:>4} uses across {len(words[c])} words")
    print(f"\nwrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
