"""Apply rewordings, but only the ones that actually pay.

The first two batches traded one rare syllable for another: replacing 견학 with 구경
removed 학 and 딱히 with 굳이 introduced 굳. The net was still positive, 201 down to
168, but a good share of the work cancelled itself out.

So a proposal is now checked before it is kept. A replacement is accepted only if every
syllable it introduces is already carried by a glyph somewhere in the script. Anything
that would create a new rare syllable is rejected and reported, so the churn is visible
instead of hiding inside a net figure.
"""
from __future__ import annotations

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSV = ROOT / "05_docs/script_translated_full.csv"
MAPS = ("korean_charmap.csv", "korean_charmap_extended.csv")

# (find, replace) -- one word each, sentence structure untouched
PROPOSALS = [
    ("이미 늦은 것입니다", "이미 때가 지난 것입니다"),
    ("굳이 감사하실", "따로 감사하실"),
    ("몸소 부딪쳐 알게 된", "몸소 몸으로 알게 된"),
    ("몬스터가 나옵니다", "몬스터가 나타나오"),
    ("것을 알아챈 모양이다", "것을 아는 모양이다"),
    ("왕의 무덤에", "왕의 능에"),
    ("왕가 강탈을 노리고", "왕가를 빼앗으려 하고"),
    ("성낸다고", "화를 내도"),
    ("약속은 이뤘나", "약속은 다했나"),
    ("어둠의 분신", "암흑의 분신"),
    ("껍데기만 흉내", "모양만 흉내"),
    ("머리카락 빛깔은", "머리카락 색은"),
    ("헉!", "앗!"),
    ("큭...", "윽..."),
    ("웃지 마라", "우습게 보지 마라"),
    ("눌러앉아", "머물러"),
    ("쵸코의", "초코의"),
]


def syllables(s):
    return {c for c in s if "가" <= c <= "힣"}


def main() -> None:
    with CSV.open(encoding="utf-8-sig", newline="") as f:
        r = csv.DictReader(f)
        fields = r.fieldnames
        rows = list(r)
    ko = next(c for c in fields if "korean" in c.lower())
    lines = [r for r in rows if (r[ko] or "").strip()]

    placed = set()
    for name in MAPS:
        with (ROOT / "05_docs" / name).open(encoding="utf-8-sig") as f:
            for x in csv.DictReader(f):
                placed.add(x["char"])
    present = {c for r in lines for c in r[ko] if "가" <= c <= "힣"}
    before_new = len(present - placed)

    accepted, rejected, missing = [], [], []
    for find, repl in PROPOSALS:
        if not any(find in (r[ko] or "") for r in lines):
            missing.append(find)
            continue
        # a syllable the script does not already carry costs a slot of its own
        introduced = syllables(repl) - syllables(find) - present
        if introduced:
            rejected.append((find, repl, "".join(sorted(introduced))))
        else:
            accepted.append((find, repl))

    changed = 0
    for row in rows:
        k = row[ko] or ""
        if not k.strip():
            continue
        before = k
        for find, repl in accepted:
            k = k.replace(find, repl)
        if k != before:
            row[ko] = k
            changed += 1
    with CSV.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    after = {c for r in rows if (r[ko] or "").strip()
             for c in r[ko] if "가" <= c <= "힣"}
    print(f"proposals            : {len(PROPOSALS)}")
    print(f"  accepted           : {len(accepted)}  (applied to {changed} rows)")
    print(f"  rejected           : {len(rejected)}  would introduce a new syllable")
    print(f"  phrase not found   : {len(missing)}")
    print(f"\nsyllables needing a slot: {before_new} -> {len(after - placed)}")
    if rejected:
        print("\nrejected, and what each would have introduced")
        for find, repl, intro in rejected:
            print(f"  {find}  ->  {repl}   [{intro}]")
    if missing:
        print(f"\nphrases not found: {missing}")


if __name__ == "__main__":
    main()
