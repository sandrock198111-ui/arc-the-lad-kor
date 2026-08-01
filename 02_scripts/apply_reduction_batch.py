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
    ("어둠의 분신", "암흑의 분신"),
    ("왕의 묘에", "왕의 무덤에"),
    ("편이 낫지 않을까", "편이 좋지 않을까"),
    ("그 틈을 파고드는", "그 사이를 파고드는"),
    ("맥 빠진", "얼빠진"),
    ("챔피언으로 둔갑", "우승자로 둔갑"),
    ("안에서 썩어 죽을", "안에서 무너져 갈"),
    ("그래서는 늦습니다", "그래서는 이미 늦은 것입니다"),
    ("눈이 맑았어", "눈이 고왔어"),
    ("승부를 펼칠", "승부를 벌일"),
    ("왕가 찬탈을", "왕가 강탈을"),
    ("멋있는 척하기는", "잘난 체하기는"),
    ("봉인의 기술이 밝혀져", "봉인의 기술이 드러나"),
    ("때 엉망이 된", "때 망가진"),
    ("약속은 이뤘나", "약속은 지켰나"),
    ("가볍게 보지", "우습게 보지"),
    ("덤으로 이 나라의", "겸사겸사 이 나라의"),
    ("화낸다고", "성낸다고"),
    ("한심하기 짝이 없군", "한심하기 그지없군"),
    ("그 무렵 이곳은", "그 시절 이곳은"),
    ("돌, 즉 의지를", "돌, 곧 의지를"),
    ("무엇이옵니까", "무슨 일이신지요"),
    ("것을 줍는 일이", "것을 얻는 일이"),
    ("죽임을 당할 뻔했어요", "하마터면 죽임을 당했어요"),
    ("몬스터가 나타납니다", "몬스터가 나옵니다"),
    ("여기 묵어도 좋다네", "여기 머물러도 좋다네"),
    ("아이들이 어슬렁거릴 곳", "아이들이 나다닐 곳"),
    ("몸소 부딪쳐 알게 된", "몸소 겪어 알게 된"),
    ("소름이 돋는구나", "소름이 끼치는구나"),
    ("이래 봬도", "이래 보여도"),
    ("돈이 될 만한", "값이 될 만한"),
    ("마음을 뒷받침하는", "마음을 받치는"),
    ("지하 깊은 곳에 홀로 숨어", "지하 깊은 곳에 혼자 숨어"),
    ("끔찍한 일이", "무서운 일이"),
    ("곤란하군요", "난처하군요"),
    ("계획에 맞섰다는군", "계획에 반대했다는군"),
    ("방값은 서비스야", "숙박은 공짜야"),
    ("소문이 내게 닿았다", "소문이 내게 들려왔다"),
    ("빼앗아 독차지해서는", "빼앗아 혼자 가져서는"),
    ("것을 눈치챈 모양이다", "것을 알아챈 모양이다"),
    ("긴 세월 동안", "긴 시간 동안"),
    ("국왕 밑의 장군", "국왕 아래 장군"),
    ("껍데기만 흉내", "겉만 흉내"),
    ("모든 것을 훤히 보고", "모든 것을 다 보고"),
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
