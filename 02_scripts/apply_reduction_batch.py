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
    # 보류 3건 -- 단순 교환이 아니라 제3의 표현으로 우회
    ("어둠의 분신", "그림자 분신"),
    ("머리카락 빛깔은", "머리카락은 무슨 빛"),
    ("큭...", "크윽..."),
    # 1~2회
    ("얌전히 있어 줘서", "조용히 있어 줘서"),
    ("컨디션이 안 좋으니", "몸이 안 좋으니"),
    ("그만둬, 그만두지", "멈춰, 멈추지"),
    ("아나운서: 현재,", "아나운서: 지금,"),
    ("모두 맞힌 건", "모두 맞춘 건"),
    ("승부를 벌일", "승부를 할"),
    ("슬픈 일이구먼", "가슴 아픈 일이구먼"),
    ("국민 신앙의 대상", "국민이 믿는 대상"),
    ("흉내 내어 계승", "따라 하며 계승"),
    ("편지가 도착한다는", "편지가 온다는"),
    ("방값은 서비스야", "돈은 안 받겠네"),
    ("동력석 채굴장입니다", "동력석을 캐는 곳입니다"),
    ("나라가 순식간에 부유해졌습니다", "나라가 단숨에 부유해졌습니다"),
    ("술주정뱅이는", "술 취한 자는"),
    ("대신이 추진하는", "대신이 밀고 있는"),
    ("오랜만인 것 같아", "오래된 것 같아"),
    ("검에 깃든 정령", "검에 서린 정령"),
    ("하필으로", "하필로"),
    ("다툼에 지쳐", "싸움에 지쳐"),
    ("리에 양, 귀엽구먼", "리에 양, 예쁘구먼"),
    # 3회
    ("실컷 떠들고", "마음껏 떠들고"),
    ("있을지도 모릅니다", "있을지도 모른다 하옵니다"),
    ("몬스터를 퇴치해", "몬스터를 없애"),
    ("어쩔 수 있는", "어찌할 수 있는"),
    ("완전히 쇠약해진", "아주 쇠약해진"),
    ("가끔 보러 오는", "때때로 보러 오는"),
    ("많은 비극을 낳는다", "많은 불행을 낳는다"),
    ("커다란 힘이", "거대한 힘이"),
    ("아이 취급하지", "아이로 보지"),
    ("장례는 사흘 전에", "장례는 삼 일 전에"),
    ("인간이라는 존재에게", "인간이라는 것에"),
    ("너 자신도 당황스럽겠지", "너 자신도 어리둥절하겠지"),
    ("큰 힘은 느껴지지만", "큰 힘은 느낄 수 있지만"),
    # 4회 이상 중 단어가 적은 것
    ("어쩌지?", "어찌하지?"),
    ("창고나 감옥밖에는", "곳간이나 감옥밖에는"),
    ("박식한 건지", "많이 아는 건지"),
    ("조사해 놓고", "조사해 두고"),
    ("비슷한 수치가", "같은 수치가"),
    ("강한 상대를 골라", "강한 상대를 정해"),
    ("풋내기들이었지만", "애송이들이었지만"),
    ("뼈대도 없어 보이는", "줏대도 없어 보이는"),
    ("뭐가 나쁘다는", "뭐가 잘못이라는"),
    ("팔렌시아의 대청소부터다", "팔렌시아를 싹 치우는 것부터다"),
    ("이긴 횟수를", "이긴 수를"),
    ("더욱 레벨 차이가", "레벨 차이가 더"),
    ("칭호를 받을", "이름을 받을"),
    ("잠깐 부탁이", "잠시 부탁이"),
    ("나쁜 짓을", "못된 짓을"),
    ("힘 시험도 겸해서", "힘 시험도 할 겸"),
    ("어쨌든 내 가게로", "아무튼 내 가게로"),
    ("등급을 두고", "차례를 두고"),
    ("책임지지 않겠소", "책임을 지지 않겠소"),
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
