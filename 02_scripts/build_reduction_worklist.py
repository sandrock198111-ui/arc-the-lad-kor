"""Apply the agreed rewordings and write the working list for the rest.

Every new syllable costs one glyph slot, and the ones that appear once or twice cost a
whole slot for a single word. Rewording that word removes the slot without touching the
sentence, which is the cheapest way to close the gap between the roughly 904 syllables
the finished script needs and the 507 already placed.

Three kinds of entry come out of this:

  applied   the rewording is done, the syllable is gone
  held      a substitution exists but weakens the line, or the word is a proper noun,
            or removing the syllable would introduce a different rare one -- these need
            a person to decide, so they are listed apart rather than guessed at
  pending   not yet proposed; the sentence is included so the next pass has context

A held entry is not a failure. 웃 for わらつちゃう and 햇 for 日の光 have no synonym
that keeps the meaning, and paying a glyph slot is the right price there.
"""
from __future__ import annotations

import csv
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSV = ROOT / "05_docs/script_translated_full.csv"
OUT = ROOT / "05_docs/syllable_reduction_worklist.csv"
MAPS = ("korean_charmap.csv", "korean_charmap_extended.csv")
HANGUL = re.compile(r"[가-힣]+")

# agreed this session; empty replacement means the line keeps the syllable
APPLIED = [
    ("수고를 덜었군", "수고를 던 셈이군"), ("견학하고", "구경하고"),
    ("솜씨가", "실력이"), ("명에 따랐을 뿐", "명을 따를 뿐"),
    ("이르다고 봅니다만", "이르다고 생각합니다만"), ("발걸음을 옮겨", "찾아가"),
    ("암살당했습니다", "살해당했습니다"), ("멀리서", "먼 곳에서"),
    ("균형은", "조화는"), ("봉인을 푸는", "봉인을 해제하는"),
    ("기뻐하실", "좋아하실"), ("에릴베를 높입니다", "에릴베를 늘립니다"),
    ("컬렉션이", "수집품이"), ("빼앗겼을 때", "빼앗긴 때"),
    ("뱃속에", "배 속에"), ("잘도 탔군", "잘도 타는군"),
    ("꼴좋군", "잘됐군"), ("일으켰습니다", "일으킨 것입니다"),
    # this batch
    ("암흑의 분신", "어둠의 분신"), ("딱히 감사하실", "굳이 감사하실"),
    ("발견한 아이템", "찾은 아이템"), ("익힐 수 없는", "배울 수 없는"),
    ("한바퀴 둘러보고", "두루 둘러보고"), ("그랬더니", "그런데"),
    ("그럴 터인데", "그러할 터인데"), ("찬탈을 꾀하고", "찬탈을 노리고"),
    ("얕보지", "가볍게 보지"), ("아홉 번째", "9번째"),
    ("글쎄.", "모르지."), ("숙박비는", "방값은"), ("리에 짱", "리에 양"),
    ("차츰 나라가", "점점 나라가"), ("몸소 겪어", "몸소 부딪쳐"),
    ("국왕 휘하의", "국왕 밑의"), ("꿰뚫어 보고", "훤히 보고"),
    ("물과 녹음이", "물과 초목이"), ("겉모습만", "껍데기만"),
    ("쫓겨나는", "내몰리는"), ("지껄이고", "떠들고"),
]

HELD = {
    "웃": "わらつちゃう는 '웃음이 나온다'는 뜻이라 대체어가 의미를 옅게 만든다",
    "햇": "日の光을 '빛'으로만 옮기면 해가 사라진다",
    "앉": "住み着く의 눌러앉는 뉘앙스를 살릴 대체어가 마땅치 않다",
    "깔": "'색깔'로 바꾸면 색이 남고, '색'으로 되돌리면 색이 다시 1회가 된다",
    "켈": "스켈레톤은 몬스터 고유명이라 임의로 바꿀 수 없다",
    "붕": "대붕괴는 세계관 용어라 표기 변경에 판단이 필요하다",
}


def main() -> None:
    with CSV.open(encoding="utf-8-sig", newline="") as f:
        r = csv.DictReader(f)
        fields = r.fieldnames
        rows = list(r)
    ko = next(c for c in fields if "korean" in c.lower())
    ja = next(c for c in fields if "japanese" in c.lower())

    changed = 0
    for row in rows:
        k = row[ko] or ""
        if not k.strip():
            continue
        before = k
        for a, b in APPLIED:
            k = k.replace(a, b)
        if k != before:
            row[ko] = k
            changed += 1
    with CSV.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    placed = set()
    for name in MAPS:
        with (ROOT / "05_docs" / name).open(encoding="utf-8-sig") as f:
            for r in csv.DictReader(f):
                placed.add(r["char"])

    lines = [(r[ja] or "", r[ko]) for r in rows if (r[ko] or "").strip()]
    freq = Counter(c for _, k in lines for c in k if "가" <= c <= "힣")
    words = defaultdict(Counter)
    sample = {}
    for j, k in lines:
        for word in HANGUL.findall(k):
            for ch in set(word):
                words[ch][word] += 1
                sample.setdefault(ch, (j.replace("\n", " / ")[:70],
                                       k.replace("\n", " / ")[:70]))
    need = sorted({c for c in freq if c not in placed},
                  key=lambda c: (freq[c], len(words[c])))

    out = []
    for c in need:
        out.append({
            "음절": c,
            "상태": "보류" if c in HELD else "검토필요",
            "등장": freq[c],
            "단어수": len(words[c]),
            "단어": " ".join(f"{w}({n})" for w, n in words[c].most_common(5)),
            "원문": sample.get(c, ("", ""))[0],
            "현재 번역": sample.get(c, ("", ""))[1],
            "대체안": "",
            "보류 사유": HELD.get(c, ""),
        })
    with OUT.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0]))
        w.writeheader()
        w.writerows(out)

    held = [r for r in out if r["상태"] == "보류"]
    once = [r for r in out if r["등장"] == 1]
    print(f"rewordings applied : {changed} rows")
    print(f"distinct syllables : {len(freq)}   still needing a slot: {len(need)}")
    print(f"\nworklist {OUT.relative_to(ROOT)}")
    print(f"  보류      {len(held):>4}  판단이 필요한 것")
    print(f"  검토필요  {len(out) - len(held):>4}  가운데 1회 등장 {len(once)}")
    print("\n보류 항목")
    for r in held:
        print(f"  {r['음절']}  {r['등장']}회  {r['단어'][:28]:<30} {r['보류 사유']}")


if __name__ == "__main__":
    main()
