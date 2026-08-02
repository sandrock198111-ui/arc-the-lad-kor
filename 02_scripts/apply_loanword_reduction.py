"""Close the glyph gap by rewording, starting with the cheapest cuts.

The finished script needs 202 syllables that have no glyph, against 132 slots. The gap
is 70. Ninety-four of those syllables appear in exactly one word each, so rewording
that single word removes the syllable outright and costs the sentence nothing.

Most of these came from this session's own translation rather than from the earlier
2,024 rows -- transliterated item and place names are expensive, because a foreign
name spends a whole glyph slot on a syllable that appears nowhere else. Rewording my
own transliteration is not the same as weakening someone's dialogue, which is why this
pass runs before anything that would touch meaning.

Every proposal is checked before it is kept: a replacement is accepted only if each
syllable it introduces is already carried by a glyph somewhere. Anything that would
trade one rare syllable for another is rejected and reported, so the churn stays
visible instead of hiding inside a net figure.
"""
from __future__ import annotations

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = ROOT / "05_docs/script_translated_full.csv"
MAPS = ("korean_charmap.csv", "korean_charmap_extended.csv")

# (find, replace) -- one word each; sentence structure and meaning left alone
PROPOSALS = [
    # transliteration and UI wording, this session's own choices
    ("페이지", "쪽"), ("로맨싱", "로망"), ("링", "고리"), ("아이콘", "그림"),
    ("캐릭터", "인물"), ("바이올렛", "보라"), ("레이덴", "레이든"),
    ("스켈레톤", "해골"), ("볼륨을", "소리를"), ("맵을", "지도를"),
    ("스캔은", "조사는"), ("컨디션이", "몸 상태가"),
    # onomatopoeia and interjections
    ("캬캬캬캬캬", "크크크크크"), ("우히햐햐", "우히히히"), ("핑핑", "빙빙"),
    ("철렁철렁하다니까", "조마조마하다니까"), ("하핫", "하하"), ("으앙", "으엉"),
    ("쳇", "흥"), ("큭", "크윽"),
    # ordinary words with a plain synonym
    ("축하합니다", "경하드립니다"), ("골라 주십시오", "고르십시오"),
    ("기술을 골라", "기술을 고르고"), ("기념하여", "기려"),
    ("바꿀 수 있습니다", "바꾸어 놓을 수 있습니다"),
    ("갖고", "가지고"), ("층이 깊은", "층이 많은"), ("깊은", "긴"),
    ("왠지", "어딘가"), ("현재", "지금"), ("몇", "얼마"),
    ("모릅니다", "모르겠습니다"), ("보낸", "보내온"),
    ("완전히", "아주"), ("어쩔", "어찌할"), ("실컷", "마음껏"),
    ("어쩜", "어찌"), ("일찍이", "예전에"), ("그만둬", "그만두"),
    ("슬픈", "서러운"), ("똑똑히", "분명히"), ("꽤", "제법"),
    ("뭉개", "으깨"), ("추한", "더러운"), ("굳센", "든든한"),
    ("춤춰요", "놀아요"), ("높여", "올려"), ("견딘", "견뎌 낸"),
    ("가라앉을", "진정될"), ("뭣도", "무엇도"), ("꼬맹이로군", "애송이로군"),
    ("묻겠는데", "물어보겠는데"), ("부숴", "부수어"), ("수색에도", "수사에도"),
    ("냉정한", "침착한"), ("무덤이라고", "묘라고"), ("삶과", "생과"),
    ("탓이다", "때문이다"), ("낫네", "좋네"), ("깃들어", "서려"),
    ("두둑이", "넉넉히"), ("버팀목이", "받침이"), ("흉악한", "사악한"),
    ("더욱이", "게다가"), ("갇혀", "붙잡혀"), ("얌전히", "조용히"),
    ("그럴듯한", "제법인"), ("느낌이", "기분이"), ("짐작하신", "생각하신"),
    ("힘냅시다", "잘해 봅시다"), ("햇빛도", "해도"), ("잣는", "짜는"),
    ("멈춰 줘", "세워 줘"), ("뭡니까요", "무엇입니까요"), ("뒷일을", "뒤를"),
    ("들끓고", "우글거리고"), ("짖는", "떠드는"), ("가슴이", "마음이"),
    ("대붕괴", "대재앙"), ("빛깔은", "빛은"), ("채굴은", "캐는 일은"),
    ("겉보기와", "보기와"), ("다툼으로", "싸움으로"), ("발짝도", "걸음도"),
    ("비명횡사하였으며", "비참하게 죽었으며"),
    ("뼈대도", "기개도"), ("비슷한", "닮은"), ("술주정뱅이가", "술 취한 자가"),
    ("장로의 방패", "장로의 방어구"), ("비단 띠", "비단 장식"),
    ("흐느적", "비실비실"), ("나는 낄 테다", "나도 함께한다"),
]


def syllables(text: str) -> set[str]:
    return {c for c in text if "가" <= c <= "힣"}


def main() -> None:
    with CSV_PATH.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames
        rows = list(reader)
    lines = [r for r in rows if (r["korean"] or "").strip()]

    placed: set[str] = set()
    for name in MAPS:
        with (ROOT / "05_docs" / name).open(encoding="utf-8-sig") as handle:
            for entry in csv.DictReader(handle):
                placed.add(entry["char"])
    present = {c for r in lines for c in r["korean"] if "가" <= c <= "힣"}
    before = len(present - placed)

    accepted, rejected, missing = [], [], []
    for find, repl in PROPOSALS:
        if not any(find in r["korean"] for r in lines):
            missing.append(find)
            continue
        introduced = syllables(repl) - syllables(find) - present
        if introduced:
            rejected.append((find, repl, "".join(sorted(introduced))))
        else:
            accepted.append((find, repl))

    changed = 0
    for row in rows:
        text = row["korean"] or ""
        if not text.strip():
            continue
        original = text
        for find, repl in accepted:
            text = text.replace(find, repl)
        if text != original:
            row["korean"] = text
            changed += 1

    with CSV_PATH.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    after_present = {c for r in rows if (r["korean"] or "").strip()
                     for c in r["korean"] if "가" <= c <= "힣"}
    after = len(after_present - placed)
    print(f"proposals          : {len(PROPOSALS)}")
    print(f"  accepted         : {len(accepted)}  (applied to {changed} rows)")
    print(f"  rejected         : {len(rejected)}  would introduce a new syllable")
    print(f"  phrase not found : {len(missing)}")
    print(f"\nsyllables needing a slot: {before} -> {after}   (132 available)")
    gap = after - 132
    print("gap closed" if gap <= 0 else f"still short by {gap}")
    if rejected:
        print("\nrejected, and what each would have introduced")
        for find, repl, intro in rejected:
            print(f"  {find}  ->  {repl}   [{intro}]")
    if missing:
        print(f"\nphrases not found: {missing}")


if __name__ == "__main__":
    main()
