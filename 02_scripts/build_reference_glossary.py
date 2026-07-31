"""Build the terminology decision record from the scanned guidebook.

Source: 05_docs/참고사항/공략본/ (GAME MAGAZINE pp.88-96, Arc the Lad walkthrough).
Pages 4 and 10 carry bilingual item and accessory tables, pages 5-8 carry the
per-character skill tables, page 3 the stat names, pages 1-2 places and characters.

The guidebook is a reference, not an authority. Prior work aligned to it, so every
entry here records what it says, what the patch currently uses, and which one we keep
and why. Decision rules, in priority order:

  1. source accuracy   - if the guidebook misreads the Japanese, do not follow it
  2. proper nouns      - keep whatever is already consistent across the script
  3. genre convention  - when both are accurate, prefer the common Korean JRPG term
  4. glyph budget      - never a reason to change a word; add the glyph instead

Rule 4 matters because the opposite happened before: 책임질 became 관여할 purely
because a glyph was missing, and the change was recorded as if it were a translation
choice. Adopting every guidebook term costs 13 new glyphs against 27 free slots.
"""
from __future__ import annotations

import csv
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "05_docs"
OUT = DOCS / "terminology_decisions.csv"
HAN = re.compile(r"[가-힣]")

# (category, japanese, guidebook korean, page, note)
GUIDE = [
    # --- items, p.4 ---
    ("item", "ねばねば", "끈끈이", 4, "민첩성 저하"),
    ("item", "やる気ゼリー", "원기 젤리", 4, "헤모지 회복"),
    ("item", "みなぎる果実", "충만 과실", 4, "레벨 상승"),
    ("item", "回復果物", "회복 과실", 4, "HP 60 회복"),
    ("item", "しびれるりんご", "마비 사과", 4, ""),
    ("item", "石", "돌", 4, "던져서 타격"),
    ("item", "レコの草", "레코의 풀", 4, "방어력 상승"),
    ("item", "薬草", "약초", 4, "HP 20 회복"),
    ("item", "毒薬", "독약", 4, ""),
    ("item", "ルヴの薬", "루우의 약", 4, "마비 회복"),
    ("item", "すばやさの薬", "민첩성의 약", 4, ""),
    ("item", "小さい爆弾", "작은 폭탄", 4, ""),
    ("item", "大きい爆弾", "큰 폭탄", 4, ""),
    ("item", "万能薬", "만능약", 4, "석화 외 모든 이상 회복"),
    ("item", "聖水", "성수", 4, "독 해독"),
    ("item", "復活の薬", "부활의 약", 4, "전투불능 부활"),
    ("item", "攻撃瓶", "공격 항아리", 4, ""),
    ("item", "眠りの玉", "잠드는 구슬", 4, ""),
    ("item", "弱り玉", "약함의 구슬", 4, ""),
    ("item", "ちからの実", "힘의 열매", 4, ""),
    ("item", "パロの実", "파로의 열매", 4, ""),
    ("item", "いのちの木の実", "생명나무의 열매", 4, "HP 최대치 상승"),
    ("item", "魔力の葉", "마력의 잎", 4, "마력 상승"),
    ("item", "魔力の泉", "마력의 샘", 4, "MP 최대치 상승"),
    ("item", "目つぶしの草", "모래 풀", 4, "명중률 저하"),
    ("item", "若い葉", "젊음의 잎", 4, ""),
    ("item", "石解けハリ", "석해 침", 4, "STONED 회복"),
    ("item", "痛烈なハリ", "통렬한 침", 4, "SILENCE 회복"),
    # --- accessories, p.10 (selection with clear readings) ---
    ("accessory", "炎の守り", "불꽃의 수호", 10, ""),
    ("accessory", "氷の守り", "얼음의 수호", 10, ""),
    ("accessory", "アンチヘモジー", "안티헤모지", 10, ""),
    ("accessory", "いやしの守り", "치료의 수호", 10, ""),
    ("accessory", "魔法のカード", "마법의 카드", 10, "마력 10%"),
    ("accessory", "スリープレスカード", "슬리프리스 카드", 10, ""),
    ("accessory", "パワーアーム", "파워 암", 10, ""),
    ("accessory", "ガイガーグローブ", "가이거 글로브", 10, ""),
    ("accessory", "幻のこて", "환상의 손끝", 10, "공격력 50%"),
    ("accessory", "サングラス", "선글래스", 10, "DARKNESS 방지"),
    ("accessory", "ネックレス", "네클리스", 10, ""),
    ("accessory", "ハイパーブーツ", "하이퍼 부츠", 10, ""),
    ("accessory", "パワーリスト", "파워 리스트", 10, ""),
    ("accessory", "一角獣の角", "일각수의 뿔", 10, ""),
    ("accessory", "鏡", "거울", 10, "STONED 방지"),
    ("accessory", "古代のゆびわ", "고대의 반지", 10, ""),
    ("accessory", "幻のゆびわ", "환상의 반지", 10, "마력 50%"),
    ("accessory", "おもちゃのゆびわ", "장난감 반지", 10, ""),
    ("accessory", "幻の盾", "환상의 방패", 10, ""),
    ("accessory", "戦士の守り", "전사의 수호", 10, ""),
    ("accessory", "勇者の盾", "용사의 방패", 10, ""),
    ("accessory", "乱れる宝石", "광란의 보석", 10, ""),
    ("accessory", "アーマーストーン", "아머 스톤", 10, ""),
    ("accessory", "太陽のぼうし", "태양의 모자", 10, ""),
    ("accessory", "おし花の本", "압화 책", 10, ""),
    ("accessory", "音楽集", "음악집", 10, ""),
    ("accessory", "勇者の証", "용자의 증표", 10, ""),
    # --- Arc skills, p.5 ---
    ("skill_arc", "バーングラウンド", "뱅 그라운드", 5, "공격 MP 4/8/16"),
    ("skill_arc", "ゲイルフラッシュ", "게일 플래시", 5, "공격 MP 12/16/24"),
    ("skill_arc", "メテオフォル", "메테오 폴", 5, "공격 MP 9/14/21"),
    ("skill_arc", "トータルヒーリング", "토탈 힐링", 5, "회복 MP 7/10/15"),
    ("skill_arc", "スローエネミー", "슬로우 에네미", 5, "보조 MP 6/9/14"),
    # --- Poco skills, p.5 ---
    ("skill_poco", "荒獅子太鼓", "황사자태고", 5, "공격 MP 8/12/16"),
    ("skill_poco", "へろへろのラッパ", "비틀비틀 나팔", 5, "공격 MP 12/16/24"),
    ("skill_poco", "気合いラッパ", "기합 나팔", 5, "공격 MP 8/12/18"),
    ("skill_poco", "いやしのたてごと", "치료 거문고", 5, "보조 MP 3/5/8"),
    ("skill_poco", "のろまのベース", "둔한 베이스", 5, "보조 MP 7/11/17"),
    ("skill_poco", "韋駄天のオカリナ", "위타천 오카리나", 5, "보조 MP 4/6/9"),
    ("skill_poco", "方向の笛", "방향잡이 피리", 5, "보조 MP 10/14/18"),
    ("skill_poco", "戦の小太鼓", "전투 큰 북", 5, "보조 MP 3/5/8"),
    # --- Kukuru skills, p.6 ---
    ("skill_kukuru", "天のさばき", "하늘의 심판", 6, "공격 MP 9/14/21"),
    ("skill_kukuru", "デバイド", "디바이드", 6, "공격/회복 MP 14/21/32"),
    ("skill_kukuru", "キュア", "큐어", 6, "회복 MP 4/8/12"),
    ("skill_kukuru", "デポイズン", "디포이즌", 6, "회복 MP 3/5/8"),
    ("skill_kukuru", "リフレッシュ", "리프레시", 6, "회복 MP 8/12/18"),
    ("skill_kukuru", "リザレクション", "리서렉션", 6, "회복 MP 12/18/27"),
    ("skill_kukuru", "サイレント", "사일렌트", 6, "보조 MP 6/9/14"),
    # --- Gogen skills, p.6 ---
    ("skill_gogen", "エクスプロージョン", "익스플로전", 6, "MP 10/16/22"),
    ("skill_gogen", "ドリームノック", "드림 노크", 6, "공격 MP 6/10/16"),
    ("skill_gogen", "ダイアモンドダスト", "다이아몬드 더스트", 6, "공격 MP 14/20/26"),
    ("skill_gogen", "ウインドスラッシャー", "윈드 슬래셔", 6, "보조 MP 16/24/32"),
    ("skill_gogen", "ヒートウォール", "히트 월", 6, "공격 MP 13/20/30"),
    ("skill_gogen", "サンダーストーム", "썬더 스톰", 6, "공격 MP 18/28/38"),
    ("skill_gogen", "テレポート", "텔리포트", 6, "보조 MP 10/15/23"),
    # --- Tosh skills, p.7 ---
    ("skill_tosh", "呪縛剣", "주박검", 7, "공격 MP 5/8/12"),
    ("skill_tosh", "眞空斬", "진공참", 7, "공격 MP 16/18/20"),
    ("skill_tosh", "虎影斬", "호영참", 7, "공격 MP 20/24/28"),
    ("skill_tosh", "櫻花雷暴斬", "벚꽃뇌폭참", 7, "공격 MP 24/32/40"),
    # --- Iga skills, p.8 ---
    ("skill_iga", "心眼法", "심안법", 8, "공격 MP 2/4/6"),
    ("skill_iga", "退魔光弾", "퇴마광탄", 8, "공격 MP 6/9/14"),
    ("skill_iga", "旋風撃", "선풍격축", 8, "공격 MP 8/12/18"),
    ("skill_iga", "流星爆", "유성폭", 8, "공격 MP 9/14/21"),
    ("skill_iga", "鬼陣流影波", "귀신류영파", 8, "공격 MP 11/17/26"),
    ("skill_iga", "滅拳烈波", "멸장렬파", 8, "공격 MP 13/20/30"),
    # --- Chongara summons, p.8 ---
    ("summon", "調べる", "조사", 8, "MP 1"),
    ("summon", "ケラック", "케라크", 8, "MP 4"),
    ("summon", "モフリ", "모프리", 8, "MP 8"),
    ("summon", "ヘモジ", "헤모지", 8, "MP 14"),
    ("summon", "オドン", "오돈", 8, "MP 18"),
    ("summon", "フウジン/ライジン", "후우진/라이진", 8, "MP 30"),
    ("summon", "ちょこ", "쵸꼬", 8, "유적 던전 최하층"),
    # --- status, p.4 ---
    ("status", "SLEEP", "SLEEP", 4, ""),
    ("status", "DARKNESS", "DARKNESS", 4, ""),
    ("status", "SILENCE", "SILENCE", 4, ""),
    ("status", "POISONED", "POISONED", 4, ""),
    ("status", "HEMOZEE", "HEMOZEE", 4, ""),
    ("status", "PARALYZED", "PARALYZED", 4, ""),
    ("status", "STONED", "STONED", 4, ""),
    # --- stats, p.3 ---
    ("stat", "レベル", "레벨", 3, ""),
    ("stat", "移動力", "이동력", 3, ""),
    ("stat", "攻撃力", "공격력", 3, ""),
    ("stat", "魔力", "마력", 3, ""),
    ("stat", "防御力", "방어력", 3, ""),
    ("stat", "敏捷性", "민첩성", 3, ""),
    ("stat", "経験値", "경험치", 3, ""),
    ("stat", "ジャンプレベル", "점프 레벨", 3, ""),
    ("stat", "投げレベル", "던지기 레벨", 3, ""),
    ("stat", "反撃レベル", "반격 레벨", 3, ""),
    ("stat", "受けレベル", "받기 레벨", 3, ""),
    # --- characters, p.2 ---
    ("character", "アーク", "아크", 2, "15세, 토우빌 출신"),
    ("character", "ククル", "쿠쿠르", 2, "17세, 정령 산 신관 가문"),
    ("character", "チョンガラ", "총가라", 2, "45세 골동품상"),
    ("character", "ポコ", "포코", 2, "15세, 파렌시아 군"),
    ("character", "トッシュ", "토쉬", 2, "28세, 의적단 두목"),
    ("character", "ゴーゲン", "고겐", 2, "고대 7현자"),
    ("character", "イーガ", "이가", 2, "38세 권법가"),
    # --- places ---
    ("place", "スメリア", "스메리아", 1, ""),
    ("place", "ミルマーナ", "미르마나", 1, ""),
    ("place", "アララトス", "아라라토스", 1, ""),
    ("place", "グレイシス", "그레이시스", 1, ""),
    ("place", "ニーデル", "니델", 1, ""),
    ("place", "アリバサ", "아리바사", 1, "공략본 본문은 아리바샤"),
    ("place", "トウビル", "토우빌", 2, ""),
    ("place", "パレンシア", "파렌시아", 4, ""),
    ("place", "ラマダ", "라마다", 9, ""),
    ("place", "ロマリア", "로마리아", 9, ""),
]

# explicit rulings where the patch and the guidebook disagree
RULINGS = {
    "幻のこて": ("keep_current", "こて(小手)는 팔뚝·손목 보호구. 공략본의 '손끝'은 오독"),
    "目つぶしの草": ("keep_current", "目つぶし는 눈을 멀게 함. '눈가림'이 원문에 충실"),
    "一角獣の角": ("keep_current", "둘 다 정확. '유니콘'이 한국 JRPG 관용"),
    "ククル": ("keep_current", "외래어 표기법 ル→루. 이미 대사 전체에 사용됨"),
    "トッシュ": ("keep_current", "외래어 표기법 シュ→슈. 이미 대사 전체에 사용됨"),
    "いのちの木の実": ("adopt_guide", "공략본이 더 구체적이고 새 글리프 불필요"),
    "すばやさの薬": ("adopt_guide", "공략본이 더 구체적이고 새 글리프 불필요"),
    "復活の薬": ("adopt_guide", "축약형보다 원문에 충실하고 새 글리프 불필요"),
    "回復果物": ("adopt_guide", "果物은 과실. 새 글리프 불필요"),
    # 果実/果物 -> 과실, 実 -> 열매. The guidebook keeps this distinction and the
    # original makes it too; the patch had flattened both to 열매.
    "みなぎる果実": ("hybrid", "과실 구분은 채택, 형용사는 みなぎる에 더 가까운 '넘치는' 유지"),
    "乱れる宝石": ("keep_current", "'요동치는'이 乱れる에 충실하고 글리프도 불필요"),
    # skills: the guidebook transliterates the kanji rather than translating it,
    # so it is the weaker reference for this category. Keep the existing wording.
    "天のさばき": ("keep_current", "스킬명은 UI 폭 제약이 있어 짧은 '천벌' 유지"),
    "いやしのたてごと": ("keep_current", "たてごと(竪琴)는 하프. 공략본의 '거문고'가 오히려 의역"),
    "荒獅子太鼓": ("keep_current", "太鼓는 북. '태고'는 한국어로 통용되지 않음"),
    "のろまのベース": ("keep_current", "のろま(둔함)의 의미를 '둔화'로 유지"),
    "戦の小太鼓": ("keep_current", "小太鼓는 작은 북. '전투의 북'으로 통일"),
    "ちょこ": ("keep_current", "'초코'가 한국어 표기로 자연스러움"),
}


# wording that takes part of the guidebook and part of the current patch
HYBRID = {
    "みなぎる果実": "넘치는 과실",
}


def main() -> None:
    have = set()
    with (DOCS / "ui_glyph_store_v42_map.csv").open(encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            if r.get("char") and HAN.match(r["char"]):
                have.add(r["char"])

    cur: dict[str, set[str]] = {}
    with (DOCS / "ui_full_v42.csv").open(encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            jp, ko = (r.get("japanese") or "").strip(), (r.get("korean") or "").strip()
            if jp and ko:
                cur.setdefault(jp, set()).add(ko)

    rows = []
    for cat, jp, guide, page, note in GUIDE:
        patch = " / ".join(sorted(cur.get(jp, [])))
        if not patch:
            decision, reason = "not_in_patch", "현재 UI 테이블에 해당 문자열 없음"
            final = guide
        elif guide in cur[jp]:
            decision, reason = "already_matches", ""
            final = guide
        else:
            decision, reason = RULINGS.get(jp, ("undecided", "검토 필요"))
            if decision == "keep_current":
                final = patch
            elif decision == "hybrid":
                final = HYBRID[jp]
            else:
                final = guide
        need = "".join(sorted({c for c in final if HAN.match(c) and c not in have}))
        rows.append({
            "category": cat, "japanese": jp, "guidebook": guide,
            "current_patch": patch, "decision": decision, "final": final,
            "new_glyphs_needed": need, "reason": reason, "note": note, "page": page,
        })

    with OUT.open("w", encoding="utf-8-sig", newline="") as f:
        wcsv = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        wcsv.writeheader()
        wcsv.writerows(rows)

    from collections import Counter
    c = Counter(r["decision"] for r in rows)
    print(f"wrote {OUT}  ({len(rows)} terms)")
    for k, v in c.most_common():
        print(f"  {k:<16} {v}")
    conflicts = [r for r in rows if r["decision"] in ("keep_current", "adopt_guide", "undecided")]
    print("\nconflicts between guidebook and patch:")
    for r in conflicts:
        print(f"  [{r['decision']:<15}] {r['japanese']:<14} guide={r['guidebook']:<14} "
              f"patch={r['current_patch']:<14} -> {r['final']}"
              + (f"  (+{r['new_glyphs_needed']})" if r["new_glyphs_needed"] else ""))
    allnew = "".join(sorted({c for r in rows for c in r["new_glyphs_needed"]}))
    print(f"\nnew glyphs needed across every 'final' term: {len(allnew)}  {allnew}")


if __name__ == "__main__":
    main()
