"""Apply the wording decisions that have actually been made, and only those.

Each edit is keyed to a file and offset and states the text it expects to find, so a
run that no longer matches stops rather than guessing. Nothing is replaced globally:

  兄 -> 형        The king's brother is 형. Four lines still said 형님. Two other
                  lines are 兄貴, a subordinate addressing his boss, where 형님 is
                  the right word and a blanket replacement would have broken them.

  勇者 -> 용자    The shipping UI uses 용자 25 times and 용사 never, and the
                  terminology table records 勇者の証 as already matching the patch.
                  The story drifted to 용사; it comes back.

  one line reworded, at the user's wording: the comma falls where と closes the
  quoted clause, and のだな asks for confirmation, which 것이냐 carries and
  것이로군 does not.
"""
from __future__ import annotations

import csv
import re
import shutil
from pathlib import Path

# A slow-reveal line interleaves control codes inside a word, so the Japanese reads
# `スメ<CTRL:E4:15>リ<CTRL:E4:15>ア`. Matching on the raw cell misses those, which is
# how one 수메리아 survived a substitution that caught the other 48.
CTRL = re.compile(r"<(?:CTRL|G):[^>]*>")

ROOT = Path(__file__).resolve().parents[1]
TABLE = ROOT / "05_docs/script_translated_full.csv"
REPORT = ROOT / "01_work/analysis/wording_fixes.txt"

# (file, offset, expected text, replacement) -- a rewrite, not a global substitution.
# The expected text may be a tuple when an earlier decision has been revised, so the
# script accepts either the original wording or the one it wrote last time and lands
# on the same result whichever it finds.
REWRITES = [
    ("22/S2055.DAT", "0x478F0",
     "국왕: 그러면 형이 네 아버지라고 정령이 말한 것이로군?",
     "국왕: 그러면 형이 네 아비라고, 정령이 말했다는 것이냐?"),

    # The Japanese repeats あなた for emphasis; Korean does not need the first one,
    # and しなくてはならない reads as a calque spelled out in full.
    # The speaker was renamed by the 恵 correction after this rewrite was written, so
    # both spellings are accepted and the result carries the corrected one.
    ("32/S3061.DAT", "0x481DE",
     ("베미의 정령: 당신이 무엇을 하지 않으면 안 되는지는 당신이 정할 일입니다.",
      "은혜의 정령: 당신이 무엇을 하지 않으면 안 되는지는 당신이 정할 일입니다.",
      "베미의 정령: 무엇을 해야 하는지는 당신이 정할 일입니다."),
     "은혜의 정령: 무엇을 해야 하는지는 당신이 정할 일입니다."),
    ("32/S3062.DAT", "0x47D3A",
     ("베미의 정령: 당신이 무엇을 하지 않으면 안 되는지는 당신이 정할 일입니다.",
      "은혜의 정령: 당신이 무엇을 하지 않으면 안 되는지는 당신이 정할 일입니다.",
      "베미의 정령: 무엇을 해야 하는지는 당신이 정할 일입니다."),
     "은혜의 정령: 무엇을 해야 하는지는 당신이 정할 일입니다."),

    # Yagun uses blunt orders for his own soldiers and monsters, but addresses Arc's
    # party formally in these two meetings. A previous pass forced three lines into
    # 하오체; the full 26-line speaker audit showed that they sit among 합쇼체 lines
    # to Arc's party and were the outliers, not a deliberate character trait.
    ("31/S3031.DAT", "0x47C40",
     ("야군: 하지만 그건 아이들에게는 무리입니다. 너무 위험해요.",
      "야군: 하지만 그건 아이들에게는 무리입니다. 너무 위험합니다."),
     "야군: 하지만 그건 아이들에게는 무리입니다. 너무 위험합니다."),
    ("31/S3032.DAT", "0x479EE",
     ("야군: 다만 저곳은 우리도 애를 먹고 있는 장소다.",
      "야군: 다만 저곳은 우리도 애를 먹고 있는 곳이오.",
      "야군: 다만 저곳은 우리도 애를 먹고 있는 곳입니다."),
     "야군: 다만 저곳은 우리도 애를 먹고 있는 곳입니다."),
    ("31/S3032.DAT", "0x47A40",
     ("야군: 만일 무슨 일이 있어도 우리는 책임지지 않겠습니다.",
      "야군: 만일 무슨 일이 있어도 우리는 책임을 지지 않겠소.",
      "야군: 만일 무슨 일이 있어도 우리는 책임을 지지 않습니다."),
     "야군: 만일 무슨 일이 있어도 우리는 책임을 지지 않습니다."),
    ("31/S3031.DAT", "0x4810A",
     ("야군: 최근에는 이 근처에도 몬스터가 나타납니다.",
      "야군: 최근에는 이 근처에도 몬스터가 나타나오.",
      "야군: 최근에는 이 근처에도 몬스터가 나타나고 있습니다."),
     "야군: 최근에는 이 근처에도 몬스터가 나타나고 있습니다."),

    # This is the same three-row Choppin menu fixed locally in v191. Keep the
    # question natural without changing either option or the global choice layout.
    ("31/S3012.DAT", "0x47FF0",
     ("초핀: 무언가 제가 도움이 될 일이 있습니까?|없어|좀 물어보고 싶어",
      "초핀: 제가 도와드릴 일이 있습니까?|없어|좀 물어보고 싶어"),
     "초핀: 제가 도와드릴 일이 있습니까?|없어|좀 물어보고 싶어"),

    # v192 merges every genuine choice speaker row with its question.  These
    # corpus entries must match the runtime prompts; options are intentionally
    # unchanged because cursor/option repair is a separate concern.
    ("1/S1023.DAT", "0x47952",
     ("어머니: 아버지가 남긴 편지가 있는데 읽어 볼래?|괜찮아|읽는다",
      "어머니: 아버지가 남긴 편지를 읽을래?|괜찮아|읽는다"),
     "어머니: 아버지가 남긴 편지를 읽을래?|괜찮아|읽는다"),
    ("7/S7021.DAT", "0x48D26",
     ("출전할까요?|출전|그만",
      "대회 위원: 출전하시겠습니까?|출전|그만"),
     "대회 위원: 출전하시겠습니까?|출전|그만"),
    ("7/S7022.DAT", "0x489B6",
     ("1회전 준비?|예|아직입니다",
      "대회 위원: 1회전 준비됐습니까?|예|아직입니다"),
     "대회 위원: 1회전 준비됐습니까?|예|아직입니다"),
    ("7/S7023.DAT", "0x48A4E",
     ("2회전 준비?|예|아직입니다",
      "대회 위원: 2회전 준비됐습니까?|예|아직입니다"),
     "대회 위원: 2회전 준비됐습니까?|예|아직입니다"),
    ("7/S7024.DAT", "0x48AAE",
     ("준결승 준비?|예|아직입니다",
      "대회 위원: 준결승 준비됐습니까?|예|아직입니다"),
     "대회 위원: 준결승 준비됐습니까?|예|아직입니다"),
    ("7/S7025.DAT", "0x48AC2",
     ("결승 준비?|예|아직입니다",
      "대회 위원: 결승 준비됐습니까?|예|아직입니다"),
     "대회 위원: 결승 준비됐습니까?|예|아직입니다"),
    ("7/S7026.DAT", "0x48D28",
     ("오브전 준비?|예|아직입니다",
      "대회 위원: 오브 쟁탈전 준비됐습니까?|예|아직입니다"),
     "대회 위원: 오브 쟁탈전 준비됐습니까?|예|아직입니다"),
    ("7/S7028.DAT", "0x48028",
     ("출전할까요?|출전|그만",
      "대회 위원: 출전하시겠습니까?|출전|그만"),
     "대회 위원: 출전하시겠습니까?|출전|그만"),
    ("7/S7028.DAT", "0x48B70",
     ("정말 할까요?|승리|나중에",
      "대회 위원: 정말 출전하시겠습니까?|승리|나중에"),
     "대회 위원: 정말 출전하시겠습니까?|승리|나중에"),

    # The menu offers 150, 200 and 250 men. The 5 was dropped from two of them.
    ("6/S6054.DAT", "0x454DC", "|10|200|20|고민", "|150|200|250|고민"),

    # 600, not 200. My own number scan missed it: it compares digits and 이백 is
    # neither a digit nor in the native-numeral list.
    ("F/SF021.DAT", "0x4813E",
     "바람의 정령: 그렇다. 봉인된 이백 년 동안 줄곧 인간들이 서로 죽이는 가운데서 오가고 있었지.",
     "바람의 정령: 그렇다. 봉인된 600년 동안 줄곧 인간들이 서로 죽이는 가운데서 오가고 있었지."),

    # The whole sentence was lost; only its first syllable survived.
    ("B/SB041.DAT", "0x47AAA", "자", "자, 각자 맡은 역할을 다하도록 해라."),

    # ぼく is the child speaking of himself, which 휴 throws away.
    ("4/S4041.DAT", "0x479A4", "휴 지쳤어", "나, 이제 지쳤어."),

    # に marks where the spirit is, not who it goes to. The name keeps its ヌ: 누.
    ("4/S4033.DAT", "0x47CDC",
     "다음 정령은 그레이시누에게. 읽으시겠습니까?|읽는다|읽지 않는다",
     "다음 정령은 그레이시누에 있다. 읽으시겠습니까?|읽는다|읽지 않는다"),

    # もう一度 is "once more", not "some day".
    ("1/S1041.DAT", "0x48058",
     "산의 정령: 그렇습니다. 하지만 당신은 언젠가 다시 불을 끄러 오게 됩니다.",
     "산의 정령: 그렇습니다. 하지만 당신은 다시 한 번 불을 끄러 오게 됩니다."),
    ("1/S1041.DAT", "0x480F6",
     "산의 정령: 그것이 당신의 운명이기 때문입니다.",
     "산의 정령: 그것이 당신의 운명입니다."),

    ("21/S2041.DAT", "0x47EFE",
     "에리어 MAP을 열까요?|연다|열지 않는다",
     "에어리어 맵을 열까요?|연다|열지 않는다"),

    ("B/SB072.DAT", "0x481FE", "다들 그만두!", "다들 그만둬!"),

    # 그만두 is not an imperative; やめろ、やめないか is two of them.
    ("21/S2013.DAT", "0x47B9A",
     ("병사: 이봐! 그만두, 그만두지 못해!!",
      "병사: 이봐! 그만두, 그만두지 못해！！"),
     "병사: 이봐! 그만둬, 그만두지 못하겠나!!"),

    # 2026-08-30 runtime screenshot review: remove literal-Japanese phrasing in
    # four Grayshine lines.  The selected revisions intentionally stay within
    # V349's proven 16px Hanme glyph inventory.  The initial variants needed
    # 휴/눠/좇/얘; the only static zero-use direct-code candidates found for four
    # extra glyphs were 741..743/746, but those planes are runtime-owned, so the
    # variants were revised instead of repurposing those slots.
    ("5/S5024.DAT", "0x478E8",
     ("무슨 말을 하는 거야. 이야기가 진행되지 않잖아.",
      "뭔 소리야? 이래선 말이 안 되잖아."),
     "뭔 소리야? 이래선 말이 안 되잖아."),
    ("5/S5052.DAT", "0x47A90",
     ("아니, 살았다 살았어. 고맙다고 하겠어.",
      "아니, 살았다 살았어. 고마워하겠어.",
      "이야, 덕분에 살았군. 고맙다."),
     "이야, 덕분에 살았군. 고맙다."),
    ("5/S5052.DAT", "0x47ADA",
     ("고맙다는 말은 하겠지만 보물은 나누지 않을 거야. 말만 하는 건 공짜니까.",
      "고맙다는 말은 하겠지만 보물은 나누지 않을 거야. 말만 하는 건 돈이 안 드니까.",
      "고맙다고는 해 주지. 하지만 보물은 나누지 않을 거야. 말이야 공짜니까."),
     "고맙다고는 해 주지. 하지만 보물은 나누지 않을 거야. 말이야 공짜니까."),
    ("5/S5052.DAT", "0x47B28",
     ("요슈아: 사람은 욕망을 위해서만 사는 것이 아니다.",
      "요슈아: 사람은 욕망만 따라 사는 게 아니다."),
     "요슈아: 사람은 욕망만 따라 사는 게 아니다."),
]

# (japanese must contain, japanese must NOT contain, before, after)
SUBSTITUTIONS = [
    ("兄", "兄貴", "형님", "형"),

    # Numbers. These are not slips of the pen: the source table was decoded wrongly
    # until it was regenerated today, and 150 -> 10 and 250 -> 20 show a digit being
    # dropped rather than a figure being misjudged. Each guide line is duplicated
    # across six or seven scene files, so one entry repairs all of them.
    ("召喚獣は全部で6", None, "전부 합쳐 둘까지", "전부 합쳐 여섯까지"),
    # Digits, not 여덟 and 일곱: 덟 and 곱 have no glyph and the table is full. The
    # Japanese writes these as digits too, so nothing is lost. Each pair below accepts
    # either the original wording or the interim one, so a rerun lands in one place.
    ("楽器は、全部で8つ", None, "전부 여섯 개", "전부 8개"),
    ("楽器は、全部で8つ", None, "전부 여덟 개", "전부 8개"),
    # 兵隊 is Poco himself becoming a strong soldier, not a unit.
    ("楽器は、全部で8つ", None, "상당히 강한 부대가 될 수 있겠군요",
     "상당히 강한 병사가 될 수 있겠군요"),
    ("7人の戦士", None, "네 명의 전사", "7인의 전사"),
    ("7人の戦士", None, "일곱 전사", "7인의 전사"),
    ("7人そろ", None, "전사 네 명이", "전사 7명이"),
    ("7人そろ", None, "전사 일곱 명이", "전사 7명이"),
    ("6度目の挑戦", None, "두 번째 도전", "여섯 번째 도전"),
    ("7度目の挑戦", None, "네 번째 도전", "7번째 도전"),
    ("7度目の挑戦", None, "일곱 번째 도전", "7번째 도전"),
    ("8度目の挑戦", None, "여섯 번째 도전", "8번째 도전"),
    ("8度目の挑戦", None, "여덟 번째 도전", "8번째 도전"),
    ("80回目の勝利", None, "60번째 승리", "80번째 승리"),
    ("160回目の勝利", None, "120번째 승리", "160번째 승리"),

    # 勇者 -> 용사, the ordinary Korean word for this in JRPG. It also means the UI
    # has to follow: it ships 용자 today, and a split between the item window and the
    # dialogue would be worse than either choice.
    ("勇者", None, "용자", "용사"),
    # スメリア and ミルマーナ take the guidebook's straight transliteration. パレンシア
    # and チョンガラ do not: there the guidebook stands alone against both this
    # translation and an independent one, so 팔렌시아 and 촌가라 stay.
    ("スメリア", None, "수메리아", "스메리아"),
    ("ミルマーナ", None, "밀마나", "미르마나"),
    # 始動 is "commence", not a machine starting. All four occurrences sit immediately
    # before a battle.
    ("始動", None, "시동", "시작"),

    # The source has モンスター 138 times and 魔物 not once, so 마물 is the
    # translator's invention and the two read as different creatures.
    ("モンスター", None, "마물", "몬스터"),
    # 僧 alone is not a Korean word for a monk.
    ("ラマダ僧", None, "라마다 승:", "라마다 승려:"),
    ("アークデーモン", None, "아크데몬", "아크 데몬"),
    # Glyph index 179 was mapped to the katakana ベ on a guess from context. Its bitmap
    # is a 53-pixel kanji with a 心 radical: it is 恵. So the spirit is 恵みの精霊,
    # a spirit of blessing, and 베미 was never a name.
    ("恵みの精霊", None, "베미의 정령", "은혜의 정령"),
    ("恵みの精霊", None, "베미의정령", "은혜의 정령"),

    # From a reader's full review, the items that hold up against the source.
    # 何が知りたい takes が in Japanese and 을 in Korean; 무엇이 is ungrammatical here.
    ("何が知りたい", None, "무엇이 알고", "무엇을 알고"),
    # The name is written ロクトール with the long mark; a key without it misses it.
    ("ロクトール", None, "록토르", "로크톨"),
    # The game writes this spirit both 地の精霊 and 土の精霊; one name in Korean.
    ("地の精霊", None, "땅의 정령", "대지의 정령"),
    ("土の精霊", None, "땅의 정령", "대지의 정령"),
    ("パレンシア城", None, "팔렌시아성", "팔렌시아 성"),
    ("5大精霊", None, "오대 정령", "5대 정령"),
    # 軍オフィス is a military headquarters; 오피스 reads as a modern office block.
    ("軍オフィス", None, "군 오피스", "군 본부"),
]

# Applied to every Korean cell: Japanese typography that came across with the text.
PUNCTUATION = [("・・・", "..."), ("・・", ".."), ("··。", "..."), ("··", ".."),
               ("。", "."), ("！", "!"), ("？", "?"), ("，", ","), ("、", ",")]


SPEAKER_GAP = re.compile(r"^([^:：|]{1,10}): (?=\S)")


def tighten_speaker(text: str) -> str:
    """Drop the space after a speaker's colon.

    The colon's ink sits dead centre of its 12-pixel cell, so it already carries five
    blank columns on its right. The text space adds a further twelve, which is why the
    label reads as `야군 :  다만` on screen. Removing it leaves about six pixels either
    side, and costs one byte less per line, which the lines that are over budget need.

    Only the label is touched: the pattern is anchored to the start of the line, so a
    colon inside a sentence keeps its spacing.
    """
    return SPEAKER_GAP.sub(lambda m: m.group(1) + ":", text, count=1)


def main() -> None:
    with TABLE.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        rows = list(reader)

    log: list[str] = ["wording fixes applied", ""]
    changed = 0

    for name, offset, expect, replacement in REWRITES:
        hit = [r for r in rows if r["source file"] == name and r["offset"] == offset]
        if len(hit) != 1:
            raise SystemExit(f"{name} {offset}: {len(hit)} rows match, expected 1")
        current = (hit[0]["korean"] or "").strip()
        accepted = (expect,) if isinstance(expect, str) else tuple(expect)
        # The speaker-gap step runs after these rewrites, so on a second run the cell
        # is already tightened while the wording here still carries its space. Compare
        # both sides in the tightened form; the replacement keeps its space and the
        # later step removes it again, so one run and ten runs land in the same place.
        same = {tighten_speaker(x) for x in accepted}
        if tighten_speaker(current) == tighten_speaker(replacement):
            log.append(f"  already done   {name} {offset}")
            continue
        if tighten_speaker(current) not in same:
            raise SystemExit(f"{name} {offset}: text is not what this edit expects\n"
                             f"  found    {current}\n"
                             f"  expected {' | '.join(accepted)}")
        hit[0]["korean"] = replacement
        changed += 1
        log += [f"  reworded       {name} {offset}",
                f"    from  {expect}", f"    to    {replacement}"]

    for needs, forbids, before, after in SUBSTITUTIONS:
        log += ["", f"  {before} -> {after}   where the Japanese has {needs}"
                    + (f" but not {forbids}" if forbids else "")]
        skipped = 0
        for row in rows:
            japanese = CTRL.sub("", row.get("japanese") or "")
            korean = row.get("korean") or ""
            if needs not in japanese or before not in korean:
                continue
            if forbids and forbids in japanese:
                skipped += 1
                log.append(f"    kept       {row['source file']} {row['offset']}  "
                           f"{korean[:44]}")
                continue
            row["korean"] = korean.replace(before, after)
            changed += 1
            log.append(f"    changed    {row['source file']} {row['offset']}  "
                       f"{row['korean'][:44]}")
        if skipped:
            log.append(f"    {skipped} line(s) deliberately left alone")

    log += ["", "  Japanese typography -> Korean"]
    punct = 0
    for row in rows:
        korean = row.get("korean") or ""
        fixed = korean
        for before, after in PUNCTUATION:
            fixed = fixed.replace(before, after)
        if fixed != korean:
            row["korean"] = fixed
            punct += 1
    changed += punct
    log.append(f"    {punct} line(s) cleaned")

    if not changed:
        log.append("")
        log.append("nothing to do; every edit was already applied")
    else:
        shutil.copy2(TABLE, TABLE.with_suffix(".csv.bak"))
        with TABLE.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    korean = sum(1 for r in rows if any("가" <= c <= "힣" for c in (r.get("korean") or "")))
    log += ["", f"cells changed          {changed}",
            f"rows with Korean       {korean}   (must stay 2650)",
            f"backup                 {TABLE.name}.bak"]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(log) + "\n", encoding="utf-8")
    # The log carries Japanese, which a cp949 console cannot encode; the file has it.
    print(f"{changed} cells changed; {korean} rows with Korean. See {REPORT.name}")


if __name__ == "__main__":
    main()
