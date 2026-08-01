"""Build a conservative original-font index map from cleanly decoded source rows.

No bitmap recognition is performed here.  A mapping becomes an ``anchor`` only when
the previous source CSV contains a complete decode and its raw encoded character
unambiguously matches that decoded character.  All other atlas indices remain
explicitly unresolved until corpus or independently aligned Japanese-script evidence
is added.
"""
from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "05_docs"
SOURCE = DOCS / "script_original_full.csv"
OLD_MAP = ROOT / "01_work/analysis/story_corpus/japanese_glyph_map.csv"
OUT = DOCS / "japanese_font_index_map.csv"

# Each entry is established by two or more ordinary dialogue records whose
# independent Japanese contexts require the same character.  Control-bearing or
# binary-looking candidates are intentionally absent.
CORPUS_PROVEN = {
    21: ("5", "5つ / 5つの石 / あと5つ"),
    22: ("2", "2度目 / 120回目 / 200年"),
    23: ("4", "4人の戦士 / 4人そろつた / 4度目"),
    24: ("6", "全部で6つ"),
    100: ("イ", "ヨッパライ / スパイ"),
    110: ("レ", "パレンシア城 / パレンシアの都"),
    127: ("グ", "ヤグン将軍 / ヤグンつて将軍"),
    191: ("え", "うげええ / 終つてねえぞ / だらしないねえ"),
    209: ("ぼ", "僕ら / 落ちこぼれ / 僕を"),
    221: ("ガ", "チョンガラ / トン・ガバ"),
    223: ("ゆ", "ゆつくり / ゆるす / ゆたかな"),
    225: ("々", "我々 / 方々"),
    279: ("ゴ", "ゴーゲンさん / ゴーゲン様"),
    280: ("ざ", "罪人（ざいにん） / ございます"),
    282: ("与", "力を与えます / ダメージを与える"),
    288: ("ふ", "きくのふり / ふつふつ"),
    291: ("忘", "忘れない / 忘れた / 存在を忘れ"),
    304: ("プ", "マップ"),
    328: ("ケ", "トヨーケの森"),
    380: ("ボ", "シンボル / ボリューム"),
    381: ("ハ", "ハンサム"),
    396: ("か", "かかわらない / かかる"),
    400: ("キ", "キャッキャッ"),
    401: ("ベ", "カベが / カベを"),
    402: ("ぐ", "すぐ / ぐつ"),
    405: ("悲", "悲しいこと / 大変悲しいお知らせ"),
    417: ("リ", "リエちゃん"),
    419: ("ザ", "アークザラッド"),
    463: ("議", "不思議な力 / 不思議な力をもつ太鼓"),
    475: ("娘", "小娘"),
    485: ("船", "飛行船"),
    493: ("口", "出口 / 入り口"),
    505: ("供", "子供"),
    506: ("ゅ", "基本中の基本"),
    507: ("牢", "牢屋 / 地下牢 / 牢をやぶり"),
    511: ("夜", "今夜 / あの夜会つた"),
    514: ("武", "武器 / 武闘大会"),
    528: ("邪", "邪魔 / 邪悪"),
    546: ("感", "力を感じる"),
    550: ("遠", "遠いところ"),
    564: ("底", "底力"),
    567: ("怒", "神の怒り"),
    568: ("帰", "帰つてこれなく / 天界に帰り"),
    573: ("退", "退治 / モンスター退治"),
    585: ("示", "示すもの"),
    595: ("認", "認めし者"),
    599: ("街", "街の中 / 街を作り"),
    610: ("連", "連れずついて来て"),
    621: ("匠", "師匠"),
    644: ("建", "建物"),
    645: ("警", "警告"),
    648: ("使", "動力石を使つて"),
    656: ("い", "やさしいのう / そうかい / 来たんかい"),
    722: ("怪", "怪しいと思う / 何か怪しい"),
    729: ("ホ", "ホント助かつた"),
    746: ("腹", "腹が出た将軍"),
    764: ("状", "状態の続いている"),
    767: ("つ", "あと一つ"),
    787: ("芽", "芽が立たず"),
    788: ("志", "意志"),
    814: ("栄", "文明を築き栄える"),
    218: ("テ", "アイテム / アイテム投げ"),
    297: ("キ", "ガキか"),
    311: ("切", "たたき切る / ぶつた切つて"),
    379: ("ワ", "パレンシアタワー"),
    385: ("防", "滅亡を防ぐ"),
    392: ("ご", "ご案内する"),
    397: ("階", "地下牢はこの下の階"),
    399: ("ベ", "レベル"),
    418: ("ヌ", "グレイシーヌ / フヌケ"),
    462: ("苦", "悲しみ、苦しみ"),
    495: ("劇", "悲劇"),
    504: ("ビ", "サービス"),
    510: ("流", "涙を流した"),
    513: ("動", "始動した / 始動しろ"),
    522: ("ひ", "ひどい目"),
    556: ("令", "ご命令どおり"),
    577: ("専", "国王専用飛行船"),
    584: ("獣", "召喚獣"),
    606: ("和", "調和のとれた国"),
    612: ("遊", "子供の遊び場 / もて遊び"),
    613: ("言", "何言つてんだ"),
    623: ("突", "突き進む / 強行突破"),
    634: ("深", "地下深く"),
    638: ("謝", "感謝しなくちゃ"),
    658: ("理", "理解を得る"),
    673: ("負", "お主達に負けてみよう"),
    686: ("絶", "絶望 / 絶対"),
    690: ("申", "アークと申したな / 申し訳が立たない"),
    698: ("執", "執着した心"),
    701: ("採", "採掘場 / 採掘"),
    750: ("欲", "欲しさゆえ"),
    753: ("馬", "じゃじゃ馬娘"),
    773: ("責", "責任をもちません"),
    782: ("除", "大掃除"),
    786: ("識", "意識を取り戻した"),
    793: ("婚", "結婚させられる"),
    810: ("械", "機械を動かす"),
    812: ("価", "価値もない"),
    816: ("敵", "敵のスメリアの戦士"),
    474: ("先", "この先から"),
    554: ("労", "ご苦労"),
    620: ("標", "道標（みちしるべ）"),
    670: ("届", "手紙が届く"),
    684: ("層", "階層が深い"),
    731: ("ゾ", "ゾンビ"),
}


def raw_indices(raw_hex: str):
    data = bytes.fromhex(raw_hex)
    pos = 0
    while pos < len(data):
        if data[pos:pos + 2] in (b"\xE6\x01", b"\xE4\x1F"):
            pos += 2
            continue
        first = data[pos]
        if 1 <= first < 0xDD:
            yield first - 1
            pos += 1
        elif 0xDD <= first <= 0xE0 and pos + 1 < len(data):
            yield (first - 0xDD) * 255 + data[pos + 1] + 0xDB
            pos += 2
        else:
            # Unknown opcodes, including E4 with a non-1F parameter, cannot be
            # silently treated as font indices.
            pos += 1


def main() -> None:
    known = {
        int(row["index"]): row["selected"]
        for row in csv.DictReader(OLD_MAP.open(encoding="utf-8-sig", newline=""))
        if row["selected"]
    }
    pairs: dict[int, set[str]] = defaultdict(set)
    source_rows = list(csv.DictReader(SOURCE.open(encoding="utf-8-sig", newline="")))
    clean = [row for row in source_rows if "<G:" not in row["decoded Japanese"] and "<CTRL:" not in row["decoded Japanese"]]
    for row in clean:
        for index in raw_indices(row["raw bytes as hex"]):
            if index in known:
                pairs[index].add(known[index])
    conflicts = {index: values for index, values in pairs.items() if len(values) != 1}
    if conflicts:
        raise SystemExit(f"anchor contradiction: {conflicts}")
    # Once a corpus entry makes a row complete, the next pass will naturally see
    # it in that clean row.  Preserve its stronger, explicit corpus provenance
    # instead of reclassifying it as an anchor.
    for index in set(pairs) & set(CORPUS_PROVEN):
        pairs.pop(index)

    with OUT.open("w", encoding="utf-8-sig", newline="") as handle:
        fields = ["glyph index", "character", "how it was established"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for index in range(1240):
            if index in pairs:
                writer.writerow({"glyph index": index, "character": next(iter(pairs[index])), "how it was established": "anchor: appears in a completely decoded corpus string"})
            elif index in CORPUS_PROVEN:
                char, evidence = CORPUS_PROVEN[index]
                writer.writerow({"glyph index": index, "character": char, "how it was established": f"corpus: independent contexts {evidence}"})
            else:
                writer.writerow({"glyph index": index, "character": "", "how it was established": "unresolved: no clean-string, corpus, or unambiguous external-Japanese-script proof"})
    print(f"clean_strings={len(clean)} anchor_indices={len(pairs)} corpus_indices={len(CORPUS_PROVEN)} unresolved_indices={1240-len(pairs)-len(CORPUS_PROVEN)}")


if __name__ == "__main__":
    main()
