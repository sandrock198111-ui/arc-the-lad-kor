from __future__ import annotations

import csv
import re
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "01_work"
CORPUS = WORK / "analysis/story_corpus/story_corpus.csv"
PATCH = ROOT / "03_output/story_choice_layout_v20_cumulative_patch_only.zip"
CHARMAP = ROOT / "05_docs/korean_charmap_extended.csv"
OUTPUT = ROOT / "05_docs/story_all_choices_v21_translation.csv"

FILLER = 0x9C
LINEBREAK_BYTES = 2
MARKER_BYTES = 2


OPTION_TRANSLATIONS = {
    "はい": "예",
    "うん": "응",
    "うむ": "그래",
    "おう": "그래",
    "わしかい": "나인가",
    "いやじゃ": "아니다",
    "やる": "한다",
    "いく": "간다",
    "やめるわい": "그만둔다",
    "やつっりやだ": "싫어",
    "まちがえました": "아닙니다",
    "まちがえたぜ": "아니다",
    "やつっりやめる": "취소",
    "やつっりやめるか": "취소",
    "やつっりやめよう": "취소",
    "やつっり、いいや": "그만",
    "やつっりいいや": "그만",
    "やつっり、いいや。": "그만",
    "こうたいする": "변경",
    "こうたいしない": "유지",
    "出発する": "출발",
    "出発しない": "취소",
    "次のージ": "다음",
    "参加する": "출전",
    "参加しない": "취소",
    "ヤミ闘技場に参加する": "비밀 투기장",
    "やりなおす": "다시",
    "つづける": "계속",
    "とんでもない": "아니오",
    "まだです": "아직입니다",
    "ぜつたい勝てる！": "반드시 이긴다",
    "まだやり残したことが・": "아직 할 일이 있다",
    "よむ": "읽는다",
    "よまない": "읽지 않는다",
    "ベつにいい": "읽지 않는다",
    "よむのやめる": "그만 읽기",
    "強くなるためには": "강해지는 법",
    "作戦をたてるには": "작전 세우기",
    "敵からダメージを受けないためには1": "피해 감소 1",
    "敵からダメージを受けないためには2": "피해 감소 2",
    "うまく戦うには": "전투 요령",
    "いろいろ教えて！": "정보",
    "いろいろ教えて！ その2": "정보 2",
    "耳よりな話を聞きたい！": "유용한 정보",
    "耳よりな話": "유용한 정보",
    "バトルの心得 その2": "전투 요령 2",
    "どうすれば強くなれるの？": "강해지는 법",
    "何か戦いのニツはあるの？": "전투 요령",
    "他に何かある？": "다른 정보",
    "もちろん！": "물론이야",
    "ちょつと自信がないな・・": "자신이 없어",
    "まだ戦い方がわからないや": "전투를 더 배울래",
    "もうちょつといたいな・・": "조금 더 있을래",
    "いろいろ教えて欲しいんだけど": "더 알려 줘",
    "ベつにない": "괜찮아",
    "ちょつと教えてほしい": "하나만 더",
    "もちろん": "물론",
    "とうぜんだよ": "당연하지",
    "はじめて聞いた": "처음 들었어",
    "エリアをオーンしますか？": "지역을 열까요?",
    "オーンする": "연다",
    "オーンしない": "열지 않는다",
    "外に出る": "나간다",
    "アーク": "아크",
    "ククル": "쿠쿠루",
    "トッシュ": "토슈",
    "ポニ": "포코",
    "ーゲン": "마법사",
    "ー": "이가",
    "チョンラ": "초카라",
    "チョピン": "초핀",
    "チョン": "초비",
    "チョース": "초스케",
    "タトルロ": "다다",
    "へモジー": "헤모지",
    "ミルマーナ": "밀마나",
    "スメリア": "스메리아",
    "アララトス": "아라라토스",
    "カーデル": "카델",
    "オカモト": "오카모토",
    "ヤマモト": "야마모토",
    "ヤマオ": "야마오",
    "ヤマシタ": "야마시타",
    "ある": "있다",
    "ない": "없다",
    "作りたかつた": "만들고 싶었다",
    "行きたかつた": "가고 싶었다",
    "あれ": "저것",
    "それ": "그것",
    "どれ": "어느 것",
    "ないしょ": "비밀",
    "でる": "나온다",
    "でるかも": "나올지도",
    "でるのでは": "나올 것이다",
    "なやむ": "고민한다",
    "きいろ": "노란색",
    "わけあつてちゃいろ": "사정상 갈색",
    "本当はあか": "사실 빨강",
    "それはだれ？": "그건 누구?",
    "すごいアテム": "대단한 아이템",
    "こわれたアテム": "망가진 아이템",
    "つぶれたアテム": "찌그러진 아이템",
    "ねばねば": "끈적끈적",
    "さいきょうこうげき": "최강 공격",
    "ふつうこうげき": "보통 공격",
    "よわいこうげき": "약한 공격",
    "がいこつ": "해골",
    "よつっらい": "갑옷병",
    "あるまじろ": "아르마딜로",
    "ストーンサークル": "돌 고리",
    "リンの位置設定": "연결 위치",
    "召喚獣": "정령수",
    "召喚獣について": "정령수 정보",
    "ポニの楽器": "포코 악기",
    "闘技場": "투기장",
    "ートウール": "불꽃",
    "ラマダ寺の修行": "라마다 수행",
    "ラマダ寺での修行": "라마다 수행",
    "ロマンシンストーン": "로망의 돌",
    "アクセサリーきぬのおびへ": "장신구 비단",
    "アララトスの遺跡ダンジョン": "아라라토스 유적",
    "ミルマーナのその後": "밀마나의 이후",
    "モンスターとの相しょう": "몬스터 상성",
    "経験値について": "경험치",
    "成長のアトバス": "성장 조언",
    "アテム・アクセサリーの効果": "아이템 정보",
    "戦闘の方向と反撃": "방향과 반격",
    "ちからの実へ": "힘의 열매",
    "パロの実へ": "파로 열매",
    "いのちの木の実へ": "생명 열매",
    "魔力の泉へ": "마력",
    "みなぎる果実へ": "활력 열매",
    "大きい爆弾へ": "큰 폭약",
    "弱りの玉へ": "약화 구슬",
    "復活の薬へ": "부활약",
    "氷の守りへ": "한기",
    "炎の守りへ": "불꽃",
    "魔法のカートへ": "마법 카드",
    "しつうのバンダナへ": "바람",
    "パワーリストへ": "파워 팔찌",
    "パーフーツへ": "바이퍼 신발",
    "いやしのお守りへ": "치유 부적",
    "がらへ": "조가비",
    "スリースカートへ": "스리 치마",
    "アンチへモジーへ": "헤모지 방지",
    "鏡へ": "거울",
    "サンラスへ": "선글라스",
    "デールのへ": "디일의 집",
    "闘技場の倉庫の中身へ": "투기장 보관소",
    "幻のこてへ": "신비 장갑",
}


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def clean(text: str) -> str:
    text = re.sub(r"<[^>]+>", "", text)
    text = text.replace("”", "").replace("\r", " ").replace("\n", " ")
    text = re.sub(r"\s+", " ", text).strip(" /。")
    return text


def translate_option(source: str) -> str:
    if re.fullmatch(r"\d+人", source):
        return source[:-1] + "명"
    try:
        return OPTION_TRANSLATIONS[source]
    except KeyError as error:
        raise ValueError(f"untranslated option: {source!r}") from error


def translate_prompt(source: str, name: str, offset: int, dynamic_e2: bool) -> str:
    if dynamic_e2:
        return "맞나?"
    if not source:
        return ""
    exact = {
        "アークの母 父さんの置き手紙があるけどよむかい？": "어머니: 아버지의 편지를 읽을래?",
        "チョピン 何か私でお力になれるこはありますか？": "초핀: 더 도와드릴까요?",
        "兵士 出発なさいますか？": "출발할까요?",
        "エントリーをやりなおしますか": "처음부터?",
        "1回戦からやりなおしになります。よろしいですか？": "1회전부터?",
        "大会委員 参加なさいますか？": "출전할까요?",
        "大会委員 1回戦の準備はいいですか？": "1회전 준비?",
        "大会委員 2回戦の準備はいいですか？": "2회전 준비?",
        "大会委員 準決勝の準備はいいですか？": "준결승 준비?",
        "大会委員 決勝の準備はいいですか？": "결승 준비?",
        "大会委員 オーフ争奪戦の準備はいいですか？": "오브전 준비?",
        "大会委員 本当にいいんですか？": "정말 할까요?",
        "次の精霊はシーヌにへ よみますか？": "그레이시누 정령문?",
        "次の精霊はアリバーシャにへ よみますか？": "아리바 정령문?",
        "次の精霊はカーデルにへ よみますか？": "카델 정령문?",
        "最後の精霊はスメリアにへ よみますか？": "스메리아 정령문?",
        "攻撃": "",
        "防御": "",
        "どうする？": "",
        "それでもいいか？": "괜찮을까?",
        "いつでもいいぞ": "준비됐나?",
        "いくかね": "갈까?",
        "まかせなさい": "맡겨 두게",
        "ぬりゃーーー": "시작할까?",
        "んつ、どりゃーーー": "시작할까?",
        "痛いのやだな。でもやる？": "아파도 할까?",
        "わしゃヤだが、やるかね": "할까?",
    }
    if source in exact:
        return exact[source]
    if "こうたい" in source or "かわ" in source or source in {"む？", "うむ？", "わしか？", "わしかね？", "おれかい？", "おれのばんだな？", "おれだぜ、やつっり。", "く？", "くかな？", "くだね？", "くとかわる？"}:
        return "변경?"
    if "戦闘" in source or "戦いたい" in source or source in {"いいか？", "いいのかな？", "やつっりいく？", "やるぜ。もちろんいいよな", "やろうぜ"}:
        return "전투?"
    if source == "どうしようかね":
        return "할까?"
    raise ValueError(f"untranslated prompt: {name} 0x{offset:X} {source!r}")


def encoded_length(text: str, mapping: dict[str, bytes]) -> int:
    return sum(
        1 if char == " " or char.isascii() and char.isdigit() else len(mapping.get(char, b"??"))
        for char in text
    )


def main() -> None:
    mapping = {row["char"]: bytes.fromhex(row["code_hex"]) for row in rows(CHARMAP)}
    with zipfile.ZipFile(PATCH) as archive:
        patched = {name: archive.read(name) for name in archive.namelist()}

    planned: list[dict[str, object]] = []
    errors: list[str] = []
    for row in rows(CORPUS):
        if row["confidence"] != "high" or "<CTRL:E5>" not in row["decoded_jp"]:
            continue
        name = row["file"].replace("\\", "/")
        offset = int(row["payload_start"], 0)
        capacity = int(row["capacity"])
        original_file = (WORK / name).read_bytes()
        current_file = patched.get(name, original_file)
        original = original_file[offset:offset + capacity]
        current = current_file[offset:offset + capacity]
        original_markers = [
            original[position:position + 2]
            for position in range(len(original) - 1)
            if original[position] == 0xE5
        ]
        current_markers = [
            current[position:position + 2]
            for position in range(len(current) - 1)
            if current[position] == 0xE5
        ]
        preserve = current != original and current_markers == original_markers
        parts = row["decoded_jp"].split("<CTRL:E5>")
        prompt_source = clean(parts[0])
        option_sources = [clean(part) for part in parts[1:]]
        dynamic_e2 = b"\xE2" in original[: original.find(b"\xE5")]
        if (name, offset) in {
            ("7/S7025.DAT", 0x4840C),
            ("7/S7026.DAT", 0x4821E),
        }:
            prompt = "변경?"
            options = ["변경", "유지"]
        else:
            try:
                prompt = translate_prompt(prompt_source, name, offset, dynamic_e2)
                options = [translate_option(source) for source in option_sources]
            except ValueError as error:
                errors.append(str(error))
                continue
        option_overrides = {
            ("31/S3024.DAT", 0x47F68): ["아크", "쿠쿠루", "토슈"],
            ("31/S3024.DAT", 0x47FD2): ["망자", "갑옷", "아르마"],
            ("31/S3024.DAT", 0x48052): ["강공격", "일반", "약공격"],
            ("4/S4033.DAT", 0x485C8): ["당연", "처음"],
            ("4/S4033.DAT", 0x47CDC): ["읽기", "취소"],
            ("4/S4034.DAT", 0x47D30): ["읽기", "취소"],
            ("4/S4035.DAT", 0x47D30): ["읽기", "취소"],
            ("4/S4036.DAT", 0x47CDC): ["읽기", "취소"],
            ("6/S6054.DAT", 0x450F6): ["밀마", "스메", "아라라", "카델"],
            ("6/S6054.DAT", 0x451F4): ["아크", "쿠쿠루", "다다", "헤모"],
            ("6/S6054.DAT", 0x452F2): ["오카", "야모", "야오", "시타"],
            ("6/S6054.DAT", 0x453E6): ["예", "아마", "확실", "고민"],
            ("6/S6054.DAT", 0x454DC): ["10", "200", "20", "고민"],
            ("6/S6054.DAT", 0x455E0): ["있음", "없음", "제작", "여행"],
            ("6/S6054.DAT", 0x456DA): ["저", "그", "어", "비밀"],
            ("6/S6054.DAT", 0x457D4): ["20", "21", "22", "23"],
            ("6/S6054.DAT", 0x458CE): ["대단함", "고장", "찌그러진", "달라붙음"],
            ("6/S6054.DAT", 0x459CA): ["황금", "갈", "빨강", "누구?"],
            ("7/S7028.DAT", 0x48B70): ["승리", "나중에"],
        }
        if (name, offset) in option_overrides:
            options = option_overrides[(name, offset)]
        if dynamic_e2:
            options = ["예"] if len(options) == 1 else ["예", "아니오"]
        options = [option.replace("취소", "그만") for option in options]
        if (name, offset) == ("C1/SC081.DAT", 0x47030):
            prompt = "갈까"

        if preserve:
            payload_length: int | str = ""
            overflow: int | str = ""
            mode = "preserve_current"
        else:
            prompt_length = encoded_length(prompt, mapping)
            if dynamic_e2:
                prompt_length += 2
            payload_length = prompt_length
            if prompt:
                payload_length += LINEBREAK_BYTES
            payload_length += len(options) * MARKER_BYTES
            payload_length += sum(encoded_length(option, mapping) for option in options)
            payload_length += max(0, len(options) - 1) * LINEBREAK_BYTES
            overflow = max(0, payload_length - capacity)
            mode = "vertical_inline"
        planned.append(
            {
                "file": name,
                "offset": f"0x{offset:X}",
                "capacity": capacity,
                "mode": mode,
                "dynamic_e2": int(dynamic_e2),
                "marker_types": "|".join(marker.hex().upper() for marker in original_markers),
                "text": "|".join([prompt, *options]),
                "payload_length": payload_length,
                "overflow": overflow,
                "source": " / ".join(clean(part) for part in parts),
            }
        )

    if errors:
        raise SystemExit("\n".join(errors))
    fields = [
        "file", "offset", "capacity", "mode", "dynamic_e2", "marker_types",
        "text", "payload_length", "overflow", "source",
    ]
    with OUTPUT.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(planned)
    overflows = [row for row in planned if row["overflow"] not in {"", 0}]
    print(f"planned={len(planned)} preserve={sum(row['mode'] == 'preserve_current' for row in planned)}")
    print(f"overflows={len(overflows)}")
    for row in overflows:
        print(f"{row['file']} {row['offset']} {row['payload_length']}/{row['capacity']} {row['text']}")
    print(OUTPUT)


if __name__ == "__main__":
    main()
