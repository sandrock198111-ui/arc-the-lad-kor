"""v144: repair the "learned a skill" message.

On screen it read `2음의 문번 그라운드를 배웠다`. The message is built from three pieces,
and the game concatenates them: an opening fragment, the skill name, a closing fragment.

    0x82550  opening   original 0x82508, one byte 0x5B, which draws 「
    0x82554  closing   original 0x8250C, `」をおぼえた`, translated to `를 배웠다.`
    skill name from the table at 0x811C4, here 번 그라운드

Two separate faults, both visible in that one line:

1. The opening fragment was never extracted, so it was never translated and never
   relocated -- its pointer still holds the original address 0x82508. That address is
   no longer a string. The repack laid 죽음의 문 down at 0x82507, so the pointer now
   starts one byte into it: the second byte of 죽 is read as a one-byte code and draws
   some other glyph, then 음의 문 follows. That is the whole of `2음의 문`.

2. The closing fragment WAS translated, and the translation dropped the 」 that the
   Japanese `」をおぼえた` began with. So even with the opener restored the brackets
   would not have closed.

The item message is the same template and is intact, which is what makes this provable
rather than guessed: 0x82470 points at a live 0x5B and 0x82474 at `」를 손에 넣었습니다.`,
and the game draws 「거울」를 손에 넣었습니다. This build gives the skill message the same
two bracket glyphs, byte for byte, and checks that they render identically.

Nothing is written over. Both fragments are pointer-referenced, so the new bytes go into
the free space after the reserved block and the two pointers are rewritten -- the old
addresses are simply abandoned.

A third string is repaired with them, found by checking every relocated UI string
against the list that relocated it. 能力 -> 기량 (pointer 0x82638) was placed three
bytes in front of that same item message with no room for a terminator, so it reads
`기량」를 손에 넣었습니다.` -- the same kind of collision, caught by the other side of it.

Four more pointers are broken the same way and are NOT fixed here, because what they
should say is not known and this project does not repair pointers by guessing. They are
listed in the report and in 05_docs/codex_notes.txt.
"""
from __future__ import annotations

import hashlib
import pickle
import struct
import sys
import zipfile
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from plan_bulk_insertion import (  # noqa: E402
    CACHE, LOOKUP_N, LOOKUP_SRC, RAM_TO_FILE, bitmap, drawable, tokens,
)

BASE_ZIP = ROOT / "03_output/arc1_v143_mirumana_2FA1F130.zip"
BASE_SHA = "2FA1F1300CF9DC47B6B46E07BDE49EE207D66989EE5536CA6B397981D60E1036"
OUT_DIR, OUT_STEM = ROOT / "03_output", "arc1_v144_learn_message"
ANALYSIS = ROOT / "01_work/analysis/arc1_v144_learn_message"

ITEM_OPEN, ITEM_CLOSE = 0x82470, 0x82474      # the template that still works
SKILL_OPEN, SKILL_CLOSE = 0x82550, 0x82554    # the one being repaired
# 能力, unterminated. The earlier UI pass rendered it 기량, which is a paraphrase; the
# word is 능력, and it labels a column beside 대전 성적 and 勝 on the versus-record
# screen. It is being relocated anyway, so the new spelling costs nothing.
ABILITY, ABILITY_LEN, ABILITY_WAS, ABILITY_TEXT = 0x82638, 3, "기량", "능력"
POSSESSIVE, WIN = 0x82558, 0x82630        # 」の and 勝, both buried the same way
FREE_START, FREE_END = 0x8F3D8, 0x8F800


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system", "create_version",
                 "extract_version", "flag_bits", "volume", "internal_attr",
                 "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def main() -> None:
    if digest(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not v143")
    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}
    exe = bytearray(members["PSX.EXE"])
    font = members["COMM.IMG"]
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())

    def target(at: int) -> int:
        value = struct.unpack_from("<I", exe, at)[0]
        if not (RAM_TO_FILE <= value < RAM_TO_FILE + len(exe)):
            raise SystemExit(f"0x{at:X} is not a pointer")
        return value - RAM_TO_FILE

    def string_at(start: int) -> bytes:
        end = start
        while end < len(exe) and exe[end]:
            end += 1
        return bytes(exe[start:end])

    lut = struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP_SRC - RAM_TO_FILE)

    def index_of(token: bytes) -> int | None:
        if len(token) == 1:
            return token[0] - 1
        if 0xDD <= token[0] <= 0xE8:
            return (token[0] - 0xDD) * 255 + token[1] + 0xDB
        if token[0] in (0xE9, 0xEA):
            slot = (token[0] - 0xE9) * 254 + token[1] - 1
            return lut[slot] if 0 <= slot < LOOKUP_N else None
        return None

    def glyphs(payload: bytes) -> list[tuple[int, ...] | None]:
        out = []
        for token in tokens(payload):
            index = index_of(token)
            out.append(bitmap(bytes(exe), font, index)
                       if index is not None and drawable(bytes(exe), index) else None)
        return out

    def spell(payload: bytes) -> str:
        return "".join(shapes.get(g) or ("?" if g and any(g) else " ")
                       for g in glyphs(payload))

    item_open = string_at(target(ITEM_OPEN))
    item_close = string_at(target(ITEM_CLOSE))
    skill_close = string_at(target(SKILL_CLOSE))
    if len(item_open) != 1:
        raise SystemExit("the item message's opening fragment is not one byte")
    if item_close[:1] != item_close[:1].rjust(1, b"\0") or len(item_close) < 2:
        raise SystemExit("the item message's closing fragment is too short")
    if skill_close[:1] == item_close[:1]:
        raise SystemExit("the skill closer already starts with the closing bracket")

    opener = item_open                       # the same byte the item message opens with
    closer = item_close[:1] + skill_close    # its closing bracket, then 를 배웠다.

    # the brackets must be the same picture the item message draws, not merely the same
    # byte -- that is what makes this a repair and not a guess
    if glyphs(opener) != glyphs(item_open):
        raise SystemExit("the opening bracket does not draw what the item message draws")
    if glyphs(closer)[0] != glyphs(item_close)[0]:
        raise SystemExit("the closing bracket does not draw what the item message draws")
    if spell(closer)[1:] != spell(skill_close):
        raise SystemExit("prepending the bracket changed the rest of the sentence")

    # v143 already put three strings here. Start after the last one's terminator, not on
    # top of it: walking back over zeros lands on the terminator itself, which the first
    # attempt did, truncating 미르마나 군본부.
    last = FREE_END - 1
    while last >= FREE_START and exe[last] == 0:
        last -= 1
    cursor = FREE_START if last < FREE_START else last + 2
    if any(exe[cursor:FREE_END]):
        raise SystemExit("the tail of the free space is not empty")
    if cursor > FREE_START and exe[cursor - 1] != 0:
        raise SystemExit("the byte before the cursor is not a terminator")

    # 能力 was laid down three bytes in front of the item message's closing fragment, so
    # it never got a terminator and runs straight into it. Its length comes from the
    # relocation list, not from scanning for a zero that is not there. The old spelling
    # is checked before replacing it, so this stops rather than repairing the wrong bytes.
    ability_at = target(ABILITY)
    if spell(bytes(exe[ability_at:ability_at + ABILITY_LEN])) != ABILITY_WAS:
        raise SystemExit(f"0x{ABILITY:X} does not read as {ABILITY_WAS}")
    if exe[ability_at + ABILITY_LEN] == 0:
        raise SystemExit(f"0x{ABILITY:X} is already terminated; nothing to repair")

    # Two more of the buried fragments can be named without guessing.
    #
    # 0x82558 was `5A 1C`. 5A is the closing bracket -- the same byte both working
    # closers begin with, and the original `5A 2F 3B D2 46 1F` reads をお・えた after it,
    # which only parses as 」をおぼえた. 1C is の in 05_docs/japanese_charmap_manual.csv.
    # The fragments beside it in the table are 공격력이, 방어력이, 민첩성이 and 상승, so
    # the sentence it builds is 「이름」의 공격력이 N 상승. In Korean that fragment is 」의.
    #
    # 0x82630 was `D5`, 勝 in the same charmap, and it sits beside 대전 성적 and 能力 in
    # the versus-record screen. One syllable: 승.
    # Never spell a UI string with an 0xE2 lead. 0xE2 is the slot redirect in a script
    # body, and while nothing says the executable's own text drawer reads it that way,
    # nothing says it does not either -- and across the whole UI pool, 566 strings use an
    # 0xE0 lead and 2,139 use the 0xE9/0xEA lookup while not one uses 0xE2. 능 happens to
    # have exactly two spellings, 0xE2 0xB6 and 0xEA 0x27, so this matters for this build.
    # Order of preference: one byte, then the wide range without 0xE2, then the lookup.
    def safe_encode(text: str) -> bytes:
        out = bytearray()
        for char in text:
            for code in (c for c in codes_for(char) if c[0] != 0xE2):
                out += code
                break
            else:
                raise SystemExit(f"{char} has no code outside the 0xE2 range")
        return bytes(out)

    def codes_for(char: str) -> list[bytes]:
        found = []
        for code in range(0x01, 0xDD):
            if drawable(bytes(exe), code - 1) and \
                    shapes.get(bitmap(bytes(exe), font, code - 1)) == char:
                found.append(bytes((code,)))
        for lead in range(0xDD, 0xE9):
            for trail in range(0x01, 0xFF):
                index = (lead - 0xDD) * 255 + trail + 0xDB
                if drawable(bytes(exe), index) and \
                        shapes.get(bitmap(bytes(exe), font, index)) == char:
                    found.append(bytes((lead, trail)))
        for slot, index in enumerate(lut):
            if drawable(bytes(exe), index) and \
                    shapes.get(bitmap(bytes(exe), font, index)) == char:
                found.append(bytes((0xE9 + slot // 254, slot % 254 + 1)))
        return found

    extras = []
    for at, text, note in ((POSSESSIVE, "의", "」의"),
                           (WIN, "승", "승"),
                           (ABILITY, ABILITY_TEXT, f"{ABILITY_WAS} -> {ABILITY_TEXT}")):
        body = safe_encode(text)
        payload = (item_close[:1] + body) if at == POSSESSIVE else body
        if spell(payload) != (spell(item_close[:1]) + text if at == POSSESSIVE else text):
            raise SystemExit(f"0x{at:X} did not read back as intended")
        extras.append((at, payload, note))

    written = []
    for at, payload, label in ((SKILL_OPEN, opener, "여는 조각"),
                               (SKILL_CLOSE, closer, "닫는 조각"),
                               *extras):
        if cursor + len(payload) + 1 > FREE_END:
            raise SystemExit("ran out of room after the reserved block")
        was = target(at)
        exe[cursor:cursor + len(payload)] = payload
        exe[cursor + len(payload)] = 0
        struct.pack_into("<I", exe, at, cursor + RAM_TO_FILE)
        written.append((at, was, cursor, payload, label))
        cursor += len(payload) + 1

    before = members["PSX.EXE"]
    changed = [i for i in range(len(before)) if before[i] != exe[i]]
    allowed = set(range(FREE_START, cursor))
    allowed |= {a + k for a, _, _, _, _ in written for k in range(4)}
    if stray := [i for i in changed if i not in allowed]:
        raise SystemExit(f"{len(stray)} bytes changed outside the new text and its pointers")
    if len(exe) != len(before):
        raise SystemExit("PSX.EXE changed size")
    if target(ITEM_OPEN) != struct.unpack_from("<I", before, ITEM_OPEN)[0] - RAM_TO_FILE:
        raise SystemExit("the item message was disturbed")
    members["PSX.EXE"] = bytes(exe)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tmp = OUT_DIR / f"{OUT_STEM}_building.zip"
    with ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    with ZipFile(tmp) as check:
        if {i.filename: check.read(i.filename) for i in check.infolist()} != members:
            raise SystemExit("the archive did not read back as written")
    with ZipFile(BASE_ZIP) as base:
        differing = sorted(n for n in members if members[n] != base.read(n))
    if differing != ["PSX.EXE"]:
        raise SystemExit(f"members differing from v143: {differing}")

    stamp = digest(tmp.read_bytes())
    final = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    tmp.replace(final)
    (OUT_DIR / "LATEST.txt").write_text(
        f"ship this one\n  file    {final.name}\n  sha256  {stamp}\n", encoding="utf-8")

    name = string_at(0x81F9D)      # 번 그라운드, the skill in the report
    lines = [
        "v144 스킬 습득 메시지 복구",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {final.name}",
        f"        sha256 {stamp}",
        "",
        "화면에 나오던 것   2음의 문번 그라운드를 배웠다",
        f"고친 뒤            {spell(opener)}{spell(name)}{spell(closer)}",
        f"같은 틀인 아이템   {spell(item_open)}<아이템 이름>{spell(item_close)}",
        "",
        "repointed",
        *(f"  {label} 0x{at:X}: 0x{was:X} -> 0x{now:X}  {payload.hex(' ')}  {spell(payload)!r}"
          for at, was, now, payload, label in written),
        "",
        f"bytes changed  {len(changed)}: {sum(len(p) + 1 for *_, p, _ in written)} of new "
        f"text plus 4 per pointer",
        "",
        f"곁들여 고친 것   0x{ABILITY:X} 能力. 아이템 메시지 닫는 조각 세 바이트 앞에",
        f"                 놓여 종결자가 없었고, 그래서 '{ABILITY_WAS}{spell(item_close)}'로",
        f"                 읽혔다. 철자도 {ABILITY_WAS}에서 {ABILITY_TEXT}로 바로잡았다 --",
        f"                 能力은 그대로 능력이고 {ABILITY_WAS}은 의역이었다.",
        "",
        "두 가지 고장이 한 줄에 겹쳐 있었다",
        "  1. 여는 조각은 추출된 적이 없어 번역도 이전도 되지 않았고, 포인터가 원본 주소",
        "     0x82508을 그대로 들고 있었다. 그 자리는 이제 문자열이 아니다 -- 재배치가",
        "     0x82507에 죽음의 문을 놓아서, 포인터는 죽의 둘째 바이트부터 읽는다. 그 바이트가",
        "     한 바이트 코드로 해석되어 다른 글자를 그리고 뒤이어 음의 문이 따라온다.",
        "  2. 닫는 조각은 번역됐지만 원문 」をおぼえた 의 」가 번역에서 빠졌다.",
        "",
        "verified",
        "  base digest matches v143",
        "  두 괄호가 아이템 메시지가 그리는 것과 같은 바이트일 뿐 아니라 같은 그림인지",
        "    비트맵으로 대조했다 -- 이것이 추측이 아니라 복구인 근거",
        "  괄호를 앞에 붙여도 뒤 문장이 변하지 않음을 다시 디코드해 확인",
        "  아이템 메시지의 포인터는 건드리지 않았다",
        "  새 글자와 포인터 밖으로 바뀐 바이트 없음, PSX.EXE 크기 그대로",
        "  v143과 다른 멤버는 PSX.EXE 뿐",
        "",
        "여기서 고치지 않은 것 -- 같은 원인, 무슨 글자였는지 모름",
        "  0x82634 원본 2바이트 DD CB   지금 다이아몬드 더스트 한가운데",
        "      바로 앞이 勝, 바로 뒤가 能力인 대전 성적 화면이라 敗일 가능성이 크지만",
        "      DD CB는 문자표에 없다. 추측으로 포인터를 고치지 않는다는 규칙에 따라 남긴다.",
        "  0x8299C 원본 1바이트 BF, 몬스터 기술 이름표 [2]  지금 감싸기 한가운데라 '기'로 보임",
        "      문자표에 없고 주변으로도 좁혀지지 않는다.",
        "",
        "NOT verified here: a cold boot. Learn a spell and read the message.",
        "",
        "rollback: v143",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
