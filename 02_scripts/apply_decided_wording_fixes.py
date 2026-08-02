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
    ("32/S3061.DAT", "0x481DE",
     "베미의 정령: 당신이 무엇을 하지 않으면 안 되는지는 당신이 정할 일입니다.",
     "베미의 정령: 무엇을 해야 하는지는 당신이 정할 일입니다."),
    ("32/S3062.DAT", "0x47D3A",
     "베미의 정령: 당신이 무엇을 하지 않으면 안 되는지는 당신이 정할 일입니다.",
     "베미의 정령: 무엇을 해야 하는지는 당신이 정할 일입니다."),

    # Yagun speaks politely to Arc's party, bluntly to his own soldiers, and in 하오체
    # when he is being a general at them. The 하오체 lines are the character and stay.
    # Only the flat 반말 among them is the slip, and it becomes 하오체 to match the
    # line beside it rather than 합쇼체, which would flatten him the other way.
    ("31/S3032.DAT", "0x479EE",
     ("야군: 다만 저곳은 우리도 애를 먹고 있는 장소다.",
      "야군: 다만 저곳은 우리도 애를 먹고 있는 곳입니다."),
     "야군: 다만 저곳은 우리도 애를 먹고 있는 곳이오."),
    ("31/S3032.DAT", "0x47A40",
     "야군: 만일 무슨 일이 있어도 우리는 책임지지 않겠습니다.",
     "야군: 만일 무슨 일이 있어도 우리는 책임을 지지 않겠소."),
    ("31/S3031.DAT", "0x4810A",
     "야군: 최근에는 이 근처에도 몬스터가 나타납니다.",
     "야군: 최근에는 이 근처에도 몬스터가 나타나오."),
]

# (japanese must contain, japanese must NOT contain, before, after)
SUBSTITUTIONS = [
    ("兄", "兄貴", "형님", "형"),
    ("勇者", None, "용사", "용자"),
    # スメリア and ミルマーナ take the guidebook's straight transliteration. パレンシア
    # and チョンガラ do not: there the guidebook stands alone against both this
    # translation and an independent one, so 팔렌시아 and 촌가라 stay.
    ("スメリア", None, "수메리아", "스메리아"),
    ("ミルマーナ", None, "밀마나", "미르마나"),
    # 始動 is "commence", not a machine starting. All four occurrences sit immediately
    # before a battle.
    ("始動", None, "시동", "시작"),
]


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

    log += ["", "  speaker label: dropping the space after the colon"]
    tightened = 0
    for row in rows:
        korean = row.get("korean") or ""
        fixed = tighten_speaker(korean)
        if fixed != korean:
            row["korean"] = fixed
            tightened += 1
    changed += tightened
    log.append(f"    {tightened} line(s) tightened")

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
