"""Find every line whose Korean states a different number from its Japanese.

Seven of these were reported by a reader. They are not scattered slips: the numbers
are wrong in a way that looks systematic, and the source table was regenerated only
today after glyph index 208 was found to have been decoded wrong since before the
translation was written. A translator working from a stale reading would copy whatever
digit the table showed.

So rather than fix the seven, this asks the whole corpus the same question. Numbers are
compared as values, not as text, so 7 matches 七 and 여섯 matches 6, and a line is only
reported when a value appears on one side and not the other.

It reads and reports. It changes nothing: a mismatch can be a legitimate choice, as
when a count is rephrased rather than stated.
"""
from __future__ import annotations

import csv
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TABLE = ROOT / "05_docs/script_translated_full.csv"
OUT = ROOT / "01_work/analysis/number_mismatch.csv"
REPORT = ROOT / "01_work/analysis/number_mismatch.txt"

CTRL = re.compile(r"<(?:CTRL|G):[^>]*>")

KANJI = {"一": 1, "二": 2, "三": 3, "四": 4, "五": 5, "六": 6,
         "七": 7, "八": 8, "九": 9, "十": 10}
NATIVE = {"하나": 1, "한": 1, "둘": 2, "두": 2, "셋": 3, "세": 3, "넷": 4, "네": 4,
          "다섯": 5, "여섯": 6, "일곱": 7, "여덟": 8, "아홉": 9, "열": 10}
SINO = {"일": 1, "이": 2, "삼": 3, "사": 4, "오": 5, "육": 6, "칠": 7, "팔": 8,
        "구": 9, "십": 10}
# 이, 사, 오 and 구 are ordinary words far more often than they are numerals, so the
# Sino set is only consulted when the syllable is immediately followed by a counter.
COUNTER = "명번째개인마리번차례"


def japanese_values(text: str) -> set[int]:
    out = {int(m) for m in re.findall(r"\d+", text)}
    out |= {KANJI[c] for c in text if c in KANJI}
    return out


def korean_values(text: str) -> set[int]:
    out = {int(m) for m in re.findall(r"\d+", text)}
    for word, value in NATIVE.items():
        if word in text:
            out.add(value)
    for i, ch in enumerate(text):
        if ch in SINO and i + 1 < len(text) and text[i + 1] in COUNTER:
            out.add(SINO[ch])
    return out


def main() -> None:
    with TABLE.open(encoding="utf-8-sig", newline="") as handle:
        rows = [r for r in csv.DictReader(handle)
                if any("가" <= c <= "힣" for c in (r.get("korean") or ""))]

    flagged = []
    for row in rows:
        japanese = CTRL.sub("", row.get("japanese") or "")
        korean = row.get("korean") or ""
        jp, kr = japanese_values(japanese), korean_values(korean)
        missing = jp - kr
        if not missing:
            continue
        flagged.append({
            "file": row["source file"], "offset": row["offset"],
            "japanese_numbers": " ".join(str(v) for v in sorted(jp)),
            "korean_numbers": " ".join(str(v) for v in sorted(kr)) or "-",
            "missing": " ".join(str(v) for v in sorted(missing)),
            "japanese": japanese.replace("\n", " / "),
            "korean": korean,
        })

    with OUT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(flagged[0]) if flagged else
                                ["file", "offset", "japanese_numbers", "korean_numbers",
                                 "missing", "japanese", "korean"])
        writer.writeheader()
        writer.writerows(flagged)

    both = [f for f in flagged if f["korean_numbers"] != "-"]
    lines = [
        "lines whose Korean does not carry a number its Japanese states",
        "",
        f"translated lines        {len(rows)}",
        f"flagged                 {len(flagged)}",
        f"  Korean states some other number instead   {len(both)}   <- read these first",
        f"  Korean states no number at all            {len(flagged) - len(both)}",
        "",
        "The second group is often fine: a count can be rephrased, or carried by a word",
        "this does not recognise. The first group is where a wrong figure hides, because",
        "the line does give a number and it is not the one the source gives.",
        "",
        "worst: Japanese says one thing, Korean says another",
        "",
    ]
    for f in both[:40]:
        lines.append(f"  {f['file']} {f['offset']}   JP {f['japanese_numbers']:<10}"
                     f" KR {f['korean_numbers']}")
        lines.append(f"      {f['korean'][:76]}")
    lines += ["", f"-> {OUT.relative_to(ROOT)}"]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{len(flagged)} flagged, {len(both)} of them state a different number. "
          f"See {REPORT.name}")


if __name__ == "__main__":
    main()
