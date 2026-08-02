"""Export the translation for reading, arranged so tone problems are visible.

Reading 2,650 lines in file order does not show that a character speaks politely in
one scene and bluntly in the next, because the two lines are hundreds of rows apart.
So this writes the same corpus twice: once in story order for reading through, and
once grouped by speaker so a character's whole voice sits together.

Speech level is guessed from the sentence ending, which is enough to flag a speaker
worth looking at and not enough to judge a line. The flag says "these lines disagree",
never "this line is wrong" -- a character may switch register deliberately, and only a
reader can tell that from a slip.
"""
from __future__ import annotations

import csv
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRANSLATED = ROOT / "05_docs/script_translated_full.csv"
BY_STORY = ROOT / "05_docs/review_translation_by_story.csv"
BY_SPEAKER = ROOT / "05_docs/review_translation_by_speaker.csv"
REPORT = ROOT / "01_work/analysis/translation_review.txt"

# Endings that settle the register. Longest first: 합니다 must win over 다.
POLITE = ("습니다", "ㅂ니다", "습니까", "십시오", "세요", "예요", "에요", "어요",
          "아요", "이요", "지요", "네요", "군요", "나요", "까요", "죠", "요")
PLAIN = ("는다", "ㄴ다", "겠다", "이다", "았다", "었다", "한다", "온다", "간다",
         "구나", "는걸", "잖아", "거야", "야", "어", "아", "지", "네", "군", "자",
         "라", "니", "냐", "다")

SPEAKER = re.compile(r"^\s*([^:：|]{1,10})\s*[:：]\s*")


def speaker_of(text: str) -> str:
    m = SPEAKER.match(text)
    return m.group(1).strip() if m else ""


def body_of(text: str) -> str:
    m = SPEAKER.match(text)
    return text[m.end():] if m else text


def register(text: str) -> str:
    """polite / plain / '' -- judged on the last sentence that ends in a verb."""
    parts = [p for p in re.split(r"[.!?…\|]+", body_of(text)) if p.strip()]
    for part in reversed(parts):
        tail = part.strip().rstrip("\"')」』.…~-")
        if not tail:
            continue
        for ending in POLITE:
            if tail.endswith(ending):
                return "polite"
        for ending in PLAIN:
            if tail.endswith(ending):
                return "plain"
    return ""


def main() -> None:
    with TRANSLATED.open(encoding="utf-8-sig", newline="") as handle:
        rows = [r for r in csv.DictReader(handle)
                if any("가" <= c <= "힣" for c in (r.get("korean") or ""))]

    records = []
    for row in rows:
        korean = (row["korean"] or "").strip()
        records.append({
            "file": row["source file"],
            "offset": row["offset"],
            "speaker": speaker_of(korean),
            "register": register(korean),
            "japanese": (row["japanese"] or "").strip(),
            "korean": korean,
        })

    levels: dict[str, Counter] = defaultdict(Counter)
    for r in records:
        if r["speaker"] and r["register"]:
            levels[r["speaker"]][r["register"]] += 1
    mixed = {s: c for s, c in levels.items() if len(c) > 1 and sum(c.values()) >= 3}

    for r in records:
        c = levels.get(r["speaker"])
        r["mixed_register"] = "MIXED" if r["speaker"] in mixed else ""
        r["speaker_lines"] = sum(c.values()) if c else ""

    fields = ["file", "offset", "speaker", "register", "mixed_register",
              "speaker_lines", "japanese", "korean"]

    def dump(path: Path, ordered):
        with path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(ordered)

    dump(BY_STORY, sorted(records, key=lambda r: (r["file"], int(r["offset"], 0))))
    dump(BY_SPEAKER, sorted(
        records,
        key=lambda r: (r["speaker"] == "", r["speaker"], r["file"],
                       int(r["offset"], 0))))

    named = sum(1 for r in records if r["speaker"])
    lines = [
        "translation review export",
        "",
        f"lines exported            {len(records)}",
        f"  with a speaker label    {named}",
        f"  without                 {len(records) - named}",
        f"distinct speakers         {len(levels)}",
        f"speakers mixing register  {len(mixed)}   <- worth reading first",
        "",
        "Register is guessed from the sentence ending. It is a flag, not a verdict:",
        "a character may change register on purpose, and only a reader can tell that",
        "from a slip.",
        "",
        "speakers whose lines disagree, most lines first:",
    ]
    for speaker, counts in sorted(mixed.items(), key=lambda kv: -sum(kv[1].values()))[:25]:
        total = sum(counts.values())
        lines.append(f"  {speaker:<12} {total:>4} lines   "
                     f"polite {counts.get('polite', 0):>3}  plain {counts.get('plain', 0):>3}")
    lines += [
        "",
        f"story order   {BY_STORY.relative_to(ROOT)}",
        f"by speaker    {BY_SPEAKER.relative_to(ROOT)}",
        "",
        "Both files carry the same rows and the same columns; only the order differs.",
        "Edit `05_docs/script_translated_full.csv`, not these -- they are exports.",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
