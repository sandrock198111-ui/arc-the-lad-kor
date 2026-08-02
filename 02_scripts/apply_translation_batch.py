"""Write one batch of translations into the master CSV, refusing anything unsafe.

The translation is applied by (source file, offset), never by row order. An earlier
pass lost work by rewriting the file from a partially built list, so nothing here
rebuilds the table: rows are matched, the Korean cell is filled, and every other cell
is left exactly as it was.

A batch is rejected whole rather than half-applied. The checks are:

  the key exists            a typo in a file name or offset would silently drop a line
  the row is still empty    refuses to overwrite a translation already in the file
  no leftover markup        <G:...>, <CTRL:...> and literal \\n must not survive; the
                            established convention for all 2,024 earlier rows is plain
                            flowing Korean with the speaker as "이름: "
  no Japanese characters    a kana or kanji left in the output means a line was copied
                            rather than translated

Usage:  python 02_scripts/apply_translation_batch.py batch.json
        where batch.json is [{"file": ..., "offset": ..., "ko": ...}, ...]
"""
from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = ROOT / "05_docs/script_translated_full.csv"

MARKUP = re.compile(r"<G:\d+>|<CTRL:[^>]*>|\\n")
JAPANESE = re.compile(r"[\u3040-\u30FF\u4E00-\u9FFF]")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: apply_translation_batch.py <batch.json>")
    batch = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))

    with CSV_PATH.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames
        rows = list(reader)
    index = {(r["source file"], r["offset"]): r for r in rows}

    problems: list[str] = []
    staged: list[tuple[dict, str]] = []
    for item in batch:
        key = (item["file"], str(item["offset"]))
        row = index.get(key)
        text = (item["ko"] or "").strip()
        if row is None:
            problems.append(f"no such row: {key}")
            continue
        if (row["korean"] or "").strip():
            problems.append(f"already translated, refusing to overwrite: {key}")
            continue
        if not text:
            problems.append(f"empty translation: {key}")
            continue
        leftover = MARKUP.findall(text)
        if leftover:
            problems.append(f"markup survived {key}: {leftover}")
            continue
        japanese = JAPANESE.findall(text)
        if japanese:
            problems.append(f"untranslated Japanese in {key}: {''.join(japanese)[:20]}")
            continue
        staged.append((row, text))

    if problems:
        print(f"batch rejected, {len(problems)} problems, nothing written")
        for line in problems[:25]:
            print(f"  {line}")
        raise SystemExit(1)

    for row, text in staged:
        row["korean"] = text
        row["source of the translation (existing / new)"] = "new"

    with CSV_PATH.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    done = sum(1 for r in rows if (r["korean"] or "").strip())
    remaining = sum(1 for r in rows
                    if not (r["korean"] or "").strip() and (r["japanese"] or "").strip())
    print(f"applied {len(staged)} rows")
    print(f"  translated {done} / {len(rows)}     remaining {remaining}")


if __name__ == "__main__":
    main()
