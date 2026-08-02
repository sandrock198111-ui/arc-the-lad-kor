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
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TABLE = ROOT / "05_docs/script_translated_full.csv"
REPORT = ROOT / "01_work/analysis/wording_fixes.txt"

# (file, offset, must contain, before -> after) -- a rewrite, not a global substitution
REWRITES = [
    ("22/S2055.DAT", "0x478F0",
     "국왕: 그러면 형이 네 아버지라고 정령이 말한 것이로군?",
     "국왕: 그러면 형이 네 아비라고, 정령이 말했다는 것이냐?"),
]

# (japanese must contain, japanese must NOT contain, before, after)
SUBSTITUTIONS = [
    ("兄", "兄貴", "형님", "형"),
    ("勇者", None, "용사", "용자"),
]


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
        if current == replacement:
            log.append(f"  already done   {name} {offset}")
            continue
        if current != expect:
            raise SystemExit(f"{name} {offset}: text is not what this edit expects\n"
                             f"  found    {current}\n  expected {expect}")
        hit[0]["korean"] = replacement
        changed += 1
        log += [f"  reworded       {name} {offset}",
                f"    from  {expect}", f"    to    {replacement}"]

    for needs, forbids, before, after in SUBSTITUTIONS:
        log += ["", f"  {before} -> {after}   where the Japanese has {needs}"
                    + (f" but not {forbids}" if forbids else "")]
        skipped = 0
        for row in rows:
            japanese = row.get("japanese") or ""
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
    print("\n".join(log))


if __name__ == "__main__":
    main()
