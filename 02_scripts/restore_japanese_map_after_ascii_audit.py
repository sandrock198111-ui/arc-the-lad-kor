"""Restore proven Japanese mappings erased by the broad ASCII-rule repair.

The ASCII audit correctly rejected ``index + 32`` for indices 26..94, but its
map rewrite also removed older manual/exact Japanese mappings.  A mapping is
restored only when the old atlas catalogue and every character occurrence in
the repaired source CSV agree.  Unresolved indices remain blank.
"""
from __future__ import annotations

import argparse
import csv
import io
import subprocess
from collections import Counter, defaultdict
from pathlib import Path

from repair_ascii_glyph_overreach import raw_events, tokens


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "05_docs"
MAP = DOCS / "japanese_font_index_map.csv"
ATLAS = ROOT / "01_work" / "analysis" / "story_corpus" / "japanese_glyph_map.csv"
BASELINE_REF = "291ba49"


def read_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        return reader.fieldnames or [], list(reader)


def baseline_source_rows() -> list[dict[str, str]]:
    data = subprocess.check_output(
        ["git", "show", f"{BASELINE_REF}:05_docs/script_original_full.csv"],
        cwd=ROOT,
    )
    return list(csv.DictReader(io.StringIO(data.decode("utf-8-sig"), newline="")))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    fields, map_rows = read_rows(MAP)
    source_rows = baseline_source_rows()
    _, atlas_rows = read_rows(ATLAS)
    current = {int(row["glyph index"]): row for row in map_rows}
    atlas = {
        int(row["index"]): row
        for row in atlas_rows
        if row["selected"] and row["match"] in {"manual", "exact"}
    }

    observed: dict[int, set[str]] = defaultdict(set)
    occurrences: Counter[int] = Counter()
    for row in source_rows:
        events = raw_events(bytes.fromhex(row["raw bytes as hex"]))
        visible = tokens(row["decoded Japanese"])
        if len(events) != len(visible):
            raise SystemExit(
                f"raw/text alignment failed at {row['source file']}:{row['byte offset']}"
            )
        for (kind, value), token in zip(events, visible):
            if kind != "glyph" or not isinstance(value, int) or len(token) != 1:
                continue
            observed[value].add(token)
            occurrences[value] += 1

    conflicts = {index: values for index, values in observed.items() if len(values) > 1}
    if conflicts:
        raise SystemExit(f"source mapping conflicts: {conflicts}")

    restored: list[tuple[int, str, int, str]] = []
    for index, values in sorted(observed.items()):
        if len(values) != 1 or current[index]["character"] or index not in atlas:
            continue
        character = next(iter(values))
        if atlas[index]["selected"] != character:
            raise SystemExit(
                f"atlas/source disagreement at {index}: "
                f"atlas={atlas[index]['selected']!r} source={character!r}"
            )
        restored.append((index, character, occurrences[index], atlas[index]["match"]))

    print(f"restorable_indices={len(restored)}")
    print("indices=" + ",".join(str(index) for index, _, _, _ in restored))
    for index, character, count, match in restored:
        print(f"  {index}={character} occurrences={count} atlas={match}")

    if not args.apply:
        print("dry run: no files written")
        return

    for index, character, count, match in restored:
        current[index]["character"] = character
        current[index]["how it was established"] = (
            f"restored {match} atlas mapping; repaired source occurrences={count}, conflicts=0"
        )
    with MAP.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(map_rows)
    print(f"wrote {MAP}")


if __name__ == "__main__":
    main()
