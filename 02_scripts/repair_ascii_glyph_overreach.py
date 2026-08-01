"""Repair the unsupported 0..94 ASCII glyph expansion without guessing Japanese.

``2109797`` applied ``index = character code - 32`` to every unresolved atlas
index from 0 through 94.  The original COMM.IMG contact sheet proves only
0..25: index 0 is the blank ASCII space and 1..25 are ``!`` through ``9``.
Indices 26..94 are Japanese/non-ASCII shapes.

The source table itself was first added in ``2109797``, so it has no earlier
Git snapshot.  Its retained raw bytes are therefore the authority: an index in
26..94 is restored only when that raw glyph currently displays exactly as the
unsupported ASCII candidate.  The task-start HEAD snapshot is the authority for
existing Korean text.  This makes the repair reversible and ensures that text
cleared by the earlier mistaken repair is restored exactly, not retranslated.
"""
from __future__ import annotations

import argparse
import csv
import io
import re
import subprocess
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "05_docs"
SOURCE = DOCS / "script_original_full.csv"
TRANSLATED = DOCS / "script_translated_full.csv"
MAP = DOCS / "japanese_font_index_map.csv"
AUDIT = DOCS / "ascii_glyph_rule_audit.csv"
REPORT = DOCS / "ascii_glyph_rule_repair_report.md"

# The pre-2109797 tree has no script_original_full.csv.  HEAD supplies the
# task-start table; raw bytes plus the original COMM.IMG audit constrain every
# source correction below.
TASK_START_COMMIT = "HEAD"
VALID_ASCII = frozenset(range(0, 26))
REJECTED_ASCII = frozenset(range(26, 95))
TOKEN_RE = re.compile(r"<(?:CTRL:[0-9A-F]{2}|G:\d+)>|\n|\f|.", re.S)


def git_text(revision: str, path: Path) -> str:
    relative = path.relative_to(ROOT).as_posix()
    return subprocess.check_output(
        ["git", "show", f"{revision}:{relative}"], cwd=ROOT
    ).decode("utf-8-sig")


def git_revision(revision: str) -> str:
    return subprocess.check_output(["git", "rev-parse", revision], cwd=ROOT).decode().strip()


def read_csv_text(text: str) -> tuple[list[str], list[dict[str, str]]]:
    reader = csv.DictReader(io.StringIO(text))
    return reader.fieldnames or [], list(reader)


def read_git_csv(revision: str, path: Path) -> tuple[list[str], list[dict[str, str]]]:
    return read_csv_text(git_text(revision, path))


def read_disk_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        return reader.fieldnames or [], list(reader)


def write_rows(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def source_key(row: dict[str, str]) -> tuple[str, str]:
    return row["source file"], row["byte offset"]


def translated_key(row: dict[str, str]) -> tuple[str, str]:
    return row["source file"], row["offset"]


def raw_events(raw: bytes) -> list[tuple[str, int | str]]:
    """One event per token emitted by the established story-corpus decoder."""
    events: list[tuple[str, int | str]] = []
    pos = 0
    while pos < len(raw):
        pair = raw[pos:pos + 2]
        if pair == b"\xE6\x01":
            events.append(("control", "\n")); pos += 2; continue
        if pair == b"\xE4\x1F":
            events.append(("control", "\f")); pos += 2; continue
        byte = raw[pos]
        if 1 <= byte < 0xDD:
            events.append(("glyph", byte - 1)); pos += 1; continue
        if 0xDD <= byte <= 0xE0 and pos + 1 < len(raw):
            events.append(("glyph", (byte - 0xDD) * 255 + raw[pos + 1] + 0xDB)); pos += 2; continue
        events.append(("control", f"<CTRL:{byte:02X}>")); pos += 1
    return events


def resolve_ascii(text: str, allowed: frozenset[int]) -> str:
    def replace(match: re.Match[str]) -> str:
        index = int(match.group(1))
        return chr(index + 32) if index in allowed else match.group(0)
    return re.sub(r"<G:(\d+)>", replace, text)


def tokens(text: str) -> list[str]:
    return TOKEN_RE.findall(text)


def assert_same_source_identity(
    head_rows: list[dict[str, str]], current_rows: list[dict[str, str]]
) -> None:
    if len(current_rows) != len(head_rows):
        raise SystemExit(f"on-disk source table has {len(current_rows)} rows; task-start table has {len(head_rows)}")
    for head, other in zip(head_rows, current_rows):
            if (
                source_key(head), head["raw bytes as hex"]
            ) != (
                source_key(other), other["raw bytes as hex"]
            ):
                raise SystemExit(f"on-disk source identity differs at {source_key(head)}; refusing mixed recovery")


def build_corrected_source(
    head_rows: list[dict[str, str]], current_rows: list[dict[str, str]]
) -> tuple[list[dict[str, str]], set[tuple[str, str]], Counter[int]]:
    """Undo only raw 26..94 glyphs falsely written as their ASCII candidates."""
    corrected: list[dict[str, str]] = []
    untrusted_keys: set[tuple[str, str]] = set()
    reverted = Counter()
    unexpected_current: list[tuple[str, str]] = []

    for head, current in zip(head_rows, current_rows):
        key = source_key(head)
        broad_text = head["decoded Japanese"]
        events = raw_events(bytes.fromhex(head["raw bytes as hex"]))
        old_tokens = tokens(broad_text)
        if len(events) != len(old_tokens):
            raise SystemExit(
                f"raw/token alignment failed at {key}: raw={len(events)}, text={len(old_tokens)}"
            )
        corrected_tokens = list(old_tokens)
        interrupted_tokens = list(old_tokens)
        changed_this_row = False
        for position, ((kind, value), old) in enumerate(zip(events, old_tokens)):
            if kind != "glyph" or not isinstance(value, int):
                continue
            if value in VALID_ASCII:
                # Existing source mappings may deliberately use full-width
                # Japanese punctuation for a visually similar atlas glyph.
                # This repair touches only the token that the faulty ASCII
                # rule could actually have written.  Index 0 is the sole
                # valid token altered by the interrupted repair.
                if value == 0 and old == " ":
                    interrupted_tokens[position] = "<G:0>"
                continue
            if value in REJECTED_ASCII and old == chr(value + 32):
                corrected_tokens[position] = f"<G:{value}>"
                interrupted_tokens[position] = f"<G:{value}>"
                changed_this_row = True
                reverted[value] += 1
        corrected_text = "".join(corrected_tokens)
        interrupted_text = "".join(interrupted_tokens)
        if current["decoded Japanese"] not in {broad_text, interrupted_text, corrected_text}:
            unexpected_current.append(key)
            continue
        if changed_this_row:
            untrusted_keys.add(key)
        output = dict(head)
        output["decoded Japanese"] = corrected_text
        corrected.append(output)

    if unexpected_current:
        raise SystemExit(
            "on-disk source contains changes outside the known interrupted repair at "
            + ", ".join(f"{file}:{offset}" for file, offset in unexpected_current[:5])
        )
    return corrected, untrusted_keys, reverted


def build_corrected_translation(
    head_rows: list[dict[str, str]], current_rows: list[dict[str, str]], corrected_source: dict[tuple[str, str], str],
    untrusted_keys: set[tuple[str, str]],
) -> tuple[list[dict[str, str]], int, int]:
    """Restore HEAD translations verbatim, then clear only actually reverted rows."""
    if len(head_rows) != len(current_rows):
        raise SystemExit("on-disk and task-start translated tables have different row counts")

    restored_from_intermediate = 0
    unexpected_current: list[tuple[str, str]] = []
    corrected: list[dict[str, str]] = []
    cleared = 0
    label_col = "source of the translation (existing / new)"

    for head, current in zip(head_rows, current_rows):
        key = translated_key(head)
        if translated_key(current) != key:
            raise SystemExit(f"on-disk translated row order/key differs at {key}")
        # The interrupted repair was allowed only to blank Korean/source labels;
        # any other edit could be user work and must stop this automatic recovery.
        if current["korean"] != head["korean"]:
            if current["korean"].strip() or not head["korean"].strip():
                unexpected_current.append(key)
            elif key not in untrusted_keys:
                restored_from_intermediate += 1
        output = dict(head)
        source_text = corrected_source.get(key)
        if source_text is None:
            raise SystemExit(f"corrected source is missing {key}")
        output["japanese"] = source_text
        if key in untrusted_keys and output["korean"].strip():
            output["korean"] = ""
            if label_col in output:
                output[label_col] = ""
            cleared += 1
        corrected.append(output)

    if unexpected_current:
        raise SystemExit(
            "on-disk Korean has changes not made by the interrupted repair at "
            + ", ".join(f"{file}:{offset}" for file, offset in unexpected_current[:5])
        )
    return corrected, cleared, restored_from_intermediate


def corrected_map(current_fields: list[str], current_rows: list[dict[str, str]]) -> list[dict[str, str]]:
    """Replace just 0..94, eliminating the duplicate rows from the first repair."""
    char_col = "character"
    how_col = "how it was established"
    if char_col not in current_fields or how_col not in current_fields:
        raise SystemExit("font-index map schema changed; expected character and how-it-was-established columns")
    body = []
    for row in current_rows:
        try:
            index = int(row.get("glyph index", ""))
        except ValueError:
            index = -1
        if not 0 <= index <= 94:
            body.append(dict(row))
    for index in range(95):
        row = {field: "" for field in current_fields}
        row["glyph index"] = str(index)
        if index in VALID_ASCII:
            row[char_col] = chr(index + 32)
            row[how_col] = "ascii rule: original COMM.IMG audit, index = code - 32"
        else:
            row[how_col] = "original COMM.IMG audit: Japanese/non-ASCII; ASCII rule rejected"
        body.append(row)
    body.sort(key=lambda row: int(row["glyph index"]) if row.get("glyph index", "").isdigit() else 1 << 30)
    return body


def audit_rows() -> list[dict[str, str | int]]:
    rows: list[dict[str, str | int]] = []
    for index in range(95):
        valid = index in VALID_ASCII
        rows.append({
            "glyph index": index,
            "candidate from index + 32": chr(index + 32),
            "atlas row": index // 84,
            "atlas column": (index % 84) // 4,
            "bitplane": index % 4,
            "classification": (
                "ASCII rule valid (blank space)" if index == 0 else
                "ASCII rule valid" if valid else
                "Japanese/non-ASCII; ASCII rule rejected"
            ),
            "decision": chr(index + 32) if valid else f"<G:{index}>",
            "basis": (
                "original COMM.IMG 12x12 bitplane is blank, matching ASCII space" if index == 0 else
                "original COMM.IMG 12x12 bitplane visibly matches the candidate ASCII glyph" if valid else
                "original COMM.IMG 12x12 bitplane visibly does not match candidate ASCII; character is not inferred"
            ),
            "bitmap evidence": "01_work/analysis/ascii_glyph_audit/ascii_indices_000_094.csv",
        })
    return rows


def build_report(
    task_start: str, source_rows: list[dict[str, str]], reverted: Counter[int],
    untrusted_keys: set[tuple[str, str]], translated_rows: list[dict[str, str]],
    cleared: int,
) -> str:
    unresolved = Counter(
        int(match.group(1))
        for row in source_rows
        for match in re.finditer(r"<G:(\d+)>", row["decoded Japanese"])
    )
    no_glyph = sum("<G:" not in row["decoded Japanese"] for row in source_rows)
    strict = sum(
        "<G:" not in row["decoded Japanese"] and "<CTRL:" not in row["decoded Japanese"]
        for row in source_rows
    )
    korean_total = sum(bool(row["korean"].strip()) for row in translated_rows)
    return (
        "# ASCII glyph-rule audit and repair\n\n"
        "## Verified range\n\n"
        "- Original COMM.IMG LBA 667 was read from the original disc only.\n"
        "- Valid range: **indices 0..25**. Index 0 is a blank space; 1..25 are `!` through `9`.\n"
        "- Rejected range: **indices 26..94**. Each is a visible Japanese/non-ASCII glyph, not the matching ASCII code.\n"
        "- `script_original_full.csv` did not exist before `2109797`; each correction is instead proved against its retained raw bytes.\n"
        f"- Existing Korean authority: `{task_start}`.\n\n"
        "## Measured result\n\n"
        f"- Source rows returned to unresolved markers: {len(untrusted_keys):,}\n"
        f"- Invalid ASCII substitutions returned to `<G:n>`: {sum(reverted.values()):,}\n"
        f"- Actually encountered rejected indices: {sorted(reverted)}\n"
        f"- Fully glyph-decoded source strings (no `<G:`): {no_glyph:,}/{len(source_rows):,}\n"
        f"- Strings with neither unresolved glyph nor unresolved control marker: {strict:,}/{len(source_rows):,}\n"
        f"- Remaining unresolved glyph indices: {len(unresolved)}\n"
        f"- Remaining unresolved glyph occurrences: {sum(unresolved.values()):,}\n"
        f"- Korean cells cleared because these {len(untrusted_keys):,} source rows are untrustworthy: {cleared:,}\n"
        f"- Non-empty Korean cells after this source-integrity repair: {korean_total:,}\n\n"
        "No Korean wording was created, changed, or judged. No disc image, output archive, backup, ZIP, or emulator was touched.\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="measure and verify without writing files")
    args = parser.parse_args()

    source_fields, head_source = read_git_csv(TASK_START_COMMIT, SOURCE)
    current_source_fields, current_source = read_disk_csv(SOURCE)
    if source_fields != current_source_fields:
        raise SystemExit("source CSV schema differs across snapshots")
    assert_same_source_identity(head_source, current_source)
    corrected_source, untrusted_keys, reverted = build_corrected_source(head_source, current_source)

    translated_fields, head_translated = read_git_csv(TASK_START_COMMIT, TRANSLATED)
    current_translated_fields, current_translated = read_disk_csv(TRANSLATED)
    if translated_fields != current_translated_fields:
        raise SystemExit("translated CSV schema differs from task-start snapshot")
    source_by_key = {source_key(row): row["decoded Japanese"] for row in corrected_source}
    corrected_translated, cleared, restored_from_intermediate = build_corrected_translation(
        head_translated, current_translated, source_by_key, untrusted_keys
    )

    map_fields, current_map = read_disk_csv(MAP)
    new_map = corrected_map(map_fields, current_map)
    new_audit = audit_rows()
    task_start = git_revision(TASK_START_COMMIT)
    report = build_report(
        task_start, corrected_source, reverted, untrusted_keys,
        corrected_translated, cleared,
    )

    print(f"valid ASCII indices: 0..25 ({len(VALID_ASCII)})")
    print(f"rejected substitutions: rows={len(untrusted_keys)} occurrences={sum(reverted.values())} indices={sorted(reverted)}")
    print(f"Korean cells: clear={cleared} restore_exact={restored_from_intermediate} retained={sum(bool(r['korean'].strip()) for r in corrected_translated)}")
    unresolved = Counter(
        int(match.group(1)) for row in corrected_source
        for match in re.finditer(r"<G:(\d+)>", row["decoded Japanese"])
    )
    print(f"fully decoded (no <G:): {sum('<G:' not in r['decoded Japanese'] for r in corrected_source)}/{len(corrected_source)}")
    print(f"unresolved: indices={len(unresolved)} occurrences={sum(unresolved.values())}")
    if args.dry_run:
        print("dry run: no files written")
        return

    write_rows(SOURCE, source_fields, corrected_source)
    write_rows(TRANSLATED, translated_fields, corrected_translated)
    write_rows(MAP, map_fields, new_map)
    write_rows(AUDIT, list(new_audit[0]), new_audit)
    REPORT.write_text(report, encoding="utf-8")
    print("wrote corrected corpus, translated corpus, font map, audit, and report")


if __name__ == "__main__":
    main()
