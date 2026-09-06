"""Resolve the last three reviewed name rows without new glyphs or slots.

The immutable input is the verified V359 recovery2 archive.  Two オドン rows
use the user-approved approximation 오톤; the Ramada quiz keeps 초핀/초비
distinct and restores 촌가라.  No EXE, COMM, glyph, VRAM, or E2 slot changes
are permitted by this builder.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import review_editor as e
import build_arc1_v357_user_reviewed_dialogue_bankb as b
import build_arc1_v359_review_all as previous
import build_arc1_v359_slot_recovery as recovery


ROOT = recovery.ROOT
BASE = ROOT / "03_output/arc1_v359_slot_recovery2_TEST_ONLY.zip"
BASE_SHA256 = "517ABAFD7486091977DBED1F0A548E61A2D12BA933B0E78FDBC61D2B735A04A5"
OUT = ROOT / "03_output/arc1_v359_review_215_TEST_ONLY.zip"
ANALYSIS = ROOT / "01_work/analysis/dialogue_review_20260905/remaining_names"
CANONICAL_BEFORE_SHA256 = "3D95CCB869E9A42AFD2967C4A2302DD67A108EB667A5DD2BD0603CFFD529956F"

TARGETS = {
    1481: "너, 오톤이구나!!",
    1482: "내 집에 오톤이 눌러살고 있다니...",
    1703: "|초핀|초비|초스케|촌가라",
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def main() -> None:
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    snapshot = ANALYSIS / "canonical_before.csv"
    if not snapshot.exists():
        shutil.copy2(ROOT / "05_docs/script_translated_full.csv", snapshot)
    if sha(snapshot.read_bytes()) != CANONICAL_BEFORE_SHA256:
        raise RuntimeError("remaining-names canonical baseline drift")
    if sha(BASE.read_bytes()) != BASE_SHA256:
        raise RuntimeError("recovery2 baseline drift")

    e.TRANSLATED = snapshot
    editor = e.Editor.__new__(e.Editor)
    editor.load()
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        old = {info.filename: archive.read(info) for info in infos}
    current = dict(old)
    records: list[dict] = []

    for number, target in TARGETS.items():
        line = editor.lines[number - 1]
        name = line.file
        offset = int(line.offset, 0)
        before = current[name]
        encoded = b.encoded(target, editor.table)  # Missing glyph is a hard error.
        spans, controls = b.structure(line.raw)
        content = [(lo, hi) for lo, hi in spans if hi > lo]

        planner = previous.Planner(name, before, editor.originals[name], editor.table)
        if line.is_choice:
            parts = [part.strip() for part in target.split("|") if part.strip()]
            if len(parts) != len(content):
                raise RuntimeError(f"row {number}: choice span mismatch")
            if any(b.wrapped_rows(b.encoded(part, editor.table)) != 1 for part in parts):
                raise RuntimeError(f"row {number}: choice row wraps")
        else:
            if len(content) != 1:
                raise RuntimeError(f"row {number}: unexpected prose structure")
            parts = [target]

        for (lo, hi), part in zip(content, parts):
            planner.place(offset + lo, hi - lo, part, f"row {number}")
        after = bytes(planner.data)

        # This change is specifically approved as a no-slot solution.
        for lo, hi in content:
            if after[offset + lo] == 0xE2:
                raise RuntimeError(f"row {number}: unexpectedly allocated an E2 slot")
        for position, token in controls:
            if after[offset + position:offset + position + 2] != token:
                raise RuntimeError(f"row {number}: control moved")

        decoded = previous.read_tokens(after, offset, len(line.raw))
        reverse = {value: key for key, value in editor.table.items()}
        visible = "".join(reverse[token] for token in decoded if token[0] not in b.STRUCTURAL_LEADS)
        if previous.compact(visible) != previous.compact(target):
            raise RuntimeError(f"row {number}: decoded text mismatch: {visible!r}")

        if line.is_choice:
            visible_rows = [b.wrapped_rows(b.encoded(part, editor.table)) for part in parts]
        else:
            visible_rows = [b.wrapped_rows(encoded)]
            if visible_rows[0] > max(4, line.rows):
                raise RuntimeError(f"row {number}: dialogue window overflow")

        current[name] = after
        records.append({
            "row": number,
            "file": name,
            "offset": line.offset,
            "before": line.korean,
            "target": target,
            "capacity_bytes": [hi - lo for lo, hi in content],
            "encoded_bytes": [len(b.encoded(part, editor.table)) for part in parts],
            "visible_rows": visible_rows,
            "control_count": len(controls),
            "e2_slots_added": 0,
            "writes": previous.hunks(before, after),
            "readback": "PASS",
        })

    changed = {name for name in old if current[name] != old[name]}
    if changed != {"5/S5025.DAT", "6/S6054.DAT"}:
        raise RuntimeError(f"unexpected member changes: {sorted(changed)}")
    if any(len(current[name]) != len(old[name]) for name in old):
        raise RuntimeError("member size changed")

    # Guard every byte write and every other dialogue in the two touched files.
    replay = {name: bytearray(data) for name, data in old.items()}
    for record in records:
        for write in record["writes"]:
            before = bytes.fromhex(write["before"])
            after = bytes.fromhex(write["after"])
            at = write["at"]
            member = replay[record["file"]]
            if member[at:at + len(before)] != before:
                raise RuntimeError("overlapping/unexpected write")
            member[at:at + len(before)] = after
    if any(bytes(replay[name]) != current[name] for name in old):
        raise RuntimeError("hunk replay mismatch")

    untouched = 0
    changed_rows = set(TARGETS)
    for line in editor.lines:
        if line.file not in changed or line.n in changed_rows:
            continue
        offset = int(line.offset, 0)
        old_tokens = previous.read_tokens(old[line.file], offset, len(line.raw))
        new_tokens = previous.read_tokens(current[line.file], offset, len(line.raw))
        if old_tokens != new_tokens:
            raise RuntimeError(f"neighbor row changed: {line.n}")
        untouched += 1

    if OUT.exists():
        with ZipFile(OUT) as archive:
            if any(archive.read(name) != current[name] for name in current):
                raise RuntimeError("existing output differs; refusing overwrite")
    else:
        with ZipFile(OUT, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
            for info in infos:
                archive.writestr(
                    info,
                    current[info.filename],
                    compress_type=ZIP_DEFLATED,
                    compresslevel=9,
                )

    report = {
        "status": "NAME ROW CHECKS PASS / RUNTIME PENDING / TEST_ONLY",
        "base": str(BASE),
        "base_sha256": BASE_SHA256,
        "zip": str(OUT),
        "zip_sha256": sha(OUT.read_bytes()),
        "changed_files": sorted(changed),
        "untouched_neighbor_rows": untouched,
        "review_total": 215,
        "review_resolved": 215,
        "review_held": 0,
        "rows": records,
    }
    (ANALYSIS / "build_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(report["status"])
    print(report["zip_sha256"])


if __name__ == "__main__":
    main()
