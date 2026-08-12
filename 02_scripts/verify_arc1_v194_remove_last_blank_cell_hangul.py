#!/usr/bin/env python3
"""Independent verification for v194's EA9B/함 dynamic reroute."""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v171_ui_asset_recovery as v171  # noqa: E402
import build_arc1_v193_restore_skill_range_levelup_dynamic as v193  # noqa: E402
import plan_arc1_v171_ui_asset_recovery as plan171  # noqa: E402
import verify_arc1_v191_yagun_choice_local_fixes as runtime  # noqa: E402


BASE = ROOT / "03_output/arc1_v193_restore_skill_range_levelup_dynamic_946B3F5E.zip"
ORIGINAL = ROOT / "00_original/arc.zip"
OUTPUTS = ROOT / "03_output"
PATTERN = "arc1_v194_remove_last_blank_cell_hangul_*.zip"
REPORT = ROOT / "01_work/analysis/arc1_v194_remove_last_blank_cell_hangul/verification.txt"
PSX, COMM = "PSX.EXE", "COMM.IMG"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def main() -> None:
    candidates = sorted(OUTPUTS.glob(PATTERN))
    if len(candidates) != 1:
        raise SystemExit(f"expected one v194 output, found {len(candidates)}")
    output = candidates[0]
    with ZipFile(BASE) as archive:
        names = archive.namelist()
        before = {name: archive.read(name) for name in names}
    with ZipFile(ORIGINAL) as archive:
        original = archive.read(COMM)
    with ZipFile(output) as archive:
        if archive.namelist() != names:
            raise SystemExit("member order changed")
        after = {name: archive.read(name) for name in names}

    changed = sorted(name for name in names if before[name] != after[name])
    if changed != [COMM, PSX] or any(len(before[n]) != len(after[n]) for n in names):
        raise SystemExit("member scope or length differs")
    lookup_at = v171.old.file_at(v171.PACKED_LOOKUP_RAM)
    lookup = plan171.unpack_fixed(after[PSX][lookup_at:lookup_at + 568], 413, 11)
    if lookup[408] != 1760:
        raise SystemExit(f"EA9B lookup is {lookup[408]}, not dynamic source 224")
    if runtime.runtime_decoder(after[PSX])(bytes.fromhex("EA 9B")) != "\ud568":
        raise SystemExit("EA9B does not decode as 함")

    # Full physical cell 1240 (row14/col16/plane0) and its three neighbours
    # must all be back to the untouched original cell.
    for y in range(168, 180):
        for x in range(192, 204):
            if v193.pixel(after[COMM], x, y) != v193.pixel(original, x, y):
                raise SystemExit(f"restored 함 cell differs at {x},{y}")
    if after[PSX][v193.LEVELUP_PAYLOAD_OFFSET:v193.LEVELUP_PAYLOAD_OFFSET + 12] != v193.NEW_LEVELUP:
        raise SystemExit("level-up payload regressed")
    if v193.range_differences(original, after[COMM]) != [v193.EXPECTED_INHERITED_RANGE_DIFF]:
        raise SystemExit("skill-range source regressed")

    psx_diffs = [i for i, p in enumerate(zip(before[PSX], after[PSX])) if p[0] != p[1]]
    comm_diffs = sum(a != b for a, b in zip(before[COMM], after[COMM]))
    if len(psx_diffs) != 2 or comm_diffs != 32:
        raise SystemExit(f"change counts differ: PSX={len(psx_diffs)} COMM={comm_diffs}")

    lines = [
        "v194 independent verification PASS",
        f"output={output.name}",
        f"sha256={digest(output.read_bytes())}",
        "EA9B=dynamic source 224=함 PASS",
        "row14_col16=original-exact PASS",
        "v193_skill_range_and_levelup=preserved PASS",
        "all_DAT_members=byte-identical PASS",
        "member_order_and_lengths=PASS",
        f"PSX_lookup_changed_bytes={len(psx_diffs)}",
        f"COMM_restored_bytes={comm_diffs}",
        "emulator_run=NO",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
