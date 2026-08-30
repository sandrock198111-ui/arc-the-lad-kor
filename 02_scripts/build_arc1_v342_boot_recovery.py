#!/usr/bin/env python3
"""Build V342: boot/display recovery by rolling back V341's range-cursor hook.

V341 reached normal CPU code with no exception, but its uploaded runtime state
had a completely black thumbnail.  The only high-risk V341 change was the
pre-DrawOT cursor refresh chain.  V342 therefore keeps the three independent
repairs (choice completion, bottom-help W16 Y, and Orkas spelling) and restores
all four cursor-control ranges byte-for-byte from V340.

The invisible item/skill range cursor consequently remains open.  This is a
boot recovery build, not a cursor fix.
"""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = ROOT / "03_output/arc1_v341_runtime_ui_recovery_TEST_ONLY_FCAF5CFB.zip"
BASE_SHA256 = "FCAF5CFB8BAC230A041DC68E9B23B0F6916112D8F5406B2312DD19CE2A4E33D2"
ROLLBACK = ROOT / "03_output/arc1_v340_battle_choice_ui_geometry_TEST_ONLY_3F63BFD1.zip"
ROLLBACK_SHA256 = "3F63BFD149A100152DE8B1B3223136CC501AF5AC19E19F443D4519142F9C783E"
OUTPUT_STEM = "arc1_v342_boot_recovery_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v341"
ANALYSIS = ROOT / "01_work/analysis/arc1_v342_boot_recovery"
PSX = "PSX.EXE"

# Exact V341 cursor-control changes to remove.  Payload/descriptor/UV/RLE were
# never changed by V341 and are intentionally outside this rollback envelope.
ROLLBACK_RANGES = (
    (0x2060, 4, "frame_DrawOT_call"),
    (0x3E14, 8, "range_initializer"),
    (0x75590, 0x34, "pre_DrawOT_cursor_gate"),
    (0x8F0D0, 36, "resident_uploader_epilogue"),
)


class BuildError(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def read_archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        return names, {name: archive.read(name) for name in names}


def write_archive(path: Path, names: list[str], members: dict[str, bytes]) -> None:
    with ZipFile(path, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for name in names:
            info = ZipInfo(name, date_time=(2026, 8, 30, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, members[name], compress_type=ZIP_DEFLATED, compresslevel=9)


def changed_offsets(before: bytes, after: bytes) -> list[int]:
    if len(before) != len(after):
        raise BuildError("member size changed")
    return [index for index, pair in enumerate(zip(before, after, strict=True)) if pair[0] != pair[1]]


def main() -> None:
    if sha(BASE.read_bytes()) != BASE_SHA256 or sha(ROLLBACK.read_bytes()) != ROLLBACK_SHA256:
        raise BuildError("input archive hash drift")
    names, base = read_archive(BASE)
    old_names, old = read_archive(ROLLBACK)
    if len(names) != 164 or names != old_names:
        raise BuildError("archive member topology drift")

    members = dict(base)
    exe = bytearray(base[PSX])
    old_exe = old[PSX]
    for offset, size, _label in ROLLBACK_RANGES:
        exe[offset:offset + size] = old_exe[offset:offset + size]
    members[PSX] = bytes(exe)

    changed_members = [name for name in names if members[name] != base[name]]
    if changed_members != [PSX]:
        raise BuildError(f"unexpected changed members: {changed_members}")
    allowed = set()
    for offset, size, _label in ROLLBACK_RANGES:
        allowed.update(range(offset, offset + size))
    actual = set(changed_offsets(base[PSX], members[PSX]))
    if not actual or not actual <= allowed:
        raise BuildError("cursor rollback Expected-Write envelope mismatch")
    for offset, size, _label in ROLLBACK_RANGES:
        if members[PSX][offset:offset + size] != old_exe[offset:offset + size]:
            raise BuildError("cursor range did not restore to V340")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    tmp_full = ROOT / "03_output" / f"{OUTPUT_STEM}.zip"
    tmp_delta = ROOT / "03_output" / f"{DELTA_STEM}.zip"
    write_archive(tmp_full, names, members)
    write_archive(tmp_delta, [PSX], {PSX: members[PSX]})
    full_hash, delta_hash = sha(tmp_full.read_bytes()), sha(tmp_delta.read_bytes())
    final_full = tmp_full.with_name(f"{OUTPUT_STEM}_{full_hash[:8]}.zip")
    final_delta = tmp_delta.with_name(f"{DELTA_STEM}_{delta_hash[:8]}.zip")
    for target in (final_full, final_delta):
        if target.exists():
            target.unlink()
    tmp_full.replace(final_full)
    tmp_delta.replace(final_delta)

    rows = []
    for offset in sorted(actual):
        label = next(label for start, size, label in ROLLBACK_RANGES if start <= offset < start + size)
        rows.append({
            "member": PSX,
            "offset": f"0x{offset:X}",
            "before": f"{base[PSX][offset]:02X}",
            "after": f"{members[PSX][offset]:02X}",
            "reason": label,
        })
    with (ANALYSIS / "expected_writes.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    manifest = {
        "version": "V342",
        "status": "STATIC_PASS_RUNTIME_PENDING",
        "base": {"file": BASE.name, "sha256": BASE_SHA256},
        "rollback_source": {"file": ROLLBACK.name, "sha256": ROLLBACK_SHA256},
        "output": {"file": final_full.name, "sha256": full_hash},
        "delta": {"file": final_delta.name, "sha256": delta_hash},
        "changed_members_vs_v341": [PSX],
        "rollback_ranges": [
            {"offset": f"0x{offset:X}", "size": size, "label": label}
            for offset, size, label in ROLLBACK_RANGES
        ],
        "preserved_v341_repairs": [
            "15 battle choice completion metadata fixes",
            "bottom-help W16-only Y-1 with E7 icons fixed",
            "오르카스 언덕 region/location label",
        ],
        "known_open": ["item/skill range cursor remains V340-invisible"],
        "v341_failure": "black thumbnail; CPU ExcCode=0 at normal text-render code; frame/display regression",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V342 boot/display recovery build",
        f"base={BASE.name} sha256={BASE_SHA256}",
        f"output={final_full.name} sha256={full_hash}",
        f"delta={final_delta.name} sha256={delta_hash}",
        f"PSX.EXE sha256={sha(members[PSX])}",
        f"changed_members_vs_v341={','.join(changed_members)}",
        f"changed_PSX_bytes={len(actual)}; Expected-Write exact",
        "cursor_control=V340 byte exact at frame hook, initializer, gate, uploader epilogue",
        "preserved=choice alignment,bottom-help W16 Y,오르카스 언덕",
        "range_cursor=OPEN (V340 behavior restored)",
        "runtime=PENDING cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    (ANALYSIS / "runtime_checklist.txt").write_text(
        "V342 cold-boot checklist\n"
        "1. Confirm BIOS/title/load/game display appears (V341 black-screen regression absent).\n"
        "2. Confirm choice alignment, bottom-help text/icon split, and 오르카스 언덕 remain fixed.\n"
        "3. Range cursor is expected to remain open/invisible; do not treat that as a new V342 regression.\n"
        "4. Save a fresh V342 DUCCU state for attribution.\n",
        encoding="utf-8",
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
