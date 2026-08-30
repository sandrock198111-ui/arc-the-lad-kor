#!/usr/bin/env python3
"""Build V343: repair the V341 W16 helper's lost-RA infinite loop.

V341 inserted a JAL into the formerly-leaf common glyph builder at
0x8016B5F4 without saving the caller's return address.  The helper returned to
0x8016B5FC, but the glyph builder's own final ``jr ra`` then returned to the
same mid-function address forever.  Fresh V341 and V342 DUCCU states both
prove r31=0x8016B5FC while the CPU cycles inside 0x8016B5FC..0x8016B660.

V343 preserves V342 byte-for-byte except for two control-flow words:

* 0x8016B5F4: JAL helper -> J helper (do not clobber r31)
* 0x8019D040: JR r31 -> J 0x8016B5FC (fixed helper continuation)

The existing packet-Y store remains the helper return jump's delay slot.
"""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = ROOT / "03_output/arc1_v342_boot_recovery_TEST_ONLY_9EAEC08A.zip"
BASE_SHA256 = "9EAEC08A3D94120C712D72321AC28D26272EF771D53CC465542090AC78D24E1C"
BASE_PSX_SHA256 = "C1A4FC63449A58939295849F033679A1EC52B6EC587A52736BF476C6CA77144D"
OUTPUT_STEM = "arc1_v343_ra_safe_w16_hook_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v342"
ANALYSIS = ROOT / "01_work/analysis/arc1_v343_ra_safe_w16_hook"
PSX = "PSX.EXE"

RAM_TO_FILE = 0x8011A800
HOOK_RAM = 0x8016B5F4
HOOK_FILE = HOOK_RAM - RAM_TO_FILE
HELPER_RAM = 0x8019D024
HELPER_TAIL_RAM = 0x8019D040
HELPER_TAIL_FILE = HELPER_TAIL_RAM - RAM_TO_FILE
CONTINUATION_RAM = 0x8016B5FC
DELAY_FILE = HELPER_TAIL_FILE + 4

OLD_HOOK = 0x0C067409       # jal 0x8019D024
NEW_HOOK = 0x08067409       # j   0x8019D024
OLD_HELPER_TAIL = 0x03E00008  # jr  ra
NEW_HELPER_TAIL = 0x0805AD7F  # j   0x8016B5FC
HELPER_DELAY = 0xA4A2002E     # sh  v0,0x2e(a1)


class BuildError(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def word(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


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


def changed_offsets(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise BuildError("member size changed")
    return {index for index, pair in enumerate(zip(before, after, strict=True)) if pair[0] != pair[1]}


def main() -> None:
    if not BASE.is_file() or sha(BASE.read_bytes()) != BASE_SHA256:
        raise BuildError("V342 base archive hash drift")
    names, base = read_archive(BASE)
    if len(names) != 164 or sha(base[PSX]) != BASE_PSX_SHA256:
        raise BuildError("V342 member topology or PSX hash drift")

    exe = bytearray(base[PSX])
    premises = {
        HOOK_FILE: OLD_HOOK,
        HELPER_TAIL_FILE: OLD_HELPER_TAIL,
        DELAY_FILE: HELPER_DELAY,
    }
    for offset, expected in premises.items():
        if word(exe, offset) != expected:
            raise BuildError(f"control-flow premise drift at 0x{offset:X}")

    struct.pack_into("<I", exe, HOOK_FILE, NEW_HOOK)
    struct.pack_into("<I", exe, HELPER_TAIL_FILE, NEW_HELPER_TAIL)
    if word(exe, DELAY_FILE) != HELPER_DELAY:
        raise BuildError("helper packet-Y delay slot changed")

    final = dict(base)
    final[PSX] = bytes(exe)
    changed_members = [name for name in names if final[name] != base[name]]
    if changed_members != [PSX]:
        raise BuildError(f"unexpected changed members: {changed_members}")

    allowed = set(range(HOOK_FILE, HOOK_FILE + 4)) | set(range(HELPER_TAIL_FILE, HELPER_TAIL_FILE + 4))
    actual = changed_offsets(base[PSX], final[PSX])
    if not actual or not actual <= allowed:
        raise BuildError(f"Expected-Write envelope mismatch: {sorted(actual ^ allowed)}")
    if word(final[PSX], HOOK_FILE) != NEW_HOOK or word(final[PSX], HELPER_TAIL_FILE) != NEW_HELPER_TAIL:
        raise BuildError("control-flow readback failed")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    tmp_full = ROOT / "03_output" / f"{OUTPUT_STEM}.zip"
    tmp_delta = ROOT / "03_output" / f"{DELTA_STEM}.zip"
    write_archive(tmp_full, names, final)
    write_archive(tmp_delta, [PSX], {PSX: final[PSX]})
    full_hash = sha(tmp_full.read_bytes())
    delta_hash = sha(tmp_delta.read_bytes())
    final_full = tmp_full.with_name(f"{OUTPUT_STEM}_{full_hash[:8]}.zip")
    final_delta = tmp_delta.with_name(f"{DELTA_STEM}_{delta_hash[:8]}.zip")
    for target in (final_full, final_delta):
        if target.exists():
            target.unlink()
    tmp_full.replace(final_full)
    tmp_delta.replace(final_delta)

    labels = (
        (HOOK_FILE, 4, "leaf_hook_jal_to_j_preserve_ra"),
        (HELPER_TAIL_FILE, 4, "helper_fixed_continuation_jump"),
    )
    rows: list[dict[str, str]] = []
    for offset in sorted(actual):
        label = next(label for start, size, label in labels if start <= offset < start + size)
        rows.append({
            "member": PSX,
            "offset": f"0x{offset:X}",
            "before": f"{base[PSX][offset]:02X}",
            "after": f"{final[PSX][offset]:02X}",
            "reason": label,
        })
    with (ANALYSIS / "expected_writes.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    manifest = {
        "version": "V343",
        "status": "STATIC_PASS_RUNTIME_PENDING",
        "base": {"file": BASE.name, "sha256": BASE_SHA256, "runtime": "FAIL_BLACK_SCREEN"},
        "output": {"file": final_full.name, "sha256": full_hash},
        "delta": {"file": final_delta.name, "sha256": delta_hash},
        "changed_members_vs_v342": [PSX],
        "changed_psx_bytes": len(actual),
        "control_flow": {
            "hook": {"ram": f"0x{HOOK_RAM:08X}", "before": f"0x{OLD_HOOK:08X}", "after": f"0x{NEW_HOOK:08X}"},
            "helper_tail": {"ram": f"0x{HELPER_TAIL_RAM:08X}", "before": f"0x{OLD_HELPER_TAIL:08X}", "after": f"0x{NEW_HELPER_TAIL:08X}"},
            "continuation": f"0x{CONTINUATION_RAM:08X}",
            "delay_slot_preserved": f"0x{HELPER_DELAY:08X}",
        },
        "preserved": [
            "all V342 non-PSX members byte exact",
            "V342 cursor-control rollback",
            "V341 choice completion DAT metadata",
            "V341 bottom-help W16 conditional Y behavior",
            "V341 Orkas region/location label",
        ],
        "runtime_evidence": {
            "v341_v342_ra": "0x8016B5FC",
            "v341_pc": "0x8016B64C",
            "v342_pc": "0x8016B60C",
            "exception_code": 0,
            "display_rectangle": "320x224 valid but all-zero VRAM",
        },
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V343 RA-safe W16 helper build",
        f"base={BASE.name} sha256={BASE_SHA256}",
        f"output={final_full.name} sha256={full_hash}",
        f"delta={final_delta.name} sha256={delta_hash}",
        f"PSX.EXE sha256={sha(final[PSX])}",
        f"changed_members_vs_v342={','.join(changed_members)}",
        f"changed_PSX_bytes={len(actual)}; Expected-Write exact",
        "hook=JAL->J at 0x8016B5F4; r31 no longer clobbered",
        "helper_tail=JR RA->J 0x8016B5FC; packet-Y store delay slot preserved",
        "all DAT/COMM and all other V342 bytes preserved",
        "runtime=PENDING cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    (ANALYSIS / "runtime_checklist.txt").write_text(
        "V343 cold-boot checklist\n"
        "1. Confirm BIOS/title/load/game display appears; save a fresh V343 DUCCU state.\n"
        "2. Confirm r31 is not trapped at 0x8016B5FC and the displayed VRAM rectangle is nonzero.\n"
        "3. Confirm choice alignment, bottom-help text/icon split, and Orkas label remain fixed.\n"
        "4. Item/skill range cursor remains the inherited V340-open issue.\n",
        encoding="utf-8",
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
