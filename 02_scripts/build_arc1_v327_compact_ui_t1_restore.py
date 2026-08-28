#!/usr/bin/env python3
"""Build V327: restore the live $t1 value clobbered by V326's UV helper.

V325's common glyph builder loads $t1=160 at 0x8016B524 and later uses it
at 0x8016B640 to give physical blank 160 a six-pixel advance.  V326's UV
helper reused $t1 for its synthetic-range test and U coordinate, then returned
without restoring it.  Consequently ordinary Korean spaces advanced by 14px.

The helper already returns through a `j 0x8016B5B0` followed by a nop.  V327
changes only that delay-slot word to `ori $t1,$zero,160`, restoring the exact
value expected by the still-running leaf function on every helper path.
"""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import build_arc1_v324_static_ui_cursor_recovery as v324  # noqa: E402


BASE = ROOT / "03_output/arc1_v326_compact_ui_recovery_TEST_ONLY_B1768404.zip"
BASE_SHA256 = "B1768404E175886882D49AFD1C34255D532750E3927B8696CD53A1885039D4BE"
BASE_PSX_SHA256 = "B5D4628AF4112B1CE7E847C5ABF749AAE01943F6FECE974240F588E22D517589"
OUTPUT_STEM = "arc1_v327_compact_ui_t1_restore_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v326"
ANALYSIS = ROOT / "01_work/analysis/arc1_v327_compact_ui_t1_restore"

PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800
UV_RESTORE_RAM = 0x8019B140
UV_RESTORE_FILE = UV_RESTORE_RAM - RAM_TO_FILE
OLD_WORD = 0x00000000
NEW_WORD = 0x340900A0  # ori t1,zero,160

T1_INIT_RAM = 0x8016B524
T1_COMPARE_RAM = 0x8016B640
BLANK_ADVANCE_RAM = 0x8016B648
EXPECTED_CONTRACT = {
    T1_INIT_RAM: 0x340900A0,       # ori t1,zero,160
    T1_COMPARE_RAM: 0x14890002,    # bne a0,t1,+2
    BLANK_ADVANCE_RAM: 0x34030006, # ori v1,zero,6
}


class BuildError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def build_once(before: dict[str, bytes]) -> dict[str, bytes]:
    members = dict(before)
    exe = bytearray(before[PSX])
    if struct.unpack_from("<I", exe, UV_RESTORE_FILE)[0] != OLD_WORD:
        raise BuildError("V326 UV return delay slot drift")
    for address, expected in EXPECTED_CONTRACT.items():
        offset = address - RAM_TO_FILE
        if struct.unpack_from("<I", exe, offset)[0] != expected:
            raise BuildError(f"stock blank-advance contract drift at 0x{address:08X}")
    # The preceding word must remain the V326 jump back into the stock builder.
    if struct.unpack_from("<I", exe, UV_RESTORE_FILE - 4)[0] != 0x0805AD6C:
        raise BuildError("UV helper return jump drift")
    struct.pack_into("<I", exe, UV_RESTORE_FILE, NEW_WORD)
    members[PSX] = bytes(exe)
    return members


def main() -> None:
    if not BASE.is_file() or v324.sha256_file(BASE) != BASE_SHA256:
        raise BuildError(f"V326 base hash mismatch: {BASE}")
    infos, before = v324.read_archive(BASE)
    if len(before) != 164:
        raise BuildError("base archive topology drift")
    if sha256_bytes(before[PSX]) != BASE_PSX_SHA256:
        raise BuildError("V326 PSX.EXE hash mismatch")

    final = build_once(before)
    second = build_once(before)
    if final != second:
        raise BuildError("in-memory deterministic rebuild mismatch")

    changed = [name for name in before if before[name] != final[name]]
    if changed != [PSX]:
        raise BuildError(f"changed member set drift: {changed}")
    if any(len(before[name]) != len(final[name]) for name in before):
        raise BuildError("member size changed")
    actual = {
        offset
        for offset, (old, new) in enumerate(zip(before[PSX], final[PSX], strict=True))
        if old != new
    }
    # Little-endian 0x340900A0 is A0 00 09 34; byte +1 remains zero.
    expected = {UV_RESTORE_FILE, UV_RESTORE_FILE + 2, UV_RESTORE_FILE + 3}
    if actual != expected:
        raise BuildError(f"Expected-Write mismatch: {sorted(actual)}")

    # Execute the relevant state contract independently of the machine words.
    for glyph in (0, 159, 160, 959, *range(960, 973), 973, 1238):
        t1_after_helper = 160
        width = 6 if glyph == t1_after_helper else 14
        if glyph == 160 and width != 6:
            raise BuildError("blank advance contract failed")
        if glyph != 160 and width != 14:
            raise BuildError(f"nonblank advance regression: {glyph}")

    output_path, output_hash = v324.write_archive(OUTPUT_STEM, infos, final, None)
    delta_path, delta_hash = v324.write_archive(DELTA_STEM, infos, final, {PSX})
    with ZipFile(output_path) as archive:
        names = [info.filename for info in archive.infolist() if not info.is_dir()]
        expected_names = [info.filename for info in infos if not info.is_dir()]
        if names != expected_names or any(archive.read(name) != final[name] for name in final):
            raise BuildError("full ZIP round-trip/topology mismatch")
    with ZipFile(delta_path) as archive:
        if archive.namelist() != [PSX] or archive.read(PSX) != final[PSX]:
            raise BuildError("delta ZIP mismatch")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    with (ANALYSIS / "expected_writes.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("member", "offset", "before", "after", "purpose"))
        for offset in sorted(actual):
            writer.writerow((
                PSX, f"0x{offset:X}", f"{before[PSX][offset]:02X}",
                f"{final[PSX][offset]:02X}", "restore_t1_160_in_uv_return_delay_slot",
            ))
    with (ANALYSIS / "t1_contract.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("address", "word", "meaning"))
        writer.writerow((f"0x{T1_INIT_RAM:08X}", "0x340900A0", "stock ori t1,zero,160"))
        writer.writerow((f"0x{UV_RESTORE_RAM:08X}", "0x340900A0", "V327 restore in jump delay slot"))
        writer.writerow((f"0x{T1_COMPARE_RAM:08X}", "0x14890002", "stock bne a0,t1"))
        writer.writerow((f"0x{BLANK_ADVANCE_RAM:08X}", "0x34030006", "stock blank advance 6"))

    manifest = {
        "build": "V327 TEST_ONLY compact UI t1 live-register restore",
        "base": {"path": str(BASE), "sha256": BASE_SHA256},
        "output": {"path": str(output_path), "sha256": output_hash},
        "delta": {"path": str(delta_path), "sha256": delta_hash},
        "changed_members": [PSX],
        "changed_bytes": {PSX: len(actual)},
        "patch": {
            "file_offset": f"0x{UV_RESTORE_FILE:X}",
            "ram_address": f"0x{UV_RESTORE_RAM:08X}",
            "old_word": f"0x{OLD_WORD:08X}",
            "new_word": f"0x{NEW_WORD:08X}",
            "instruction": "ori t1,zero,160",
        },
        "preserved": "all V326 compact glyphs, UI strings, DAT and every byte outside one PSX word",
        "V326_status": "DO NOT USE: UV helper clobbers live t1 and expands physical blank 160 from 6px to 14px",
        "known_blocker": "V326 raw-code helper still remaps ordinary D14/D16 Hangul globally; fixed by V329",
        "runtime": "Superseded before approval",
        "release_status": "FAILED DIAGNOSTIC; DO NOT USE OR DISTRIBUTE",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V327 TEST ONLY - compact UI live $t1 restore",
        f"base={BASE.name}",
        f"output={output_path.name}",
        f"sha256={output_hash}",
        f"delta={delta_path.name}",
        f"delta_sha256={delta_hash}",
        "changed_members=PSX.EXE",
        "changed_bytes=3 in one word at file 0x80940 / RAM 0x8019B140",
        "patch=nop -> ori t1,zero,160 in UV helper return-jump delay slot",
        "blank_contract=physical160 advances 6px; all other glyphs keep 14px",
        "all V326 data outside one word=byte exact",
        "KNOWN BLOCKER=global raw-code helper remains; V327 DO NOT USE (fixed by V329)",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
