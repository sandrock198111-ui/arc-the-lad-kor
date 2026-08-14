#!/usr/bin/env python3
"""Build v217 TEST ONLY: fully refresh whichever A/B cache page is selected.

v216 moved the selector handoff out of game-owned RAM and stopped the world-map
Data Bus Error. Runtime states taken after that transition prove a separate
coherency bug: the selected destination contained only 4/28, then 16/28, then
28/28 owner glyphs. The original frame routine uploads only physical cells
named by the previous active mask, which is valid for one fixed destination but
not after switching between A and B.

This build changes one instruction in the resident frame. The selected safe
destination is rebuilt from all seven physical cells every frame. No new RAM,
VRAM, DAT, COMM.IMG, lookup, or cache-owner layout is introduced.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile

import build_arc1_v216_relocate_selector_handoff as v216


build = v216.build
old = v216.old

OUT_STEM = "arc1_v217_full_selected_destination_refresh_TEST_ONLY"
FRAME = 0x801FF668
ACTIVE_LOAD_INDEX = 17
ORIGINAL_SAFE_FRAME = v216.safe_frame


def full_refresh_frame(address: int, huffman_address: int,
                       layout: dict[str, tuple[int, int]]) -> bytes:
    """Ignore the stale per-page mask and rebuild all seven selected cells."""
    blob = bytearray(ORIGINAL_SAFE_FRAME(address, huffman_address, layout))
    if address != FRAME or len(blob) != 584:
        raise SystemExit(
            f"v216 frame layout differs: address=0x{address:08X} size={len(blob)}"
        )
    words = list(struct.unpack(f"<{len(blob) // 4}I", blob))
    expected = old.i_type(0x23, build.T0, build.S0, 0)  # lw s0,0(t0)
    replacement = old.i_type(0x09, build.ZERO, build.S0, -1)
    if words[ACTIVE_LOAD_INDEX] != expected:
        raise SystemExit(
            f"v216 active-mask load differs at frame word {ACTIVE_LOAD_INDEX}"
        )
    if sum(word == expected for word in words) != 1:
        raise SystemExit("v216 active-mask load is no longer unique")
    words[ACTIVE_LOAD_INDEX] = replacement
    return struct.pack(f"<{len(words)}I", *words)


def one_v216_archive() -> Path:
    matches = sorted(build.OUT_DIR.glob(
        "arc1_v216_relocate_selector_handoff_TEST_ONLY_????????.zip"
    ))
    if len(matches) != 1:
        raise SystemExit(f"expected one v216 archive, found: {matches}")
    return matches[0]


def one_output() -> Path:
    matches = sorted(build.OUT_DIR.glob(f"{OUT_STEM}_????????.zip"))
    if len(matches) != 1:
        raise SystemExit(f"expected one v217 archive, found: {matches}")
    return matches[0]


def main() -> None:
    v216_archive = one_v216_archive()
    v216.safe_frame = full_refresh_frame
    v216.OUT_STEM = OUT_STEM
    v216.main()

    output = one_output()
    with ZipFile(v216_archive) as archive:
        v216_members = {item.filename: archive.read(item.filename)
                        for item in archive.infolist()}
    with ZipFile(output) as archive:
        v217_members = {item.filename: archive.read(item.filename)
                        for item in archive.infolist()}

    if v216_members.keys() != v217_members.keys():
        raise SystemExit("v217 archive member set differs from v216")
    changed_members = [
        name for name in v216_members if v216_members[name] != v217_members[name]
    ]
    if changed_members != [build.PSX]:
        raise SystemExit(f"v217 changed unexpected members: {changed_members}")

    before = v216_members[build.PSX]
    after = v217_members[build.PSX]
    changed_words = [
        offset for offset in range(0, len(after), 4)
        if before[offset:offset + 4] != after[offset:offset + 4]
    ]
    resident_source = old.file_at(build.v171.SOURCE_BASE)
    expected_at = (
        resident_source
        + FRAME - build.v171.RESIDENT_BASE
        + ACTIVE_LOAD_INDEX * 4
    )
    if changed_words != [expected_at]:
        raise SystemExit(
            f"v217 PSX.EXE word delta differs: {[hex(x) for x in changed_words]}"
        )

    old_finish_at = old.file_at(build.FINISH)
    if after[old_finish_at:old_finish_at + v216.OLD_FINISH_N] != \
            before[old_finish_at:old_finish_at + v216.OLD_FINISH_N]:
        raise SystemExit("v217 changed the game-owned old finish range")

    report = build.REPORT.read_text(encoding="utf-8")
    report = report.replace(
        "v216 TEST ONLY - selector handoff relocated out of game-owned RAM",
        "v217 TEST ONLY - full refresh of the selected A/B cache destination",
        1,
    )
    report += "\n".join([
        f"parent={v216_archive.name}",
        "runtime_evidence_v216_selected_shapes=slot1_4of28,slot2_16of28,slot3_28of28",
        f"frame_patch=0x{FRAME + ACTIVE_LOAD_INDEX * 4:08X} "
        "lw_s0_active_mask -> addiu_s0_zero_minus1",
        "selected_destination_refresh=7_physical_cells_28_planes_every_frame",
        "upload_bytes_per_frame=504",
        "new_RAM=0; new_VRAM=0; resident_growth=0",
        "DAT=byte-identical_to_v216 PASS",
        "COMM.IMG=byte-identical_to_v216 PASS",
        "game_owned_0x801A2060_0x801A2083=byte-identical_to_v216 PASS",
        "runtime=PENDING; emulator_run=NO",
        "rollback=v210; v214-v216 are runtime failures",
        "",
    ])
    build.REPORT.write_text(report, encoding="utf-8")
    print(f"v217_output={output}")
    print(f"v217_sha256={hashlib.sha256(output.read_bytes()).hexdigest().upper()}")
    print(f"changed_word=0x{FRAME + ACTIVE_LOAD_INDEX * 4:08X}")


if __name__ == "__main__":
    main()
