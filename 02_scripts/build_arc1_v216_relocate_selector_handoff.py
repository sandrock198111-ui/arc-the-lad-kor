#!/usr/bin/env python3
"""Build v216 TEST ONLY: keep selector execution out of game-owned RAM.

v215 correctly classified real 12x12 SPRT packets, but its 36-byte finish
fragment occupied 0x801A2060..0x801A2083.  The world-map transition writes
live game data into the latter part of that range and v215 consequently
executed a data pointer as MIPS code.

This build removes the finish fragment entirely.  The already-guarded tail of
the selector overlap fragment jumps directly to the resident frame routine.
The frame routine derives destination A/B from the conflict flags, updates the
upload rectangle itself, and retains its original 584-byte size.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile

import build_arc1_v215_correct_packet_layout_selector as v215


parent = v215.parent
build = parent.build
old = build.old

OUT_STEM = "arc1_v216_relocate_selector_handoff_TEST_ONLY"
HANDOFF = build.OVERLAP + 21 * 4
OLD_FINISH_N = 36

ORIGINAL_SELECTOR_BLOBS = v215.selector_blobs
ORIGINAL_BUILD_FRAME = parent.ORIGINAL_BUILD_FRAME


def branch_target(pc: int, word: int) -> int:
    immediate = ((word & 0xFFFF) ^ 0x8000) - 0x8000
    return pc + 4 + immediate * 4


def selector_blobs(frame: int, rect: int) -> tuple[bytes, bytes, bytes, bytes]:
    """Reuse v215 classification, but terminate inside the proven overlap block."""
    configured_finish_n = build.FINISH_N
    build.FINISH_N = OLD_FINISH_N
    try:
        overlap, entry, classify, _old_finish = ORIGINAL_SELECTOR_BLOBS(frame, rect)
    finally:
        build.FINISH_N = configured_finish_n

    overlap_words = list(struct.unpack(f"<{len(overlap) // 4}I", overlap))
    entry_words = list(struct.unpack(f"<{len(entry) // 4}I", entry))

    if overlap_words[21:] != [build.NOP, build.NOP, build.NOP]:
        raise SystemExit("v215 overlap tail is no longer three NOPs")

    old_exit = build.branch(
        0x05, build.T2, build.ZERO, build.ENTRY + 8 * 4, build.FINISH
    )
    if entry_words[8] != old_exit:
        raise SystemExit("v215 selector exit branch differs")
    entry_words[8] = build.branch(
        0x05, build.T2, build.ZERO, build.ENTRY + 8 * 4, HANDOFF
    )

    overlap_words[21] = old.j(frame)
    overlap_words[22] = old.i_type(0x09, build.A3, build.A1, -1)
    # flags-1 is zero only for A-only conflict, therefore zero means B.
    overlap_words[23] = build.NOP

    return (
        struct.pack(f"<{len(overlap_words)}I", *overlap_words),
        struct.pack(f"<{len(entry_words)}I", *entry_words),
        classify,
        b"",
    )


def safe_frame(address: int, huffman_address: int,
               layout: dict[str, tuple[int, int]]) -> bytes:
    """Patch v212's frame in place; keep all later instruction addresses stable."""
    blob = bytearray(ORIGINAL_BUILD_FRAME(address, huffman_address, layout))
    words = list(struct.unpack(f"<{len(blob) // 4}I", blob))
    active = layout["active_mask"][0]
    owners = layout["owners"][0]
    rect = layout["upload_rect"][0]

    if rect - active != 8 or owners - active != -58:
        raise SystemExit("resident layout offsets differ")

    expected = [
        old.i_type(0x0F, build.ZERO, build.S4, rect >> 16),
        old.i_type(0x0D, build.S4, build.S4, rect & 0xFFFF),
        old.move(build.S7, build.A1),
        old.i_type(0x0F, build.ZERO, build.T0, active >> 16),
        old.i_type(0x0D, build.T0, build.T0, active & 0xFFFF),
        old.i_type(0x23, build.T0, build.S0, 0),
        old.i_type(0x0F, build.ZERO, build.S1, owners >> 16),
    ]
    if words[11:18] != expected:
        raise SystemExit("v212 frame prologue differs before relocation")
    old_protect = words[18]
    if old_protect >> 26 != 0x04:
        raise SystemExit("v212 protect branch differs")
    protect = branch_target(address + 18 * 4, old_protect)
    if words[19] != old.i_type(0x0D, build.S1, build.S1, owners & 0xFFFF):
        raise SystemExit("v212 owners delay slot differs")
    if words[20] != old.i_type(0x09, build.SP, build.S2, 0):
        raise SystemExit("v212 S2 work-buffer setup differs")

    selected = address + 15 * 4
    words[11:21] = [
        old.i_type(0x0D, build.ZERO, build.S7, build.CACHE_A_Y),
        build.branch(0x05, build.A1, build.ZERO, address + 12 * 4, selected),
        old.i_type(0x0F, build.ZERO, build.T0, active >> 16),
        old.i_type(0x0D, build.ZERO, build.S7, build.CACHE_B_Y),
        old.i_type(0x0D, build.T0, build.T0, active & 0xFFFF),
        old.i_type(0x29, build.T0, build.S7, rect + 2 - active),
        old.i_type(0x23, build.T0, build.S0, 0),
        old.i_type(0x09, build.T0, build.S4, rect - active),
        build.branch(0x04, build.S0, build.ZERO, address + 19 * 4, protect),
        old.i_type(0x09, build.T0, build.S1, owners - active),
    ]

    replacements = (
        (old.move(build.T0, build.S2), old.move(build.T0, build.SP)),
        (old.move(build.T1, build.S2), old.move(build.T1, build.SP)),
        (old.move(build.A1, build.S2), old.move(build.A1, build.SP)),
    )
    for before, after in replacements:
        matches = [index for index, word in enumerate(words) if word == before]
        if len(matches) != 1:
            raise SystemExit(f"frame S2 work-buffer reference differs: {matches}")
        words[matches[0]] = after

    result = struct.pack(f"<{len(words)}I", *words)
    if len(result) != 584:
        raise SystemExit("v216 resident frame size changed")
    return result


def output_zip() -> Path:
    matches = sorted(build.OUT_DIR.glob(f"{OUT_STEM}_????????.zip"))
    if len(matches) != 1:
        raise SystemExit(f"expected one v216 output, found: {matches}")
    return matches[0]


def main() -> None:
    build.FINISH_N = 0
    parent.selector_blobs = selector_blobs
    parent.ORIGINAL_BUILD_FRAME = safe_frame
    parent.OUT_STEM = OUT_STEM
    parent.main()

    output = output_zip()
    with ZipFile(build.BASE) as archive:
        base_exe = archive.read(build.PSX)
    with ZipFile(output) as archive:
        exe = archive.read(build.PSX)

    old_finish_at = old.file_at(build.FINISH)
    if exe[old_finish_at:old_finish_at + OLD_FINISH_N] != \
            base_exe[old_finish_at:old_finish_at + OLD_FINISH_N]:
        raise SystemExit("game-owned 0x801A2060..0x801A2083 changed")
    if build.direct_refs(exe, build.FINISH, build.FINISH + OLD_FINISH_N):
        raise SystemExit("v216 still directly references the game-owned finish range")

    layout, _resident_blobs, code_base = build.v190.resident_layout()
    decoder_blob = build.v190.build_decoder(code_base, layout)
    huffman = (code_base + len(decoder_blob) + 3) & ~3
    huffman_blob = build.v190.build_huffman(huffman, layout)
    frame = (huffman + len(huffman_blob) + 3) & ~3
    frame_blob = parent.marked_frame(frame, huffman, layout)
    source_at = old.file_at(build.v171.SOURCE_BASE)
    frame_at = source_at + frame - build.v171.RESIDENT_BASE
    if exe[frame_at:frame_at + len(frame_blob)] != frame_blob:
        raise SystemExit("archived v216 frame differs")

    report = build.REPORT.read_text(encoding="utf-8")
    report = report.replace(
        "v214 TEST ONLY - strict marked per-frame A/B dynamic-cache selector",
        "v216 TEST ONLY - selector handoff relocated out of game-owned RAM",
        1,
    )
    report += "\n".join([
        "v216_real_packet_layout=PASS (inherits corrected v215 u16 width/height)",
        f"selector_handoff=0x{HANDOFF:08X} inside guarded overlap tail",
        "selector_finish_fragment=removed",
        "game_owned_0x801A2060_0x801A2083=byte-identical_to_v210 PASS",
        "direct_references_to_old_finish=0 PASS",
        "frame_selected_Y=A480_or_B384; packet_V=low_byte_224_or_128",
        "frame_work_buffer=SP directly; S2 temporary removed",
        "resident_frame_size=584 unchanged",
        "resident_growth=0; heap_boundary=0x801FF8B0 unchanged",
        "runtime=PENDING; emulator_run=NO",
        "rollback=v210; v214 and v215 are runtime failures",
        "",
    ])
    build.REPORT.write_text(report, encoding="utf-8")
    print(f"v216_output={output}")
    print(f"v216_sha256={hashlib.sha256(output.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
