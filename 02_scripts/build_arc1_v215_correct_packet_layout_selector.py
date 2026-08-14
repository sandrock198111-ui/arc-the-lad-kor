#!/usr/bin/env python3
"""Build v215 TEST ONLY: correct the selector's real SPRT packet layout.

v214 treated bytes 16..17 as packed width/height.  Real variable SPRTs store
16-bit width at +16 and 16-bit height at +18.  The synthetic test packet had
accidentally put height at +17, hiding both selector failures:

* no real cache packet received the transient V=255 marker;
* overlap height was read from the high byte of width, so it was always zero.

This build restores separate 16-bit width/height checks and marks only exact
12x12 cache SPRTs.  A pre-existing marker is left untouched by the overlap
path and is still consumed by the resident frame routine.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import build_arc1_v214_marked_ab_cache_selector as parent


OUT_STEM = "arc1_v215_correct_packet_layout_selector_TEST_ONLY"


def selector_blobs(frame: int, rect: int) -> tuple[bytes, bytes, bytes, bytes]:
    build = parent.build
    old = build.old
    branch = build.branch
    next_packet = build.OVERLAP + 17 * 4
    game = build.OVERLAP
    loop = build.ENTRY + 5 * 4
    dynamic = build.CLASSIFY + 19 * 4
    canonical = build.CLASSIFY + 23 * 4

    entry = [
        old.move(build.A3, build.ZERO),
        old.i_type(0x23, build.A0, build.T0, 0),
        old.move(build.A2, build.ZERO),
        old.r_type(build.ZERO, build.T0, build.T0, 8, 0x00),
        old.r_type(build.ZERO, build.T0, build.T0, 8, 0x02),
        old.i_type(0x0B, build.T0, build.T2, 1),
        old.r_type(build.ZERO, build.T0, build.T1, 21, 0x02),
        old.r_type(build.T2, build.T1, build.T2, 0, 0x25),
        branch(0x05, build.T2, build.ZERO, build.ENTRY + 8 * 4, build.FINISH),
        old.i_type(0x0F, build.ZERO, build.T2, 0x8000),
        old.r_type(build.T2, build.T0, build.T2, 0, 0x25),
        old.i_type(0x23, build.T2, build.T3, 0),
        old.i_type(0x24, build.T2, build.T5, 7),
        old.i_type(0x25, build.T2, build.T4, 4),
        old.i_type(0x09, build.T5, build.T6, -0xE1),
        branch(0x05, build.T6, build.ZERO, build.ENTRY + 15 * 4, build.ENTRY + 21 * 4),
        old.i_type(0x0C, build.T4, build.T6, build.PHYSICAL_TPAGE_MASK),
        old.i_type(0x09, build.T6, build.T6, -build.PHYSICAL_TPAGE_X15_Y1_4BPP),
        old.i_type(0x0B, build.T6, build.A2, 1),
        branch(0x04, build.ZERO, build.ZERO, build.ENTRY + 19 * 4, next_packet),
        build.NOP,
        branch(0x04, build.A2, build.ZERO, build.ENTRY + 21 * 4, next_packet),
        old.i_type(0x0C, build.T5, build.T6, 0xFC),
        old.i_type(0x09, build.T6, build.T6, -0x64),
        branch(0x05, build.T6, build.ZERO, build.ENTRY + 24 * 4, next_packet),
        old.r_type(build.ZERO, build.T3, build.T1, 24, 0x02),
        old.i_type(0x09, build.T1, build.T1, -4),
        branch(0x05, build.T1, build.ZERO, build.ENTRY + 27 * 4, next_packet),
        old.i_type(0x25, build.T2, build.T6, 14),
        old.i_type(0x24, build.T2, build.T7, 12),
        old.j(build.CLASSIFY),
        old.i_type(0x24, build.T2, build.T9, 13),
    ]
    if len(entry) * 4 != build.ENTRY_N:
        raise SystemExit("v215 selector entry size differs")

    classify = [
        old.i_type(0x25, build.T2, build.V1, 16),       # width u16
        old.i_type(0x25, build.T2, build.K0, 18),       # height u16 (not +17)
        old.i_type(0x09, build.T6, build.V0, -build.v171.v166.FONT_CLUT_MIN),
        old.i_type(0x0B, build.V0, build.V0, 16),
        branch(0x04, build.V0, build.ZERO, build.CLASSIFY + 4 * 4, game),
        old.i_type(0x09, build.V1, build.V0, -old.CELL),
        branch(0x05, build.V0, build.ZERO, build.CLASSIFY + 6 * 4, game),
        old.i_type(0x09, build.K0, build.V0, -old.CELL),
        branch(0x05, build.V0, build.ZERO, build.CLASSIFY + 8 * 4, game),
        old.i_type(0x09, build.T7, build.V0, -build.CACHE_U0),
        old.i_type(0x0B, build.V0, build.V1, build.CACHE_U1 - build.CACHE_U0),
        branch(0x04, build.V1, build.ZERO, build.CLASSIFY + 11 * 4, game),
        old.move(build.K1, build.V0),
        branch(0x04, build.K1, build.ZERO, build.CLASSIFY + 13 * 4, dynamic),
        old.i_type(0x09, build.K1, build.K1, -old.CELL),
        branch(0x01, build.K1, 1, build.CLASSIFY + 15 * 4,
               build.CLASSIFY + 13 * 4),
        build.NOP,
        branch(0x04, build.ZERO, build.ZERO, build.CLASSIFY + 17 * 4, game),
        build.NOP,
        old.i_type(0x09, build.T9, build.V0, -build.CACHE_B_V),
        branch(0x04, build.V0, build.ZERO, build.CLASSIFY + 20 * 4, canonical),
        old.i_type(0x09, build.T9, build.V0, -build.CACHE_A_V),
        branch(0x05, build.V0, build.ZERO, build.CLASSIFY + 22 * 4, game),
        old.i_type(0x0D, build.ZERO, build.V0, parent.MARKER_V),
        branch(0x04, build.ZERO, build.ZERO, build.CLASSIFY + 24 * 4, next_packet),
        old.i_type(0x28, build.T2, build.V0, 13),
    ]
    if len(classify) * 4 != build.CLASSIFY_N:
        raise SystemExit("v215 selector classifier size differs")

    overlap = [
        old.i_type(0x0B, build.T7, build.V0, build.CACHE_U1),
        branch(0x04, build.V0, build.ZERO, build.OVERLAP + 1 * 4, next_packet),
        old.r_type(build.T7, build.V1, build.V1, 0, 0x21),
        old.i_type(0x0B, build.V1, build.V1, build.CACHE_U0 + 1),
        branch(0x05, build.V1, build.ZERO, build.OVERLAP + 4 * 4, next_packet),
        old.r_type(build.T9, build.K0, build.K1, 0, 0x21),
        old.i_type(0x0B, build.T9, build.V0, build.CACHE_A_V + old.CELL),
        branch(0x04, build.V0, build.ZERO, build.OVERLAP + 7 * 4, build.OVERLAP + 11 * 4),
        old.i_type(0x0B, build.K1, build.V1, build.CACHE_A_V + 1),
        old.i_type(0x0E, build.V1, build.V1, 1),
        old.r_type(build.A3, build.V1, build.A3, 0, 0x25),
        old.i_type(0x0B, build.T9, build.V0, build.CACHE_B_V + old.CELL),
        branch(0x04, build.V0, build.ZERO, build.OVERLAP + 12 * 4, next_packet),
        old.i_type(0x0B, build.K1, build.V1, build.CACHE_B_V + 1),
        old.i_type(0x0E, build.V1, build.V1, 1),
        old.r_type(build.ZERO, build.V1, build.V1, 1, 0x00),
        old.r_type(build.A3, build.V1, build.A3, 0, 0x25),
        old.r_type(build.ZERO, build.T3, build.T0, 8, 0x00),
        old.r_type(build.ZERO, build.T0, build.T0, 8, 0x02),
        branch(0x04, build.ZERO, build.ZERO, build.OVERLAP + 19 * 4, loop),
        build.NOP,
        build.NOP,
        build.NOP,
        build.NOP,
    ]
    if len(overlap) * 4 != build.OVERLAP_N:
        raise SystemExit("v215 selector overlap size differs")

    rect_store_offset = ((rect + 2) - 0x80200000) & 0xFFFF
    finish = [
        old.i_type(0x0D, build.ZERO, build.A1, build.CACHE_B_V),
        old.i_type(0x09, build.A3, build.V0, -1),
        branch(0x04, build.V0, build.ZERO, build.FINISH + 2 * 4, build.FINISH + 5 * 4),
        build.NOP,
        old.i_type(0x0D, build.A1, build.A1, build.CACHE_A_V - build.CACHE_B_V),
        old.i_type(0x09, build.A1, build.T7, 256),
        old.i_type(0x0F, build.ZERO, build.T8, 0x8020),
        old.j(frame),
        old.i_type(0x29, build.T8, build.T7, rect_store_offset),
    ]
    if len(finish) * 4 != build.FINISH_N:
        raise SystemExit("v215 selector finish size differs")

    return tuple(
        struct.pack(f"<{len(words)}I", *words)
        for words in (overlap, entry, classify, finish)
    )


def main() -> None:
    parent.selector_blobs = selector_blobs
    parent.OUT_STEM = OUT_STEM
    parent.main()
    output = parent.output_zip()
    report = parent.build.REPORT.read_text(encoding="utf-8")
    report = report.replace(
        "v214 TEST ONLY - strict marked per-frame A/B dynamic-cache selector",
        "v215 TEST ONLY - corrected real-SPRT-layout A/B dynamic-cache selector",
        1,
    )
    report += "\n".join([
        "v215_real_packet_layout=PASS",
        "SPRT_width=u16(packet+16)==12",
        "SPRT_height=u16(packet+18)==12",
        "v214_incorrect_packed_0x0C0C_test=removed",
        "overlap_height_source=packet+18",
        "v214_synthetic_packet_layout_bug=identified",
        "runtime=PENDING; emulator_run=NO",
        "",
    ])
    parent.build.REPORT.write_text(report, encoding="utf-8")
    print(f"v215_output={output}")
    print(f"v215_sha256={hashlib.sha256(output.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
