"""Build v214 TEST ONLY: strict A/B cache selection with a transient V marker.

v211 moved the upload rectangle but patched a dead U helper, so cache glyph
packets continued to read the old horizontal coordinate.  v213b made the A/B
selector strict, but its resident frame scan still identified packets more
loosely than the selector.  This build bridges those two stages without
growing the full resident block:

* the strict selector marks only proven cache SPRTs with V=255;
* the frame routine accepts only that transient marker;
* immediately before DrawOT it replaces V=255 with the selected real V
  (A=224 or B=128).

The available save-state corpus is audited separately and must contain zero
pre-existing packets matching the V=255 marker signature before this builder
will run.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile

import build_arc1_v213_strict_ab_cache_selector as build


MARKER_V = 255
OUT_STEM = "arc1_v214_marked_ab_cache_selector_TEST_ONLY"
MARKER_REPORT = build.ROOT / "01_work/analysis/arc1_cache_marker_v255/report.txt"


def require_marker_audit() -> str:
    if not MARKER_REPORT.exists():
        raise SystemExit("V=255 marker audit report is missing")
    text = MARKER_REPORT.read_text(encoding="utf-8", errors="strict")
    required = (
        "savestates_total=435",
        "savestates_decoded=435",
        "savestates_failed=0",
        "existing_marker_signature_V255=0",
    )
    missing = [line for line in required if line not in text.splitlines()]
    if missing:
        raise SystemExit(f"V=255 marker audit does not prove safety: {missing}")
    return text


def selector_blobs(frame: int, rect: int) -> tuple[bytes, bytes, bytes, bytes]:
    """Assemble a strict selector that tags only cache glyph SPRTs."""
    old = build.old
    branch = build.branch
    next_packet = build.OVERLAP + 19 * 4
    game = build.OVERLAP
    loop = build.ENTRY + 5 * 4
    dynamic = build.CLASSIFY + 16 * 4
    canonical = build.CLASSIFY + 22 * 4

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
        raise SystemExit("v214 selector entry size differs")

    # Width and height are compared as one little-endian halfword (0x0C0C).
    # Reloading them in the game-overlap fragment leaves room for the third
    # accepted V value, the transient marker 255.
    classify = [
        old.i_type(0x25, build.T2, build.V1, 16),
        old.i_type(0x09, build.T6, build.V0, -build.v171.v166.FONT_CLUT_MIN),
        old.i_type(0x0B, build.V0, build.V0, 16),
        branch(0x04, build.V0, build.ZERO, build.CLASSIFY + 3 * 4, game),
        old.i_type(0x09, build.V1, build.V1, -0x0C0C),
        branch(0x05, build.V1, build.ZERO, build.CLASSIFY + 5 * 4, game),
        old.i_type(0x09, build.T7, build.V0, -build.CACHE_U0),
        old.i_type(0x0B, build.V0, build.V1, build.CACHE_U1 - build.CACHE_U0),
        branch(0x04, build.V1, build.ZERO, build.CLASSIFY + 8 * 4, game),
        old.move(build.K1, build.V0),
        branch(0x04, build.K1, build.ZERO, build.CLASSIFY + 10 * 4, dynamic),
        old.i_type(0x09, build.K1, build.K1, -old.CELL),
        branch(0x01, build.K1, 1, build.CLASSIFY + 12 * 4, build.CLASSIFY + 10 * 4),
        build.NOP,
        branch(0x04, build.ZERO, build.ZERO, build.CLASSIFY + 14 * 4, game),
        build.NOP,
        old.i_type(0x09, build.T9, build.V0, -build.CACHE_B_V),
        branch(0x04, build.V0, build.ZERO, build.CLASSIFY + 17 * 4, canonical),
        old.i_type(0x09, build.T9, build.V0, -build.CACHE_A_V),
        branch(0x04, build.V0, build.ZERO, build.CLASSIFY + 19 * 4, canonical),
        old.i_type(0x09, build.T9, build.V0, -MARKER_V),
        branch(0x05, build.V0, build.ZERO, build.CLASSIFY + 21 * 4, game),
        old.i_type(0x0D, build.ZERO, build.V0, MARKER_V),
        branch(0x04, build.ZERO, build.ZERO, build.CLASSIFY + 23 * 4, next_packet),
        old.i_type(0x28, build.T2, build.V0, 13),
        build.NOP,
    ]
    if len(classify) * 4 != build.CLASSIFY_N:
        raise SystemExit("v214 selector classifier size differs")

    overlap = [
        old.i_type(0x24, build.T2, build.V1, 16),
        old.i_type(0x24, build.T2, build.K0, 17),
        old.i_type(0x0B, build.T7, build.V0, build.CACHE_U1),
        branch(0x04, build.V0, build.ZERO, build.OVERLAP + 3 * 4, next_packet),
        old.r_type(build.T7, build.V1, build.V1, 0, 0x21),
        old.i_type(0x0B, build.V1, build.V1, build.CACHE_U0 + 1),
        branch(0x05, build.V1, build.ZERO, build.OVERLAP + 6 * 4, next_packet),
        old.r_type(build.T9, build.K0, build.K1, 0, 0x21),
        old.i_type(0x0B, build.T9, build.V0, build.CACHE_A_V + old.CELL),
        branch(0x04, build.V0, build.ZERO, build.OVERLAP + 9 * 4, build.OVERLAP + 13 * 4),
        old.i_type(0x0B, build.K1, build.V1, build.CACHE_A_V + 1),
        old.i_type(0x0E, build.V1, build.V1, 1),
        old.r_type(build.A3, build.V1, build.A3, 0, 0x25),
        old.i_type(0x0B, build.T9, build.V0, build.CACHE_B_V + old.CELL),
        branch(0x04, build.V0, build.ZERO, build.OVERLAP + 14 * 4, next_packet),
        old.i_type(0x0B, build.K1, build.V1, build.CACHE_B_V + 1),
        old.i_type(0x0E, build.V1, build.V1, 1),
        old.r_type(build.ZERO, build.V1, build.V1, 1, 0x00),
        old.r_type(build.A3, build.V1, build.A3, 0, 0x25),
        old.r_type(build.ZERO, build.T3, build.T0, 8, 0x00),
        old.r_type(build.ZERO, build.T0, build.T0, 8, 0x02),
        branch(0x04, build.ZERO, build.ZERO, build.OVERLAP + 21 * 4, loop),
        build.NOP,
        build.NOP,
    ]
    if len(overlap) * 4 != build.OVERLAP_N:
        raise SystemExit("v214 selector overlap size differs")

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
        raise SystemExit("v214 selector finish size differs")
    return tuple(
        struct.pack(f"<{len(words)}I", *words)
        for words in (overlap, entry, classify, finish)
    )


ORIGINAL_BUILD_FRAME = build.v212.build_frame


def marked_frame(address: int, huffman_address: int,
                 layout: dict[str, tuple[int, int]]) -> bytes:
    blob = bytearray(ORIGINAL_BUILD_FRAME(address, huffman_address, layout))
    old_word = build.old.i_type(0x09, build.T5, build.T5, -build.v171.CACHE_V)
    new_word = build.old.i_type(0x09, build.T5, build.T5, -MARKER_V)
    words = list(struct.unpack(f"<{len(blob) // 4}I", blob))
    matches = [index for index, word in enumerate(words) if word == old_word]
    if len(matches) != 1:
        raise SystemExit(f"frame cache-V comparison count differs: {matches}")
    struct.pack_into("<I", blob, matches[0] * 4, new_word)
    if bytes(blob).count(struct.pack("<I", new_word)) != 1:
        raise SystemExit("frame marker comparison is not unique")
    return bytes(blob)


def model(packets: list[dict[str, int]]) -> tuple[int, list[int], int]:
    """Independent Python mirror for the marker handoff."""
    current_page = False
    flags = 0
    out: list[int] = []
    for packet in packets:
        if packet["cmd"] == 0xE1:
            current_page = (
                packet["tpage"] & build.PHYSICAL_TPAGE_MASK
            ) == build.PHYSICAL_TPAGE_X15_Y1_4BPP
            continue
        v = packet.get("v", 0)
        if not current_page or packet["cmd"] & 0xFC != 0x64 or packet.get("count", 4) != 4:
            out.append(v)
            continue
        u = packet["u"]
        is_cache = (
            build.v171.v166.FONT_CLUT_MIN <= packet["clut"] < build.v171.v166.FONT_CLUT_MIN + 16
            and packet["w"] == build.old.CELL and packet["h"] == build.old.CELL
            and build.CACHE_U0 <= u < build.CACHE_U1
            and (u - build.CACHE_U0) % build.old.CELL == 0
            and v in (build.CACHE_A_V, build.CACHE_B_V, MARKER_V)
        )
        if is_cache:
            out.append(MARKER_V)
            continue
        if u < build.CACHE_U1 and u + packet["w"] > build.CACHE_U0:
            bottom = v + packet["h"]
            if v < build.CACHE_A_V + build.old.CELL and bottom > build.CACHE_A_V:
                flags |= 1
            if v < build.CACHE_B_V + build.old.CELL and bottom > build.CACHE_B_V:
                flags |= 2
        out.append(v)
    selected = build.CACHE_B_V if flags == 1 else build.CACHE_A_V
    return selected, out, flags


def run_model_tests() -> None:
    tpage = {"cmd": 0xE1, "tpage": 31}
    font = {
        "cmd": 0x64, "count": 4, "u": build.CACHE_U0,
        "v": build.CACHE_A_V, "w": 12, "h": 12,
        "clut": build.v171.v166.FONT_CLUT_MIN,
    }
    game_a = dict(font, u=0, v=160, w=128, h=96, clut=0x79C0)
    game_b = dict(font, v=build.CACHE_B_V, clut=0x0010)
    if model([tpage, font]) != (224, [MARKER_V], 0):
        raise SystemExit("v214 model canonical marker failed")
    if model([tpage, dict(font, v=MARKER_V)]) != (224, [MARKER_V], 0):
        raise SystemExit("v214 model persistent marker failed")
    if model([tpage, dict(font, v=128), game_a]) != (128, [MARKER_V, 160], 1):
        raise SystemExit("v214 model A conflict failed")
    if model([tpage, game_b, font]) != (224, [128, MARKER_V], 2):
        raise SystemExit("v214 model B-only conflict failed")


def output_zip() -> Path:
    matches = sorted(build.OUT_DIR.glob(f"{OUT_STEM}_????????.zip"))
    if len(matches) != 1:
        raise SystemExit(f"expected one v214 output, found: {matches}")
    return matches[0]


def main() -> None:
    marker_audit = require_marker_audit()
    run_model_tests()

    build.selector_blobs = selector_blobs
    build.v212.build_frame = marked_frame
    build.OUT_STEM = OUT_STEM
    build.ANALYSIS = build.ROOT / "01_work/analysis" / OUT_STEM
    build.REPORT = build.ANALYSIS / "build_report.txt"
    build.DISASSEMBLY = build.ANALYSIS / "mips_disassembly.txt"
    build.main()

    output = output_zip()
    with ZipFile(output) as archive:
        exe = archive.read(build.PSX)
    layout, _blobs, code_base = build.v190.resident_layout()
    decoder_blob = build.v190.build_decoder(code_base, layout)
    huffman = (code_base + len(decoder_blob) + 3) & ~3
    huffman_blob = build.v190.build_huffman(huffman, layout)
    frame = (huffman + len(huffman_blob) + 3) & ~3
    source_at = build.old.file_at(build.v171.SOURCE_BASE)
    frame_at = source_at + frame - build.v171.RESIDENT_BASE
    frame_blob = marked_frame(frame, huffman, layout)
    if exe[frame_at:frame_at + len(frame_blob)] != frame_blob:
        raise SystemExit("archived v214 frame differs from marker frame")

    classify_at = build.old.file_at(build.CLASSIFY)
    classify = exe[classify_at:classify_at + build.CLASSIFY_N]
    marker_store = struct.pack("<I", build.old.i_type(0x28, build.T2, build.V0, 13))
    if classify.count(marker_store) != 1:
        raise SystemExit("selector marker store count differs")

    report = build.REPORT.read_text(encoding="utf-8")
    report = report.replace(
        "v213 TEST ONLY - strict per-frame A/B dynamic-cache selector",
        "v214 TEST ONLY - strict marked per-frame A/B dynamic-cache selector",
        1,
    )
    report += "\n".join([
        "v214_marker_handoff=PASS",
        f"transient_packet_marker_V={MARKER_V}",
        "strict_selector_writes_marker_only_to=DMA4+SPRT+physical_tpage+font_CLUT+12x12+cache_U+V(A/B/marker)",
        "resident_frame_accepts_only_marker_V=255 before rewriting selected real V",
        "marker_corpus_savestates=435",
        "marker_corpus_active_packets=299742",
        "marker_corpus_existing_signature=0",
        "selector_python_model=PASS",
        "archived_marker_frame_match=PASS",
        "runtime=PENDING; emulator_run=NO",
        "",
    ])
    build.REPORT.write_text(report, encoding="utf-8")
    print(f"v214_output={output}")
    print(f"v214_sha256={hashlib.sha256(output.read_bytes()).hexdigest().upper()}")
    print(marker_audit)


if __name__ == "__main__":
    main()
