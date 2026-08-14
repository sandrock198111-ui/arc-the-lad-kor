#!/usr/bin/env python3
"""Build v219 TEST ONLY: fail-closed cache markers and owner decoding.

v218 borrowed and restored the selected cache rectangle correctly in the
static model, but its frame tail treated every OT node whose byte +13 was FF
as a cache glyph.  A normal zero-word OT link node on the BIOS screen already
has that byte value.  v218 consequently persisted an all-active mask, then
decoded empty owner sentinels (FFFF) as source 65535.

This successor keeps v218's one-DrawOT borrow/restore design while changing
the transient marker to a paired signature:

    marker_V = 0xFF - packet_U

The frame accepts the signature only on a four-word DMA packet.  The selector
still writes it only after the complete v215 strict SPRT classifier succeeds.
Owner values are also range-checked before Huffman decoding, so FFFF and every
other invalid source id fail closed.

The temporary stack layout is compacted from 0x2C0 to the mathematical 0x270
minimum for the 504-byte VRAM backup, 72-byte decode buffer, saved A0 and nine
callee-saved registers.  Kernel-reserved k0/k1 are not used.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile

import build_arc1_v218_borrow_restore_selected_cache as v218


v216 = v218.v216
build = v218.build
old = v218.old
v171 = build.v171
v190 = build.v190

OUT_STEM = "arc1_v219_failclosed_borrow_restore_TEST_ONLY"
MARKER_REPORT = build.ROOT / "01_work/analysis/arc1_cache_marker_uv_complement/report.txt"
FRAME = v218.FRAME
FRAME_N = v218.FRAME_N
STOREIMAGE = v218.STOREIMAGE
GPU_SYNC = v218.GPU_SYNC
BACKUP_BYTES = v218.BACKUP_BYTES
STACK_SIZE = 0x270
MARKER_SUM = 0xFF

ZERO, V0, A0, A1 = build.ZERO, build.V0, build.A0, build.A1
T0, T1, T2, T3, T4, T5, T6, T7 = (
    build.T0, build.T1, build.T2, build.T3,
    build.T4, build.T5, build.T6, build.T7,
)
T8, T9 = build.T8, build.T9
SP, RA = build.SP, build.RA
S0, S1, S2, S3, S4, S5, S6, S7 = (
    build.S0, build.S1, build.S2, build.S3,
    build.S4, build.S5, build.S6, build.S7,
)
NOP = build.NOP
JR_RA = old.r_type(RA, ZERO, ZERO, 0, 0x08)


ORIGINAL_V216_SELECTOR_BLOBS = v216.selector_blobs


def require_marker_audit() -> str:
    if not MARKER_REPORT.exists():
        raise SystemExit("v219 paired-marker audit report is missing")
    text = MARKER_REPORT.read_text(encoding="utf-8", errors="strict")
    lines = text.splitlines()
    required = (
        "savestates_failed=0",
        "existing_paired_marker_signature=0",
        "bios_false_node_seen=1",
        "bios_false_node_signature=0",
    )
    missing = [item for item in required if item not in lines]
    if missing:
        raise SystemExit(f"v219 paired-marker audit does not prove safety: {missing}")
    return text


def require_legacy_marker_audit_current_corpus() -> str:
    """Keep the inherited v214 guard without freezing its old state count."""
    path = v216.parent.MARKER_REPORT
    if not path.exists():
        raise SystemExit("legacy V=255 marker audit report is missing")
    text = path.read_text(encoding="utf-8", errors="strict")
    lines = text.splitlines()
    required = ("savestates_failed=0", "existing_marker_signature_V255=0")
    missing = [item for item in required if item not in lines]
    if missing:
        raise SystemExit(f"legacy marker audit does not prove safety: {missing}")
    return text


def signature_selector_blobs(frame: int, rect: int) -> tuple[bytes, bytes, bytes, bytes]:
    """Replace the ambiguous V=255 marker with V=(255-U)."""
    overlap, entry, classify, finish = ORIGINAL_V216_SELECTOR_BLOBS(frame, rect)
    words = list(struct.unpack(f"<{len(classify) // 4}I", classify))
    before = old.i_type(0x0D, ZERO, V0, v216.parent.MARKER_V)
    # nor v0,t7,zero: the stored low byte is 0xFF-U for the seven cache U's.
    after = old.r_type(T7, ZERO, V0, 0, 0x27)
    hits = [index for index, word in enumerate(words) if word == before]
    if hits != [23]:
        raise SystemExit(f"v219 selector marker instruction differs: {hits}")
    words[hits[0]] = after
    classify = struct.pack(f"<{len(words)}I", *words)
    return overlap, entry, classify, finish


def failclosed_frame(address: int, huffman_address: int,
                     layout: dict[str, tuple[int, int]]) -> bytes:
    owners = layout["owners"][0]
    active = layout["active_mask"][0]
    rect = layout["upload_rect"][0]
    expand = layout["nibble_expand"][0]
    if address != FRAME or active - rect != -8 or owners - rect != -66:
        raise SystemExit("v219 resident frame/layout address differs")

    decoded_at = 0x00
    backup_at = 0x48
    saved_a0 = 0x240
    save = {
        RA: 0x264, S0: 0x260, S1: 0x25C, S2: 0x258,
        S3: 0x254, S4: 0x250, S5: 0x24C, S6: 0x248, S7: 0x244,
    }
    if decoded_at + 72 > backup_at:
        raise SystemExit("v219 decode buffer overlaps VRAM backup")
    if backup_at + BACKUP_BYTES != saved_a0:
        raise SystemExit("v219 VRAM backup does not end at saved A0")
    if max(save.values()) + 4 > STACK_SIZE:
        raise SystemExit("v219 saved registers exceed compact stack frame")

    asm = old.Assembler(address)
    asm.emit(old.i_type(0x09, SP, SP, -STACK_SIZE))
    for reg, offset in save.items():
        asm.emit(old.i_type(0x2B, SP, reg, offset))
    asm.emit(old.i_type(0x2B, SP, A0, saved_a0))

    old.load_address(asm, S4, rect)
    asm.emit(old.i_type(0x0D, ZERO, S7, build.CACHE_A_Y))
    asm.branch(0x05, A1, ZERO, "destination_ready")
    asm.emit(NOP)
    asm.emit(old.i_type(0x0D, ZERO, S7, build.CACHE_B_Y))
    asm.label("destination_ready")
    asm.emit(old.i_type(0x29, S4, S7, 2))

    # The three resident objects are adjacent.  Relative addressing saves the
    # exact five words needed by the stronger marker signature below.
    asm.emit(old.i_type(0x23, S4, S0, active - rect))
    asm.emit(old.i_type(0x09, S4, S1, owners - rect))   # load-delay spacer
    asm.branch(0x04, S0, ZERO, "protect")
    asm.emit(old.move(S2, ZERO))

    asm.emit(old.i_type(0x09, ZERO, S2, 1))
    asm.emit(old.i_type(0x0D, ZERO, T0, 21))
    asm.emit(old.i_type(0x29, S4, T0, 4))
    asm.emit(old.move(A0, S4))
    asm.emit(old.jal(STOREIMAGE))
    asm.emit(old.i_type(0x09, SP, A1, backup_at))
    asm.emit(old.jal(GPU_SYNC))
    asm.emit(old.move(A0, ZERO))
    asm.emit(old.i_type(0x0D, ZERO, T0, 3))
    asm.emit(old.i_type(0x29, S4, T0, 4))

    asm.emit(old.i_type(0x09, SP, S3, decoded_at))
    asm.emit(old.move(S5, ZERO))
    asm.label("cell_loop")
    asm.emit(old.i_type(0x0C, S0, V0, 0x0F))
    asm.emit(old.r_type(ZERO, S0, S0, 4, 0x02))
    asm.branch(0x04, V0, ZERO, "cell_next")
    asm.emit(old.move(T0, SP))
    asm.emit(old.i_type(0x0D, ZERO, T1, 18))
    asm.label("clear_loop")
    asm.emit(old.i_type(0x2B, T0, ZERO, 0))
    asm.emit(old.i_type(0x09, T1, T1, -1))
    asm.branch(0x05, T1, ZERO, "clear_loop")
    asm.emit(old.i_type(0x09, T0, T0, 4))
    asm.emit(old.move(S6, ZERO))
    asm.label("plane_loop")
    asm.emit(old.r_type(ZERO, S5, T0, 3, 0x00))
    asm.emit(old.r_type(ZERO, S6, T1, 1, 0x00))
    asm.emit(old.r_type(T0, T1, T0, 0, 0x21))
    asm.emit(old.r_type(S1, T0, T0, 0, 0x21))
    asm.emit(old.i_type(0x25, T0, A0, 0))
    asm.emit(old.move(A1, S3))
    # Reject FFFF and every other corrupt/out-of-range owner before Huffman.
    asm.emit(old.i_type(0x0B, A0, T8, v190.plan.SOURCE_N))
    asm.branch(0x04, T8, ZERO, "plane_next")
    asm.emit(NOP)
    asm.emit(old.jal(huffman_address))
    asm.emit(NOP)
    old.load_address(asm, A0, expand)
    asm.emit(old.move(T0, S3))
    asm.emit(old.move(T1, SP))
    asm.emit(old.i_type(0x0D, ZERO, T2, old.CELL))
    asm.label("row_loop")
    asm.emit(old.i_type(0x25, T0, T3, 0))
    asm.emit(old.i_type(0x0D, ZERO, T4, 8))
    asm.label("nibble_loop")
    asm.emit(old.r_type(T4, T3, T6, 0, 0x06))
    asm.emit(old.i_type(0x0C, T6, T6, 0x0F))
    asm.emit(old.r_type(ZERO, T6, T6, 1, 0x00))
    asm.emit(old.r_type(A0, T6, T6, 0, 0x21))
    asm.emit(old.i_type(0x25, T6, T6, 0))
    asm.emit(old.i_type(0x25, T1, T7, 0))
    asm.emit(old.r_type(S6, T6, T6, 0, 0x04))
    asm.emit(old.r_type(T7, T6, T7, 0, 0x25))
    asm.emit(old.i_type(0x29, T1, T7, 0))
    asm.emit(old.i_type(0x09, T4, T4, -4))
    asm.branch(0x01, T4, 1, "nibble_loop")
    asm.emit(old.i_type(0x09, T1, T1, 2))
    asm.emit(old.i_type(0x09, T2, T2, -1))
    asm.branch(0x05, T2, ZERO, "row_loop")
    asm.emit(old.i_type(0x09, T0, T0, 2))
    asm.label("plane_next")
    asm.emit(old.i_type(0x09, S6, S6, 1))
    asm.emit(old.i_type(0x0B, S6, T0, old.PLANES))
    asm.branch(0x05, T0, ZERO, "plane_loop")
    asm.emit(old.r_type(ZERO, S5, T0, 1, 0x00))
    asm.emit(old.r_type(T0, S5, T0, 0, 0x21))
    asm.emit(old.i_type(0x09, T0, T0, v171.CACHE_X))
    asm.emit(old.i_type(0x29, S4, T0, 0))
    asm.emit(old.move(A0, S4))
    asm.emit(old.jal(old.LOADIMAGE))
    asm.emit(old.move(A1, SP))
    asm.label("cell_next")
    asm.emit(old.i_type(0x09, S5, S5, 1))
    asm.emit(old.i_type(0x0B, S5, T0, v190.CACHE_CELLS))
    asm.branch(0x05, T0, ZERO, "cell_loop")
    asm.emit(NOP)

    # Walk every OT node, but accept only a four-word packet carrying the
    # selector's paired U+V=255 signature.  The BIOS link node is count zero
    # with U=V=255 and therefore cannot pass this test.
    asm.label("protect")
    asm.emit(old.i_type(0x23, SP, T1, saved_a0))
    asm.emit(old.move(T8, ZERO))
    asm.emit(old.i_type(0x23, T1, T1, 0))
    asm.emit(old.i_type(0x0F, ZERO, T2, 0x0020))
    asm.emit(old.r_type(ZERO, T1, T1, 8, 0x00))
    asm.emit(old.r_type(ZERO, T1, T1, 8, 0x02))
    asm.emit(old.i_type(0x0D, ZERO, T9, v171.v166.OT_WALK_LIMIT))
    asm.label("ot_loop")
    asm.branch(0x04, T1, ZERO, "ot_done")
    asm.emit(old.r_type(T1, T2, T3, 0, 0x2B))
    asm.branch(0x04, T3, ZERO, "ot_done")
    asm.emit(old.i_type(0x0F, ZERO, T3, 0x8000))
    asm.emit(old.r_type(T3, T1, T3, 0, 0x25))
    asm.emit(old.i_type(0x23, T3, T4, 0))
    asm.emit(old.i_type(0x24, T3, T5, 13))
    asm.emit(old.i_type(0x24, T3, T6, 12))
    asm.emit(old.r_type(ZERO, T4, T7, 24, 0x02))
    asm.emit(old.r_type(ZERO, T4, T1, 8, 0x00))
    asm.emit(old.i_type(0x09, T7, T7, -4))
    asm.branch(0x05, T7, ZERO, "ot_next")
    asm.emit(old.r_type(T5, T6, T5, 0, 0x21))
    asm.emit(old.i_type(0x09, T5, T5, -MARKER_SUM))
    asm.branch(0x05, T5, ZERO, "ot_next")
    asm.emit(NOP)
    asm.emit(old.i_type(0x09, ZERO, T8, -1))
    asm.emit(old.i_type(0x28, T3, S7, 13))
    asm.label("ot_next")
    asm.emit(old.r_type(ZERO, T1, T1, 8, 0x02))
    asm.emit(old.i_type(0x09, T9, T9, -1))
    asm.branch(0x05, T9, ZERO, "ot_loop")
    asm.emit(NOP)
    asm.label("ot_done")
    asm.emit(old.i_type(0x2B, S4, T8, active - rect))
    asm.emit(old.i_type(0x23, SP, A0, saved_a0))
    asm.emit(old.jal(old.DRAWOT))
    asm.emit(NOP)

    asm.branch(0x04, S2, ZERO, "restore_done")
    asm.emit(old.move(A0, ZERO))
    asm.emit(old.jal(GPU_SYNC))
    asm.emit(NOP)
    asm.emit(old.i_type(0x0D, ZERO, T0, v171.CACHE_X))
    asm.emit(old.i_type(0x29, S4, T0, 0))
    asm.emit(old.i_type(0x0D, ZERO, T0, 21))
    asm.emit(old.i_type(0x29, S4, T0, 4))
    asm.emit(old.move(A0, S4))
    asm.emit(old.jal(old.LOADIMAGE))
    asm.emit(old.i_type(0x09, SP, A1, backup_at))
    asm.label("restore_done")

    for reg, offset in save.items():
        asm.emit(old.i_type(0x23, SP, reg, offset))
    asm.emit(JR_RA)
    asm.emit(old.i_type(0x09, SP, SP, STACK_SIZE))

    if len(asm.words) != FRAME_N // 4:
        raise SystemExit(
            f"v219 frame size differs: {len(asm.words) * 4}/{FRAME_N} bytes"
        )
    result = asm.finish()
    if len(result) != FRAME_N:
        raise SystemExit("v219 resident frame byte size differs")
    return result


def one_v218_archive() -> Path:
    matches = sorted(build.OUT_DIR.glob(
        "arc1_v218_borrow_restore_selected_cache_TEST_ONLY_????????.zip"
    ))
    if len(matches) != 1:
        raise SystemExit(f"expected one v218 archive, found: {matches}")
    return matches[0]


def one_output() -> Path:
    matches = sorted(build.OUT_DIR.glob(f"{OUT_STEM}_????????.zip"))
    if len(matches) != 1:
        raise SystemExit(f"expected one v219 archive, found: {matches}")
    return matches[0]


def main() -> None:
    marker_audit = require_marker_audit()
    # v214 encoded the then-current corpus size (435) as a permanent literal.
    # The corpus has since grown; retain its safety predicates, not stale count.
    v216.parent.require_marker_audit = require_legacy_marker_audit_current_corpus
    parent = one_v218_archive()
    v216.selector_blobs = signature_selector_blobs
    v216.safe_frame = failclosed_frame
    # The inherited v214 wrapper rewrites a V=224 comparison to V=255.  v219
    # has no such comparison; its paired-signature frame is already final.
    v216.parent.marked_frame = failclosed_frame
    v216.OUT_STEM = OUT_STEM
    v216.main()

    output = one_output()
    with ZipFile(parent) as archive:
        before = {item.filename: archive.read(item.filename)
                  for item in archive.infolist()}
    with ZipFile(output) as archive:
        after = {item.filename: archive.read(item.filename)
                 for item in archive.infolist()}
    changed = [name for name in before if before[name] != after[name]]
    if changed != [build.PSX]:
        raise SystemExit(f"v219 changed unexpected members: {changed}")
    if any(len(before[name]) != len(after[name]) for name in before):
        raise SystemExit("v219 changed an archive member size")

    report = build.REPORT.read_text(encoding="utf-8")
    report = report.replace(
        "v216 TEST ONLY - selector handoff relocated out of game-owned RAM",
        "v219 TEST ONLY - fail-closed paired-marker borrow/restore",
        1,
    )
    report += "\n".join([
        f"parent={parent.name}",
        f"resident_frame=0x{FRAME:08X} size={FRAME_N} unchanged",
        "marker_signature=DMA_words_4 AND (U+V==255)",
        "marker_corpus=" + next(
            line.split("=", 1)[1] for line in marker_audit.splitlines()
            if line.startswith("savestates_total=")
        ) + " savestates; all OT node kinds included",
        "strict_selector_marker_V=255-U",
        f"owner_guard=unsigned_source_id<{v190.plan.SOURCE_N}; FFFF rejected",
        f"stack_frame=0x{STACK_SIZE:X} ({STACK_SIZE}) down_from_v218_0x2C0",
        "kernel_reserved_registers_in_frame=0",
        "persistent_RAM_growth=0; resident_growth=0; heap_boundary=unchanged",
        "new_VRAM=0; DAT=unchanged; COMM.IMG=unchanged",
        "runtime=PENDING; emulator_run=NO",
        "rollback=v210; v218 runtime FAIL at BIOS/game-init boundary",
        "",
    ])
    build.REPORT.write_text(report, encoding="utf-8")
    print(f"v219_output={output}")
    print(f"v219_sha256={hashlib.sha256(output.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
