#!/usr/bin/env python3
"""Build v218 TEST ONLY: borrow the selected cache rectangle for one DrawOT.

v216 can select destination A or B without touching the rectangle used by the
current OT.  Its missing lifetime rule is that pixels written on an earlier
frame remain in VRAM after the destination is returned to the game.  The world
map therefore samples old Hangul pixels from A even though the selector has
correctly moved the current cache upload to B.

This frame routine keeps the v216 selector and resident layout.  Only while a
dynamic cache mask is active it:

1. reads the selected 21x12-halfword rectangle to a 504-byte stack buffer;
2. waits for StoreImage's asynchronous DMA tail;
3. composes and uploads the requested completed Hangul cells;
4. executes the original DrawOT;
5. waits for that draw and restores the saved rectangle.

No persistent RAM, VRAM, archive member, DAT, COMM.IMG, heap boundary, or
resident size is added.  The 504-byte backup exists only in this call frame.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile

import build_arc1_v216_relocate_selector_handoff as v216


build = v216.build
old = v216.old
v171 = build.v171
v190 = build.v190

OUT_STEM = "arc1_v218_borrow_restore_selected_cache_TEST_ONLY"
FRAME = 0x801FF668
FRAME_N = 584
STOREIMAGE = 0x801780FC
GPU_SYNC = 0x80176BA8
BACKUP_BYTES = 21 * old.CELL * 2

ZERO, A0, A1 = build.ZERO, build.A0, build.A1
T0, T1, T2, T3, T4, T5, T6, T7 = (
    build.T0, build.T1, build.T2, build.T3,
    build.T4, build.T5, build.T6, build.T7,
)
T8, T9, K0 = build.T8, build.T9, build.K0
SP, RA = build.SP, build.RA
S0, S1, S2, S3, S4, S5, S6, S7 = (
    build.S0, build.S1, build.S2, build.S3,
    build.S4, build.S5, build.S6, build.S7,
)
NOP = build.NOP
JR_RA = old.r_type(RA, ZERO, ZERO, 0, 0x08)


def borrow_restore_frame(address: int, huffman_address: int,
                         layout: dict[str, tuple[int, int]]) -> bytes:
    owners = layout["owners"][0]
    active = layout["active_mask"][0]
    rect = layout["upload_rect"][0]
    expand = layout["nibble_expand"][0]
    if address != FRAME or active - rect != -8:
        raise SystemExit("v218 resident frame/layout address differs")

    stack_size = 0x2C0
    backup_at = 0x80
    decoded_at = 0x48
    saved_a0 = 0x280
    save = {
        RA: 0x2BC, S0: 0x2B8, S1: 0x2B4, S2: 0x2B0,
        S3: 0x2AC, S4: 0x2A8, S5: 0x2A4, S6: 0x2A0, S7: 0x29C,
    }
    if backup_at + BACKUP_BYTES > saved_a0:
        raise SystemExit("v218 stack backup overlaps saved registers")

    asm = old.Assembler(address)
    asm.emit(old.i_type(0x09, SP, SP, -stack_size))
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

    old.load_address(asm, T0, active)
    asm.emit(old.i_type(0x23, T0, S0, 0))
    old.load_address(asm, S1, owners)                    # load-delay spacer
    asm.branch(0x04, S0, ZERO, "protect")
    asm.emit(old.move(S2, ZERO))                         # branch delay: not borrowed

    # Borrow the complete seven-cell destination. StoreImage leaves a DMA tail,
    # so the linked GPU synchroniser is mandatory before this buffer is trusted.
    asm.emit(old.i_type(0x09, ZERO, S2, 1))
    asm.emit(old.i_type(0x0D, ZERO, T0, 21))
    asm.emit(old.i_type(0x29, S4, T0, 4))
    asm.emit(old.move(A0, S4))
    asm.emit(old.jal(STOREIMAGE))
    asm.emit(old.i_type(0x09, SP, A1, backup_at))
    asm.emit(old.move(A0, ZERO))
    asm.emit(old.jal(GPU_SYNC))
    asm.emit(NOP)
    asm.emit(old.i_type(0x0D, ZERO, T0, 3))
    asm.emit(old.i_type(0x29, S4, T0, 4))

    asm.emit(old.i_type(0x09, SP, S3, decoded_at))
    asm.emit(old.move(S5, ZERO))
    asm.label("cell_loop")
    asm.emit(old.i_type(0x0C, S0, K0, 0x0F))
    asm.emit(old.r_type(ZERO, S0, S0, 4, 0x02))
    asm.branch(0x04, K0, ZERO, "cell_next")
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
    asm.emit(old.i_type(0x09, A0, T8, 1))
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

    # V=255 is a transient marker written by the immediately preceding strict
    # selector.  The 435-state preflight found zero pre-existing occurrences.
    # Any marker keeps all seven cells live for the next persistent-OT frame.
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
    asm.emit(old.r_type(ZERO, T4, T1, 8, 0x00))         # load-delay spacer
    asm.emit(old.i_type(0x09, T5, T5, -v171.CACHE_V))   # v214 builder retargets to V=255
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
    asm.emit(NOP)
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
    asm.emit(old.i_type(0x09, SP, SP, stack_size))

    if len(asm.words) > FRAME_N // 4:
        raise SystemExit(
            f"v218 frame grew beyond resident boundary: {len(asm.words) * 4} bytes"
        )
    while len(asm.words) < FRAME_N // 4:
        asm.emit(NOP)
    result = asm.finish()
    if len(result) != FRAME_N:
        raise SystemExit("v218 resident frame size differs")
    return result


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
        raise SystemExit(f"expected one v218 archive, found: {matches}")
    return matches[0]


def main() -> None:
    parent = one_v216_archive()
    v216.safe_frame = borrow_restore_frame
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
        raise SystemExit(f"v218 changed unexpected members: {changed}")
    if any(len(before[name]) != len(after[name]) for name in before):
        raise SystemExit("v218 changed an archive member size")

    old_finish_at = old.file_at(build.FINISH)
    if after[build.PSX][old_finish_at:old_finish_at + v216.OLD_FINISH_N] != \
            before[build.PSX][old_finish_at:old_finish_at + v216.OLD_FINISH_N]:
        raise SystemExit("v218 changed the game-owned old selector finish range")

    report = build.REPORT.read_text(encoding="utf-8")
    report = report.replace(
        "v216 TEST ONLY - selector handoff relocated out of game-owned RAM",
        "v218 TEST ONLY - one-DrawOT borrow/restore of selected cache rectangle",
        1,
    )
    report += "\n".join([
        f"parent={parent.name}",
        f"resident_frame=0x{FRAME:08X} size={FRAME_N} unchanged",
        f"temporary_backup=stack+0x80 size={BACKUP_BYTES}",
        "borrow_rect=x961,y(selected_384_or_480),w21,h12",
        "active_call_order=StoreImage -> GPU_sync -> cache_LoadImage(s) -> DrawOT -> GPU_sync -> restore_LoadImage",
        "inactive_call_order=DrawOT_only",
        "persistent_marker_policy=any_strict_V255_marker_keeps_all_28_slots_live_next_frame",
        "persistent_RAM_growth=0; resident_growth=0; heap_boundary=unchanged",
        "new_VRAM=0; DAT=unchanged; COMM.IMG=unchanged",
        "runtime=PENDING; emulator_run=NO",
        "rollback=v210; v214-v217 are runtime failures",
        "",
    ])
    build.REPORT.write_text(report, encoding="utf-8")
    print(f"v218_output={output}")
    print(f"v218_sha256={hashlib.sha256(output.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
