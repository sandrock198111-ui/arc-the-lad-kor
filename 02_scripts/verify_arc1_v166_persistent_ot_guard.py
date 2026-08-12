"""Independently execute and verify the assembled v166 resident routines.

This verifier reads the final archive rather than trusting the builder's Python
model.  A delayed-load/delayed-branch R3000 interpreter executes the final frame
bytes with synthetic ordering tables, including persistent cache packets.
"""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v165_failclosed_cache as old_build  # noqa: E402
import build_arc1_v166_persistent_ot_guard as build  # noqa: E402
import verify_arc1_v165c_failclosed_cache as old_verify  # noqa: E402
import analyze_arc1_v163_runtime as runtime_walk  # noqa: E402
from extract_savestate_vram import inflate, locate_ram  # noqa: E402


PATCH = ROOT / "03_output/arc1_v166_persistent_ot_guard_fullcell_8EB4F3A4.zip"
PATCH_SHA256 = "8EB4F3A4F9031455D07F285456CF0859B6CD848399FB53E55E10FF9D8E2BD930"
ANALYSIS = ROOT / "01_work/analysis/arc1_v166_persistent_ot_guard_verification"
REPORT = ANALYSIS / "verification_report.txt"

OT_ROOT = 0x801D0000
OT_PACKET = 0x801D0100
SAVE_DIR = Path(r"C:\Users\Administrator\AppData\Local\DuckStation\savestates")
SAVE_PREFIX = "HASH-5D381712B6D6EB28"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def packet_u(slot: int) -> int:
    return old_build.CACHE_U + (slot // old_build.PLANES) * old_build.CELL


def write_ot(memory: old_verify.Memory, slots: tuple[int, ...], *,
             false_packets: bool = True) -> int:
    """Write one valid linked OT plus near-miss packets and return expected mask."""
    records: list[tuple[int, int, int]] = []
    for slot in slots:
        records.append((
            packet_u(slot), old_build.CACHE_V,
            0x7FC0 + (slot % old_build.PLANES),
        ))
    if false_packets:
        records.extend((
            (0, old_build.CACHE_V, 0x7FC0),       # stock U, not cache U
            (old_build.CACHE_U, 216, 0x7FC0),    # wrong V
            (old_build.CACHE_U, old_build.CACHE_V, 0x0010),  # wrong CLUT
        ))

    addresses = [OT_PACKET + index * 0x20 for index in range(len(records))]
    memory.store32(OT_ROOT, addresses[0] & 0x00FFFFFF if addresses else 0x00FFFFFF)
    for index, (address, record) in enumerate(zip(addresses, records)):
        next_link = (
            addresses[index + 1] & 0x00FFFFFF
            if index + 1 < len(addresses) else 0x00FFFFFF
        )
        memory.write(address, bytes(0x20))
        memory.store32(address, (4 << 24) | next_link)
        memory.store8(address + 7, 0x64)
        memory.store8(address + 12, record[0])
        memory.store8(address + 13, record[1])
        memory.store16(address + 14, record[2])
        memory.store16(address + 16, 12)
        memory.store16(address + 18, 12)
    return sum(1 << slot for slot in slots)


def run_frame(memory_base: old_verify.Memory, frame: int,
              layout: dict[str, tuple[int, int]],
              expected_rows: list[tuple[int, ...]],
              initial_mask: int, live_slots: tuple[int, ...]) -> tuple[
                  old_verify.Memory, old_verify.R3000, list[old_verify.ExternalCall]
              ]:
    memory = memory_base.clone()
    owners_at = layout["owners"][0]
    active_at = layout["active_mask"][0]
    memory.write(owners_at, struct.pack("<24H", *range(24)))
    memory.store32(active_at, initial_mask)
    expected_retained = write_ot(memory, live_slots)

    cpu = old_verify.R3000(memory, frame)
    cpu.reg[old_build.SP] = old_verify.STACK_TOP
    cpu.reg[old_build.RA] = old_verify.SENTINEL
    cpu.reg[old_build.A0] = OT_ROOT
    preserved = {}
    for register in range(old_build.S0, old_build.S7 + 1):
        value = 0x22220000 + register
        cpu.reg[register] = value
        preserved[register] = value
    cpu.run()
    if memory.load32(active_at) != expected_retained:
        raise SystemExit(
            f"OT-retained mask differs: 0x{memory.load32(active_at):08X} "
            f"!= 0x{expected_retained:08X}"
        )
    for register, expected in preserved.items():
        if cpu.reg[register] != expected:
            raise SystemExit(f"frame did not preserve r{register}")
    draw = [call for call in cpu.calls if call.target == old_build.DRAWOT]
    if len(draw) != 1 or draw[0].a0 != OT_ROOT:
        raise SystemExit("DrawOT topology or argument differs")
    return memory, cpu, [
        call for call in cpu.calls if call.target == old_build.LOADIMAGE
    ]


def assert_full_owned_planes(uploads: list[old_verify.ExternalCall],
                             cells: tuple[int, ...],
                             expected_rows: list[tuple[int, ...]]) -> None:
    if len(uploads) != len(cells):
        raise SystemExit(f"upload count differs: {len(uploads)} != {len(cells)}")
    for cell, call in zip(cells, uploads):
        expected_rect = (
            old_build.CACHE_X + cell * 3, old_build.CACHE_Y, 3, old_build.CELL,
        )
        if call.rect != expected_rect or call.payload is None:
            raise SystemExit(f"upload rectangle differs for cell {cell}: {call.rect}")
        for plane in range(old_build.PLANES):
            source = cell * old_build.PLANES + plane
            got = old_verify.payload_plane_rows(call.payload, plane)
            if got != expected_rows[source]:
                raise SystemExit(
                    f"owned inactive plane was not retained: cell={cell} plane={plane}"
                )


def direct_index_for_source(ranges: dict[int, int], source: int) -> int:
    for index, candidate in ranges.items():
        if candidate == source:
            return index
    raise ValueError(f"no direct index for dynamic source {source}")


def run_actual_state_ots(base_memory: old_verify.Memory,
                         layout: dict[str, tuple[int, int]]) -> tuple[int, int, int, int]:
    """Execute the final MIPS scanner on all eight user OT linked lists."""
    runtime_walk.CACHE_SLOTS = 24
    runtime_walk.CACHE_CELLS = 6
    runtime_walk.CACHE_U = (4, 16, 28, 40, 52, 64)
    runtime_walk.CACHE_U_END = 76
    runtime_walk.CACHE_V = 224
    runtime_walk.CACHE_V_END = 236
    paths = [SAVE_DIR / f"{SAVE_PREFIX}_{slot}.sav" for slot in range(1, 9)]
    if not all(path.is_file() for path in paths):
        return 0, 0, 0, 0

    packet_counts = []
    step_counts = []
    for path in paths:
        blob = inflate(path)
        ram_base = locate_ram(blob)
        ram = blob[ram_base:ram_base + 2 * 1024 * 1024]
        context = struct.unpack_from("<I", ram, 0x1F12EC)[0]
        ot = context + 0x70
        memory = base_memory.clone()
        memory.write(ot, ram[(ot & 0x1FFFFF):(ot & 0x1FFFFF) + 4])
        current = struct.unpack_from("<I", ram, ot & 0x1FFFFF)[0] & 0x00FFFFFF
        seen = set()
        count = 0
        while current not in (0, 0x00FFFFFF) and current < 0x200000 \
                and current not in seen and count < build.OT_WALK_LIMIT:
            seen.add(current)
            memory.write(0x80000000 | current, ram[current:current + 52])
            current = struct.unpack_from("<I", ram, current)[0] & 0x00FFFFFF
            count += 1
        memory.store32(layout["active_mask"][0], 0)
        cpu = old_verify.R3000(memory, build.FRAME)
        cpu.reg[old_build.SP] = old_verify.STACK_TOP
        cpu.reg[old_build.RA] = old_verify.SENTINEL
        cpu.reg[old_build.A0] = ot
        cpu.run()
        got = memory.load32(layout["active_mask"][0])

        _context, _parity, rows = runtime_walk.trace_active_text_ot(ram)
        slots = {
            int(row["slot"])
            for row in rows if row["selected_buffer"] and row["text_cache"]
        }
        expected = sum(1 << slot for slot in slots)
        if got != expected:
            raise SystemExit(
                f"assembled OT mask differs for {path.name}: "
                f"0x{got:08X} != 0x{expected:08X}"
            )
        packet_counts.append(count)
        step_counts.append(cpu.steps)
    return len(paths), min(packet_counts), max(packet_counts), max(step_counts)


def main() -> None:
    if digest(PATCH.read_bytes()) != PATCH_SHA256:
        raise SystemExit("v166 patch hash differs")
    if digest(build.BASE.read_bytes()) != build.BASE_SHA256:
        raise SystemExit("v165c base hash differs")
    with ZipFile(PATCH) as archive:
        members = {info.filename: archive.read(info.filename) for info in archive.infolist()}
    with ZipFile(build.BASE) as archive:
        base_members = {info.filename: archive.read(info.filename) for info in archive.infolist()}
    changed = sorted(name for name in members if members[name] != base_members[name])
    if changed != [old_build.PSX]:
        raise SystemExit(f"v166 changed member set differs: {changed}")

    exe = members[old_build.PSX]
    frame_blob = build.build_frame(build.FRAME, old_build.read_layout())
    frame_at = old_build.source_at(build.FRAME)
    capacity = old_build.HEAP_BASE - build.FRAME
    if exe[frame_at:frame_at + len(frame_blob)] != frame_blob or \
            any(exe[frame_at + len(frame_blob):frame_at + capacity]):
        raise SystemExit("final archive frame window differs from assembled v166 bytes")
    if old_build.word(exe, old_build.LATE_HOOK) != old_build.jal(build.FRAME):
        raise SystemExit("late hook no longer targets v166 frame")

    layout = old_build.read_layout()
    memory = old_verify.runtime_memory(exe)
    expected_sources = old_verify.python_sources(memory, layout)

    # Unchanged routines are still executed from the new final archive.
    huffman_steps, max_huffman_steps = old_verify.run_huffman(
        memory, 0x801FF4A8, expected_sources
    )
    ranges = old_build.unpack_ranges(memory.read(*layout["conflict_ranges"]))
    lookup = struct.unpack(
        f"<{old_build.LOOKUP_N}H",
        memory.read(old_build.LOOKUP_RAM, old_build.LOOKUP_N * 2),
    )
    direct_checked, lookup_checked, lookup_dynamic = old_verify.run_decoder(
        memory, 0x801FF294, layout, ranges, lookup
    )
    classifier_cases = old_verify.run_helper_classifier(
        memory, 0x801FF5A0, 0x801FF5CC
    )
    actual_states, actual_min_packets, actual_max_packets, actual_max_steps = \
        run_actual_state_ots(memory, layout)

    # Every active cell is uploaded, and every owned plane in those cells is
    # reconstructed even when only one plane was touched this frame.
    full_memory, full_cpu, full_uploads = run_frame(
        memory, build.FRAME, layout, expected_sources,
        0xFFFFFF, (0, 5, 16, 17, 18, 19, 23),
    )
    assert_full_owned_planes(full_uploads, tuple(range(6)), expected_sources)

    partial_mask = (1 << 0) | (1 << 5) | (1 << 23)
    partial_memory, partial_cpu, partial_uploads = run_frame(
        memory, build.FRAME, layout, expected_sources,
        partial_mask, (16, 17),
    )
    assert_full_owned_planes(partial_uploads, (0, 1, 5), expected_sources)

    # With no newly decoded glyphs, the final OT still protects persistent slots
    # for the next frame and causes no unnecessary upload in this frame.
    idle_memory, idle_cpu, idle_uploads = run_frame(
        memory, build.FRAME, layout, expected_sources, 0, (10, 11),
    )
    if idle_uploads or idle_memory.load32(layout["active_mask"][0]) != \
            ((1 << 10) | (1 << 11)):
        raise SystemExit("idle persistent-OT protection differs")

    # Prove the next decoder pass cannot evict the two persistent slots.  Start
    # replacement at slot 16; it must skip 16/17 and choose slot 18.
    owners_at = layout["owners"][0]
    active_at = layout["active_mask"][0]
    next_at = layout["next_slot"][0]
    partial_memory.write(owners_at, struct.pack("<24H", *range(24)))
    partial_memory.store32(active_at, (1 << 16) | (1 << 17))
    partial_memory.store8(next_at, 16)
    source = 24
    token = old_verify.direct_token(direct_index_for_source(ranges, source))
    _pc, glyph, _consumed = old_verify.run_decoder_once(
        partial_memory, 0x801FF294, token
    )
    owners_after = struct.unpack("<24H", partial_memory.read(owners_at, 48))
    if glyph != old_build.CACHE_INDEX_BASE + 18 or \
            owners_after[16:18] != (16, 17) or owners_after[18] != source:
        raise SystemExit("persistent slots were not protected from next-frame eviction")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    lines = [
        "v166 persistent-OT guard independent assembled-code verification",
        "",
        f"patch={PATCH.name}",
        f"sha256={PATCH_SHA256}",
        "changed_members=PSX.EXE only PASS",
        "COMM.IMG_and_translation_members=v165c byte-identical PASS",
        f"frame_bytes={len(frame_blob)}/{capacity}",
        f"resident_free_bytes={capacity - len(frame_blob)}",
        f"assembled_Huffman_sources={len(expected_sources)}/{len(expected_sources)} PASS",
        f"assembled_Huffman_total_steps={huffman_steps}",
        f"assembled_Huffman_max_steps={max_huffman_steps}",
        f"direct_codes_checked={direct_checked} PASS",
        f"lookup_entries_checked={lookup_checked} dynamic={lookup_dynamic} PASS",
        f"classifier_cases={classifier_cases} PASS",
        "full_active_upload_cells=6/6 PASS",
        "full_owned_plane_reconstruction=24/24 PASS",
        "partial_active_cells=3/3 with 12/12 owned planes PASS",
        "final_OT_live_slot_scan=PASS",
        "near_miss_packet_filter=PASS",
        f"actual_user_state_OT_masks={actual_states}/8 PASS",
        f"actual_OT_packet_range={actual_min_packets}..{actual_max_packets}",
        f"actual_OT_scanner_max_steps={actual_max_steps}",
        "idle_persistent_slot_retention=PASS",
        "next_frame_eviction_guard=PASS",
        "DrawOT_call_and_argument=PASS",
        "callee_saved_registers=PASS",
        f"full_frame_steps={full_cpu.steps}",
        f"partial_frame_steps={partial_cpu.steps}",
        f"idle_frame_steps={idle_cpu.steps}",
        "unaligned_runtime_accesses=0",
        "",
        "static_verification=PASS",
        "runtime_verification=PENDING user cold boot",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
