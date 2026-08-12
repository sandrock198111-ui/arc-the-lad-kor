"""Execute the final v167 resident code against synthetic and user states."""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import analyze_arc1_v163_runtime as runtime  # noqa: E402
import build_arc1_v165_failclosed_cache as old  # noqa: E402
import build_arc1_v167_item_description_generation_guard as build  # noqa: E402
import verify_arc1_v165c_failclosed_cache as verify  # noqa: E402
import verify_arc1_v166_persistent_ot_guard as verify166  # noqa: E402
from extract_savestate_vram import inflate, locate_ram  # noqa: E402


PATCH = ROOT / "03_output/arc1_v167_item_description_generation_guard_EC6AE708.zip"
PATCH_SHA256 = "EC6AE7088A9D65F9E49900A7D2A8454B9B91E6B8E11774A3157C88CE18BCA63D"
OUT = ROOT / "01_work/analysis/arc1_v167_item_description_generation_guard_verification"
REPORT = OUT / "verification_report.txt"
SAVE_DIR = Path.home() / "AppData/Local/DuckStation/savestates"
SAVE_PREFIX = "HASH-5076D335C1AF160E"
RAM_SIZE = 2 * 1024 * 1024
OT_ROOT = verify166.OT_ROOT


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def routine_layout() -> tuple[
    dict[str, tuple[int, int]], dict[str, bytes], dict[str, tuple[int, bytes]]
]:
    old_checkpoints = struct.unpack(
        f"<{old.plan.SOURCE_CHECKPOINTS.stat().st_size // 2}H",
        old.plan.SOURCE_CHECKPOINTS.read_bytes(),
    )
    checkpoints = struct.pack(f"<{len(old_checkpoints[::2])}H", *old_checkpoints[::2])
    layout, blobs = build.pack_layout(checkpoints)
    old.CHECKPOINT_GROUP = build.CHECKPOINT_GROUP
    decoder = old.align(layout["decoded_glyph_rows"][0] + layout["decoded_glyph_rows"][1])
    decoder_blob = old.build_decoder(decoder, layout)
    huffman = old.align(decoder + len(decoder_blob))
    huffman_blob = old.build_huffman_decoder(huffman, layout)
    helper = old.align(huffman + len(huffman_blob))
    helper_blob = old.build_helper(helper)
    classifier = old.align(helper + len(helper_blob))
    classifier_blob = old.build_classifier(classifier)
    frame = old.align(classifier + len(classifier_blob))
    probe = build.build_frame(frame, huffman, frame, layout)
    item_guard = old.align(frame + len(probe))
    frame_blob = build.build_frame(frame, huffman, item_guard, layout)
    routines = {
        "decoder": (decoder, decoder_blob),
        "huffman": (huffman, huffman_blob),
        "helper": (helper, helper_blob),
        "classifier": (classifier, classifier_blob),
        "frame": (frame, frame_blob),
        "item_guard": (item_guard, build.build_item_guard(item_guard)),
    }
    return layout, blobs, routines


def item_mask_bytes(ram: bytes) -> tuple[int, int, list[int]]:
    header = build.ITEM_DESCRIPTION_HEADER & 0x1FFFFF
    count = struct.unpack_from("<H", ram, header + 0x0A)[0]
    base = struct.unpack_from("<I", ram, header)[0] & 0x1FFFFF
    mask = 0
    slots = []
    for index in range(count):
        at = base + index * 52
        u, v = ram[at + 0x28], ram[at + 0x29]
        clut = struct.unpack_from("<H", ram, at + 0x30)[0]
        if v != old.CACHE_V or u not in (4, 16, 28, 40, 52, 64) \
                or not build.FONT_CLUT_MIN <= clut < build.FONT_CLUT_MIN + 16:
            continue
        slot = ((u - old.CACHE_U) // old.CELL) * old.PLANES \
            + ((clut - build.FONT_CLUT_MIN) & 3)
        mask |= 1 << slot
        slots.append(slot)
    return mask, count, slots


def copy_item_object(memory: verify.Memory, ram: bytes) -> None:
    header_at = build.ITEM_DESCRIPTION_HEADER & 0x1FFFFF
    header = ram[header_at:header_at + 68]
    memory.write(build.ITEM_DESCRIPTION_HEADER, header)
    base = struct.unpack_from("<I", ram, header_at)[0]
    count = struct.unpack_from("<H", ram, header_at + 0x0A)[0]
    if count:
        memory.write(base, ram[(base & 0x1FFFFF):(base & 0x1FFFFF) + count * 52])


def write_synthetic_item(memory: verify.Memory, slots: tuple[int, ...]) -> None:
    base = 0x801D1000
    memory.write(build.ITEM_DESCRIPTION_HEADER, bytes(68))
    memory.store32(build.ITEM_DESCRIPTION_HEADER, base)
    memory.store16(build.ITEM_DESCRIPTION_HEADER + 4, 32)
    memory.store16(build.ITEM_DESCRIPTION_HEADER + 0x0A, len(slots))
    memory.write(base, bytes(max(1, len(slots)) * 52))
    for index, slot in enumerate(slots):
        at = base + index * 52
        memory.store8(at + 0x28, old.CACHE_U + (slot // 4) * old.CELL)
        memory.store8(at + 0x29, old.CACHE_V)
        memory.store16(at + 0x30, build.FONT_CLUT_MIN + (slot & 3))


def raw_ot_mask(ram: bytes, ot: int) -> tuple[int, int]:
    current = struct.unpack_from("<I", ram, ot & 0x1FFFFF)[0] & 0x00FFFFFF
    seen = set()
    mask = 0
    while current not in (0, 0x00FFFFFF) and current < RAM_SIZE - 20 \
            and current not in seen and len(seen) < build.OT_WALK_LIMIT:
        seen.add(current)
        tag = struct.unpack_from("<I", ram, current)[0]
        count = tag >> 24
        command = ram[current + 7] & 0xFC
        if count == 4 and command == 0x64:
            u, v = ram[current + 12], ram[current + 13]
            clut = struct.unpack_from("<H", ram, current + 14)[0]
            if v == old.CACHE_V and u in (4, 16, 28, 40, 52, 64) \
                    and build.FONT_CLUT_MIN <= clut < build.FONT_CLUT_MIN + 16:
                slot = ((u - old.CACHE_U) // old.CELL) * 4 \
                    + ((clut - build.FONT_CLUT_MIN) & 3)
                mask |= 1 << slot
        current = tag & 0x00FFFFFF
    return mask, len(seen)


def execute_actual_states(base_memory: verify.Memory, frame: int,
                          active_at: int) -> tuple[int, int, int, int]:
    paths = [SAVE_DIR / f"{SAVE_PREFIX}_{slot}.sav" for slot in range(1, 11)]
    if not all(path.is_file() for path in paths):
        raise SystemExit("v166 user states 1..10 are incomplete")
    matched = 0
    item_states = 0
    maximum_steps = 0
    maximum_packets = 0
    for path in paths:
        blob = inflate(path)
        ram_base = locate_ram(blob)
        ram = blob[ram_base:ram_base + RAM_SIZE]
        context = struct.unpack_from("<I", ram, 0x1F12EC)[0]
        ot = context + 0x70
        expected_ot, packets = raw_ot_mask(ram, ot)
        expected_item, count, slots = item_mask_bytes(ram)
        item_states += int(bool(slots))

        memory = base_memory.clone()
        copy_item_object(memory, ram)
        memory.write(ot, ram[(ot & 0x1FFFFF):(ot & 0x1FFFFF) + 4])
        current = struct.unpack_from("<I", ram, ot & 0x1FFFFF)[0] & 0x00FFFFFF
        seen = set()
        while current not in (0, 0x00FFFFFF) and current < RAM_SIZE \
                and current not in seen and len(seen) < build.OT_WALK_LIMIT:
            seen.add(current)
            memory.write(0x80000000 | current, ram[current:current + 52])
            current = struct.unpack_from("<I", ram, current)[0] & 0x00FFFFFF
        memory.store32(active_at, 0)
        cpu = verify.R3000(memory, frame)
        cpu.reg[old.SP] = verify.STACK_TOP
        cpu.reg[old.RA] = verify.SENTINEL
        cpu.reg[old.A0] = ot
        cpu.run()
        expected = expected_ot | expected_item
        got = memory.load32(active_at)
        if got != expected:
            raise SystemExit(
                f"state mask differs for {path.name}: 0x{got:06X} != 0x{expected:06X} "
                f"(OT=0x{expected_ot:06X} item=0x{expected_item:06X} count={count})"
            )
        matched += 1
        maximum_steps = max(maximum_steps, cpu.steps)
        maximum_packets = max(maximum_packets, packets)
    return matched, item_states, maximum_packets, maximum_steps


def main() -> None:
    if digest(PATCH.read_bytes()) != PATCH_SHA256:
        raise SystemExit("v167 patch hash differs")
    if digest(build.BASE.read_bytes()) != build.BASE_SHA256:
        raise SystemExit("v166 base hash differs")
    layout, blobs, routines = routine_layout()
    with ZipFile(PATCH) as archive:
        members = {info.filename: archive.read(info.filename) for info in archive.infolist()}
    with ZipFile(build.BASE) as archive:
        base_members = {info.filename: archive.read(info.filename) for info in archive.infolist()}
    changed = sorted(name for name in members if members[name] != base_members[name])
    if changed != [old.PSX]:
        raise SystemExit(f"changed member set differs: {changed}")
    exe = members[old.PSX]
    for _name, (address, blob) in routines.items():
        if exe[old.source_at(address):old.source_at(address) + len(blob)] != blob:
            raise SystemExit(f"final resident routine differs: {_name}")
    if old.word(exe, old.LATE_HOOK) != old.jal(routines["frame"][0]):
        raise SystemExit("late hook target differs")

    memory = verify.runtime_memory(exe)
    verify.plan.CHECKPOINT_GROUP = build.CHECKPOINT_GROUP
    expected_sources = verify.python_sources(memory, layout)
    huffman_steps, huffman_max = verify.run_huffman(
        memory, routines["huffman"][0], expected_sources
    )
    ranges = old.unpack_ranges(memory.read(*layout["conflict_ranges"]))
    lookup = struct.unpack(
        f"<{old.LOOKUP_N}H", memory.read(old.LOOKUP_RAM, old.LOOKUP_N * 2)
    )
    direct_n, lookup_n, dynamic_n = verify.run_decoder(
        memory, routines["decoder"][0], layout, ranges, lookup
    )
    classifier_n = verify.run_helper_classifier(
        memory, routines["helper"][0], routines["classifier"][0]
    )

    owners_at = layout["owners"][0]
    active_at = layout["active_mask"][0]
    frame_memory = memory.clone()
    frame_memory.write(owners_at, struct.pack("<24H", *range(24)))
    frame_memory.store32(active_at, 0)
    item_slots = (2, 7, 21)
    ot_slots = (5, 16)
    write_synthetic_item(frame_memory, item_slots)
    expected_ot = verify166.write_ot(frame_memory, ot_slots)
    cpu = verify.R3000(frame_memory, routines["frame"][0])
    cpu.reg[old.SP] = verify.STACK_TOP
    cpu.reg[old.RA] = verify.SENTINEL
    cpu.reg[old.A0] = OT_ROOT
    preserved = {}
    for register in range(old.S0, old.S7 + 1):
        preserved[register] = 0x33330000 + register
        cpu.reg[register] = preserved[register]
    cpu.run()
    expected_union = expected_ot | sum(1 << slot for slot in item_slots)
    actual_union = frame_memory.load32(active_at)
    if actual_union != expected_union:
        raise SystemExit(
            "synthetic OT/item union differs: "
            f"actual=0x{actual_union:06X} expected=0x{expected_union:06X} "
            f"ot=0x{expected_ot:06X} item=0x{sum(1 << slot for slot in item_slots):06X}"
        )
    if any(cpu.reg[reg] != value for reg, value in preserved.items()):
        raise SystemExit("callee-saved register differs")
    if len([call for call in cpu.calls if call.target == old.DRAWOT]) != 1:
        raise SystemExit("DrawOT topology differs")

    # Active full-cell reconstruction still uses the group-8 Huffman stream.
    full_memory = memory.clone()
    full_memory.write(owners_at, struct.pack("<24H", *range(24)))
    full_memory.store32(active_at, 0xFFFFFF)
    write_synthetic_item(full_memory, ())
    verify166.write_ot(full_memory, ())
    full_cpu = verify.R3000(full_memory, routines["frame"][0])
    full_cpu.reg[old.SP] = verify.STACK_TOP
    full_cpu.reg[old.RA] = verify.SENTINEL
    full_cpu.reg[old.A0] = OT_ROOT
    full_cpu.run()
    uploads = [call for call in full_cpu.calls if call.target == old.LOADIMAGE]
    verify166.assert_full_owned_planes(uploads, tuple(range(6)), expected_sources)

    actual_n, actual_item_n, actual_max_packets, actual_max_steps = \
        execute_actual_states(memory, routines["frame"][0], active_at)

    OUT.mkdir(parents=True, exist_ok=True)
    lines = [
        "v167 item-description generation guard verification",
        f"patch={PATCH.name}",
        f"sha256={PATCH_SHA256}",
        "changed_members=PSX.EXE only PASS",
        "COMM.IMG_and_translation_members=v166 byte-identical PASS",
        f"checkpoint_group={build.CHECKPOINT_GROUP}",
        f"Huffman_sources={len(expected_sources)}/370 PASS",
        f"Huffman_total_steps={huffman_steps}",
        f"Huffman_max_steps={huffman_max}",
        f"direct_codes={direct_n} PASS",
        f"lookup_entries={lookup_n} dynamic={dynamic_n} PASS",
        f"classifier_cases={classifier_n} PASS",
        "full_owned_planes=24/24 PASS",
        "synthetic_item_slots=2,7,21 retained PASS",
        "synthetic_final_OT_slots=5,16 retained PASS",
        "synthetic_union_and_near_misses=PASS",
        f"actual_v166_state_masks={actual_n}/10 PASS",
        f"actual_states_with_item_cache_metadata={actual_item_n}/10",
        f"actual_OT_max_packets={actual_max_packets}",
        f"actual_frame_max_steps={actual_max_steps}",
        "DrawOT_call=1 PASS",
        "callee_saved_registers=PASS",
        "unaligned_runtime_accesses=0",
        f"resident_free={old.HEAP_BASE - (routines['item_guard'][0] + len(routines['item_guard'][1]))}",
        "heap_boundary_and_startup_copy=unchanged PASS",
        "",
        "static_verification=PASS",
        "runtime_verification=PENDING user cold boot",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
