"""Independent archive and R3000 verification for Arc the Lad v171.

The builder proves its source-level plan.  This verifier reads only the final ZIP
and immutable controls, reconstructs the copied resident image, executes the final
decoder/Huffman/frame machine code, and checks every archive-visible UI recovery.
It never starts an emulator and never modifies a game archive.
"""
from __future__ import annotations

import csv
import hashlib
import re
import struct
import sys
from collections import Counter
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import audit_resident_routines as resident_audit  # noqa: E402
import build_arc1_v165_failclosed_cache as old  # noqa: E402
import build_arc1_v171_ui_asset_recovery as build  # noqa: E402
import plan_arc1_v171_ui_asset_recovery as plan  # noqa: E402
import verify_arc1_v165c_failclosed_cache as machine  # noqa: E402
from build_ui_full_v26 import PSX_LOAD_BASE, raw_string  # noqa: E402


PATCH = ROOT / "03_output/arc1_v171_native_ui_assets_28slot_cache_18E5C2DC.zip"
PATCH_SHA256 = "18E5C2DC2B84ECCD9A91E742983996EAB35E28F20BA86EB2A0124F497424E8AC"
BASE = plan.BASE
BASE_SHA256 = plan.BASE_SHA256
ORIGINAL = plan.ORIGINAL
ORIGINAL_SHA256 = plan.ORIGINAL_SHA256
CONTROL = plan.CONTROL
CONTROL_SHA256 = plan.CONTROL_SHA256
OUT = ROOT / "01_work/analysis/arc1_v171_native_ui_assets_28slot_cache_verification"
REPORT = OUT / "verification_report.txt"

PSX, COMM = "PSX.EXE", "COMM.IMG"
STACK_TOP = 0x801E0000
TOKEN_RAM = 0x80010000
RESULT_RAM = 0x80010200
INTENTIONAL_BLANK_CELLS = {
    (12, 11), (12, 18),
    (19, 15), (19, 16), (19, 17), (19, 18), (19, 19),
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def load(path: Path, expected: str):
    data = path.read_bytes()
    if digest(data) != expected:
        raise SystemExit(f"archive hash differs: {path.name}")
    with ZipFile(path) as archive:
        infos = archive.infolist()
        return infos, {info.filename: archive.read(info.filename) for info in infos}


def cell_bytes(font: bytes, row: int, col: int) -> bytes:
    return b"".join(
        font[(row * old.CELL + y) * 0x380 + col * 6:
             (row * old.CELL + y) * 0x380 + (col + 1) * 6]
        for y in range(old.CELL)
    )


def plane_bitmap(font: bytes, index: int) -> tuple[int, ...]:
    return build.plane_bitmap(font, index)


def blank_refilled(original: bytes, current: bytes) -> set[tuple[int, int]]:
    result: set[tuple[int, int]] = set()
    for row in range(512 // old.CELL):
        for col in range(1792 // old.CELL):
            before = cell_bytes(original, row, col)
            after = cell_bytes(current, row, col)
            if before != after and not any(before):
                result.add((row, col))
    return result


def parse_report_routines() -> tuple[int, int]:
    text = build.REPORT.read_text(encoding="utf-8")
    decoder = re.search(r"^decoder 0x([0-9A-F]+) / (\d+) bytes$", text, re.MULTILINE)
    frame = re.search(r"^frame routine 0x([0-9A-F]+) / (\d+) bytes$", text, re.MULTILINE)
    if not decoder or not frame:
        raise SystemExit("build report lacks audit-compatible routine lines")
    return int(decoder.group(1), 16), int(frame.group(1), 16)


def final_layout(exe: bytes):
    layout, blobs, code_base = build.resident_layout()
    decoder = code_base
    decoder_blob = build.build_decoder(decoder, layout)
    huffman = build.align(decoder + len(decoder_blob))
    huffman_blob = build.build_huffman(huffman, layout)
    frame = build.align(huffman + len(huffman_blob))
    frame_blob = build.build_frame(frame, huffman, layout)
    if (decoder, frame) != parse_report_routines():
        raise SystemExit("report routine addresses differ from archive layout")
    if frame + len(frame_blob) != old.HEAP_BASE:
        raise SystemExit("resident routines do not end exactly at the frozen heap boundary")

    source = exe[old.file_at(old.SOURCE_BASE):old.file_at(old.SOURCE_BASE) + old.COPY_N]
    for address, expected, name in (
        (decoder, decoder_blob, "decoder"),
        (huffman, huffman_blob, "huffman"),
        (frame, frame_blob, "frame"),
    ):
        at = address - old.RESIDENT_BASE
        if source[at:at + len(expected)] != expected:
            raise SystemExit(f"final resident {name} differs from assembled bytes")

    for name, expected in blobs.items():
        address, size = layout[name]
        at = address - old.RESIDENT_BASE
        got = source[at:at + size]
        if name == "owners":
            expected = struct.pack(f"<{build.CACHE_N}H", *([0xFFFF] * build.CACHE_N))
        elif name == "upload_rect":
            expected = struct.pack("<4H", build.CACHE_X, build.CACHE_Y, 3, old.CELL)
        if got != expected:
            raise SystemExit(f"final resident data differs: {name}")
    return layout, decoder, huffman, frame


def runtime_memory(exe: bytes) -> machine.Memory:
    memory = machine.Memory()
    memory.write(PSX_LOAD_BASE, exe)
    source = exe[old.file_at(old.SOURCE_BASE):old.file_at(old.SOURCE_BASE) + old.COPY_N]
    memory.write(old.RESIDENT_BASE, source)
    memory.write(STACK_TOP - 0x200, bytes(0x400))
    memory.write(TOKEN_RAM, bytes(0x400))
    return memory


def decode_sources(memory: machine.Memory, layout) -> list[tuple[int, ...]]:
    rows_at, rows_n = layout["huffman_rows"]
    stream_at, stream_n = layout["source_bitstream"]
    rows = struct.unpack(f"<{rows_n // 2}H", memory.read(rows_at, rows_n))
    counts = memory.read(build.HUFFMAN_COUNTS_RAM, len(plan.HUFFMAN_COUNTS.read_bytes()))
    checkpoints = struct.unpack(
        f"<{plan.SOURCE_CHECKPOINTS.stat().st_size // 2}H",
        memory.read(build.HUFFMAN_CHECKPOINTS_RAM, plan.SOURCE_CHECKPOINTS.stat().st_size),
    )
    stream = memory.read(stream_at, stream_n)

    def symbol(position: int) -> tuple[int, int]:
        code = first_code = first_symbol = 0
        for count in counts:
            byte, bit = divmod(position, 8)
            code = (code << 1) | ((stream[byte] >> (7 - bit)) & 1)
            position += 1
            delta = code - first_code
            if 0 <= delta < count:
                return rows[first_symbol + delta], position
            first_symbol += count
            first_code = (first_code + count) << 1
        raise RuntimeError("invalid final Huffman code")

    result: list[tuple[int, ...]] = []
    for source in range(plan.SOURCE_N):
        group, within = divmod(source, plan.CHECKPOINT_GROUP)
        position = checkpoints[group]
        decoded: list[int] = []
        for ordinal in range((within + 1) * plan.ENCODED_ROWS):
            value, position = symbol(position)
            if ordinal >= within * plan.ENCODED_ROWS:
                decoded.append(value)
        decoded.append(0)
        result.append(tuple(decoded))
    return result


def direct_ranges(exe: bytes) -> dict[int, int]:
    blob = exe[old.file_at(build.RANGE_RAM):old.file_at(build.RANGE_RAM) + build.RANGE_BYTES]
    result: dict[int, int] = {}
    source = 0
    for at in range(0, len(blob), 2):
        packed = struct.unpack_from("<H", blob, at)[0]
        start, field = packed & 0x7FF, packed >> 11
        length = 39 if field == 31 else field + 1
        for delta in range(length):
            result[start + delta] = source + delta
        source += length
    if len(result) != plan.NEW_DIRECT_N or source != plan.NEW_DIRECT_N:
        raise SystemExit("final direct range map is not 254 entries")
    return result


def packed_lookup(exe: bytes) -> list[int]:
    blob = exe[
        old.file_at(build.PACKED_LOOKUP_RAM):
        old.file_at(build.PACKED_LOOKUP_RAM) + build.PACKED_LOOKUP_BYTES
    ]
    values = plan.unpack_fixed(blob, plan.LOOKUP_N, plan.LOOKUP_BITS)
    if len(values) != plan.LOOKUP_N:
        raise SystemExit("final packed lookup length differs")
    return values


def run_huffman(memory: machine.Memory, address: int,
                expected: list[tuple[int, ...]]) -> tuple[int, int]:
    total = maximum = 0
    for source, rows in enumerate(expected):
        trial = memory.clone()
        trial.write(RESULT_RAM, bytes(24))
        cpu = machine.R3000(trial, address)
        cpu.reg[old.A0] = source
        cpu.reg[old.A1] = RESULT_RAM
        cpu.reg[old.RA] = machine.SENTINEL
        cpu.run()
        got = struct.unpack("<12H", trial.read(RESULT_RAM, 24))
        if got != rows:
            raise SystemExit(f"assembled Huffman differs at source {source}")
        total += cpu.steps
        maximum = max(maximum, cpu.steps)
    return total, maximum


def run_decoder_once(memory: machine.Memory, decoder: int,
                     token: bytes) -> tuple[int, int, int]:
    memory.write(TOKEN_RAM, token + b"\0\0")
    memory.store32(RESULT_RAM, 0)
    cpu = machine.R3000(memory, decoder)
    cpu.reg[old.V1] = token[0]
    cpu.reg[old.A1] = TOKEN_RAM
    cpu.reg[old.A2] = RESULT_RAM
    cpu.run()
    consumed = machine.u32(memory.load32(RESULT_RAM) - TOKEN_RAM)
    return cpu.pc, cpu.reg[old.V1], consumed


def direct_token(index: int) -> bytes:
    if 0 <= index < 220:
        return bytes((index + 1,))
    group, remainder = divmod(index - 220, 255)
    if not 0 <= group < 12 or not 0 <= remainder < 254:
        raise ValueError(index)
    return bytes((0xDD + group, remainder + 1))


def run_decoder(memory: machine.Memory, decoder: int, layout,
                ranges: dict[int, int], lookup: list[int]) -> tuple[int, int, int]:
    owners = layout["owners"][0]
    active = layout["active_mask"][0]
    next_slot = layout["next_slot"][0]
    checked = dynamic = 0
    for index in range(220 + 11 * 255 + 254):
        try:
            token = direct_token(index)
        except ValueError:
            continue
        trial = memory.clone()
        pc, glyph, consumed = run_decoder_once(trial, decoder, token)
        if index in ranges:
            if (pc, glyph, consumed) != (old.DECODE_RETURN, build.CACHE_INDEX_BASE,
                                         len(token)):
                raise SystemExit(f"direct dynamic route differs at index {index}")
            if trial.load16(owners) != ranges[index] or trial.load32(active) != 1:
                raise SystemExit(f"direct source ownership differs at index {index}")
            dynamic += 1
        else:
            expected = old.SINGLE_PATH if len(token) == 1 else old.WIDE_PATH
            if pc != expected:
                raise SystemExit(f"stock direct route differs at index {index}")
        checked += 1
    if dynamic != plan.NEW_DIRECT_N:
        raise SystemExit("assembled direct dynamic count differs")

    lookup_dynamic = 0
    for slot, value in enumerate(lookup):
        token = bytes((0xE9 + slot // 254, slot % 254 + 1))
        trial = memory.clone()
        pc, glyph, consumed = run_decoder_once(trial, decoder, token)
        expected = value
        if value == plan.SPECIAL_STATIC_TAG:
            expected = plan.SPECIAL_STATIC_VALUE
        elif value >= plan.DYNAMIC_TAG:
            expected = build.CACHE_INDEX_BASE
            lookup_dynamic += 1
        if (pc, glyph, consumed) != (old.DECODE_RETURN, expected, 2):
            raise SystemExit(f"lookup route differs at slot {slot}")

    trial = memory.clone()
    indices = sorted(ranges)[:build.CACHE_N + 1]
    for slot, index in enumerate(indices[:build.CACHE_N]):
        pc, glyph, consumed = run_decoder_once(trial, decoder, direct_token(index))
        if (pc, glyph, consumed) != (
            old.DECODE_RETURN, build.CACHE_INDEX_BASE + slot, len(direct_token(index))
        ):
            raise SystemExit(f"28-slot fill differs at slot {slot}")
    owners_before = trial.read(owners, build.CACHE_N * 2)
    next_before = trial.load32(next_slot)
    pc, glyph, consumed = run_decoder_once(
        trial, decoder, direct_token(indices[build.CACHE_N])
    )
    if (pc, glyph, consumed) != (
        old.DECODE_RETURN, 0, len(direct_token(indices[build.CACHE_N]))
    ):
        raise SystemExit("29th simultaneous miss did not fail closed")
    if trial.read(owners, build.CACHE_N * 2) != owners_before or \
            trial.load32(next_slot) != next_before or \
            trial.load32(active) != (1 << build.CACHE_N) - 1:
        raise SystemExit("29th miss changed full-cache state")
    trial.store32(active, 0)
    _pc, glyph, _consumed = run_decoder_once(
        trial, decoder, direct_token(indices[build.CACHE_N])
    )
    if glyph != build.CACHE_INDEX_BASE:
        raise SystemExit("post-frame replacement did not reuse slot zero")
    return checked, len(lookup), lookup_dynamic


def payload_rows(payload: bytes, plane: int) -> tuple[int, ...]:
    if len(payload) != 72:
        raise SystemExit("cache-cell upload is not 72 bytes")
    result = []
    for y in range(old.CELL):
        row = 0
        for x in range(old.CELL):
            value = payload[y * 6 + x // 2]
            nibble = (value >> (4 * (x & 1))) & 0xF
            row = (row << 1) | ((nibble >> plane) & 1)
        result.append(row)
    return tuple(result)


def run_frame(memory: machine.Memory, frame: int, layout,
              expected: list[tuple[int, ...]]) -> tuple[int, int]:
    owners = layout["owners"][0]
    active = layout["active_mask"][0]

    def execute(mask: int):
        trial = memory.clone()
        trial.write(owners, struct.pack(f"<{build.CACHE_N}H", *range(build.CACHE_N)))
        trial.store32(active, mask)
        cpu = machine.R3000(trial, frame)
        cpu.reg[old.SP] = STACK_TOP
        cpu.reg[old.RA] = machine.SENTINEL
        cpu.reg[old.A0] = 0x81234560
        preserved = {}
        for register in range(old.S0, old.S7 + 1):
            value = 0x11110000 + register
            cpu.reg[register] = value
            preserved[register] = value
        cpu.run()
        for register, value in preserved.items():
            if cpu.reg[register] != value:
                raise SystemExit(f"frame did not preserve r{register}")
        if cpu.reg[old.SP] != STACK_TOP:
            raise SystemExit("frame did not restore SP")
        uploads = [call for call in cpu.calls if call.target == old.LOADIMAGE]
        draws = [call for call in cpu.calls if call.target == old.DRAWOT]
        if len(draws) != 1 or draws[0].a0 != 0x81234560:
            raise SystemExit("frame did not preserve the displaced DrawOT call")
        if trial.load32(active) != 0:
            raise SystemExit("empty synthetic OT did not clear next-frame active mask")
        return trial, cpu, uploads

    full, full_cpu, uploads = execute((1 << build.CACHE_N) - 1)
    del full
    if len(uploads) != build.CACHE_CELLS:
        raise SystemExit("full frame did not upload seven complete cells")
    for cell, call in enumerate(uploads):
        expected_rect = (build.CACHE_X + cell * 3, build.CACHE_Y, 3, old.CELL)
        if call.rect != expected_rect or call.payload is None:
            raise SystemExit(f"upload rectangle differs at cell {cell}")
        for plane in range(old.PLANES):
            source = cell * old.PLANES + plane
            if payload_rows(call.payload, plane) != expected[source]:
                raise SystemExit(f"uploaded source differs at cell {cell} plane {plane}")

    partial_mask = (1 << 0) | (1 << 5) | (1 << 27)
    _partial, partial_cpu, uploads = execute(partial_mask)
    if [call.rect[0] for call in uploads if call.rect] != [961, 964, 979]:
        raise SystemExit("partial frame uploaded the wrong cache cells")
    # The active mask selects complete physical cells for upload.  Once a cell is
    # selected, all four current owners are deliberately rebuilt: an inactive
    # plane may still hold a valid cached glyph, and copying it is harmless when
    # no packet refers to that plane.  The decoder never reassigns a slot that is
    # protected by the current/previous OT union.
    for cell, call in zip((0, 1, 6), uploads):
        assert call.payload is not None
        for plane in range(old.PLANES):
            source = cell * old.PLANES + plane
            if payload_rows(call.payload, plane) != expected[source]:
                raise SystemExit(f"partial frame plane differs at source {source}")
    return full_cpu.steps, partial_cpu.steps


def verify_system_strings(base_exe: bytes, exe: bytes) -> tuple[int, int]:
    rows = [row for row in plan.read_csv(build.SYSTEM_CSV)
            if row["status"] != "battle_hud_pointer_repaired"]
    mapping = build.current_char_mapping()
    for row in rows:
        pointer = int(row["pointer_offset"], 0)
        target = struct.unpack_from("<I", exe, pointer)[0] - PSX_LOAD_BASE
        if raw_string(exe, target) != build.encode_system(row["korean"], mapping):
            raise SystemExit(f"semantic system-string readback differs at 0x{pointer:X}")

    owned = {int(row["pointer_offset"], 0) for row in rows}
    external: dict[int, bytes] = {}
    for offset in range(0, len(base_exe) - 3, 4):
        target = struct.unpack_from("<I", base_exe, offset)[0] - PSX_LOAD_BASE
        if any(start <= target < end for start, end in build.OMITTED_POOLS) \
                and offset not in owned:
            external[offset] = raw_string(base_exe, target)
    if tuple(sorted(external)) != build.EXPECTED_EXTERNAL_POOL_POINTERS:
        raise SystemExit("external system fragment set differs")
    for pointer, expected in external.items():
        target = struct.unpack_from("<I", exe, pointer)[0] - PSX_LOAD_BASE
        if raw_string(exe, target) != expected:
            raise SystemExit(f"external fragment changed at 0x{pointer:X}")

    for start, end in build.PROTECTED_POOL_POINTER_WORDS:
        if exe[start:end] != base_exe[start:end]:
            raise SystemExit(f"embedded pointer word changed at 0x{start:X}")
    return len(rows), len(external)


def main() -> None:
    base_infos, base = load(BASE, BASE_SHA256)
    patch_infos, patch = load(PATCH, PATCH_SHA256)
    _original_infos, original = load(ORIGINAL, ORIGINAL_SHA256)
    _control_infos, control = load(CONTROL, CONTROL_SHA256)
    if [info.filename for info in patch_infos] != [info.filename for info in base_infos]:
        raise SystemExit("archive member order changed")
    if any(len(patch[name]) != len(base[name]) for name in base):
        raise SystemExit("archive member length changed")
    changed = [name for name in base if patch[name] != base[name]]
    if set(changed) != {PSX, COMM} or len(changed) != 2:
        raise SystemExit(f"changed member set differs: {changed}")

    exe, font = patch[PSX], patch[COMM]
    if blank_refilled(original[COMM], font) != INTENTIONAL_BLANK_CELLS:
        raise SystemExit("original-blank cell changes exceed the seven explicit UI assets")
    for row, col in plan.UI_CELLS:
        if (row, col) not in {(11, 7), (11, 8)} and \
                cell_bytes(font, row, col) != cell_bytes(original[COMM], row, col):
            raise SystemExit(f"native UI cell differs at {row},{col}")
    for row, col in build.ICON_CELLS:
        if cell_bytes(font, row, col) != cell_bytes(control[COMM], row, col):
            raise SystemExit(f"verified button bank differs at {row},{col}")
    for name, index in build.PUNCTUATION_INDICES.items():
        if plane_bitmap(font, index) != plane_bitmap(control[COMM], index):
            raise SystemExit(f"verified punctuation differs: {name}")
    if any(plane_bitmap(font, build.SPACE_INDEX)):
        raise SystemExit("v170 blank space filler regressed")

    system_n, external_n = verify_system_strings(base[PSX], exe)
    pointer_total, pointer_dead, _samples = resident_audit.pointer_damage(original[PSX], exe)
    if pointer_total != 4093 or pointer_dead:
        raise SystemExit("original pointer integrity differs")

    layout, decoder, huffman, frame = final_layout(exe)
    memory = runtime_memory(exe)
    sources = decode_sources(memory, layout)
    if len(sources) != plan.SOURCE_N or any(len(rows) != old.CELL for rows in sources):
        raise SystemExit("decoded source dimensions differ")
    huffman_total, huffman_max = run_huffman(memory, huffman, sources)
    ranges = direct_ranges(exe)
    lookup = packed_lookup(exe)
    direct_n, lookup_n, lookup_dynamic = run_decoder(
        memory, decoder, layout, ranges, lookup
    )
    full_steps, partial_steps = run_frame(memory, frame, layout, sources)

    routine_problems = []
    for name, address, size in (
        ("decoder", decoder, len(build.build_decoder(decoder, layout))),
        ("frame routine", frame, len(build.build_frame(frame, huffman, layout))),
    ):
        routine_problems.extend(resident_audit.check(exe, name, address, size))
    if routine_problems:
        raise SystemExit("resident routine audit differs: " + routine_problems[0])

    OUT.mkdir(parents=True, exist_ok=True)
    kinds = Counter(row["kind"] for row in plan.read_csv(plan.SOURCE_MANIFEST))
    lines = [
        f"{PATCH.stem} independent UI-asset/cache verification",
        "",
        f"patch={PATCH.name}", f"sha256={PATCH_SHA256}",
        "changed_members=PSX.EXE COMM.IMG", "changed_other_members=0",
        "archive_member_order=PASS", "archive_member_lengths=PASS",
        "",
        "native_UI_cells=26/26 PASS",
        "intentional_original_blank_cells=7/7 exact PASS",
        "button_bank_cells=5/5 v151-exact PASS",
        "punctuation_planes=4/4 v151-exact PASS",
        "blank_space_plane=PASS",
        f"system_semantic_strings={system_n}/123 PASS",
        f"external_system_fragments={external_n}/16 byte-exact PASS",
        "embedded_pointer_words=2/2 byte-exact PASS",
        f"original_RAM_pointers={pointer_total}/4093 valid PASS",
        "",
        f"dynamic_sources={len(sources)}/462 PASS",
        "source_kinds=" + " ".join(f"{key}:{value}" for key, value in sorted(kinds.items())),
        f"assembled_Huffman_total_steps={huffman_total}",
        f"assembled_Huffman_max_steps={huffman_max}",
        f"direct_routes_checked={direct_n}",
        "direct_dynamic_routes=254/254 PASS",
        f"lookup_routes_checked={lookup_n}",
        f"lookup_dynamic_entries={lookup_dynamic}",
        "cache_fill=28/28 PASS", "29th_miss_fail_closed=PASS",
        "post_frame_replacement=PASS",
        "full_cache_uploads=7 complete cells PASS",
        "partial_cache_uploads=x961,x964,x979 PASS",
        f"full_frame_interpreter_steps={full_steps}",
        f"partial_frame_interpreter_steps={partial_steps}",
        "callee_saved_registers_and_SP=PASS",
        "DrawOT_displaced_call=PASS",
        "decoder_nonlinking_J_return=PASS",
        "resident_alignment_branches_delays=PASS",
        "resident_used=5356/5356 exact",
        "",
        "result=PASS_STATIC_AND_SYNTHETIC_R3000",
        "runtime=PENDING user cold boot",
        "promotion_to_bible=NO until runtime verification",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(REPORT)


if __name__ == "__main__":
    main()
