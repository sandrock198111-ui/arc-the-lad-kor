#!/usr/bin/env python3
"""Build V326: restore the stock compact UI glyph path on top of V325.

V325 correctly re-encoded the pointer-proven Korean UI for the 16px Hanme
atlas.  Runtime states then proved that a second, old path still emits raw
one-byte codes with a six-pixel packet width for counters, levels and time.
Those raw codes retained their original meanings (blank, slash, digits and a
compact auxiliary glyph), but the 16px atlas now stores Hangul at the same
physical indices.  The visible symptoms are therefore deterministic: blank
becomes "다", digits become unrelated Hangul, and compact status rows break.

This build keeps every V325 Hangul glyph and DAT byte unchanged.  It copies the
thirteen observed stock 12x12 compact glyphs into an otherwise inaccessible
x=240 texture strip, remaps only their legacy raw codes to synthetic indices,
and redirects the U/V packet coordinates for those synthetic indices.  It also
restores two original E7 controller-icon token arrays and re-encodes the three
configuration strings that V325 deliberately inherited as opaque V241 data.
"""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import build_arc1_v324_static_ui_cursor_recovery as v324  # noqa: E402
import build_arc1_v325_ui_reencode as v325  # noqa: E402
import build_ui_glyph_store_v41 as v41  # noqa: E402


BASE = ROOT / "03_output/arc1_v325_ui_reencode_TEST_ONLY_7828AA04.zip"
BASE_SHA256 = "7828AA04F6A0684981332924C30B4139ABFCA5065138FA899C4D429E87C74CD1"
BASE_PSX_SHA256 = "5596B543172B8A682F9507072E1CD84C49C15FFCFE0E51410B2707F7BD1D3105"
BASE_COMM_SHA256 = "82A2D0BC60A216558BE41292F35187A376316B9BAB837BAF525C8F20C06E4565"

ORIGINAL = ROOT / "00_original/arc.zip"
ORIGINAL_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"
ORIGINAL_COMM_SHA256 = "6C7565B6C326A99A29266482868F17A144FF7D15B871D7D8F8B852EC41014A26"
CELL_AUDIT = ROOT / "01_work/analysis/font_cell_audit_full/cell_consumers.csv"
CELL_AUDIT_SHA256 = "63EF327777CC8A4E072AF68B8A1FE2B2EF4DFD8570D6176980157B7BBF7D5A73"

OUTPUT_STEM = "arc1_v326_compact_ui_recovery_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v325"
ANALYSIS = ROOT / "01_work/analysis/arc1_v326_compact_ui_recovery"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
RAM_TO_FILE = 0x8011A800
A0 = 4

# V325 left exactly 488 zero bytes at the tail of the second verified UI pool.
# Nineteen empty-string pointers intentionally target 0x808AD, so the first
# four bytes remain zero and executable code starts at the next aligned word.
FREE_START = 0x808AC
HELPER_START = 0x808B0
FREE_END = 0x80A94
DIRECT_HELPER_FILE = HELPER_START
DIRECT_HELPER_RAM = RAM_TO_FILE + DIRECT_HELPER_FILE
DIRECT_TRAMPOLINE_SOURCE = 0x8EF44
DIRECT_STOCK_RAM = 0x8016B3E0
DIRECT_RETURN_RAM = 0x8016B410

UV_HOOK_RAM = 0x8016B5A8
UV_HOOK_FILE = UV_HOOK_RAM - RAM_TO_FILE
UV_RETURN_RAM = 0x8016B5B0

EXPECTED_DIRECT_TRAMPOLINE = struct.pack("<II", 0x0805ACF8, 0)
EXPECTED_UV_HOOK_WORDS = struct.pack("<II", 0xA0A20029, 0x90C3000D)
EXPECTED_EMPTY_POINTERS = (
    0x811C0, 0x81708, 0x81B6C, 0x81B70, 0x81B74, 0x81C34,
    0x81C90, 0x81CB0, 0x81CB4, 0x81CB8, 0x81CBC, 0x81CC0,
    0x81CC4, 0x81CC8, 0x81CCC, 0x81CD0, 0x81CD4, 0x81CD8,
    0x82170,
)

# Synthetic values are deliberately outside the 15-column static atlas.
# Their modulo-four plane remains meaningful, while the U/V hook points them
# at a side strip that normal stride-60 decoding cannot address.
SYNTH_BASE = 960
SYNTH_COUNT = 13
STRIP_X = 240
STRIP_Y = 176
STRIP_CELL = 16
SOURCE_CELL = 12
ROW_BYTES = 896

# slot, raw byte, original physical index, diagnostic label
COMPACT_GLYPHS = (
    (0, 0x01, 0, "blank"),
    (1, 0x10, 15, "slash"),
    (2, 0x11, 16, "digit_0"),
    (3, 0x12, 17, "digit_1"),
    (4, 0x13, 18, "digit_2"),
    (5, 0x14, 19, "digit_3"),
    (6, 0x15, 20, "digit_4"),
    (7, 0x16, 21, "digit_5"),
    (8, 0x17, 22, "digit_6"),
    (9, 0x18, 23, "digit_7"),
    (10, 0x19, 24, "digit_8"),
    (11, 0x1A, 25, "digit_9"),
    (12, 0x80, 127, "compact_aux_127"),
)

MANUAL_POINTERS = (0x8234C, 0x82350, 0x825F0, 0x825F4, 0x825F8)
EXPECTED_OLD_PAYLOADS = {
    0x8234C: bytes.fromhex("DD 10 DD 0A B3 A1 DD AD DD 47 A1 DD 89 24"),
    0x82350: bytes.fromhex("DD 31 DD 32 A1 DD A3 B3 A1 8B DD D2 A1 DE 2B 35"),
    0x825F0: bytes.fromhex("DE C8 83 EA 9B"),
    0x825F4: bytes.fromhex("8A 69"),
    0x825F8: bytes.fromhex("D9 9C 8A 69"),
}


class BuildError(RuntimeError):
    pass


@dataclass(frozen=True)
class ManualString:
    pointer: int
    label: str
    semantic: str
    payload: bytes
    offset: int


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def changed_offsets(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise BuildError("member size changed")
    return {
        offset
        for offset, (old, new) in enumerate(zip(before, after, strict=True))
        if old != new
    }


def pointer_target(exe: bytes | bytearray, pointer: int) -> int:
    target = struct.unpack_from("<I", exe, pointer)[0] - RAM_TO_FILE
    if not 0 <= target < len(exe):
        raise BuildError(f"pointer outside PSX.EXE: 0x{pointer:X}->0x{target:X}")
    return target


def raw_string(exe: bytes | bytearray, offset: int) -> bytes:
    end = exe.find(0, offset, min(len(exe), offset + 512))
    if end < 0:
        raise BuildError(f"unterminated string at 0x{offset:X}")
    return bytes(exe[offset:end])


def align(value: int, boundary: int = 16) -> int:
    return (value + boundary - 1) & -boundary


def build_direct_helper(address: int) -> bytes:
    """Map only the compact raw codes; tail-jump to stock for every other byte."""
    asm = v41.Assembler(address)
    asm.emit(v41.i_type(0x0D, v41.ZERO, v41.T0, 0x01))       # ori t0,zero,1
    asm.branch(0x04, v41.V1, v41.T0, "blank")               # beq v1,t0,blank
    asm.emit(v41.i_type(0x0D, v41.ZERO, v41.T0, 0x10))       # delay: ori t0,zero,10
    asm.emit(v41.i_type(0x09, v41.V1, v41.T1, -0x10))        # addiu t1,v1,-10
    asm.emit(v41.i_type(0x0B, v41.T1, v41.T0, 0x0B))         # sltiu t0,t1,11
    asm.branch(0x05, v41.T0, v41.ZERO, "digit")             # bnez t0,digit
    asm.emit(0)
    asm.emit(v41.i_type(0x0D, v41.ZERO, v41.T0, 0x80))       # ori t0,zero,80
    asm.branch(0x05, v41.V1, v41.T0, "stock")               # bne v1,t0,stock
    asm.emit(0)
    asm.emit(v41.i_type(0x0D, v41.ZERO, v41.V1, SYNTH_BASE + 12))
    asm.branch(0x04, v41.ZERO, v41.ZERO, "mapped")
    asm.emit(0)
    asm.label("blank")
    asm.emit(v41.i_type(0x0D, v41.ZERO, v41.V1, SYNTH_BASE))
    asm.branch(0x04, v41.ZERO, v41.ZERO, "mapped")
    asm.emit(0)
    asm.label("digit")
    asm.emit(v41.i_type(0x09, v41.T1, v41.V1, SYNTH_BASE + 1))
    asm.label("mapped")
    asm.emit(v41.i_type(0x09, v41.A1, v41.V0, 1))             # addiu v0,a1,1
    asm.emit(v41.i_type(0x2B, v41.A2, v41.V0, 0))             # sw v0,0(a2)
    asm.emit(v41.j(DIRECT_RETURN_RAM))
    asm.emit(0)
    asm.label("stock")
    asm.emit(v41.j(DIRECT_STOCK_RAM))
    asm.emit(0)
    helper = asm.finish()
    if len(helper) != 92:
        raise BuildError(f"direct helper size drift: {len(helper)}")
    return helper


def build_uv_helper(address: int) -> bytes:
    """Recreate the overwritten V store and override U/V only for synthetic indices."""
    asm = v41.Assembler(address)
    asm.emit(v41.i_type(0x28, v41.A1, v41.V0, 0x29))          # sb v0,29(a1)
    asm.emit(v41.i_type(0x09, A0, v41.T0, -SYNTH_BASE))      # addiu t0,a0,-960
    asm.emit(v41.i_type(0x0B, v41.T0, v41.T1, SYNTH_COUNT))  # sltiu t1,t0,13
    asm.branch(0x04, v41.T1, v41.ZERO, "done")               # beqz t1,done
    asm.emit(0)
    asm.emit(v41.i_type(0x0D, v41.ZERO, v41.T1, STRIP_X))    # ori t1,zero,240
    asm.emit(v41.i_type(0x28, v41.A1, v41.T1, 0x28))          # sb t1,28(a1)
    asm.emit(v41.r_type(v41.ZERO, v41.T0, v41.T0, 2, 0x02))  # srl t0,t0,2
    asm.emit(v41.r_type(v41.ZERO, v41.T0, v41.T0, 4, 0x00))  # sll t0,t0,4
    asm.emit(v41.i_type(0x09, v41.T0, v41.T0, STRIP_Y))      # addiu t0,t0,176
    asm.emit(v41.i_type(0x28, v41.A1, v41.T0, 0x29))          # sb t0,29(a1)
    asm.label("done")
    asm.emit(v41.j(UV_RETURN_RAM))
    asm.emit(0)
    helper = asm.finish()
    if len(helper) != 52:
        raise BuildError(f"UV helper size drift: {len(helper)}")
    return helper


def remap_raw(raw: int) -> int:
    """Executable helper truth table, expressed independently for build guards."""
    if raw == 0x01:
        return SYNTH_BASE
    if 0x10 <= raw <= 0x1A:
        return SYNTH_BASE + 1 + raw - 0x10
    if raw == 0x80:
        return SYNTH_BASE + 12
    return raw - 1


def read_original_plane(comm: bytes, physical: int) -> tuple[int, ...]:
    cell, plane = divmod(physical, 4)
    row, col = divmod(cell, 21)
    bit = 1 << plane
    rows: list[int] = []
    for y in range(SOURCE_CELL):
        value = 0
        for x in range(SOURCE_CELL):
            pixel_x = col * SOURCE_CELL + x
            at = (row * SOURCE_CELL + y) * ROW_BYTES + pixel_x // 2
            shift = 0 if pixel_x % 2 == 0 else 4
            if ((comm[at] >> shift) & 0xF) & bit:
                value |= 1 << (SOURCE_CELL - 1 - x)
        rows.append(value)
    return tuple(rows)


def pixel_nibble(comm: bytes | bytearray, x: int, y: int) -> int:
    at = y * ROW_BYTES + x // 2
    return (comm[at] >> (0 if x % 2 == 0 else 4)) & 0xF


def set_plane_pixel(comm: bytearray, x: int, y: int, plane: int, enabled: bool) -> None:
    at = y * ROW_BYTES + x // 2
    shift = 0 if x % 2 == 0 else 4
    nibble = (comm[at] >> shift) & 0xF
    bit = 1 << plane
    nibble = (nibble | bit) if enabled else (nibble & (~bit & 0xF))
    if shift == 0:
        comm[at] = (comm[at] & 0xF0) | nibble
    else:
        comm[at] = (comm[at] & 0x0F) | (nibble << 4)


def read_strip_plane(comm: bytes, slot: int) -> tuple[int, ...]:
    plane = slot & 3
    base_y = STRIP_Y + (slot >> 2) * STRIP_CELL
    rows: list[int] = []
    for y in range(SOURCE_CELL):
        value = 0
        for x in range(SOURCE_CELL):
            if pixel_nibble(comm, STRIP_X + x, base_y + y) & (1 << plane):
                value |= 1 << (SOURCE_CELL - 1 - x)
        rows.append(value)
    return tuple(rows)


def write_compact_strip(base: bytes, original: bytes) -> tuple[bytes, list[dict[str, object]]]:
    comm = bytearray(base)
    # A non-zero target would mean this build is silently overwriting art.
    for y in range(STRIP_Y, STRIP_Y + 4 * STRIP_CELL):
        for x in range(STRIP_X, STRIP_X + SOURCE_CELL):
            if pixel_nibble(comm, x, y):
                raise BuildError(f"compact strip target is not blank: ({x},{y})")

    rows: list[dict[str, object]] = []
    for slot, raw, source, label in COMPACT_GLYPHS:
        source_rows = read_original_plane(original, source)
        plane = slot & 3
        base_y = STRIP_Y + (slot >> 2) * STRIP_CELL
        for y, bits in enumerate(source_rows):
            for x in range(SOURCE_CELL):
                set_plane_pixel(
                    comm,
                    STRIP_X + x,
                    base_y + y,
                    plane,
                    bool(bits & (1 << (SOURCE_CELL - 1 - x))),
                )
        if read_strip_plane(comm, slot) != source_rows:
            raise BuildError(f"compact strip readback failed: slot {slot}")
        rows.append(
            {
                "slot": slot,
                "raw_code": f"0x{raw:02X}",
                "source_original_index": source,
                "synthetic_index": SYNTH_BASE + slot,
                "label": label,
                "plane": plane,
                "texture_u_before_halfwidth_adjust": STRIP_X,
                "packet_u_after_halfwidth_adjust": STRIP_X + 4,
                "texture_v": base_y,
                "source_plane_sha256": sha256_bytes(struct.pack(">12H", *source_rows)),
            }
        )

    # Neighbor plane bits inside shared 4bpp nibbles are protected by exact
    # per-plane comparisons.  Slot zero is intentionally blank.
    for slot in range(SYNTH_COUNT):
        expected_source = COMPACT_GLYPHS[slot][2]
        if read_strip_plane(comm, slot) != read_original_plane(original, expected_source):
            raise BuildError(f"strip plane neighbor drift: {slot}")
    return bytes(comm), rows


def load_audit() -> dict[tuple[int, int], tuple[int, int]]:
    with CELL_AUDIT.open(encoding="utf-8-sig", newline="") as handle:
        return {
            (int(row["row"]), int(row["col"])):
            (int(row["text_reads"]), int(row["nontext_reads"]))
            for row in csv.DictReader(handle)
        }


def manual_payloads(exe: bytes, comm: bytes) -> list[tuple[int, str, str, bytes]]:
    records = v325.load_records()
    code_map, _physical, _pieces, _candidates = v325.build_code_map(exe, comm, records)

    def encoded(text: str) -> bytes:
        return v325.encode_text(text, code_map)

    attack = "\uacf5\uaca9"
    open_link = "\uc5f0\uacb0 \uc5f4\uae30"
    end_action = "\ud589\ub3d9 \ub05d"
    status = "\uc0c1\ud0dc \ud655\uc778"
    confirm = "\ud655\uc778\ud568"
    view = "\ubcf4\uae30"
    no_view = "\uc548 \ubcf4\uae30"
    return [
        (0x8234C, "battle_help_attack_link", attack + " / " + open_link,
         b"\xE7\x02" + encoded(attack) + b"\xE7\x05" + encoded(open_link)),
        (0x82350, "battle_help_end_status", end_action + " / " + status,
         b"\xE7\x03" + encoded(end_action) + b"\xE7\x08" + encoded(status)),
        (0x825F0, "configuration_confirm", confirm, encoded(confirm)),
        (0x825F4, "configuration_view", view, encoded(view)),
        (0x825F8, "configuration_no_view", no_view, encoded(no_view)),
    ]


def build_once(before: dict[str, bytes], original_comm: bytes) -> tuple[dict[str, bytes], dict[str, object]]:
    exe = bytearray(before[PSX])
    comm_before = before[COMM]

    if exe[DIRECT_TRAMPOLINE_SOURCE:DIRECT_TRAMPOLINE_SOURCE + 8] != EXPECTED_DIRECT_TRAMPOLINE:
        raise BuildError("resident direct-decoder trampoline drift")
    if exe[UV_HOOK_FILE:UV_HOOK_FILE + 8] != EXPECTED_UV_HOOK_WORDS:
        raise BuildError("stock U/V hook words drift")
    if any(exe[FREE_START:FREE_END]):
        raise BuildError("V325 verified free pool is no longer zero")

    pointer_hits: list[tuple[int, int]] = []
    for offset in range(0, len(exe) - 3, 4):
        target = struct.unpack_from("<I", exe, offset)[0] - RAM_TO_FILE
        if FREE_START <= target < FREE_END:
            pointer_hits.append((offset, target))
    expected_hits = [(pointer, 0x808AD) for pointer in EXPECTED_EMPTY_POINTERS]
    if pointer_hits != expected_hits:
        raise BuildError(f"free-pool pointer audit drift: {pointer_hits[:8]}")

    for pointer, expected in EXPECTED_OLD_PAYLOADS.items():
        target = pointer_target(exe, pointer)
        if raw_string(exe, target) != expected:
            raise BuildError(f"manual base payload drift at pointer 0x{pointer:X}")

    direct = build_direct_helper(DIRECT_HELPER_RAM)
    uv_file = align(DIRECT_HELPER_FILE + len(direct))
    uv_ram = RAM_TO_FILE + uv_file
    uv = build_uv_helper(uv_ram)
    data_at = align(uv_file + len(uv))
    if data_at >= FREE_END:
        raise BuildError("helpers exhausted free pool")

    exe[DIRECT_HELPER_FILE:DIRECT_HELPER_FILE + len(direct)] = direct
    exe[uv_file:uv_file + len(uv)] = uv
    struct.pack_into("<I", exe, DIRECT_TRAMPOLINE_SOURCE, v41.j(DIRECT_HELPER_RAM))
    struct.pack_into("<I", exe, UV_HOOK_FILE, v41.j(uv_ram))

    manual_rows: list[ManualString] = []
    cursor = data_at
    for pointer, label, semantic, payload in manual_payloads(before[PSX], before[COMM]):
        if b"\x00" in payload or b"\xFF" in payload:
            raise BuildError(f"unsafe manual payload: {label}")
        end = cursor + len(payload) + 1
        if end > FREE_END:
            raise BuildError("manual strings exhausted free pool")
        exe[cursor:end] = payload + b"\x00"
        struct.pack_into("<I", exe, pointer, RAM_TO_FILE + cursor)
        manual_rows.append(ManualString(pointer, label, semantic, payload, cursor))
        cursor = end

    if any(exe[FREE_START:HELPER_START]):
        raise BuildError("empty-string sentinel at 0x808AD was overwritten")
    for pointer in EXPECTED_EMPTY_POINTERS:
        if pointer_target(exe, pointer) != 0x808AD or raw_string(exe, 0x808AD):
            raise BuildError(f"empty pointer no longer empty: 0x{pointer:X}")
    for row in manual_rows:
        if pointer_target(exe, row.pointer) != row.offset or raw_string(exe, row.offset) != row.payload:
            raise BuildError(f"manual string readback failed: {row.label}")

    # The two help strings must preserve the original E7 token arrays exactly.
    expected_e7 = {
        0x8234C: (b"\xE7\x02", b"\xE7\x05"),
        0x82350: (b"\xE7\x03", b"\xE7\x08"),
    }
    for row in manual_rows[:2]:
        controls = tuple(row.payload[index:index + 2]
                         for index in range(len(row.payload) - 1)
                         if row.payload[index] == 0xE7)
        if controls != expected_e7[row.pointer]:
            raise BuildError(f"E7 control array drift: {row.label}/{controls}")

    comm, compact_rows = write_compact_strip(comm_before, original_comm)
    final = dict(before)
    final[PSX] = bytes(exe)
    final[COMM] = comm

    psx_changes = changed_offsets(before[PSX], final[PSX])
    comm_changes = changed_offsets(before[COMM], final[COMM])
    allowed_psx = (
        set(range(DIRECT_HELPER_FILE, cursor))
        | set(range(DIRECT_TRAMPOLINE_SOURCE, DIRECT_TRAMPOLINE_SOURCE + 4))
        | set(range(UV_HOOK_FILE, UV_HOOK_FILE + 4))
        | {byte for pointer in MANUAL_POINTERS for byte in range(pointer, pointer + 4)}
    )
    allowed_comm = {
        y * ROW_BYTES + x // 2
        for y in range(STRIP_Y, STRIP_Y + 4 * STRIP_CELL)
        for x in range(STRIP_X, STRIP_X + SOURCE_CELL)
    }
    if not psx_changes or not psx_changes <= allowed_psx:
        raise BuildError(f"PSX Expected-Write violation: {sorted(psx_changes - allowed_psx)[:8]}")
    if not comm_changes or not comm_changes <= allowed_comm:
        raise BuildError(f"COMM Expected-Write violation: {sorted(comm_changes - allowed_comm)[:8]}")
    if set(name for name in before if before[name] != final[name]) != {PSX, COMM}:
        raise BuildError("changed member set drift")
    if any(len(before[name]) != len(final[name]) for name in before):
        raise BuildError("archive member size drift")

    # Every non-target raw byte must retain the original stock direct result.
    target_raw = {raw for _slot, raw, _source, _label in COMPACT_GLYPHS}
    for raw in range(1, 0xDD):
        value = remap_raw(raw)
        if raw in target_raw:
            slot = next(slot for slot, item, _source, _label in COMPACT_GLYPHS if item == raw)
            if value != SYNTH_BASE + slot:
                raise BuildError(f"compact remap truth-table failure: 0x{raw:02X}")
        elif value != raw - 1:
            raise BuildError(f"stock direct-code regression: 0x{raw:02X}")

    meta: dict[str, object] = {
        "direct_helper_file": DIRECT_HELPER_FILE,
        "direct_helper_ram": DIRECT_HELPER_RAM,
        "direct_helper_size": len(direct),
        "uv_helper_file": uv_file,
        "uv_helper_ram": uv_ram,
        "uv_helper_size": len(uv),
        "manual_data_start": data_at,
        "used_end": cursor,
        "free_bytes_remaining": FREE_END - cursor,
        "manual_rows": manual_rows,
        "compact_rows": compact_rows,
        "psx_changes": psx_changes,
        "comm_changes": comm_changes,
        "allowed_psx": allowed_psx,
        "allowed_comm": allowed_comm,
        "direct_helper": direct,
        "uv_helper": uv,
    }
    return final, meta


def main() -> None:
    fixed = (
        (BASE, BASE_SHA256, "V325 base"),
        (ORIGINAL, ORIGINAL_SHA256, "original archive"),
        (CELL_AUDIT, CELL_AUDIT_SHA256, "509-state cell audit"),
    )
    for path, expected, label in fixed:
        if not path.is_file() or v324.sha256_file(path) != expected:
            raise BuildError(f"{label} hash mismatch: {path}")

    infos, before = v324.read_archive(BASE)
    if sha256_bytes(before[PSX]) != BASE_PSX_SHA256:
        raise BuildError("V325 PSX.EXE hash mismatch")
    if sha256_bytes(before[COMM]) != BASE_COMM_SHA256:
        raise BuildError("V325 COMM.IMG hash mismatch")
    with ZipFile(ORIGINAL) as archive:
        original_comm = archive.read(COMM)
    if sha256_bytes(original_comm) != ORIGINAL_COMM_SHA256:
        raise BuildError("original COMM.IMG hash mismatch")

    # The strip crosses old 12px column 20, rows 14..19.  Historical runtime
    # audit recorded zero non-text reads for every one of those cells.
    audit = load_audit()
    for row in range(14, 20):
        if (row, 20) not in audit or audit[(row, 20)][1] != 0:
            raise BuildError(f"compact strip non-text consumer drift: row {row}")

    final, meta = build_once(before, original_comm)
    second, second_meta = build_once(before, original_comm)
    if final != second:
        raise BuildError("in-memory deterministic rebuild mismatch")
    for key in ("direct_helper", "uv_helper", "psx_changes", "comm_changes"):
        if meta[key] != second_meta[key]:
            raise BuildError(f"deterministic metadata mismatch: {key}")

    output_path, output_hash = v324.write_archive(OUTPUT_STEM, infos, final, None)
    delta_path, delta_hash = v324.write_archive(DELTA_STEM, infos, final, {PSX, COMM})
    with ZipFile(output_path) as archive:
        names = [info.filename for info in archive.infolist() if not info.is_dir()]
        expected_names = [info.filename for info in infos if not info.is_dir()]
        if names != expected_names or any(archive.read(name) != final[name] for name in final):
            raise BuildError("full ZIP round-trip/topology mismatch")
    with ZipFile(delta_path) as archive:
        if set(archive.namelist()) != {PSX, COMM}:
            raise BuildError("delta ZIP member set mismatch")
        if any(archive.read(name) != final[name] for name in (PSX, COMM)):
            raise BuildError("delta ZIP payload mismatch")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    compact_rows = meta["compact_rows"]
    with (ANALYSIS / "compact_glyphs.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(compact_rows[0]))
        writer.writeheader()
        writer.writerows(compact_rows)

    manual_rows: list[ManualString] = meta["manual_rows"]  # type: ignore[assignment]
    with (ANALYSIS / "manual_ui_strings.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        fieldnames = ("pointer", "label", "semantic", "string_offset", "encoded_hex")
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in manual_rows:
            writer.writerow({
                "pointer": f"0x{row.pointer:X}",
                "label": row.label,
                "semantic": row.semantic,
                "string_offset": f"0x{row.offset:X}",
                "encoded_hex": row.payload.hex(" ").upper(),
            })

    with (ANALYSIS / "helper_words.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("helper", "address", "word"))
        for label, address, payload in (
            ("direct", int(meta["direct_helper_ram"]), meta["direct_helper"]),
            ("uv", int(meta["uv_helper_ram"]), meta["uv_helper"]),
        ):
            words = struct.unpack(f"<{len(payload) // 4}I", payload)  # type: ignore[arg-type]
            for index, word in enumerate(words):
                writer.writerow((label, f"0x{address + index * 4:08X}", f"0x{word:08X}"))

    psx_changes: set[int] = meta["psx_changes"]  # type: ignore[assignment]
    comm_changes: set[int] = meta["comm_changes"]  # type: ignore[assignment]
    with (ANALYSIS / "expected_writes.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("member", "offset", "before", "after", "region"))
        for member, offsets in ((PSX, psx_changes), (COMM, comm_changes)):
            for offset in sorted(offsets):
                if member == PSX:
                    if DIRECT_HELPER_FILE <= offset < int(meta["used_end"]):
                        region = "verified_free_pool_helpers_and_strings"
                    elif DIRECT_TRAMPOLINE_SOURCE <= offset < DIRECT_TRAMPOLINE_SOURCE + 4:
                        region = "resident_direct_decoder_source_trampoline"
                    elif UV_HOOK_FILE <= offset < UV_HOOK_FILE + 4:
                        region = "common_glyph_uv_hook"
                    else:
                        region = "manual_ui_pointer"
                else:
                    region = "compact_stock_glyph_strip"
                writer.writerow((
                    member, f"0x{offset:X}",
                    f"{before[member][offset]:02X}", f"{final[member][offset]:02X}", region,
                ))

    manifest = {
        "build": "V326 TEST_ONLY compact UI glyph and control-token recovery",
        "base": {"path": str(BASE), "sha256": BASE_SHA256},
        "output": {"path": str(output_path), "sha256": output_hash},
        "delta": {"path": str(delta_path), "sha256": delta_hash},
        "changed_members": [COMM, PSX],
        "changed_bytes": {PSX: len(psx_changes), COMM: len(comm_changes)},
        "compact_path": {
            "raw_codes": [f"0x{raw:02X}" for _slot, raw, _source, _label in COMPACT_GLYPHS],
            "synthetic_indices": [SYNTH_BASE, SYNTH_BASE + SYNTH_COUNT - 1],
            "texture_strip": {"x": STRIP_X, "y": STRIP_Y, "width": 12, "height": 64},
            "direct_helper": {
                "file": f"0x{int(meta['direct_helper_file']):X}",
                "ram": f"0x{int(meta['direct_helper_ram']):08X}",
                "bytes": int(meta["direct_helper_size"]),
            },
            "uv_helper": {
                "file": f"0x{int(meta['uv_helper_file']):X}",
                "ram": f"0x{int(meta['uv_helper_ram']):08X}",
                "bytes": int(meta["uv_helper_size"]),
            },
            "packet": "stock W=6 path retains U += 4; copied 12px glyph central 6px is sampled exactly",
        },
        "manual_strings": [
            {
                "pointer": f"0x{row.pointer:X}",
                "label": row.label,
                "semantic": row.semantic,
                "offset": f"0x{row.offset:X}",
                "payload": row.payload.hex(" ").upper(),
            }
            for row in manual_rows
        ],
        "free_pool": {
            "range": [f"0x{FREE_START:X}", f"0x{FREE_END:X}"],
            "used_end": f"0x{int(meta['used_end']):X}",
            "remaining_bytes": int(meta["free_bytes_remaining"]),
            "empty_string_0x808AD_preserved": True,
        },
        "preserved": {
            "V325_Hanme16_atlas_outside_compact_strip": "byte exact",
            "V325_UI_strings_except_five_manual_pointers": "byte exact",
            "all_DAT": "byte exact",
            "member_sizes": "byte exact",
        },
        "known_blocker": (
            "DO NOT USE: UV helper clobbers live t1=160 from 0x8016B524; "
            "physical blank 160 therefore advances 14px instead of 6px; "
            "raw-code helper also remaps ordinary D14/D16 Hangul globally"
        ),
        "runtime": "PENDING user cold boot; inspect states 1-10 equivalents",
        "release_status": "FAILED DIAGNOSTIC; DO NOT USE OR DISTRIBUTE",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V326 TEST ONLY - compact UI glyph/control-token recovery",
        f"base={BASE.name}",
        f"output={output_path.name}",
        f"sha256={output_hash}",
        f"delta={delta_path.name}",
        f"delta_sha256={delta_hash}",
        "changed_members=COMM.IMG,PSX.EXE",
        f"changed_bytes=PSX.EXE:{len(psx_changes)},COMM.IMG:{len(comm_changes)}",
        f"compact_raw_codes={len(COMPACT_GLYPHS)}; synthetic={SYNTH_BASE}..{SYNTH_BASE + SYNTH_COUNT - 1}",
        f"helpers=direct:{meta['direct_helper_size']}B,uv:{meta['uv_helper_size']}B",
        f"free_pool_remaining={meta['free_bytes_remaining']}B",
        "manual_pointers=0x8234C,0x82350,0x825F0,0x825F4,0x825F8",
        "V325 Hangul/UI/DAT outside Expected-Write ranges=byte exact",
        "KNOWN BLOCKERS=UV helper t1 clobber and global raw-code remap of D14/D16 Hangul",
        "status=STATIC FAIL; DO NOT USE (t1 fixed by V327, raw helper removed by V329)",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
