"""Build v73 with a dual-texture-page common UI glyph renderer.

v72 proved that relocating high-row glyph planes can overwrite battle sprites.
This build starts again from the runtime-safe v71 archive, leaves COMM.IMG and
all DAT members untouched, and renders the existing glyph atlas in two passes:
rows 0-20 on texture page y=0 and rows 22+ on texture page y=256.
"""

from __future__ import annotations

import csv
import hashlib
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32  # noqa: E402


BASE = ROOT / "03_output" / "ui_hud_e7_v71_leaf_font_ring_help_patch_only.zip"
OUTPUT = ROOT / "03_output" / "ui_hud_e7_v73_dual_tpage_renderer_patch_only.zip"
GLYPH_MAP = ROOT / "05_docs" / "ui_glyph_store_v42_map.csv"
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_hud_e7_v73"
REPORT = ANALYSIS / "build_report.txt"
DISASSEMBLY = ANALYSIS / "mips_disassembly.txt"

BASE_SHA256 = "C9FE5D3F3521748CDD53A43A7A47895CC1747928D2804A9502D877B4D47A250D"
PSX_MEMBER = "PSX.EXE"
COMM_MEMBER = "COMM.IMG"
PSX_LOAD_BASE = 0x8011A800

STATE_INIT_HOOK = 0x8016B148
GLYPH_FLAG_HOOK = 0x8016B5D8
RENDERER_HOOK = 0x8016B764
ADD_PRIM = 0x80178F84
SET_DRAW_MODE = 0x80177484

CAVE_START = 0x801A2080
CAVE_LIMIT = 0x801A2304
CAVE_SIZE = CAVE_LIMIT - CAVE_START

LOOKUP_ADDRESS = 0x801A7520
LOOKUP_COUNT = 409
INDICES_PER_ROW = 84
HIGH_ROW_START = 22

EXPECTED_HOOKS = {
    STATE_INIT_HOOK: bytes.fromhex("00 00 26 AE 04 00 24 A6"),
    GLYPH_FLAG_HOOK: bytes.fromhex("0E 00 C2 90 00 00 00 00"),
    RENDERER_HOOK: bytes.fromhex("D0 FF BD 27 2C 00 BF AF"),
}

# MIPS register numbers.
ZERO = 0
V0 = 2
V1 = 3
A0 = 4
A1 = 5
A2 = 6
A3 = 7
T0 = 8
S0 = 16
S1 = 17
S2 = 18
S3 = 19
S4 = 20
S5 = 21
S6 = 22
S7 = 23
SP = 29
RA = 31


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def file_offset(address: int) -> int:
    offset = address - PSX_LOAD_BASE
    if not 0 <= offset < 0x8E000:
        raise ValueError(f"address outside PSX.EXE: 0x{address:08X}")
    return offset


def clone_info(info: ZipInfo) -> ZipInfo:
    copied = ZipInfo(info.filename, info.date_time)
    copied.compress_type = ZIP_DEFLATED
    copied.comment = info.comment
    copied.extra = info.extra
    copied.internal_attr = info.internal_attr
    copied.external_attr = info.external_attr
    copied.create_system = info.create_system
    copied.flag_bits = info.flag_bits
    return copied


def j(address: int) -> int:
    return 0x08000000 | ((address >> 2) & 0x03FFFFFF)


def jal(address: int) -> int:
    return 0x0C000000 | ((address >> 2) & 0x03FFFFFF)


def i_type(op: int, rs: int, rt: int, immediate: int) -> int:
    return (op << 26) | (rs << 21) | (rt << 16) | (immediate & 0xFFFF)


def r_type(rs: int, rt: int, rd: int, shift: int, function: int) -> int:
    return (
        (rs << 21)
        | (rt << 16)
        | (rd << 11)
        | (shift << 6)
        | function
    )


@dataclass
class BranchFixup:
    index: int
    op: int
    rs: int
    rt: int
    label: str


class Assembler:
    def __init__(self, address: int) -> None:
        self.address = address
        self.words: list[int] = []
        self.labels: dict[str, int] = {}
        self.fixups: list[BranchFixup] = []

    @property
    def current_address(self) -> int:
        return self.address + len(self.words) * 4

    def emit(self, word: int) -> None:
        self.words.append(word & 0xFFFFFFFF)

    def label(self, name: str) -> None:
        if name in self.labels:
            raise ValueError(f"duplicate label: {name}")
        self.labels[name] = len(self.words)

    def branch(self, op: int, rs: int, rt: int, label: str) -> None:
        self.fixups.append(BranchFixup(len(self.words), op, rs, rt, label))
        self.emit(0)

    def finish(self) -> bytes:
        words = list(self.words)
        for fixup in self.fixups:
            if fixup.label not in self.labels:
                raise ValueError(f"undefined label: {fixup.label}")
            pc = self.address + fixup.index * 4
            target = self.address + self.labels[fixup.label] * 4
            delta = (target - (pc + 4)) // 4
            if not -0x8000 <= delta <= 0x7FFF:
                raise ValueError(f"branch out of range: {fixup.label}")
            words[fixup.index] = i_type(fixup.op, fixup.rs, fixup.rt, delta)
        return struct.pack(f"<{len(words)}I", *words)


def build_reserve_helper(address: int) -> bytes:
    asm = Assembler(address)
    asm.emit(i_type(0x2B, S1, A2, 0))       # sw a2,0(s1)
    asm.emit(i_type(0x09, A0, A0, -1))      # addiu a0,a0,-1
    asm.emit(i_type(0x29, S1, A0, 4))       # sh a0,4(s1)
    asm.emit(r_type(RA, ZERO, ZERO, 0, 0x08))
    asm.emit(0)
    return asm.finish()


def build_flag_helper(address: int) -> bytes:
    asm = Assembler(address)
    asm.emit(i_type(0x24, A2, V0, 0x0E))    # lbu v0,0xe(a2)
    asm.emit(i_type(0x0B, T0, V1, HIGH_ROW_START))
    asm.branch(0x05, V1, ZERO, "done")      # bnez v1,done
    asm.emit(0)
    asm.emit(i_type(0x0D, V0, V0, 0x80))    # ori v0,v0,0x80
    asm.label("done")
    asm.emit(r_type(RA, ZERO, ZERO, 0, 0x08))
    asm.emit(0)
    return asm.finish()


def build_renderer(address: int) -> tuple[bytes, int]:
    asm = Assembler(address)

    # Main renderer prologue and shared state.
    asm.emit(i_type(0x09, SP, SP, -0x50))
    for reg, offset in (
        (RA, 0x4C), (S7, 0x48), (S6, 0x44), (S5, 0x40), (S4, 0x3C),
        (S3, 0x38), (S2, 0x34), (S1, 0x30), (S0, 0x2C),
    ):
        asm.emit(i_type(0x2B, SP, reg, offset))
    asm.emit(r_type(A0, ZERO, S2, 0, 0x21))       # move s2,a0
    asm.emit(r_type(A1, ZERO, S7, 0, 0x21))       # move s7,a1
    asm.emit(i_type(0x0F, ZERO, S6, 0x801F))
    asm.emit(i_type(0x23, S6, S6, 0x12EC))        # lw s6,0x12ec(s6)
    asm.emit(0)                                    # R3000 load delay
    asm.emit(i_type(0x25, S6, V0, 0x0870))        # lhu v0,0x870(s6)
    asm.emit(0)                                    # R3000 load delay
    asm.emit(r_type(ZERO, V0, S4, 2, 0x00))       # sll s4,v0,2
    asm.emit(r_type(S4, V0, S4, 0, 0x21))         # addu s4,s4,v0
    asm.emit(r_type(ZERO, S4, S4, 2, 0x00))       # sll s4,s4,2 (*20)
    asm.emit(r_type(ZERO, S7, V0, 2, 0x00))
    asm.emit(i_type(0x09, V0, S3, 0x70))
    asm.emit(r_type(S3, S6, S3, 0, 0x21))         # s3 = OT entry

    # Low-page glyphs, then the existing low-page draw-mode packet.
    asm.emit(r_type(ZERO, ZERO, S5, 0, 0x21))
    pass_call_1 = len(asm.words)
    asm.emit(0)
    asm.emit(0)
    asm.emit(i_type(0x25, S6, V0, 0x0870))
    asm.emit(0)                                    # R3000 load delay
    asm.emit(r_type(ZERO, V0, A1, 1, 0x00))
    asm.emit(r_type(A1, V0, A1, 0, 0x21))
    asm.emit(r_type(ZERO, A1, A1, 2, 0x00))
    asm.emit(i_type(0x09, A1, A1, 0x2C))
    asm.emit(r_type(A1, S2, A1, 0, 0x21))
    asm.emit(r_type(S3, ZERO, A0, 0, 0x21))
    asm.emit(jal(ADD_PRIM))
    asm.emit(0)

    # High-page glyphs.
    asm.emit(i_type(0x0D, ZERO, S5, 0x80))
    pass_call_2 = len(asm.words)
    asm.emit(0)
    asm.emit(0)

    # Use the reserved final glyph packet as a per-state, double-buffered
    # high-page DR_TPAGE packet.
    asm.emit(i_type(0x21, S2, V0, 4))             # lh v0,4(s2)
    asm.emit(0)                                    # R3000 load delay
    asm.emit(r_type(ZERO, V0, V1, 1, 0x00))
    asm.emit(r_type(V1, V0, V1, 0, 0x21))
    asm.emit(r_type(ZERO, V1, V1, 2, 0x00))
    asm.emit(r_type(V1, V0, V1, 0, 0x21))
    asm.emit(r_type(ZERO, V1, V1, 2, 0x00))       # v1 = max*52
    asm.emit(i_type(0x23, S2, S1, 0))
    asm.emit(0)                                    # R3000 load delay
    asm.emit(r_type(S1, V1, S1, 0, 0x21))
    asm.emit(r_type(S1, S4, S1, 0, 0x21))         # s1 = packet
    asm.emit(i_type(0x2B, SP, ZERO, 0x10))
    asm.emit(r_type(S1, ZERO, A0, 0, 0x21))
    asm.emit(r_type(ZERO, ZERO, A1, 0, 0x21))
    asm.emit(r_type(ZERO, ZERO, A2, 0, 0x21))
    asm.emit(i_type(0x0F, ZERO, A3, 0x801F))
    asm.emit(i_type(0x25, A3, A3, 0x2FFC))
    asm.emit(0)                                    # R3000 load delay
    asm.emit(i_type(0x0D, A3, A3, 0x10))          # texture page y=256
    asm.emit(jal(SET_DRAW_MODE))
    asm.emit(0)
    asm.emit(r_type(S3, ZERO, A0, 0, 0x21))
    asm.emit(r_type(S1, ZERO, A1, 0, 0x21))
    asm.emit(jal(ADD_PRIM))
    asm.emit(0)

    for reg, offset in (
        (RA, 0x4C), (S7, 0x48), (S6, 0x44), (S5, 0x40), (S4, 0x3C),
        (S3, 0x38), (S2, 0x34), (S1, 0x30), (S0, 0x2C),
    ):
        asm.emit(i_type(0x23, SP, reg, offset))
    asm.emit(r_type(RA, ZERO, ZERO, 0, 0x08))
    asm.emit(i_type(0x09, SP, SP, 0x50))

    # Internal pass: select glyphs by the metadata high-page flag, populate
    # the current display buffer's sprite packet, and add it to the OT.
    asm.label("draw_pass")
    pass_address = asm.current_address
    asm.emit(i_type(0x2B, SP, RA, 0x28))
    asm.emit(r_type(ZERO, ZERO, S0, 0, 0x21))
    asm.emit(r_type(ZERO, ZERO, S1, 0, 0x21))
    asm.emit(i_type(0x21, S2, V0, 0x0A))
    asm.emit(0)                                    # R3000 load delay
    asm.branch(0x06, V0, ZERO, "pass_done")       # blez v0,done
    asm.emit(0)
    asm.label("pass_loop")
    asm.emit(i_type(0x23, S2, V1, 0))
    asm.emit(0)                                    # R3000 load delay
    asm.emit(r_type(V1, S1, V1, 0, 0x21))
    asm.emit(i_type(0x24, V1, V0, 0x2B))
    asm.emit(0)                                    # R3000 load delay
    asm.emit(i_type(0x0C, V0, T0, 0x80))
    asm.branch(0x05, T0, S5, "pass_skip")         # bne t0,s5,skip
    asm.emit(0)
    asm.emit(r_type(V1, S4, A1, 0, 0x21))
    for source, target, load_op, store_op in (
        (0x2C, 0x08, 0x25, 0x29),
        (0x2E, 0x0A, 0x25, 0x29),
        (0x28, 0x0C, 0x24, 0x28),
        (0x29, 0x0D, 0x24, 0x28),
        (0x2A, 0x10, 0x24, 0x29),
    ):
        asm.emit(i_type(load_op, V1, V0, source))
        asm.emit(0)                                # R3000 load delay
        asm.emit(i_type(store_op, A1, V0, target))
    asm.emit(i_type(0x24, V1, V0, 0x2B))
    asm.emit(0)                                    # R3000 load delay
    asm.emit(i_type(0x0C, V0, V0, 0x7F))
    asm.emit(i_type(0x29, A1, V0, 0x12))
    asm.emit(i_type(0x25, V1, V0, 0x30))
    asm.emit(0)                                    # R3000 load delay
    asm.emit(i_type(0x29, A1, V0, 0x0E))
    asm.emit(r_type(S3, ZERO, A0, 0, 0x21))
    asm.emit(jal(ADD_PRIM))
    asm.emit(0)
    asm.label("pass_skip")
    asm.emit(i_type(0x21, S2, V0, 0x0A))
    asm.emit(i_type(0x09, S0, S0, 1))
    asm.emit(r_type(S0, V0, V0, 0, 0x2A))         # slt v0,s0,v0
    asm.branch(0x05, V0, ZERO, "pass_loop")
    asm.emit(i_type(0x09, S1, S1, 0x34))
    asm.label("pass_done")
    asm.emit(i_type(0x23, SP, RA, 0x28))
    asm.emit(0)                                    # R3000 load delay
    asm.emit(r_type(RA, ZERO, ZERO, 0, 0x08))
    asm.emit(0)

    asm.words[pass_call_1] = jal(pass_address)
    asm.words[pass_call_2] = jal(pass_address)
    return asm.finish(), pass_address


def build_cave() -> tuple[bytes, dict[str, int]]:
    reserve_address = CAVE_START
    reserve = build_reserve_helper(reserve_address)
    flag_address = reserve_address + len(reserve)
    flag = build_flag_helper(flag_address)
    renderer_address = (flag_address + len(flag) + 3) & ~3
    renderer, pass_address = build_renderer(renderer_address)
    used_end = renderer_address + len(renderer)
    if used_end > CAVE_LIMIT:
        raise SystemExit(
            f"dual-page renderer exceeds cave by {used_end - CAVE_LIMIT} bytes"
        )
    cave = bytearray(CAVE_SIZE)
    for address, payload in (
        (reserve_address, reserve),
        (flag_address, flag),
        (renderer_address, renderer),
    ):
        start = address - CAVE_START
        cave[start : start + len(payload)] = payload
    return bytes(cave), {
        "reserve": reserve_address,
        "flag": flag_address,
        "renderer": renderer_address,
        "pass": pass_address,
        "used_end": used_end,
    }


def current_lookup_rows(psx: bytes) -> list[int]:
    offset = file_offset(LOOKUP_ADDRESS)
    return [
        struct.unpack_from("<H", psx, offset + index * 2)[0] // INDICES_PER_ROW
        for index in range(LOOKUP_COUNT)
    ]


def main() -> None:
    if sha256(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v71 base archive hash differs")
    with ZipFile(BASE, "r") as source:
        infos = source.infolist()
        original = {info.filename: source.read(info.filename) for info in infos}

    psx = bytearray(original[PSX_MEMBER])
    for address, expected in EXPECTED_HOOKS.items():
        offset = file_offset(address)
        if psx[offset : offset + len(expected)] != expected:
            raise SystemExit(f"hook source differs at 0x{address:08X}")

    cave_offset = file_offset(CAVE_START)
    existing_cave = psx[cave_offset : cave_offset + CAVE_SIZE]
    if any(existing_cave):
        raise SystemExit("selected executable cave is not zero in v71")

    rows = current_lookup_rows(psx)
    if 21 in rows:
        raise SystemExit("row 21 crosses the texture-page boundary")
    high_count = sum(row >= HIGH_ROW_START for row in rows)
    if high_count != 57:
        raise SystemExit(f"unexpected high-page mapping count: {high_count}")

    cave, layout = build_cave()
    psx[cave_offset : cave_offset + len(cave)] = cave
    struct.pack_into(
        "<II", psx, file_offset(STATE_INIT_HOOK), jal(layout["reserve"]), 0
    )
    struct.pack_into(
        "<II", psx, file_offset(GLYPH_FLAG_HOOK), jal(layout["flag"]), 0
    )
    struct.pack_into(
        "<II", psx, file_offset(RENDERER_HOOK), j(layout["renderer"]), 0
    )

    members = dict(original)
    members[PSX_MEMBER] = bytes(psx)
    changed_members = [name for name in members if members[name] != original[name]]
    if changed_members != [PSX_MEMBER]:
        raise SystemExit(f"unexpected changed members: {changed_members}")
    if members[COMM_MEMBER] != original[COMM_MEMBER]:
        raise SystemExit("COMM.IMG changed")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as target:
        for info in infos:
            target.writestr(clone_info(info), members[info.filename])

    with ZipFile(OUTPUT, "r") as built:
        readback = {info.filename: built.read(info.filename) for info in built.infolist()}
    if readback != members:
        raise SystemExit("ZIP readback differs")

    # Independent hook and cave readback.
    built_psx = readback[PSX_MEMBER]
    expected_hooks = {
        STATE_INIT_HOOK: struct.pack("<II", jal(layout["reserve"]), 0),
        GLYPH_FLAG_HOOK: struct.pack("<II", jal(layout["flag"]), 0),
        RENDERER_HOOK: struct.pack("<II", j(layout["renderer"]), 0),
    }
    for address, expected in expected_hooks.items():
        offset = file_offset(address)
        if built_psx[offset : offset + 8] != expected:
            raise SystemExit(f"hook readback differs at 0x{address:08X}")
    if built_psx[cave_offset : cave_offset + len(cave)] != cave:
        raise SystemExit("cave readback differs")

    # Confirm that the CSV and live table agree on the absence of boundary row
    # 21. The live table remains authoritative because later builds moved a few
    # entries without rewriting the historical map.
    with GLYPH_MAP.open(encoding="utf-8-sig", newline="") as handle:
        map_rows = list(csv.DictReader(handle))
    if len(map_rows) != LOOKUP_COUNT:
        raise SystemExit("glyph-map record count differs")
    if any(int(row["physical_index"]) // INDICES_PER_ROW == 21 for row in map_rows):
        raise SystemExit("historical glyph map contains row 21")

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    disassembly = []
    used_size = layout["used_end"] - CAVE_START
    for instruction in md.disasm(cave[:used_size], CAVE_START):
        disassembly.append(
            f"{instruction.address:08X}  {instruction.mnemonic:<8} {instruction.op_str}"
        )
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    DISASSEMBLY.write_text("\n".join(disassembly) + "\n", encoding="utf-8")

    changed_offsets = [
        index for index, (before, after) in enumerate(zip(original[PSX_MEMBER], psx))
        if before != after
    ]
    REPORT.write_text(
        "\n".join(
            [
                "ui_hud_e7_v73 dual-tpage renderer build report",
                f"base={BASE}",
                f"base_sha256={BASE_SHA256}",
                f"output={OUTPUT}",
                f"output_sha256={sha256(OUTPUT.read_bytes())}",
                "changed_members=PSX.EXE",
                "unchanged_members=COMM.IMG and all DAT members",
                f"lookup_records={LOOKUP_COUNT}",
                f"high_page_records={high_count}",
                "boundary_row_21_records=0",
                f"reserve_helper=0x{layout['reserve']:08X}",
                f"flag_helper=0x{layout['flag']:08X}",
                f"renderer=0x{layout['renderer']:08X}",
                f"draw_pass=0x{layout['pass']:08X}",
                f"cave_used_bytes={used_size}",
                f"cave_free_bytes={CAVE_SIZE - used_size}",
                f"changed_psx_bytes={len(changed_offsets)}",
                "reserved_slots_per_text_state=1",
                "static_readback=PASS",
                "runtime_verification=PENDING",
                "v72_status=REJECTED_SPRITE_TEXTURE_OVERWRITE",
                "",
            ]
        ),
        encoding="utf-8",
    )

    print(OUTPUT)
    print(f"SHA256 {sha256(OUTPUT.read_bytes())}")
    print(f"Cave used {used_size}/{CAVE_SIZE} bytes")
    print(f"High-page mappings {high_count}")
    print("COMM.IMG unchanged")


if __name__ == "__main__":
    main()
