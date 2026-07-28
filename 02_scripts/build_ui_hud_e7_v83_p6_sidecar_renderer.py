"""Build the v83 P6 renderer diagnostic without reusing glyph-record bytes.

v81 and v82 carried the P6 marker in bytes that are part of the live glyph
record. This diagnostic keeps the proven P6 VRAM page, but records P6 status
in a small executable-side sidecar keyed by text-state pointer and glyph
index. The game-owned glyph record remains unchanged.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from build_ui_hud_e7_v73_dual_tpage_renderer import (
    A0,
    A1,
    A2,
    A3,
    RA,
    S0,
    S2,
    T0,
    V0,
    V1,
    ZERO,
    Assembler,
    i_type,
    j,
    jal,
    r_type,
)


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "ex" / "코덱스" / "ui_hud_e7_v80_p6_only_vram_probe_patch_only.zip"
V81 = ROOT / "ex" / "코덱스" / "ui_hud_e7_v81_p6_minimal_separate_renderer_test_patch_only.zip"
SOURCE_JP = (
    ROOT
    / "01_work"
    / "analysis"
    / "p6_web_method_2026-07-28"
    / "source_jp"
    / "31"
    / "S3032.DAT"
)
OUTPUT = ROOT / "03_output" / "ui_hud_e7_v83_p6_sidecar_renderer_test_patch_only.zip"
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_hud_e7_v83"
REPORT = ANALYSIS / "build_report.txt"
DISASSEMBLY = ANALYSIS / "mips_disassembly.txt"

BASE_SHA256 = "039A1BD2F5441940B57EAE9D46A809F04F3BC98CD958C427759FA8732FC6975B"
PSX_MEMBER = "PSX.EXE"
COMM_MEMBER = "COMM.IMG"
TEST_MEMBER = "31/S3032.DAT"
PSX_LOAD_BASE = 0x8011A800

GLYPH_HOOK = 0x8016B5D8
GLYPH_RETURN = 0x8016B5E0
RENDERER_HOOK = 0x8016B764

MAIN_CAVE_START = 0x801A2074
MAIN_CAVE_END = 0x801A2304
RENDERER_SOURCE_START = 0x801A20B0
RENDERER_SOURCE_END = 0x801A2304
RENDERER_ENTRY = 0x801A22A0
PASS_MARKER_CALL = 0x801A2204
PASS_TPAGE_MASK = 0x801A2260

TAIL_CAVE_START = 0x801A86EC
TAIL_CAVE_END = 0x801A8800
SIDECAR_ADDRESS = 0x801A87F4
BITMAP_GLYPHS = 64

TEST_TEXT_START = 0x4794E
TEST_TEXT_END = 0x47962

EXPECTED_V80_HOOKS = {
    GLYPH_HOOK: bytes.fromhex("0E 00 C2 90 00 00 00 00"),
    RENDERER_HOOK: bytes.fromhex("D0 FF BD 27 2C 00 BF AF"),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def file_offset(address: int) -> int:
    offset = address - PSX_LOAD_BASE
    if not 0 <= offset <= 0x8E000:
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


def load_address(asm: Assembler, register: int, address: int) -> None:
    upper = (address + 0x8000) >> 16
    lower = address & 0xFFFF
    asm.emit(i_type(0x0F, ZERO, register, upper))
    asm.emit(i_type(0x09, register, register, lower))


def build_glyph_helper(address: int) -> bytes:
    asm = Assembler(address)
    load_address(asm, V1, SIDECAR_ADDRESS)
    asm.emit(i_type(0x23, V1, A3, 0))             # active state
    asm.emit(0)
    asm.branch(0x05, A3, A2, "reset")             # new text state
    asm.emit(0)
    asm.emit(i_type(0x25, A2, A3, 0x0A))          # current glyph index
    asm.emit(0)
    asm.branch(0x05, A3, ZERO, "classify")
    asm.emit(0)

    asm.label("reset")
    asm.emit(i_type(0x2B, V1, A2, 0))
    asm.emit(i_type(0x2B, V1, ZERO, 4))
    asm.emit(i_type(0x2B, V1, ZERO, 8))

    asm.label("classify")
    asm.emit(i_type(0x09, T0, A3, -0x18))
    asm.emit(i_type(0x0B, A3, A3, 8))             # rows 24..31 are P6
    asm.branch(0x04, A3, ZERO, "done")
    asm.emit(0)

    asm.emit(i_type(0x24, A1, A3, 0x28))
    asm.emit(0)
    asm.emit(i_type(0x09, A3, A3, 0x28))          # P6 U origin
    asm.emit(i_type(0x28, A1, A3, 0x28))
    asm.emit(i_type(0x25, A2, A3, 0x0A))
    asm.emit(0)
    asm.emit(i_type(0x0B, A3, T0, BITMAP_GLYPHS))
    asm.branch(0x04, T0, ZERO, "done")
    asm.emit(0)

    asm.emit(r_type(ZERO, A3, T0, 5, 0x02))       # bitmap word
    asm.emit(r_type(ZERO, T0, T0, 2, 0x00))
    asm.emit(r_type(V1, T0, V1, 0, 0x21))
    asm.emit(i_type(0x0C, A3, A3, 0x1F))
    asm.emit(i_type(0x0D, ZERO, T0, 1))
    asm.emit(r_type(A3, T0, T0, 0, 0x04))         # 1 << bit
    asm.emit(i_type(0x23, V1, A3, 4))
    asm.emit(0)
    asm.emit(r_type(A3, T0, A3, 0, 0x25))
    asm.emit(i_type(0x2B, V1, A3, 4))

    asm.label("done")
    asm.emit(i_type(0x24, A2, V0, 0x0E))          # displaced original
    asm.emit(j(GLYPH_RETURN))
    asm.emit(0)
    return asm.finish()


def build_marker_helper(address: int) -> bytes:
    asm = Assembler(address)
    load_address(asm, V0, SIDECAR_ADDRESS)
    asm.emit(i_type(0x23, V0, V1, 0))
    asm.emit(0)
    asm.branch(0x05, V1, S2, "not_p6")
    asm.emit(0)
    asm.emit(i_type(0x0B, S0, V1, BITMAP_GLYPHS))
    asm.branch(0x04, V1, ZERO, "not_p6")
    asm.emit(0)
    asm.emit(r_type(ZERO, S0, V1, 5, 0x02))
    asm.emit(r_type(ZERO, V1, V1, 2, 0x00))
    asm.emit(r_type(V0, V1, V0, 0, 0x21))
    asm.emit(i_type(0x23, V0, V0, 4))
    asm.emit(i_type(0x0C, S0, V1, 0x1F))
    asm.emit(0)
    asm.emit(r_type(V1, V0, V0, 0, 0x06))         # bitmap >> bit
    asm.emit(i_type(0x0C, V0, V0, 1))
    asm.emit(r_type(ZERO, V0, V0, 7, 0x00))
    asm.emit(r_type(RA, ZERO, ZERO, 0, 0x08))
    asm.emit(0)

    asm.label("not_p6")
    asm.emit(r_type(ZERO, ZERO, V0, 0, 0x21))
    asm.emit(r_type(RA, ZERO, ZERO, 0, 0x08))
    asm.emit(0)
    return asm.finish()


def build_renderer_entry(address: int) -> bytes:
    asm = Assembler(address)
    load_address(asm, V0, SIDECAR_ADDRESS)
    asm.emit(i_type(0x23, V0, V1, 0))
    asm.emit(0)
    asm.branch(0x05, V1, A0, "original")
    asm.emit(0)
    asm.emit(i_type(0x23, V0, V1, 4))
    asm.emit(i_type(0x23, V0, V0, 8))
    asm.emit(0)
    asm.emit(r_type(V1, V0, V1, 0, 0x25))
    asm.branch(0x04, V1, ZERO, "original")
    asm.emit(0)
    asm.emit(j(RENDERER_SOURCE_START))
    asm.emit(0)

    asm.label("original")
    asm.emit(i_type(0x09, 29, 29, -0x30))
    asm.emit(j(0x8016B76C))
    asm.emit(i_type(0x2B, 29, RA, 0x2C))
    return asm.finish()


def main() -> None:
    if sha256(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v80 base archive hash differs")

    with ZipFile(BASE, "r") as source:
        infos = source.infolist()
        members = {info.filename: source.read(info.filename) for info in infos}
    with ZipFile(V81, "r") as source:
        v81_members = {info.filename: source.read(info.filename) for info in source.infolist()}

    original_psx = members[PSX_MEMBER]
    psx = bytearray(original_psx)
    for address, expected in EXPECTED_V80_HOOKS.items():
        offset = file_offset(address)
        if psx[offset : offset + len(expected)] != expected:
            raise SystemExit(f"v80 hook source differs at 0x{address:08X}")

    for start, end in (
        (MAIN_CAVE_START, MAIN_CAVE_END),
        (TAIL_CAVE_START, TAIL_CAVE_END),
    ):
        payload = psx[file_offset(start) : file_offset(end)]
        if any(payload):
            raise SystemExit(f"selected cave is not zero: 0x{start:08X}")

    v81_psx = v81_members[PSX_MEMBER]
    renderer = bytearray(
        v81_psx[
            file_offset(RENDERER_SOURCE_START) : file_offset(RENDERER_SOURCE_END)
        ]
    )
    renderer_base = RENDERER_SOURCE_START

    glyph_helper = build_glyph_helper(TAIL_CAVE_START)
    marker_address = (TAIL_CAVE_START + len(glyph_helper) + 3) & ~3
    marker_helper = build_marker_helper(marker_address)
    code_end = marker_address + len(marker_helper)
    if code_end > SIDECAR_ADDRESS:
        raise SystemExit(
            f"tail helpers exceed sidecar by {code_end - SIDECAR_ADDRESS} bytes"
        )

    marker_patch = struct.pack(
        "<IIIII",
        jal(marker_address),
        0,
        i_type(0x05, V0, 21, 0x001C),  # bne v0,s5,pass_skip
        0,
        0,
    )
    marker_offset = PASS_MARKER_CALL - renderer_base
    renderer[marker_offset : marker_offset + len(marker_patch)] = marker_patch

    # The record tpage is no longer carrying a flag, so preserve it verbatim.
    struct.pack_into("<I", renderer, PASS_TPAGE_MASK - renderer_base, 0)

    entry = build_renderer_entry(RENDERER_ENTRY)
    entry_offset = RENDERER_ENTRY - renderer_base
    if len(entry) > RENDERER_SOURCE_END - RENDERER_ENTRY:
        raise SystemExit("renderer entry exceeds the original scan stub")
    renderer[entry_offset : entry_offset + len(entry)] = entry
    renderer[
        entry_offset + len(entry) : RENDERER_SOURCE_END - renderer_base
    ] = b"\0" * (
        RENDERER_SOURCE_END - RENDERER_ENTRY - len(entry)
    )

    psx[
        file_offset(RENDERER_SOURCE_START) : file_offset(RENDERER_SOURCE_END)
    ] = renderer
    psx[
        file_offset(TAIL_CAVE_START) : file_offset(TAIL_CAVE_START) + len(glyph_helper)
    ] = glyph_helper
    psx[file_offset(marker_address) : file_offset(marker_address) + len(marker_helper)] = (
        marker_helper
    )
    psx[file_offset(SIDECAR_ADDRESS) : file_offset(SIDECAR_ADDRESS) + 12] = b"\0" * 12
    struct.pack_into("<II", psx, file_offset(GLYPH_HOOK), j(TAIL_CAVE_START), 0)
    struct.pack_into("<II", psx, file_offset(RENDERER_HOOK), j(RENDERER_ENTRY), 0)

    source_test = bytearray(SOURCE_JP.read_bytes())
    v81_test = v81_members[TEST_MEMBER]
    source_test[TEST_TEXT_START:TEST_TEXT_END] = v81_test[
        TEST_TEXT_START:TEST_TEXT_END
    ]

    members[PSX_MEMBER] = bytes(psx)
    members[COMM_MEMBER] = v81_members[COMM_MEMBER]
    members[TEST_MEMBER] = bytes(source_test)

    output_infos = list(infos)
    if TEST_MEMBER not in {info.filename for info in output_infos}:
        output_infos.append(ZipInfo(TEST_MEMBER))

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as target:
        for info in output_infos:
            payload = members[info.filename]
            target.writestr(clone_info(info), payload)

    with ZipFile(OUTPUT, "r") as built:
        readback = {info.filename: built.read(info.filename) for info in built.infolist()}
    if readback != members:
        raise SystemExit("ZIP readback differs")

    if readback[PSX_MEMBER][file_offset(GLYPH_HOOK) : file_offset(GLYPH_HOOK) + 8] != (
        struct.pack("<II", j(TAIL_CAVE_START), 0)
    ):
        raise SystemExit("glyph hook readback differs")
    if readback[PSX_MEMBER][
        file_offset(RENDERER_HOOK) : file_offset(RENDERER_HOOK) + 8
    ] != struct.pack("<II", j(RENDERER_ENTRY), 0):
        raise SystemExit("renderer hook readback differs")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    lines = []
    for start, end in (
        (RENDERER_SOURCE_START, RENDERER_SOURCE_END),
        (TAIL_CAVE_START, code_end),
    ):
        chunk = readback[PSX_MEMBER][file_offset(start) : file_offset(end)]
        lines.append(f"--- 0x{start:08X} ---")
        lines.extend(
            f"{ins.address:08X}  {ins.mnemonic:<8} {ins.op_str}"
            for ins in md.disasm(chunk, start)
        )
    DISASSEMBLY.write_text("\n".join(lines) + "\n", encoding="utf-8")

    changed_psx = sum(a != b for a, b in zip(original_psx, psx))
    REPORT.write_text(
        "\n".join(
            [
                "ui_hud_e7_v83 P6 sidecar renderer diagnostic",
                f"base={BASE}",
                f"base_sha256={BASE_SHA256}",
                f"output={OUTPUT}",
                f"output_sha256={sha256(OUTPUT.read_bytes())}",
                "architecture=text-state pointer + 64-bit external glyph bitmap",
                "glyph_record_marker=NONE",
                f"glyph_helper=0x{TAIL_CAVE_START:08X}",
                f"marker_helper=0x{marker_address:08X}",
                f"sidecar=0x{SIDECAR_ADDRESS:08X}",
                f"renderer=0x{RENDERER_SOURCE_START:08X}",
                f"renderer_entry=0x{RENDERER_ENTRY:08X}",
                f"changed_psx_bytes={changed_psx}",
                "changed_members=PSX.EXE, COMM.IMG, 31/S3032.DAT",
                "S3032_scope=first test sentence only",
                "record_0x2b_unchanged=YES",
                "record_0x32_unchanged=YES",
                "static_readback=PASS",
                "runtime_verification=PENDING",
                "diagnostic_limit=one active text state, 64 glyphs",
                "",
            ]
        ),
        encoding="utf-8",
    )

    print(OUTPUT)
    print(f"SHA256 {sha256(OUTPUT.read_bytes())}")
    print(f"glyph_helper=0x{TAIL_CAVE_START:08X}")
    print(f"marker_helper=0x{marker_address:08X}")
    print(f"sidecar=0x{SIDECAR_ADDRESS:08X}")
    print("glyph_record_marker=NONE")
    print("static_readback=PASS")


if __name__ == "__main__":
    main()
