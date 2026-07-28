"""Build v85 by relocating the v83 P6 sidecar runtime above the original BSS.

v84 kept the helper code in the executable tail by moving the BSS clear start.
Runtime savestates proved that this tail is live BSS and overwrites the helper.
This build keeps the original BSS range intact:

1. The high-address helper image is stored temporarily in the executable tail.
2. A 56-byte entry bootstrap copies it above the original BSS.
3. The original fast word-clear loop zeros the complete original BSS range.
4. P6 hooks use the relocated helper and sidecar addresses.

The executable size and every non-PSX.EXE member remain unchanged.
"""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

import build_ui_hud_e7_v83_p6_sidecar_renderer as v83  # noqa: E402


BASE = (
    ROOT
    / "03_output"
    / "ui_hud_e7_v84_p6_sidecar_bss_boundary_fix_patch_only.zip"
)
OUTPUT = (
    ROOT
    / "03_output"
    / "ui_hud_e7_v85_p6_highram_bootstrap_patch_only.zip"
)
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_hud_e7_v85"
REPORT = ANALYSIS / "build_report.txt"
DISASSEMBLY = ANALYSIS / "mips_disassembly.txt"

BASE_SHA256 = "69B696B338A5C2F7727FE3F939CB7EF20D6320F2527227202CD17D4F70C28594"
BASE_PSX_SHA256 = "0DF808977EB514989DDF726793757E17AE39DD2C205FE46ED15AE0A4456F6D9C"
PSX_MEMBER = "PSX.EXE"
PSX_LOAD_BASE = 0x8011A800
PSX_SIZE = 0x8E000

ENTRY_START = 0x801757BC
ENTRY_END = 0x801757F4
BIOS_A0_VECTOR = 0x800000A0
BIOS_MEMCPY = 0x2A

ORIGINAL_BSS_START = 0x801A86E8
ORIGINAL_BSS_END = 0x801FE3C4
HIGH_GLYPH_HELPER = ORIGINAL_BSS_END
SOURCE_START = v83.TAIL_CAVE_START
SOURCE_END = v83.TAIL_CAVE_END
COPY_SIZE = SOURCE_END - SOURCE_START
SIDECAR_OFFSET = v83.SIDECAR_ADDRESS - SOURCE_START
HIGH_SIDECAR = HIGH_GLYPH_HELPER + SIDECAR_OFFSET

# Lowest valid stack pointer found in 97 project savestate samples.
OBSERVED_MIN_SP = 0x801FFE78
MIN_REQUIRED_STACK_MARGIN = 0x1000

ZERO = v83.ZERO
V0 = v83.V0
V1 = v83.V1
A0 = v83.A0
A1 = v83.A1
A2 = v83.A2
T1 = 9


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def file_offset(address: int) -> int:
    offset = address - PSX_LOAD_BASE
    if not 0 <= offset <= PSX_SIZE:
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


def load_address_words(register: int, address: int) -> list[int]:
    upper = (address + 0x8000) >> 16
    lower = address & 0xFFFF
    return [
        v83.i_type(0x0F, ZERO, register, upper),
        v83.i_type(0x09, register, register, lower),
    ]


def build_bootstrap() -> bytes:
    """Copy the helper image, then clear the complete original BSS.

    BIOS A(2Ah) memcpy returns dst in v0. The clear loop uses that returned
    high destination as its exclusive end, which keeps the bootstrap within
    the original 14-instruction startup-clear footprint.
    """

    words: list[int] = []
    words.extend(load_address_words(A0, HIGH_GLYPH_HELPER))
    words.extend(load_address_words(A1, SOURCE_START))
    words.append(v83.i_type(0x09, ZERO, A2, COPY_SIZE))
    words.append(v83.jal(BIOS_A0_VECTOR))
    words.append(v83.i_type(0x09, ZERO, T1, BIOS_MEMCPY))
    words.extend(load_address_words(V1, ORIGINAL_BSS_START))

    clear_loop_index = len(words)
    words.append(v83.i_type(0x2B, V1, ZERO, 0))
    words.append(v83.i_type(0x09, V1, V1, 4))
    branch_index = len(words)
    delta = clear_loop_index - (branch_index + 1)
    words.append(v83.i_type(0x05, V1, V0, delta))
    words.append(0)

    # Preserve the value expected by the untouched stack-setup code at F4.
    words.append(v83.i_type(0x09, ZERO, V0, 4))

    payload = struct.pack(f"<{len(words)}I", *words)
    if len(payload) != ENTRY_END - ENTRY_START:
        raise SystemExit(
            f"bootstrap size differs: {len(payload)} != "
            f"{ENTRY_END - ENTRY_START}"
        )
    return payload


def expected_v84_entry() -> bytes:
    words = [
        0x3C02801B,  # lui v0,0x801b
        0x24428800,  # addiu v0,v0,-0x7800 (v84 boundary)
        0x3C038020,  # lui v1,0x8020
        0x2463E3C4,  # addiu v1,v1,-0x1c3c
        0xAC400000,  # sw zero,0(v0)
        0x24420004,  # addiu v0,v0,4
        0x0043082B,  # sltu at,v0,v1
        0x1420FFFC,  # bnez at,clear
        0x00000000,
        0x24020004,  # addiu v0,zero,4
        0x00000000,
        0x00000000,
        0x00000000,
        0x00000000,
    ]
    return struct.pack("<14I", *words)


def main() -> None:
    if sha256(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v84 base archive hash differs")

    with ZipFile(BASE, "r") as source:
        infos = source.infolist()
        members = {info.filename: source.read(info.filename) for info in infos}

    original_members = dict(members)
    original_psx = members[PSX_MEMBER]
    if len(original_psx) != PSX_SIZE:
        raise SystemExit(f"unexpected PSX.EXE size: 0x{len(original_psx):X}")
    if sha256(original_psx) != BASE_PSX_SHA256:
        raise SystemExit("v84 PSX.EXE hash differs")

    psx = bytearray(original_psx)
    entry_offset = file_offset(ENTRY_START)
    if psx[entry_offset : file_offset(ENTRY_END)] != expected_v84_entry():
        raise SystemExit("v84 startup-clear sequence differs")

    # Build helpers for their runtime addresses, then store their bytes in the
    # temporary executable-tail source image copied by the bootstrap.
    old_sidecar = v83.SIDECAR_ADDRESS
    v83.SIDECAR_ADDRESS = HIGH_SIDECAR
    try:
        glyph_helper = v83.build_glyph_helper(HIGH_GLYPH_HELPER)
        high_marker = (HIGH_GLYPH_HELPER + len(glyph_helper) + 3) & ~3
        marker_helper = v83.build_marker_helper(high_marker)
        renderer_entry = v83.build_renderer_entry(v83.RENDERER_ENTRY)
    finally:
        v83.SIDECAR_ADDRESS = old_sidecar

    marker_offset = high_marker - HIGH_GLYPH_HELPER
    marker_end = high_marker + len(marker_helper)
    high_end = HIGH_GLYPH_HELPER + COPY_SIZE
    if marker_end > HIGH_SIDECAR:
        raise SystemExit("relocated marker helper exceeds sidecar")
    if HIGH_SIDECAR + 12 > high_end:
        raise SystemExit("relocated sidecar exceeds copied image")
    stack_margin = OBSERVED_MIN_SP - high_end
    if stack_margin < MIN_REQUIRED_STACK_MARGIN:
        raise SystemExit(
            f"observed stack margin too small: 0x{stack_margin:X}"
        )

    source_image = bytearray(COPY_SIZE)
    source_image[0 : len(glyph_helper)] = glyph_helper
    source_image[marker_offset : marker_offset + len(marker_helper)] = marker_helper
    source_image[SIDECAR_OFFSET : SIDECAR_OFFSET + 12] = b"\0" * 12

    # Replace only the P6-dependent addresses in the existing v84 renderer.
    renderer_start = file_offset(v83.RENDERER_SOURCE_START)
    renderer_end = file_offset(v83.RENDERER_SOURCE_END)
    renderer = bytearray(psx[renderer_start:renderer_end])
    marker_patch = struct.pack(
        "<IIIII",
        v83.jal(high_marker),
        0,
        v83.i_type(0x05, V0, 21, 0x001C),
        0,
        0,
    )
    marker_call_offset = v83.PASS_MARKER_CALL - v83.RENDERER_SOURCE_START
    renderer[
        marker_call_offset : marker_call_offset + len(marker_patch)
    ] = marker_patch
    struct.pack_into(
        "<I",
        renderer,
        v83.PASS_TPAGE_MASK - v83.RENDERER_SOURCE_START,
        0,
    )
    renderer_entry_offset = v83.RENDERER_ENTRY - v83.RENDERER_SOURCE_START
    if len(renderer_entry) > v83.RENDERER_SOURCE_END - v83.RENDERER_ENTRY:
        raise SystemExit("relocated renderer entry exceeds scan stub")
    renderer[
        renderer_entry_offset : renderer_entry_offset + len(renderer_entry)
    ] = renderer_entry
    renderer[
        renderer_entry_offset + len(renderer_entry) :
    ] = b"\0" * (
        len(renderer) - renderer_entry_offset - len(renderer_entry)
    )
    psx[renderer_start:renderer_end] = renderer

    psx[file_offset(SOURCE_START) : file_offset(SOURCE_END)] = source_image
    struct.pack_into(
        "<II",
        psx,
        file_offset(v83.GLYPH_HOOK),
        v83.j(HIGH_GLYPH_HELPER),
        0,
    )
    struct.pack_into(
        "<II",
        psx,
        file_offset(v83.RENDERER_HOOK),
        v83.j(v83.RENDERER_ENTRY),
        0,
    )
    psx[entry_offset : file_offset(ENTRY_END)] = build_bootstrap()

    # The stack-setup sequence immediately after the replaced region must stay
    # byte-identical. It consumes v0=4, restored by the bootstrap's last word.
    stack_setup_start = file_offset(ENTRY_END)
    stack_setup_end = stack_setup_start + 0x20
    if psx[stack_setup_start:stack_setup_end] != original_psx[
        stack_setup_start:stack_setup_end
    ]:
        raise SystemExit("post-bootstrap stack setup changed")

    members[PSX_MEMBER] = bytes(psx)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as target:
        for info in infos:
            target.writestr(clone_info(info), members[info.filename])

    with ZipFile(OUTPUT, "r") as built:
        readback_infos = built.infolist()
        readback = {
            info.filename: built.read(info.filename) for info in readback_infos
        }
    if readback != members:
        raise SystemExit("ZIP readback differs")
    if [info.filename for info in readback_infos] != [
        info.filename for info in infos
    ]:
        raise SystemExit("ZIP member order differs")

    changed_members = [
        name for name in members if members[name] != original_members[name]
    ]
    if changed_members != [PSX_MEMBER]:
        raise SystemExit(f"unexpected changed members: {changed_members}")
    if len(members[PSX_MEMBER]) != len(original_members[PSX_MEMBER]):
        raise SystemExit("PSX.EXE size changed")

    # Model the boot sequence byte-for-byte: copy first, then clear only the
    # original BSS below the relocated image.
    ram_start = ORIGINAL_BSS_START
    ram_end = high_end
    ram = bytearray(ram_end - ram_start)
    source_ram_offset = SOURCE_START - ram_start
    high_ram_offset = HIGH_GLYPH_HELPER - ram_start
    ram[source_ram_offset : source_ram_offset + COPY_SIZE] = source_image
    ram[high_ram_offset : high_ram_offset + COPY_SIZE] = ram[
        source_ram_offset : source_ram_offset + COPY_SIZE
    ]
    clear_start = ORIGINAL_BSS_START - ram_start
    clear_end = ORIGINAL_BSS_END - ram_start
    ram[clear_start:clear_end] = b"\0" * (clear_end - clear_start)
    if any(ram[source_ram_offset : source_ram_offset + COPY_SIZE]):
        raise SystemExit("startup model did not clear the temporary source")
    if ram[high_ram_offset : high_ram_offset + COPY_SIZE] != source_image:
        raise SystemExit("startup model damaged the relocated image")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    disassembly_lines: list[str] = []
    regions = (
        (ENTRY_START, bytes(psx[file_offset(ENTRY_START) : file_offset(ENTRY_END)])),
        (v83.RENDERER_SOURCE_START, bytes(renderer)),
        (HIGH_GLYPH_HELPER, glyph_helper),
        (high_marker, marker_helper),
    )
    for address, payload in regions:
        disassembly_lines.append(f"--- 0x{address:08X} ---")
        disassembly_lines.extend(
            f"{ins.address:08X}  {ins.mnemonic:<8} {ins.op_str}"
            for ins in md.disasm(payload, address)
        )
    DISASSEMBLY.write_text(
        "\n".join(disassembly_lines) + "\n",
        encoding="utf-8",
    )

    changed_offsets = [
        index
        for index, (before, after) in enumerate(zip(original_psx, psx))
        if before != after
    ]
    REPORT.write_text(
        "\n".join(
            [
                "ui_hud_e7_v85 P6 high-RAM bootstrap",
                f"base={BASE}",
                f"base_sha256={BASE_SHA256}",
                f"base_psx_sha256={BASE_PSX_SHA256}",
                f"output={OUTPUT}",
                f"output_sha256={sha256(OUTPUT.read_bytes())}",
                f"output_psx_sha256={sha256(bytes(psx))}",
                f"entry_bootstrap=0x{ENTRY_START:08X}-0x{ENTRY_END:08X}",
                f"temporary_source=0x{SOURCE_START:08X}-0x{SOURCE_END:08X}",
                f"copy_size=0x{COPY_SIZE:X}",
                f"original_bss=0x{ORIGINAL_BSS_START:08X}-0x{ORIGINAL_BSS_END:08X}",
                f"glyph_helper=0x{HIGH_GLYPH_HELPER:08X}",
                f"marker_helper=0x{high_marker:08X}",
                f"marker_end=0x{marker_end:08X}",
                f"sidecar=0x{HIGH_SIDECAR:08X}-0x{HIGH_SIDECAR + 12:08X}",
                f"relocated_image_end=0x{high_end:08X}",
                f"observed_min_sp=0x{OBSERVED_MIN_SP:08X}",
                f"observed_stack_margin=0x{stack_margin:X}",
                f"changed_psx_bytes={len(changed_offsets)}",
                "changed_members=PSX.EXE",
                "all_other_v84_members_byte_identical=YES",
                "psx_exe_size_unchanged=YES",
                "original_bss_range_preserved=YES",
                "startup_copy_clear_model=PASS",
                "post_bootstrap_stack_setup_identical=YES",
                "zip_readback=PASS",
                "runtime_verification=PENDING",
                "",
            ]
        ),
        encoding="utf-8",
    )

    print(OUTPUT)
    print(f"SHA256 {sha256(OUTPUT.read_bytes())}")
    print(f"PSX.EXE SHA256 {sha256(bytes(psx))}")
    print(
        f"high_image=0x{HIGH_GLYPH_HELPER:08X}-0x{high_end:08X} "
        f"stack_margin=0x{stack_margin:X}"
    )
    print(f"changed_psx_bytes={len(changed_offsets)}")
    print("all_other_v84_members_byte_identical=YES")
    print("startup_copy_clear_model=PASS")
    print("static_readback=PASS")


if __name__ == "__main__":
    main()
