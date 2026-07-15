from __future__ import annotations

import hashlib
import struct
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/story_intro_e2_expanded_v06_cumulative_patch_only.zip"
BASE_HASH = "D849F637D7F1C0E5B6E170BBE3CB6ACB47E48FC045C9E0A702B60CAF26991FF5"
OUTPUT = ROOT / "03_output/story_intro_halfwidth_space_v10_cumulative_patch_only.zip"
REPORT = ROOT / "01_work/analysis/story_intro_halfwidth_space_v10_report.txt"

PSX_TARGET = "PSX.EXE"
LOAD_ADDRESS = 0x8011B000
SPACE_REGISTER_ADDRESS = 0x8016B524
ADVANCE_ADDRESS = 0x8016B63C

SPACE_REGISTER_ORIGINAL = 0x00000000
SPACE_REGISTER_PATCH = 0x3409009B  # ori t1,zero,009B


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def file_offset(address: int) -> int:
    return address - LOAD_ADDRESS + 0x800


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("v0.6 base hash differs")
    with zipfile.ZipFile(BASE) as archive:
        infos = {item.filename: item for item in archive.infolist()}
        files = {name: archive.read(name) for name in infos}
    if len(files) != 39:
        raise SystemExit("unexpected cumulative entry count")

    psx = bytearray(files[PSX_TARGET])
    register_offset = file_offset(SPACE_REGISTER_ADDRESS)
    if struct.unpack_from("<I", psx, register_offset)[0] != SPACE_REGISTER_ORIGINAL:
        raise SystemExit("glyph-builder register slot differs")
    struct.pack_into("<I", psx, register_offset, SPACE_REGISTER_PATCH)

    advance_offset = file_offset(ADVANCE_ADDRESS)
    original = struct.unpack_from("<9I", psx, advance_offset)
    expected = (
        0x90C3000D,  # lbu   v1,0D(a2)
        0x90C5000F,  # lbu   a1,0F(a2)
        0x94C20006,  # lhu   v0,06(a2)
        0x94C4000A,  # lhu   a0,0A(a2)
        0x00651821,  # addu  v1,v1,a1
        0x00431021,  # addu  v0,v0,v1
        0xA4C20006,  # sh    v0,06(a2)
        0x24840001,  # addiu a0,a0,1
        0xA4C4000A,  # sh    a0,0A(a2)
    )
    if original != expected:
        raise SystemExit("glyph-builder advance sequence differs")

    # R3000 load-delay safe: the count load at normal is independent of v0,
    # leaving one full instruction between the X load and its first use.
    patched = (
        0x90C3000D,  # lbu   v1,0D(a2) (normal width)
        0x14890002,  # bne   a0,t1,normal
        0x94C20006,  # lhu   v0,06(a2) (branch delay)
        0x34030006,  # ori   v1,zero,6 (space width)
        0x94C4000A,  # normal: lhu a0,0A(a2) (load-delay spacer)
        0x00431021,  # addu  v0,v0,v1
        0xA4C20006,  # sh    v0,06(a2)
        0x24840001,  # addiu a0,a0,1
        0xA4C4000A,  # sh    a0,0A(a2)
    )
    struct.pack_into("<9I", psx, advance_offset, *patched)
    files[PSX_TARGET] = bytes(psx)

    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            archive.writestr(infos[name], files[name])
    report = (
        "glyph_width=12\n"
        "space_glyph_index=0x9B\n"
        "space_advance=6\n"
        "font_changed=false\n"
        "r3000_load_delay_safe=true\n"
        "new_code_cave=false\n"
        f"sha256={digest(OUTPUT.read_bytes())}\n"
    )
    REPORT.write_text(report, encoding="utf-8")
    print(report, end="")
    print(OUTPUT)


if __name__ == "__main__":
    main()
