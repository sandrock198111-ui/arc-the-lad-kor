from __future__ import annotations

import hashlib
import struct
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/story_intro_halfwidth_space_v10_cumulative_patch_only.zip"
BASE_HASH = "D11C4C629C4718414D45C8AC000EF61965EC9B4309BC24AD74BD995CCE247335"
OUTPUT = ROOT / "03_output/story_intro_e2_skip_v11_cumulative_patch_only.zip"
REPORT = ROOT / "01_work/analysis/story_intro_e2_skip_v11_report.txt"

PSX_TARGET = "PSX.EXE"
LOAD_ADDRESS = 0x8011B000
HELPER_ADDRESS = 0x8018FD20
HELPER_LIMIT = 0x8018FDC5
COMPLETION_TARGET = 0x8016BE44


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def file_offset(address: int) -> int:
    return address - LOAD_ADDRESS + 0x800


def jump(address: int) -> int:
    return 0x08000000 | ((address >> 2) & 0x03FFFFFF)


def old_helper() -> bytes:
    return struct.pack(
        "<15I",
        0x8E080014,
        0x9109FFFF,
        0x2529FF7F,
        0x2D2A0010,
        0x11400007,
        0x000949C0,
        0x3C0A8011,
        0x254A4000,
        0x012A4821,
        0x912A007F,
        0x010A4021,
        0xAE080014,
        0x34020001,
        jump(COMPLETION_TARGET),
        0x00000000,
    )


def corrected_helper() -> bytes:
    return struct.pack(
        "<18I",
        0x8E080014,                    # lw    t0,14(s0)
        0x00000000,                    # nop   (t0 load delay)
        0x9109FFFF,                    # lbu   t1,-1(t0)
        0x00000000,                    # nop   (t1 load delay)
        0x2529FF7F,                    # addiu t1,t1,-0081
        0x2D2A0010,                    # sltiu t2,t1,0010
        0x11400008,                    # beq   t2,zero,done
        0x000949C0,                    # sll   t1,t1,7 (delay)
        0x3C0A8011,                    # lui   t2,8011
        0x254A4000,                    # addiu t2,t2,4000
        0x012A4821,                    # addu  t1,t1,t2
        0x912A007F,                    # lbu   t2,7F(t1)
        0x00000000,                    # nop   (t2 load delay)
        0x010A4021,                    # addu  t0,t0,t2
        0xAE080014,                    # sw    t0,14(s0)
        0x34020001,                    # done: ori v0,zero,1
        jump(COMPLETION_TARGET),       # resume original completion path
        0x00000000,                    # nop
    )


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("v0.10 base hash differs")
    with zipfile.ZipFile(BASE) as archive:
        infos = {item.filename: item for item in archive.infolist()}
        files = {name: archive.read(name) for name in infos}
    if len(files) != 39:
        raise SystemExit("unexpected cumulative entry count")

    psx = bytearray(files[PSX_TARGET])
    offset = file_offset(HELPER_ADDRESS)
    old = old_helper()
    new = corrected_helper()
    if psx[offset:offset + len(old)] != old:
        raise SystemExit("v0.10 completion helper differs")
    if offset + len(new) > file_offset(HELPER_LIMIT):
        raise SystemExit("corrected completion helper exceeds cave")
    if any(psx[offset + len(old):offset + len(new)]):
        raise SystemExit("completion helper growth area is not empty")
    psx[offset:offset + len(new)] = new
    files[PSX_TARGET] = bytes(psx)

    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            archive.writestr(infos[name], files[name])

    report = (
        "base=v0.10\n"
        "e2_inline_skip_load_delay_safe=true\n"
        "helper_address=0x8018FD20\n"
        "helper_size=72\n"
        "story_files_changed=false\n"
        "font_changed=false\n"
        f"sha256={digest(OUTPUT.read_bytes())}\n"
    )
    REPORT.write_text(report, encoding="utf-8")
    print(report, end="")
    print(OUTPUT)


if __name__ == "__main__":
    main()
