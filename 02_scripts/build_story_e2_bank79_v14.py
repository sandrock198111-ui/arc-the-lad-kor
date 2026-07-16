from __future__ import annotations

import csv
import hashlib
import struct
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))
sys.path.insert(0, str(ROOT / "02_scripts"))

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32  # noqa: E402
from build_story_sf0b1_return_full import (  # noqa: E402
    FONT_TARGET,
    write_glyph_plane,
)

BASE = ROOT / "03_output/story_s1072_e2_v13_cumulative_patch_only.zip"
BASE_HASH = "4E413AB2874F4773F431EDA592625241BC4BEE50280D78EFD563B334A426F8AE"
OUTPUT = ROOT / "03_output/story_e2_bank79_v14_cumulative_patch_only.zip"
REPORT = ROOT / "01_work/analysis/story_e2_bank79_v14_report.txt"
EXTENDED = ROOT / "05_docs/korean_charmap_extended.csv"

PSX_TARGET = "PSX.EXE"
LOAD_ADDRESS = 0x8011B000
CAVE_START = 0x8018FCD0
CAVE_LIMIT = 0x8018FDC5
LOOKUP = 0x8015EA44
COMPLETION_TARGET = 0x8016BE44
COMPLETION_HOOK = 0x8016BDC0
LOOKUP_HANDLER = CAVE_START
COMPLETION_HANDLER = 0x8018FD28


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def file_offset(address: int) -> int:
    return address - LOAD_ADDRESS + 0x800


def j(address: int) -> int:
    return 0x08000000 | ((address >> 2) & 0x03FFFFFF)


def branch(op: int, rs: int, rt: int, pc: int, target: int) -> int:
    delta = (target - (pc + 4)) // 4
    if not -0x8000 <= delta <= 0x7FFF:
        raise ValueError("branch target out of range")
    return (op << 26) | (rs << 21) | (rt << 16) | (delta & 0xFFFF)


def lookup_handler() -> bytes:
    normal = 0x8018FD1C
    low = 0x8018FD00
    common = 0x8018FD04
    words = [
        0x308800FF,  # andi  t0,a0,00FF
        0x2D090080,  # sltiu t1,t0,0080
        branch(0x05, 9, 0, 0x8018FCD8, normal),
        0x2D0900A8,  # delay: sltiu t1,t0,00A8
        branch(0x05, 9, 0, 0x8018FCE0, low),
        0x250AFF58,  # delay: addiu t2,t0,-00A8
        branch(0x04, 10, 0, 0x8018FCE8, normal),
        0x2D0900D0,  # delay: sltiu t1,t0,00D0
        branch(0x04, 9, 0, 0x8018FCF0, normal),
        0x2508FF7F,  # delay: addiu t0,t0,-0081
        branch(0x04, 0, 0, 0x8018FCF8, common),
        0x00000000,
        0x2508FF80,  # low: addiu t0,t0,-0080
        0x000811C0,  # common: sll v0,t0,7
        0x3C098011,
        0x25294000,
        0x00491021,
        0x03E00008,
        0x00000000,
        j(LOOKUP),   # normal
        0x00000000,
    ]
    return struct.pack(f"<{len(words)}I", *words)


def completion_handler() -> bytes:
    done = 0x8018FD88
    low = 0x8018FD64
    common = 0x8018FD68
    words = [
        0x8E080014,  # lw t0,14(s0)
        0x00000000,  # load delay
        0x9109FFFF,  # lbu t1,-1(t0), disk ID
        0x00000000,  # load delay
        0x2D2A0081,  # sltiu t2,t1,0081
        branch(0x05, 10, 0, 0x8018FD3C, done),
        0x2D2A00A9,  # delay: sltiu t2,t1,00A9
        branch(0x05, 10, 0, 0x8018FD44, low),
        0x252BFF57,  # delay: addiu t3,t1,-00A9
        branch(0x04, 11, 0, 0x8018FD4C, done),
        0x2D2A00D1,  # delay: sltiu t2,t1,00D1
        branch(0x04, 10, 0, 0x8018FD54, done),
        0x2529FF7E,  # delay: addiu t1,t1,-0082
        branch(0x04, 0, 0, 0x8018FD5C, common),
        0x00000000,
        0x2529FF7F,  # low: addiu t1,t1,-0081
        0x000949C0,  # common: sll t1,t1,7
        0x3C0A8011,
        0x254A4000,
        0x012A4821,
        0x912A007F,
        0x00000000,  # load delay
        0x010A4021,
        0xAE080014,
        0x34020001,  # done: ori v0,zero,1
        j(COMPLETION_TARGET),
        0x00000000,
    ]
    return struct.pack(f"<{len(words)}I", *words)


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("v0.13 base hash differs")
    with zipfile.ZipFile(BASE) as archive:
        infos = {item.filename: item for item in archive.infolist()}
        files = {name: archive.read(name) for name in infos}

    psx = bytearray(files[PSX_TARGET])
    start = file_offset(CAVE_START)
    size = CAVE_LIMIT - CAVE_START
    lookup_code = lookup_handler()
    completion_code = completion_handler()
    completion_offset = file_offset(COMPLETION_HANDLER)
    if completion_offset < start + len(lookup_code):
        raise SystemExit("handler overlap")
    if completion_offset + len(completion_code) > file_offset(CAVE_LIMIT):
        raise SystemExit("handlers exceed cave")
    psx[start:start + size] = b"\x00" * size
    psx[start:start + len(lookup_code)] = lookup_code
    psx[completion_offset:completion_offset + len(completion_code)] = completion_code
    struct.pack_into("<I", psx, file_offset(COMPLETION_HOOK), j(COMPLETION_HANDLER))
    files[PSX_TARGET] = bytes(psx)

    # v0.13 exposed three legacy low-slot mappings whose CSV entries existed
    # but whose planes were absent from this cumulative font branch.
    font = bytearray(files[FONT_TARGET])
    with EXTENDED.open(encoding="utf-8-sig", newline="") as handle:
        extended = list(csv.DictReader(handle))
    base_map = {}
    for path in (ROOT / "05_docs/korean_charmap.csv", EXTENDED):
        with path.open(encoding="utf-8-sig", newline="") as handle:
            for item in csv.DictReader(handle):
                base_map[item["char"]] = bytes.fromhex(item["code_hex"])
    for char in "괄덕량":
        write_glyph_plane(font, base_map[char], char)
    files[FONT_TARGET] = bytes(font)

    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            archive.writestr(infos[name], files[name])

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    lookup_disasm = list(md.disasm(lookup_code, LOOKUP_HANDLER))
    completion_disasm = list(md.disasm(completion_code, COMPLETION_HANDLER))
    if len(lookup_disasm) != len(lookup_code) // 4 or len(completion_disasm) != len(completion_code) // 4:
        raise SystemExit("MIPS disassembly incomplete")

    report = (
        "base=v0.13\n"
        "custom_disk_ids=81-A8,AA-D0\n"
        "custom_slots=79\n"
        "reserved_original_id=A9\n"
        f"lookup_handler_size={len(lookup_code)}\n"
        f"completion_handler_size={len(completion_code)}\n"
        "repaired_glyphs=괄,덕,량\n"
        f"sha256={digest(OUTPUT.read_bytes())}\n"
    )
    REPORT.write_text(report, encoding="utf-8")
    print(report, end="")
    print(OUTPUT)


if __name__ == "__main__":
    main()
