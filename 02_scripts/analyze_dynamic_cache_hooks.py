"""Disassemble the v151 glyph decoder and renderer for the dynamic-cache design."""
from __future__ import annotations

import hashlib
import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32

BUILD = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
BUILD_SHA = "A4358FEE5FEA4964C9DD376B630894EB5EC133EFEEDD9E5E85BBC5FDD8CA1A46"
OUT = ROOT / "01_work/analysis/dynamic_cache_design/hook_disassembly.txt"
RAM_TO_FILE = 0x8011A800

RANGES = (
    (0x8016B380, 0x8016B620, "common glyph decoder and packet builder"),
    (0x801A7480, 0x801A7560, "E9/EA lookup decoder"),
    (0x801A20B0, 0x801A2304, "current two-pass text renderer"),
    (0x801A86EC, 0x801A8800, "resident helper source"),
    (0x801A8F50, 0x801A8FD4, "resident classifier source"),
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def main() -> None:
    if sha256(BUILD.read_bytes()) != BUILD_SHA:
        raise SystemExit("v151 archive hash differs")
    with zipfile.ZipFile(BUILD) as archive:
        exe = archive.read("PSX.EXE")

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    lines = [f"build={BUILD.name}", f"sha256={BUILD_SHA}", ""]
    for start, end, label in RANGES:
        at = start - RAM_TO_FILE
        payload = exe[at:at + end - start]
        lines.append(f"--- {label}: 0x{start:08X}..0x{end:08X} ---")
        lines.extend(
            f"{ins.address:08X}  {ins.mnemonic:<8} {ins.op_str}"
            for ins in md.disasm(payload, start)
        )
        lines.append("")

    # Record exact words at the established hooks as an independent readback.
    lines.append("--- hook words ---")
    for address in (0x8016B3D4, 0x8016B5D8, 0x8016B764, 0x8011C4AC,
                    0x801A74E4, 0x801A74E8):
        word = struct.unpack_from("<I", exe, address - RAM_TO_FILE)[0]
        lines.append(f"0x{address:08X}  0x{word:08X}")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(OUT)


if __name__ == "__main__":
    main()
