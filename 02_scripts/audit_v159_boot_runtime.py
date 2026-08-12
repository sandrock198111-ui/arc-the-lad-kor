"""Read-only audit of the v159 boot hooks and GPU-transfer call sites."""
from __future__ import annotations

import hashlib
import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32

RAM_TO_FILE = 0x8011A800
V151 = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
V151_SHA = "A4358FEE5FEA4964C9DD376B630894EB5EC133EFEEDD9E5E85BBC5FDD8CA1A46"
V159 = ROOT / "03_output/arc1_v159_dynamic_cache_4E3F2466.zip"
V159_SHA = "4E3F246614B46139EBD637AA576E19397493C421338B5F257D628BCF0AF7B4D7"
OUT = ROOT / "01_work/analysis/arc1_v159_dynamic_cache/boot_runtime_audit.txt"

STOREIMAGE = 0x801780FC
LOADIMAGE = 0x80177E4C
FRAMESWAP = 0x8011C814
RESIDENT_LO, RESIDENT_HI = 0x801FE3C4, 0x801FF8B0

RANGES = (
    (0x80175780, 0x80175840, "startup copy and clear"),
    (0x8011C450, 0x8011C4D0, "frame hook caller"),
    (0x8016B3C0, 0x8016B430, "glyph decoder caller and return"),
    (0x801A7480, 0x801A7530, "E9/EA decoder entry"),
    (STOREIMAGE, STOREIMAGE + 0x300, "StoreImage"),
    (LOADIMAGE, LOADIMAGE + 0x300, "LoadImage"),
    (FRAMESWAP, FRAMESWAP + 0x100, "displaced frame function"),
    (0x801FEF40, 0x801FF2C4, "v159 resident decoder and frame routine"),
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def member(path: Path, name: str) -> bytes:
    with zipfile.ZipFile(path) as archive:
        return archive.read(name)


def word(exe: bytes, address: int) -> int:
    return struct.unpack_from("<I", exe, address - RAM_TO_FILE)[0]


def jump_target(address: int, instruction: int) -> int:
    return ((address + 4) & 0xF0000000) | ((instruction & 0x03FFFFFF) << 2)


def direct_edges(exe: bytes) -> list[tuple[int, str, int]]:
    out = []
    for offset in range(0, len(exe) - 3, 4):
        instruction = struct.unpack_from("<I", exe, offset)[0]
        opcode = instruction >> 26
        if opcode not in (2, 3):
            continue
        address = RAM_TO_FILE + offset
        out.append((address, "jal" if opcode == 3 else "j",
                    jump_target(address, instruction)))
    return out


def main() -> None:
    if sha256(V151) != V151_SHA or sha256(V159) != V159_SHA:
        raise SystemExit("frozen archive hash differs")
    old, new = member(V151, "PSX.EXE"), member(V159, "PSX.EXE")
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    lines = [
        "v159 boot/runtime read-only audit",
        f"v151={V151_SHA}",
        f"v159={V159_SHA}",
        "",
    ]

    for target, label in ((STOREIMAGE, "StoreImage"), (LOADIMAGE, "LoadImage"),
                          (FRAMESWAP, "FrameSwap")):
        lines.append(f"--- direct calls to {label} 0x{target:08X} ---")
        for build_label, exe in (("v151", old), ("v159", new)):
            hits = [(at, kind) for at, kind, dst in direct_edges(exe)
                    if kind == "jal" and dst == target]
            lines.append(f"{build_label}: " + ", ".join(
                f"0x{at:08X} {kind}" for at, kind in hits))
        lines.append("")

    lines.append("--- direct jumps/calls into reserved RAM ---")
    for build_label, exe in (("v151", old), ("v159", new)):
        hits = [(at, kind, dst) for at, kind, dst in direct_edges(exe)
                if RESIDENT_LO <= dst < RESIDENT_HI]
        lines.append(build_label)
        lines.extend(f"0x{at:08X} {kind} 0x{dst:08X}" for at, kind, dst in hits)
    lines.append("")

    for start, end, label in RANGES:
        lines.append(f"--- {label}: 0x{start:08X}..0x{end:08X} ---")
        for build_label, exe in (("v151", old), ("v159", new)):
            if not (RAM_TO_FILE <= start and end - RAM_TO_FILE <= len(exe)):
                continue
            payload = exe[start - RAM_TO_FILE:end - RAM_TO_FILE]
            lines.append(build_label)
            lines.extend(f"{ins.address:08X}  {ins.mnemonic:<8} {ins.op_str}"
                         for ins in md.disasm(payload, start))
        lines.append("")

    # The failed v158 address must be absent from v159 generated code.
    resident = new[RESIDENT_LO - RAM_TO_FILE:RESIDENT_HI - RAM_TO_FILE]
    bad_imm = struct.pack("<H", 0xEEE6)
    lines.append(f"v159_reserved_halfword_EEE6_occurrences={resident.count(bad_imm)}")
    lines.append(f"frame_hook_word=0x{word(new, 0x8011C4AC):08X}")
    lines.append(f"decoder_hook_word=0x{word(new, 0x801A74B8):08X}")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(OUT)


if __name__ == "__main__":
    main()
