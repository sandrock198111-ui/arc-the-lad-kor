"""Read-only MIPS disassembler for the PS1 executable.

Prints a virtual-address disassembly of any range inside PSX.EXE's text
section. Nothing is written back; this exists purely to locate code.

  python 02_scripts/disasm_psx_exe.py 8016B400 8016B600
  python 02_scripts/disasm_psx_exe.py 8016B518 --count 40
"""

import argparse
import struct
from pathlib import Path

import capstone

DEFAULT_EXE = Path("01_work/PSX.EXE")
TEXT_FILE_OFFSET = 0x800


def load_exe(path):
    data = path.read_bytes()
    if data[:8] != b"PS-X EXE":
        raise SystemExit(f"{path} is not a PS-EXE image")
    pc, gp, t_addr, t_size = struct.unpack("<IIII", data[0x10:0x20])
    return data, pc, t_addr, t_size


def to_offset(vaddr, t_addr, t_size):
    if not t_addr <= vaddr < t_addr + t_size:
        raise SystemExit(
            f"{vaddr:08X} is outside text {t_addr:08X}..{t_addr + t_size:08X}"
        )
    return vaddr - t_addr + TEXT_FILE_OFFSET


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("start", help="start virtual address, hex")
    ap.add_argument("end", nargs="?", help="end virtual address, hex (exclusive)")
    ap.add_argument("--count", type=int, help="instruction count instead of an end")
    ap.add_argument("--exe", type=Path, default=DEFAULT_EXE)
    args = ap.parse_args()

    data, pc, t_addr, t_size = load_exe(args.exe)
    start = int(args.start, 16)
    if args.count:
        end = start + args.count * 4
    elif args.end:
        end = int(args.end, 16)
    else:
        end = start + 0x80

    begin = to_offset(start, t_addr, t_size)
    stop = to_offset(end - 4, t_addr, t_size) + 4

    md = capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 + capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    print(f"# {args.exe}  t_addr={t_addr:08X} t_size={t_size:08X} entry={pc:08X}")
    for insn in md.disasm(data[begin:stop], start):
        raw = struct.unpack("<I", data[to_offset(insn.address, t_addr, t_size):][:4])[0]
        print(f"{insn.address:08X}  {raw:08X}  {insn.mnemonic:<10s}{insn.op_str}")


if __name__ == "__main__":
    main()
