"""Read-only cave inventory for the v212 A/B cache selector.

Only reports aligned zero runs in the loaded PSX.EXE text/data image and direct
MIPS jump/call references.  A zero run is not declared safe by this script;
the report is evidence used together with the builders that originally owned
each patch region.
"""
from __future__ import annotations

import struct
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "03_output/arc1_v210_sd031_slots_controls.zip"
STOCK = ROOT / "00_original/arc.zip"
R2F = 0x8011A800
SCAN_LO = 0x80190000
SCAN_HI = 0x801A86E8
MIN_BYTES = 32


def runs(blob: bytes, lo: int, hi: int) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    pos = lo
    while pos < hi:
        if blob[pos:pos + 4] != b"\0\0\0\0":
            pos += 4
            continue
        end = pos + 4
        while end < hi and blob[end:end + 4] == b"\0\0\0\0":
            end += 4
        if end - pos >= MIN_BYTES:
            result.append((pos, end))
        pos = end
    return result


def direct_refs(blob: bytes, target_lo: int, target_hi: int) -> list[tuple[int, str, int]]:
    refs: list[tuple[int, str, int]] = []
    for off in range(0x800, min(len(blob), 0x8E000), 4):
        word = struct.unpack_from("<I", blob, off)[0]
        op = word >> 26
        if op not in (2, 3):
            continue
        pc = R2F + off
        target = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
        if target_lo <= target < target_hi:
            refs.append((pc, "j" if op == 2 else "jal", target))
    return refs


def main() -> None:
    with zipfile.ZipFile(BASE) as archive:
        exe = archive.read("PSX.EXE")
    with zipfile.ZipFile(STOCK) as archive:
        stock = archive.read("PSX.EXE")

    lo = SCAN_LO - R2F
    hi = min(SCAN_HI - R2F, len(exe), len(stock))
    for start, end in runs(exe, lo, hi):
        ram_lo, ram_hi = R2F + start, R2F + end
        refs = direct_refs(exe, ram_lo, ram_hi)
        stock_zero = not any(stock[start:end])
        print(
            f"0x{ram_lo:08X}..0x{ram_hi - 1:08X}  {end - start:5d} bytes  "
            f"stock_zero={stock_zero}  direct_refs={len(refs)}"
        )
        for pc, kind, target in refs[:8]:
            print(f"    0x{pc:08X} {kind} 0x{target:08X}")


if __name__ == "__main__":
    main()
