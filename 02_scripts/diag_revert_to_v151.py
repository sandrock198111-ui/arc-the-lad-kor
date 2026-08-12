"""Take the v159 executable back to v151 over chosen ranges, hooks already neutral.

N1 neutralised both hooks and the game still does not boot, and the disc it was
burned onto carries the original COMM.IMG and the original .DAT files -- the only
patched member is PSX.EXE.  So the fault is in the executable and it is not the new
routines.  What is left is everything v159 changed relative to v151 outside the
hooks, and that falls into two blocks:

    0x078002~0x082FFF   RAM 0x80192802~0x8019D7FF   the UI string pool and tables
    0x08CCB8~0x08F3C7   RAM 0x801A74B8~0x801A9BC7   our code block and the tail

v151 is the last executable known to boot, so each block is put back to v151 and the
other left as v159.  One of the two discs should boot.

    python 02_scripts/diag_revert_to_v151.py P1 0x78000-0x83000
    python 02_scripts/diag_revert_to_v151.py P2 0x8CC00-0x8F800
"""
from __future__ import annotations

import hashlib
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = ROOT / "03_output/DIAG_N1_minimal_hook.zip"      # v159 with both hooks neutral
V151 = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
R2F = 0x8011A800


def main() -> None:
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    name = sys.argv[1]
    with zipfile.ZipFile(BASE) as z:
        info = z.getinfo("PSX.EXE")
        exe = bytearray(z.read("PSX.EXE"))
    with zipfile.ZipFile(V151) as z:
        old = z.read("PSX.EXE")

    total = 0
    for chunk in sys.argv[2:]:
        lo, _, hi = chunk.partition("-")
        lo, hi = int(lo, 0), int(hi, 0)
        hi = min(hi, len(old))
        n = sum(1 for i in range(lo, hi) if exe[i] != old[i])
        exe[lo:hi] = old[lo:hi]
        total += n
        print(f"  0x{lo:06X}~0x{hi:06X}  RAM 0x{lo+R2F:08X}  v151로 되돌린 바이트 {n}/{hi-lo}")

    out = ROOT / "03_output" / f"DIAG_{name}_back_to_v151.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as w:
        ni = zipfile.ZipInfo("PSX.EXE", info.date_time)
        for attr in ("compress_type", "external_attr", "create_system"):
            setattr(ni, attr, getattr(info, attr))
        w.writestr(ni, bytes(exe))
    left = sum(1 for i in range(len(old)) if exe[i] != old[i])
    print(f"\n{out.name}")
    print(f"  아직 v151과 다른 바이트 {left}개 (꼬리 제외)")
    print(f"  sha256  {hashlib.sha256(out.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
