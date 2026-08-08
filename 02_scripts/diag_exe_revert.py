"""Put chosen byte ranges of PSX.EXE back to the original, and ship nothing else.

E_onlyexe (the whole original disc plus our executable) breaks, and F_sizeonly (the
original code plus our tail and the larger t_size) does not.  So the cause is one of
the code changes, and the executable can be bisected -- with the original .DAT files
on the disc the text is Japanese and none of our renderer is needed, so any patch can
be reverted without the game losing the ability to draw a message.

The output is a one-member patch zip.  Burned over the untouched tree it produces a
disc that differs from the original in the executable only.

    python 02_scripts/diag_exe_revert.py --ranges 0x5AFBC-0x5B012 --name noboot

Known landmarks, as file offsets (RAM = offset + 0x8011A800):

    0x050F64  8B     0x8016B764, the shared text renderer entry redirected to ours
    0x05AFBC  86B    0x801757BC, the entry point: helper copy and BSS clear start
    0x087874  647B   0x801A2074, the new renderer
    0x08CC60  1010B  0x801A7460, more of it
    0x08DEEC  272B   0x801A86EC, the block the boot code copies to reserved RAM
    0x080212  10428B 0x8019AA12, the UI string pool -- data, not code
"""
from __future__ import annotations

import argparse
import hashlib
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE_ZIP = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
PRISTINE = ROOT / "00_original/arc.zip"
R2F = 0x8011A800


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ranges", required=True,
                        help="comma separated file ranges, e.g. 0x5AFBC-0x5B012,0x50F64-0x50F6C")
    parser.add_argument("--name", required=True, help="label for the output zip")
    args = parser.parse_args()

    with zipfile.ZipFile(BASE_ZIP) as z:
        info = z.getinfo("PSX.EXE")
        ours = bytearray(z.read("PSX.EXE"))
    with zipfile.ZipFile(PRISTINE) as z:
        original = z.read("PSX.EXE")

    total = 0
    for chunk in args.ranges.split(","):
        lo, _, hi = chunk.strip().partition("-")
        lo, hi = int(lo, 0), int(hi, 0)
        if hi > len(original):
            raise SystemExit(f"0x{hi:X} is past the original image")
        changed = sum(1 for i in range(lo, hi) if ours[i] != original[i])
        ours[lo:hi] = original[lo:hi]
        total += changed
        print(f"  0x{lo:06X}~0x{hi:06X}  RAM 0x{lo+R2F:08X}  되돌린 바이트 {changed}/{hi-lo}")

    left = sum(1 for i in range(len(original)) if ours[i] != original[i])
    out = ROOT / "03_output" / f"DIAG_exe_{args.name}.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as w:
        ni = zipfile.ZipInfo("PSX.EXE", info.date_time)
        for attr in ("compress_type", "external_attr", "create_system"):
            setattr(ni, attr, getattr(info, attr))
        w.writestr(ni, bytes(ours))

    print(f"\n{out.name}")
    print(f"  sha256  {hashlib.sha256(out.read_bytes()).hexdigest().upper()}")
    print(f"  이미지 안에서 아직 원본과 다른 바이트 {left}개 (꼬리 6,144B는 별도)")


if __name__ == "__main__":
    main()
