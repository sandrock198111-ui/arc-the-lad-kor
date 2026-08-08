"""Split the two places this project writes pixels into VRAM.

DIAG7 removed both at once and the block above the slime went away, so the cause is
one of them.  This script builds any combination of the two so the next question is
one build, not a new script each time.

    COMM.IMG   the font page, VRAM x 0..447 y 0..511.  543 cells the original disc
               left blank now hold Hangul.
    strips     three 936-byte blocks in the executable tail, uploaded to texture
               page 15,1 as 156x12 bands at y 380 (C), 480 (A), 500 (B).

The classifier at 0x801A8F50 sits between the strips and is code, not pixels.  It is
never touched -- DIAG6 erased it and the game stopped booting.

    python 02_scripts/diag_pixel_bisect.py --strips A,B,C          # font kept
    python 02_scripts/diag_pixel_bisect.py --font original         # strips kept
    python 02_scripts/diag_pixel_bisect.py --strips A              # one band

Do not ship any of these.  The text is deliberately wrong.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
import zipfile
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE_ZIP = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
PRISTINE = ROOT / "00_original/arc.zip"

RAM_TO_FILE = 0x8011A800
STRIP_BYTES = 936
STRIPS = {"A": (0x801A8800, 480), "B": (0x801A8BA8, 500), "C": (0x801A93CC, 380)}
CLASSIFIER = 0x801A8F50


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system", "create_version",
                 "extract_version", "flag_bits", "volume", "internal_attr",
                 "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--font", choices=("v151", "original", "blank140"), default="v151",
                        help="v151 keeps every cell; original removes them all; "
                             "blank140 restores only the 140 cells the disc left empty")
    parser.add_argument("--strips", default="",
                        help="comma separated subset of A,B,C to blank (default none)")
    parser.add_argument("--revert-rows", default="",
                        help="e.g. 0-7: put those atlas rows back to the original disc, "
                             "for bisecting the cells that were not blank to begin with")
    parser.add_argument("--tag", default="", help="extra label for the output name")
    args = parser.parse_args()
    wanted = [s.strip().upper() for s in args.strips.split(",") if s.strip()]
    for name in wanted:
        if name not in STRIPS:
            raise SystemExit(f"unknown strip {name}")

    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}
        sizes = {name: len(data) for name, data in members.items()}

    if args.font == "original":
        with ZipFile(PRISTINE) as pristine:
            members["COMM.IMG"] = pristine.read("COMM.IMG")
    elif args.font == "blank140":
        with ZipFile(ROOT / "03_output/DIAG_blank_all_filled_cells.zip") as blanked:
            members["COMM.IMG"] = blanked.read("COMM.IMG")

    reverted = 0
    if args.revert_rows:
        lo, _, hi = args.revert_rows.partition("-")
        lo, hi = int(lo), int(hi or lo)
        with ZipFile(PRISTINE) as pristine:
            original = pristine.read("COMM.IMG")
        font = bytearray(members["COMM.IMG"])
        stride = 1792 // 2
        for row in range(lo, hi + 1):
            for col in range(21):
                touched = False
                for dy in range(12):
                    at = (row * 12 + dy) * stride + (col * 12) // 2
                    if font[at:at + 6] != original[at:at + 6]:
                        touched = True
                    font[at:at + 6] = original[at:at + 6]
                reverted += touched
        members["COMM.IMG"] = bytes(font)

    exe = bytearray(members["PSX.EXE"])
    cleared = 0
    for name in wanted:
        at = STRIPS[name][0] - RAM_TO_FILE
        cleared += sum(1 for b in exe[at:at + STRIP_BYTES] if b)
        exe[at:at + STRIP_BYTES] = bytes(STRIP_BYTES)
    guard = CLASSIFIER - RAM_TO_FILE
    if not any(exe[guard:guard + 64]):
        raise SystemExit("the classifier was erased -- this build would not boot")
    members["PSX.EXE"] = bytes(exe)

    for name, data in members.items():
        if len(data) != sizes[name]:
            raise SystemExit(f"{name} changed size")

    label = {"original": "ORIG", "blank140": "BLANK140", "v151": "V151"}[args.font]
    tag = f"font{label}_strips{''.join(wanted) or 'KEPT'}"
    if args.revert_rows:
        tag += f"_rows{args.revert_rows}"
    if args.tag:
        tag += f"_{args.tag}"
    out = ROOT / "03_output" / f"DIAG_{tag}.zip"
    with ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])

    print("진단용 빌드 (배포 금지)")
    print(f"  output  {out.name}")
    print(f"  sha256  {hashlib.sha256(out.read_bytes()).hexdigest().upper()}")
    print("  COMM.IMG  " + {"original": "통째 원본",
                            "blank140": "원본이 비워 뒀던 140칸만 되돌림",
                            "v151": "v151 그대로"}[args.font])
    if wanted:
        rows = ", ".join(f"{n}(y {STRIPS[n][1]})" for n in wanted)
        print(f"  비운 스트립  {rows} -- 픽셀 {cleared}바이트")
    else:
        print("  스트립  셋 다 그대로")
    if args.revert_rows:
        print(f"  원본으로 되돌린 칸  아틀라스 행 {args.revert_rows} 안에서 {reverted}칸")


if __name__ == "__main__":
    main()
