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
    parser.add_argument("--font", choices=("v151", "original"), default="v151",
                        help="v151 keeps the 543 Hangul cells; original removes them")
    parser.add_argument("--strips", default="",
                        help="comma separated subset of A,B,C to blank (default none)")
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

    tag = f"font{'ORIG' if args.font == 'original' else 'V151'}_strips{''.join(wanted) or 'KEPT'}"
    out = ROOT / "03_output" / f"DIAG_{tag}.zip"
    with ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])

    print("진단용 빌드 (배포 금지)")
    print(f"  output  {out.name}")
    print(f"  sha256  {hashlib.sha256(out.read_bytes()).hexdigest().upper()}")
    print(f"  COMM.IMG  {'원본 (한글 칸 543개 없음)' if args.font == 'original' else 'v151 그대로'}")
    if wanted:
        rows = ", ".join(f"{n}(y {STRIPS[n][1]})" for n in wanted)
        print(f"  비운 스트립  {rows} -- 픽셀 {cleared}바이트")
    else:
        print("  스트립  셋 다 그대로")


if __name__ == "__main__":
    main()
