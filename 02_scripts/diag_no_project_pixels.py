"""Diagnostic, not a release: every pixel this project puts in VRAM, removed at once.

Reverting PSX.EXE wholesale is not a test.  The original executable has none of our
renderer, so our two-byte codes in the .DAT files decode to one broken glyph and the
message never ends -- the game stops before the slime.  DIAG3 died there.  Any
diagnostic that ships the original executable with our text is unplayable by
construction, and that includes the ones already reported as failures.

What can be removed without stopping the game is the pixel data.  The code stays, so
the renderer still runs and still ends its messages; the glyphs it draws are simply
not ours.

    COMM.IMG          back to the original -- the 543 cells we filled go away
    strip A/B/C       936 bytes each, zeroed -- what gets uploaded to page 15,1
    classifier, lookup tables, .DAT text    untouched

That is every pixel the project writes into VRAM, in one build.

    slime clean  -> the block is one of our two pixel sources, and one more build
                    tells us which
    slime dirty  -> pixels are not it.  The cause is our code or the .DAT files,
                    and the search moves there

Do not ship this.  The text is deliberately wrong.
"""
from __future__ import annotations

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
OUT = ROOT / "03_output/DIAG7_no_project_pixels.zip"

RAM_TO_FILE = 0x8011A800
STRIP_BYTES = 936
STRIPS = {"A": 0x801A8800, "B": 0x801A8BA8, "C": 0x801A93CC}
CLASSIFIER = 0x801A8F50          # code -- must survive, DIAG6 died by erasing it


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system", "create_version",
                 "extract_version", "flag_bits", "volume", "internal_attr",
                 "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def main() -> None:
    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}
    with ZipFile(PRISTINE) as pristine:
        members["COMM.IMG"] = pristine.read("COMM.IMG")

    exe = bytearray(members["PSX.EXE"])
    cleared = 0
    for name, addr in STRIPS.items():
        at = addr - RAM_TO_FILE
        if at + STRIP_BYTES > len(exe):
            raise SystemExit(f"strip {name} is past the end of the image")
        cleared += sum(1 for b in exe[at:at + STRIP_BYTES] if b)
        exe[at:at + STRIP_BYTES] = bytes(STRIP_BYTES)

    guard = CLASSIFIER - RAM_TO_FILE
    if not any(exe[guard:guard + 64]):
        raise SystemExit("the classifier was erased -- this build would not boot")
    members["PSX.EXE"] = bytes(exe)

    for name, data in members.items():
        with ZipFile(BASE_ZIP) as archive:
            if len(data) != len(archive.read(name)):
                raise SystemExit(f"{name} changed size")

    with ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])

    print("진단용 빌드 (배포 금지 -- 글자가 일부러 틀리게 나온다)")
    print(f"  base    {BASE_ZIP.name}")
    print(f"  output  {OUT.name}")
    print(f"  sha256  {hashlib.sha256(OUT.read_bytes()).hexdigest().upper()}")
    print(f"  COMM.IMG를 원본으로 되돌렸다. 스트립 셋에서 지운 픽셀 바이트 {cleared}개.")
    print("  분류 루틴 0x801A8F50은 살아 있다. 부팅한다.")


if __name__ == "__main__":
    main()
