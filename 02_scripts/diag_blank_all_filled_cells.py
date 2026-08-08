"""Diagnostic, not a release: blank every cell the original disc left empty.

v151 blanked the one run of exactly three adjacent originally-blank cells and the block
above the slime is still there, so that run was not the source. Narrowing further from
the picture has stopped working: the block blends semi-transparently with the grass, so
30x8 pixels carry 70 colours and there is no CLUT to invert.

What is still known: .DAT text is never uploaded as a texture -- searching the whole of
VRAM for the bytes of every slot and body finds nothing -- so COMM.IMG is the only place
the pixels can come from, and 543 glyphs sit in cells the disc left blank.

This build blanks all 543 at once. It is deliberately broken text: those glyphs draw as
nothing, so lines holding them lose characters. It answers one question and only one.

    slime clean  -> COMM.IMG is the source, and the 10 runs can be bisected from here
    slime dirty  -> COMM.IMG is not the source and the search moves elsewhere

Do not ship this.
"""
from __future__ import annotations

import hashlib
import sys
import zipfile
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from plan_bulk_insertion import CELL  # noqa: E402

BASE_ZIP = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
PRISTINE = ROOT / "00_original/arc.zip"
OUT = ROOT / "03_output/DIAG_blank_all_filled_cells.zip"
ROW_BYTES = 0x380


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
        original = pristine.read("COMM.IMG")
    font = bytearray(members["COMM.IMG"])

    def has_pixels(img, row: int, col: int) -> bool:
        for dy in range(CELL):
            y = row * CELL + dy
            lo = y * ROW_BYTES + (col * CELL) // 2
            if any(img[lo:lo + CELL // 2]):
                return True
        return False

    rows, cols = 512 // CELL, 1792 // CELL
    blanked = 0
    for row in range(rows):
        for col in range(cols):
            if has_pixels(original, row, col) or not has_pixels(font, row, col):
                continue
            for dy in range(CELL):
                y = row * CELL + dy
                lo = y * ROW_BYTES + (col * CELL) // 2
                font[lo:lo + CELL // 2] = original[lo:lo + CELL // 2]
            blanked += 1
    members["COMM.IMG"] = bytes(font)

    with ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    stamp = hashlib.sha256(OUT.read_bytes()).hexdigest().upper()
    print("진단용 빌드 (배포 금지)")
    print(f"  base    {BASE_ZIP.name}")
    print(f"  output  {OUT.name}")
    print(f"  sha256  {stamp}")
    print(f"  원본이 비워 뒀던 12x12 자리 {blanked}곳을 다시 비웠다.")
    print("  글자가 사라진 줄이 생긴다. 그건 예상된 것이고, 확인할 것은 슬라임 하나뿐이다.")


if __name__ == "__main__":
    main()
