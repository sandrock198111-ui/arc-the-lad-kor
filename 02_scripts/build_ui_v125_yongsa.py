"""v125: the item window says 용사 too.

The story now reads 용사 everywhere. The executable still holds one 용자, in the
equipment name `용자의 증표` at file offset 0x805CA, and a split between the item
window and the dialogue would read worse than either spelling on its own.

The edit is two bytes. `자` is the virtual code E9 C3; `사` is the physical code
E0 A5, which resolves to index 1149 through the decoder's own arithmetic. Both are
two bytes, so the string keeps its length and the pointer table is untouched --
which matters, because these UI slots are only four to twelve bytes and a longer
string would have to be repacked.

The glyph is confirmed by reading it back out of the font rather than trusting a map.
"""
from __future__ import annotations

import hashlib
import pickle
import struct
import sys
import zipfile
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from plan_bulk_insertion import bitmap  # noqa: E402

BASE_ZIP = ROOT / "03_output/story_bulk_v124_patch_only.zip"
OUTPUT = ROOT / "03_output/story_ui_v125_yongsa_patch_only.zip"
ANALYSIS = ROOT / "01_work/analysis/story_ui_v125_yongsa"
CACHE = Path(
    r"C:\Users\ADMINI~1\AppData\Local\Temp\claude\E--korean"
    r"\328ae25b-6478-4de1-a913-c780c9b01e72\scratchpad\hangul_bitmaps.pkl"
)

YONG_JA = bytes((0xE9, 0xB0, 0xE9, 0xC3))     # 용 자, as the UI stores it
SA = bytes((0xE0, 0xA5))                      # 사, a physical code of the same width
SA_INDEX = (0xE0 - 0xDD) * 255 + 0xA5 + 0xDB


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


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
    exe = bytearray(members["PSX.EXE"])
    font = members["COMM.IMG"]

    # the replacement really draws 사, checked against the rendered-glyph table
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    bits = bitmap(bytes(exe), font, SA_INDEX)
    if not bits or shapes.get(bits) != "사":
        raise SystemExit(f"index {SA_INDEX} does not hold 사")

    at = exe.find(YONG_JA)
    if at < 0:
        raise SystemExit("용자 is not in the executable; already done?")
    if exe.find(YONG_JA, at + 1) >= 0:
        raise SystemExit("more than one 용자; this build expects exactly one")
    before = bytes(exe)
    exe[at + 2:at + 4] = SA
    changed = [i for i in range(len(before)) if before[i] != exe[i]]
    if changed != [at + 2, at + 3]:
        raise SystemExit(f"changed {len(changed)} bytes, expected exactly two")
    if len(exe) != len(before):
        raise SystemExit("the executable changed length")

    members["PSX.EXE"] = bytes(exe)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    with ZipFile(OUTPUT) as check:
        rebuilt = {i.filename: check.read(i.filename) for i in check.infolist()}
    if rebuilt != members:
        raise SystemExit("the archive did not read back as written")
    differing = sorted(n for n in rebuilt if rebuilt[n] != ZipFile(BASE_ZIP).read(n))
    if differing != ["PSX.EXE"]:
        raise SystemExit(f"members changed: {differing}")

    lines = [
        "v125 the item window says 용사",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {OUTPUT.name}",
        f"        sha256 {digest(OUTPUT.read_bytes())}",
        "",
        f"changed PSX.EXE 0x{at + 2:X}..0x{at + 3:X}, two bytes",
        f"  E9 C3 -> E0 A5     자 -> 사, in `용자의 증표` at 0x{at:X}",
        "",
        "verified",
        f"  index {SA_INDEX} reads back as 사 from the font in this build",
        "  the executable holds exactly one 용자, so no other string is touched",
        "  exactly two bytes differ, and the string keeps its length, so the UI",
        "  pointer table and every other slot are untouched",
        "  COMM.IMG and every DAT member are byte-identical to the base",
        "",
        "NOT verified here: that the equipment window shows it. Look at 용사의 증표",
        "in the item list.",
        "",
        "rollback: the base archive, which this build does not modify",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
