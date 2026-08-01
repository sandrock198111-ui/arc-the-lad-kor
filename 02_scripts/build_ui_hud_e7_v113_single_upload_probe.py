"""v113: v112 with the second upload removed, to find why the two-strip build blanks.

v112 renders nothing for the expanded glyphs, and its data is not the reason. For the
failing character the layout is byte-for-byte what v108e had, and v108e worked:

    row 40, column 1, plane 3, U = 16, V = 224, tpage 0x1F, VRAM (964, 480), 40 pixels

So the fault is in what v112 does that v108e did not. Three things qualify: calling
LoadImage twice in one frame, a classifier comparing two values instead of one, and
13-column strips instead of 15.

This build removes only the first. The second LoadImage becomes five nops; everything
else -- both rectangles, the two-value classifier, the 13-column split, the lookup
remap -- stays exactly as v112 left it.

    the failing glyph renders   the second call is the fault; two transfers in one
                                frame interfere, and the fix is to space them or to
                                merge the strips into a single transfer
    still blank                 the fault is the classifier or the width, and the next
                                probe isolates those

Strip B holds five glyphs and will be blank either way; ignore it. The character to
watch is the one in strip A.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
BASE_ZIP = ROOT / "03_output/ui_hud_e7_v112_two_strips_resident_patch_only.zip"
BASE_SHA = "8DB471C1DFF49DF05443A942EA814DADB79344F5A4841C655131A2A801584866"
OUTPUT = ROOT / "03_output/ui_hud_e7_v113_single_upload_probe_patch_only.zip"

PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800
LOADIMAGE = 0x80177E4C
# reserved-RAM code lives in the executable tail: classifier then frame routine
CODE_SRC = 0x801A8800 + 936 * 2
FRAME_SRC = CODE_SRC + 36
SECOND_UPLOAD = 7          # word index of the second LoadImage block
BLOCK = 5                  # lui a0 / ori a0 / lui a1 / jal / ori a1


def sha256(b): return hashlib.sha256(b).hexdigest().upper()
def word(buf, ram): return struct.unpack_from("<I", buf, ram - RAM_TO_FILE)[0]


def clone(i: ZipInfo) -> ZipInfo:
    t = ZipInfo(i.filename, i.date_time)
    for a in ("compress_type", "comment", "extra", "create_system", "create_version",
              "extract_version", "flag_bits", "volume", "internal_attr",
              "external_attr"):
        setattr(t, a, getattr(i, a))
    return t


def main() -> None:
    if sha256(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not the verified v112 build")
    with ZipFile(BASE_ZIP) as a:
        infos = a.infolist()
        members = {i.filename: a.read(i.filename) for i in infos}
    exe = bytearray(members[PSX])

    jal_li = 0x0C000000 | ((LOADIMAGE & 0x0FFFFFFF) >> 2)
    first = FRAME_SRC + 5 * 4
    second = FRAME_SRC + (SECOND_UPLOAD + 3) * 4
    if word(exe, first) != jal_li or word(exe, second) != jal_li:
        raise SystemExit("the frame routine is not where this build expects it")

    for k in range(BLOCK):
        struct.pack_into("<I", exe, FRAME_SRC + (SECOND_UPLOAD + k) * 4 - RAM_TO_FILE, 0)

    if word(exe, first) != jal_li:
        raise SystemExit("the first upload was disturbed")
    if any(word(exe, FRAME_SRC + (SECOND_UPLOAD + k) * 4) for k in range(BLOCK)):
        raise SystemExit("the second upload was not cleared")
    diff = [i for i in range(0x800, len(exe), 4)
            if exe[i:i + 4] != members[PSX][i:i + 4]]
    if len(diff) != BLOCK:
        raise SystemExit(f"{len(diff)} words changed, expected {BLOCK}")
    if len(exe) != len(members[PSX]):
        raise SystemExit("the executable changed size")

    members[PSX] = bytes(exe)
    if OUTPUT.exists():
        raise SystemExit(f"{OUTPUT.name} already exists")
    with ZipFile(OUTPUT, "w") as t:
        for i in infos:
            t.writestr(clone(i), members[i.filename])
    with ZipFile(OUTPUT) as a:
        for n in members:
            if a.read(n) != members[n]:
                raise SystemExit(f"archive readback of {n} failed")

    print("v113 single-upload probe")
    print(f"  base   {BASE_ZIP.name}")
    print(f"  output {OUTPUT.name}")
    print(f"  sha256 {sha256(OUTPUT.read_bytes())}")
    print(f"  words changed: {len(diff)} (the second LoadImage block, now nops)")
    print(f"  PSX.EXE {len(members[PSX])} bytes, unchanged; v104 layout still applies")
    print("\n  watch the character in strip A. strip B is deliberately not uploaded.")


if __name__ == "__main__":
    main()
