"""Rebuild the mkpsxiso project so PSX.EXE can grow without moving any other file.

The game addresses its data files by sector number, not by name: PSX.EXE contains no
"COMM.IMG" string, but it does contain 307, 667 and 891 -- the sector numbers of
COMM.DAT, COMM.IMG and COMM.SND -- in a table at 0x80191154. PSX.EXE is the first file
on the disc and ends at sector 306, exactly where COMM.DAT begins, so making it one
sector larger shifts all 506 other files by one and the game reads the wrong data.

That is why v101, v102 and v103 all failed right after boot while v98 and v100 passed:
the three failures are exactly the three builds that changed the file size. The
bootstrap and 0x801CDE00, blamed earlier, had nothing to do with it.

The fix leaves the executable alone and changes the disc instead:

    dummy 284 sectors   occupies 23..306, the slot PSX.EXE used to hold
    COMM.DAT ...        unchanged, still starts at 307
    PSX.EXE             moved to the end, where it may be any size

Sector numbers are preserved by construction rather than by patching 500 of them,
and the executable is free to grow from here on -- which the remaining glyph rows
will need.

Verify the result by parsing the built image, not by trusting this script: run
verify_iso_layout.py against E:\\arc\\arc1.bin afterwards.
"""
from __future__ import annotations

import re
from pathlib import Path

SRC = Path(r"E:\arc\arc1.xml")
DST = Path(r"E:\arc\arc1_v104.xml")
EXE = Path(r"E:\korean\03_output\ui_hud_e7_v103_heap_reserved_glyphs_patch_only.zip")
SECTOR = 2048
OLD_EXE_SECTORS = 581632 // SECTOR          # 284, the slot to hold open


def main() -> None:
    text = SRC.read_text(encoding="utf-8")

    m = re.search(r'^([ \t]*)(<file name="PSX\.EXE"[^>]*/>)\s*\n', text, re.M)
    if not m:
        raise SystemExit("PSX.EXE entry not found in the project file")
    indent, exe_line = m.group(1), m.group(2)

    # 1. take the executable out of its current position
    text = text[:m.start()] + text[m.end():]
    if '<file name="PSX.EXE"' in text:
        raise SystemExit("more than one PSX.EXE entry")

    # 2. hold its sectors open so nothing after it moves
    open_tree = re.search(r'^[ \t]*<directory_tree>[ \t]*\n', text, re.M)
    if not open_tree:
        raise SystemExit("<directory_tree> not found")
    dummy = f'{indent}<dummy sectors="{OLD_EXE_SECTORS}" type="0"/>\n'
    text = text[:open_tree.end()] + dummy + text[open_tree.end():]

    # 3. put it back at the end, before the padding that already closes the disc
    tail = re.search(r'^([ \t]*)<dummy sectors="150"[^>]*/>[ \t]*\n', text, re.M)
    if not tail:
        raise SystemExit("trailing dummy not found")
    text = text[:tail.start()] + f"{indent}{exe_line}\n" + text[tail.start():]

    DST.write_text(text, encoding="utf-8")

    # report
    import zipfile
    with zipfile.ZipFile(EXE) as z:
        size = len(z.read("PSX.EXE"))
    print(f"wrote {DST}")
    print(f"  held open : {OLD_EXE_SECTORS} sectors at LBA 23..{22 + OLD_EXE_SECTORS}")
    print(f"  COMM.DAT  : stays at LBA {23 + OLD_EXE_SECTORS}")
    print(f"  PSX.EXE   : moved to the end, {size} bytes "
          f"= {(size + SECTOR - 1)//SECTOR} sectors")
    print()
    for line in text.splitlines()[:12]:
        print("  " + line)
    print("  ...")
    for line in text.splitlines()[-8:]:
        print("  " + line)


if __name__ == "__main__":
    main()
