"""Which words to reword so the cache stops being the bottleneck.

v171 is blocked by two numbers at once: 462 glyph shapes do not fit the 5,356-byte
reservation, and one line needs 26 glyphs at the same time against 24 slots.  Both
are counts of Korean syllables, and both fall if the translation stops using a few
of them.

This is the one lever nobody is pulling.  Codex is compressing the shapes and
measuring whether the VRAM band can grow; neither touches how many distinct
syllables the script actually needs.

Two things are measured:

    rarity     how often each dynamic syllable appears in the whole script.  A
               syllable used twice is a syllable one reworded line removes.
    pressure   which single text unit forces the simultaneous maximum, and what it
               would take to bring that one line under the slot count.

Nothing is written.  The output is a list of candidates for the translator.
"""
from __future__ import annotations

import csv
import struct
import sys
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from plan_bulk_insertion import tokens  # noqa: E402
from audit_static_relocation_budget import (  # noqa: E402
    index_of, text_regions, IPR, PLANES, COLS, LOOKUP_SRC, LOOKUP_N,
    RAM_TO_FILE, ORIGINAL_CSV, SLOT_BASE, SLOT_COUNT, SLOT_SIZE, POOL)

BUILD = sorted(ROOT.glob("03_output/arc1_v170_*.zip"))[-1]
ORIGINAL = ROOT / "00_original/arc.zip"
ASSIGN = ROOT / "01_work/analysis/dynamic_cache_v153_widthsafe/glyph_assignments.csv"
CELLS = ROOT / "01_work/analysis/comm_physical_cell_safety/cells.csv"

# The extra UI cells Codex identified beyond the rejected list, from agent_debate.
EXTRA = ({(10, c) for c in (6, 7, 8, 11, 19, 20)}
         | {(11, c) for c in (7, 8, 11, 12, 18, 19, 20)}
         | {(17, c) for c in range(13)})


def read(path: Path) -> list[dict]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def main() -> None:
    with zipfile.ZipFile(BUILD) as z:
        members = {n: z.read(n) for n in z.namelist()}
    with zipfile.ZipFile(ORIGINAL) as z:
        original = {n: z.read(n) for n in z.namelist()}
    lut = struct.unpack_from(f"<{LOOKUP_N}H", members["PSX.EXE"], LOOKUP_SRC - RAM_TO_FILE)

    rows = read(ASSIGN)
    index_char = {int(r["physical_index"]): r["char"] for r in rows if r["physical_index"]}
    source_char = {int(r["source_id"]): r["char"] for r in rows if r["source_id"]}

    rejected = {(int(r["row"]), int(r["col"])) for r in read(CELLS)
                if r.get("status") == "rejected_known_nontext"}
    doomed = rejected | EXTRA

    # syllables that lose their static home when those cells go back to the original
    displaced = {index_char[i] for i in index_char
                 if (i // IPR, (i % IPR) // PLANES) in doomed}
    already = set(source_char.values())
    dynamic = displaced | already

    print(f"원복 대상 물리 칸        {len(doomed)}개")
    print(f"그 칸에서 밀려나는 한글   {len(displaced)}자")
    print(f"기존 동적 한글            {len(already)}자")
    print(f"합계 동적 원천            {len(dynamic)}자")

    uses = Counter()
    worst = (0, "", [])
    units = 0
    for label, payload in [(f"unit{i}", p) for i, p in
                           enumerate(text_regions(members, original))]:
        units += 1
        here = set()
        for token in tokens(payload):
            index = index_of(token, lut)
            if index is None:
                continue
            char = index_char.get(index)
            if char in dynamic:
                uses[char] += 1
                here.add(char)
        if len(here) > worst[0]:
            worst = (len(here), label, sorted(here))

    print()
    print(f"검사한 텍스트 단위        {units}개")
    print(f"한 단위 동시 최대          {worst[0]}자   ({worst[1]})")
    if worst[2]:
        print(f"  그 단위의 동적 글자: {' '.join(worst[2])}")

    print()
    print("동적 한글의 사용 빈도 (적은 것부터)")
    rare = [(n, c) for c, n in uses.items()]
    rare.sort()
    for cut in (1, 2, 3, 5, 10):
        gone = [c for n, c in rare if n <= cut]
        print(f"  {cut:2}회 이하로 쓰이는 글자 {len(gone):3}자"
              f"  -> 전부 바꾸면 동적 원천 {len(dynamic)} -> {len(dynamic)-len(gone)}자")
    print()
    print("  1~2회만 쓰이는 글자:")
    once = [c for n, c in rare if n <= 2]
    for i in range(0, len(once), 24):
        print("    " + " ".join(once[i:i + 24]))

    never = sorted(dynamic - set(uses))
    if never:
        print()
        print(f"  텍스트에서 한 번도 안 쓰이는 동적 글자 {len(never)}자 -- 그냥 빼면 된다")
        for i in range(0, len(never), 24):
            print("    " + " ".join(never[i:i + 24]))


if __name__ == "__main__":
    main()
