"""How many glyph slots are still held by Japanese we have already replaced.

Every attempt so far has looked for empty space in COMM.IMG and found artwork
instead.  The strictest count says the original game draws text in 756 slots and
only 27 of those are free today, which is why v146, v151, v159 and v163 all ended
up writing Hangul over pictures.

But most of those 756 are not really taken.  They are held by Japanese glyphs whose
lines this project has already translated -- the bytes that referenced them are gone
from the disc, so nothing draws them any more.  A slot is only genuinely occupied if
some line still on the disc points at it.

    proven   the original game drew text there, so the cell is font and not artwork
    held     an untranslated line still on the disc references it
    free     proven and not held -- ours to take, with no guessing involved

If free covers the Hangul the build needs, the runtime cache can be dropped
entirely and every glyph becomes static.
"""
from __future__ import annotations

import csv
import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from plan_bulk_insertion import tokens  # noqa: E402
from audit_static_relocation_budget import (  # noqa: E402
    index_of, IPR, PLANES, COLS, LOOKUP_SRC, LOOKUP_N, RAM_TO_FILE,
    ORIGINAL_CSV, SLOT_BASE, SLOT_COUNT, SLOT_SIZE, POOL)

BUILD = ROOT / "03_output/arc1_v163_text_clut_classifier_773E3B82.zip"
ORIGINAL = ROOT / "00_original/arc.zip"


def rows() -> list[tuple[str, int, int]]:
    with ORIGINAL_CSV.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
        return [(r["source file"], int(r[key], 0),
                 len(bytes.fromhex(r["raw bytes as hex"].replace(" ", "")))) for r in reader]


def indices(payload: bytes, lut: tuple[int, ...]) -> set[int]:
    out = set()
    for token in tokens(payload):
        index = index_of(token, lut)
        if index is not None and index // IPR < 42 and (index % IPR) // PLANES < COLS:
            out.add(index)
    return out


def main() -> None:
    with zipfile.ZipFile(BUILD) as z:
        ours = {n: z.read(n) for n in z.namelist()}
    with zipfile.ZipFile(ORIGINAL) as z:
        stock = {n: z.read(n) for n in z.namelist()}
    lut = struct.unpack_from(f"<{LOOKUP_N}H", ours["PSX.EXE"], LOOKUP_SRC - RAM_TO_FILE)

    proven, held, mine = set(), set(), set()
    untouched = translated = 0

    for name, offset, size in rows():
        if name not in ours or offset + size > len(ours[name]):
            continue
        cur, org = ours[name][offset:offset + size], stock[name][offset:offset + size]
        proven |= indices(org, ())
        if cur == org:
            held |= indices(org, ())
            untouched += 1
        else:
            mine |= indices(cur, lut)
            translated += 1

    for name in {n for n, _, _ in rows()}:
        cur, org = ours.get(name), stock.get(name)
        if not cur or not org or len(cur) < SLOT_BASE + SLOT_COUNT * SLOT_SIZE:
            continue
        for slot in range(SLOT_COUNT):
            at = SLOT_BASE + slot * SLOT_SIZE
            a, b = cur[at:at + SLOT_SIZE], org[at:at + SLOT_SIZE]
            for block, bucket in ((b, proven), (b, held) if a == b else (a, mine)):
                if block and block[0] and 0 in block:
                    bucket |= indices(block[:block.index(0)], () if bucket is not mine else lut)

    lo, hi = POOL
    run = bytearray()
    for i in range(lo, hi):
        if ours["PSX.EXE"][i] != stock["PSX.EXE"][i] and ours["PSX.EXE"][i]:
            run.append(ours["PSX.EXE"][i])
        else:
            if len(run) > 1:
                mine |= indices(bytes(run), lut)
            run.clear()

    free = proven - held
    print(f"번역 상태   번역된 본문 {translated}개, 아직 원본 그대로인 본문 {untouched}개")
    print()
    print(f"proven  원본 게임이 글자로 그린 자리          {len(proven)}자")
    print(f"held    아직 원본 그대로인 줄이 붙잡고 있는 자리 {len(held)}자")
    print(f"free    회수 가능한 자리 (proven - held)        {len(free)}자")
    print()
    print(f"우리 한글이 지금 쓰는 자리                    {len(mine)}자")
    print()
    if len(mine) <= len(free):
        print(f"판정: 들어간다.  필요 {len(mine)}자 <= 회수 가능 {len(free)}자"
              f"  (여유 {len(free)-len(mine)}자)")
        print("      동적 캐시를 버리고 전부 고정 배치할 수 있다.")
    else:
        print(f"판정: 부족하다.  필요 {len(mine)}자 > 회수 가능 {len(free)}자"
              f"  ({len(mine)-len(free)}자 모자람)")
        print("      모자란 만큼만 캐시가 맡으면 된다.")


if __name__ == "__main__":
    main()
