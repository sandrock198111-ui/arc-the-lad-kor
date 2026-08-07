"""Every rule this project learned the hard way, checked on one build in a minute.

    python 02_scripts/check_build.py                  the newest build
    python 02_scripts/check_build.py 03_output/x.zip   a particular one

Each of these was found by someone playing the game and hitting it. That is the reason
the same scenes kept breaking: the check was written after the damage, one at a time,
and never run again on the next build. Run this instead, before burning a play session.

  glyph page      A glyph on font rows 22..39 that is not a strip draws twelve rows of
                  some other cell -- right position, wrong pixels. 25 characters shipped
                  that way in v129.
  slot terminator An external slot is 128 bytes: text, a 0x00, then the completion
                  metadata. A 127-byte payload leaves no terminator and the renderer
                  walks into the next slot.
  stranded E2     A body pointing at an empty slot draws nothing.
  window rows     A row holds 228 pixels and the window is max(original rows, 3) tall.
                  Past that the renderer fills the window and stops, and the game does
                  not come back. This froze two save states.
  choice markers  Every E5 and E6 must sit at the byte offset the original put it, or
                  the menu cursor lands on a different row from the option text.
  choice E2       A span too small for its Korean holds a two-byte E2 and the text
                  lives in a slot. That is correct and documented; what is checked is
                  that the slot exists and ends.

A failure prints the file and offset, so it can be looked at directly rather than
hunted for in game.
"""
from __future__ import annotations

import sys

# The console here is cp949, and printing the Japanese source to it raises
# UnicodeEncodeError before anything useful appears. Set the stream up rather than
# making the reader remember an environment variable.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import csv
import pickle
import struct
import sys
import zipfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from plan_bulk_insertion import (  # noqa: E402
    CACHE, CHOICE, LOOKUP_SRC, RAM_TO_FILE, SLOT_BASE, SLOT_COUNT, SLOT_SIZE,
    bitmap, drawable, has_marker, tokens,
)
from review_editor import MIN_WINDOW_ROWS, ROW_PIXELS, advance, wrapped_rows  # noqa: E402

ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"
PRISTINE = ROOT / "00_original/arc.zip"
LINEBREAK = b"\xE6\x01"


def newest() -> Path:
    found = sorted((ROOT / "03_output").glob("arc1_v1*.zip"), key=lambda p: p.stat().st_mtime)
    if not found:
        raise SystemExit("03_output에 arc1_v1*.zip 이 없습니다")
    return found[-1]


def markers(raw: bytes) -> list[tuple[int, bytes]]:
    out, position = [], 0
    for token in tokens(raw):
        if len(token) == 1 and token[0] == 0:
            break
        if token[0] == CHOICE or token == LINEBREAK:
            out.append((position, token))
        position += len(token)
    return out


def slot_of(disk: int) -> int:
    return disk - 0x81 if disk < 0xA9 else disk - 0x82


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else newest()
    with zipfile.ZipFile(path) as archive:
        blob = {n: archive.read(n) for n in archive.namelist()}
    with zipfile.ZipFile(PRISTINE) as pristine:
        original = {n: pristine.read(n) for n in pristine.namelist() if n in blob}
    exe, font = blob["PSX.EXE"], blob["COMM.IMG"]
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())

    # codes that draw a Hangul syllable the classifier cannot reach
    banned: dict[bytes, str] = {}
    for lead in range(0xDD, 0xE9):
        for trail in range(0x01, 0x100):
            index = (lead - 0xDD) * 255 + trail + 0xDB
            if not drawable(exe, index):
                bits = bitmap(exe, font, index)
                if bits and (char := shapes.get(bits)):
                    banned[bytes((lead, trail))] = char

    bodies: dict[str, list[tuple[int, bytes]]] = defaultdict(list)
    with ORIGINAL_CSV.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
        for row in reader:
            bodies[row["source file"]].append(
                (int(row[key], 0), bytes.fromhex(row["raw bytes as hex"].replace(" ", ""))))

    fail: dict[str, list[str]] = defaultdict(list)
    counts = defaultdict(int)

    for name, items in bodies.items():
        if name not in blob or name not in original:
            continue
        data, pure = blob[name], original[name]
        has_slots = len(data) >= SLOT_BASE + SLOT_COUNT * SLOT_SIZE
        for offset, raw in items:
            here = data[offset:offset + len(raw)]
            if len(here) != len(raw):
                continue
            untouched = here == pure[offset:offset + len(raw)]
            choice = has_marker(raw, CHOICE)

            if choice:
                counts["선택지"] += 1
                if markers(here) != markers(raw):
                    fail["선택지 마커가 원판과 다른 위치"].append(f"{name} 0x{offset:X}")
                # An E2 inside a choice body is how a span too small for its Korean is
                # served: two bytes in the span, the text in a slot. What must not
                # happen is that it points nowhere, or that the markers move -- the
                # check above covers the second. v135 treated the redirect itself as
                # the defect and reverted 258 working bodies to Japanese.
                if not untouched and has_slots:
                    starts = {p for p, _ in markers(here)}
                    starts = {p + 2 for p in starts} | {0}
                    position = 0
                    for token in tokens(here):
                        if len(token) == 2 and token[0] == 0xE2 and position not in starts:
                            fail["선택지 칸 중간에 E2 (글자와 구분 불가)"].append(
                                f"{name} 0x{offset:X}")
                        position += len(token)
                    position = 0
                    for token in tokens(here):
                        keep = position in starts
                        position += len(token)
                        if not keep or len(token) != 2 or token[0] != 0xE2:
                            continue
                        if True:
                            slot = slot_of(token[1])
                            if not 0 <= slot < SLOT_COUNT:
                                fail["선택지 E2의 슬롯 번호가 범위 밖"].append(f"{name} 0x{offset:X}")
                                continue
                            seg = data[SLOT_BASE + slot * SLOT_SIZE:
                                       SLOT_BASE + (slot + 1) * SLOT_SIZE]
                            if not any(seg):
                                fail["선택지 E2가 빈 슬롯을 가리킴"].append(f"{name} 0x{offset:X}")
                            elif 0 not in seg[:SLOT_SIZE - 1]:
                                fail["선택지 슬롯에 종결자 없음"].append(f"{name} 0x{offset:X}")
                text = here
            elif here[:1] == b"\xE2" and has_slots:
                slot = slot_of(here[1])
                if not 0 <= slot < SLOT_COUNT:
                    fail["E2의 슬롯 번호가 범위 밖"].append(f"{name} 0x{offset:X}")
                    continue
                seg = data[SLOT_BASE + slot * SLOT_SIZE:SLOT_BASE + (slot + 1) * SLOT_SIZE]
                counts["E2 참조"] += 1
                if not any(seg):
                    fail["E2가 빈 슬롯을 가리킴"].append(f"{name} 0x{offset:X}")
                    continue
                if 0 not in seg[:SLOT_SIZE - 1]:
                    fail["슬롯에 종결자 없음"].append(f"{name} 0x{offset:X} slot {slot}")
                text = seg[:seg.index(0)] if 0 in seg[:SLOT_SIZE - 1] else seg[:SLOT_SIZE - 1]
                window = max(sum(1 for t in tokens(raw) if t == LINEBREAK) + 1, MIN_WINDOW_ROWS)
                if wrapped_rows(text) > window:
                    fail["창을 넘침 (게임이 멈춤)"].append(
                        f"{name} 0x{offset:X}  {wrapped_rows(text)}/{window}줄 "
                        f"{sum(advance(t) for t in tokens(text))}px")
            else:
                if untouched:
                    continue
                counts["제자리"] += 1
                text = here

            if untouched and not choice:
                continue
            for token in tokens(text):
                if token in banned:
                    fail["닿을 수 없는 글리프"].append(
                        f"{name} 0x{offset:X} {banned[token]}")
                    break

    print(f"검사 대상: {path.name}")
    print(f"  본문 {sum(len(v) for v in bodies.values())} / "
          f"선택지 {counts['선택지']} / E2 {counts['E2 참조']} / 제자리 {counts['제자리']}\n")
    if not fail:
        print("모든 검사 통과")
        return
    for reason, hits in fail.items():
        print(f"FAIL  {reason}: {len(hits)}곳")
        for h in hits[:6]:
            print(f"        {h}")
        if len(hits) > 6:
            print(f"        ... {len(hits) - 6}곳 더")
    raise SystemExit(1)


if __name__ == "__main__":
    main()
