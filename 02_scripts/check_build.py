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
                  walks into the next slot. The approved V355 extension adds Bank-B
                  IDs D1..EC at DAT 0x4200..0x4FFF without changing Bank-A.
  stranded E2     A body pointing at an empty slot draws nothing.
  window rows     A row holds 228 pixels and the window is max(original rows, 3) tall.
                  Past that the renderer fills the window and stops, and the game does
                  not come back. This froze two save states.
  choice markers  Every E5 and E6 must sit at the byte offset the original put it, or
                  the menu cursor lands on a different row from the option text.
  choice width    A row holds 228px and options share rows. In a paragraph an over-long
                  row just wraps; in a menu the wrapped part lands on the cursor or on
                  the next option. Two rows regressed this way when the choices were
                  re-applied and were only found from a screenshot. A row is measured as
                  drawn: a span beginning with E2 draws its slot and the rest of the span
                  is skipped, so measuring the bytes between line breaks under-reads it.
  choice E2       A span too small for its Korean holds a two-byte E2 and the text
                  lives in a slot. That is correct and documented; what is checked is
                  that the slot exists and ends.
  exe pointers    A UI string the extractor never saw was never relocated either, so its
                  pointer still holds the original address -- and the repack has since
                  put somebody else's Korean there. The pointer then starts in the middle
                  of a glyph. That is what drew `2음의 문번 그라운드를 배웠다`: the 「 that
                  opens the message had been buried under 죽음의 문.

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
BANK_B_BASE = 0x4200
BANK_B_FIRST = 0xD1
BANK_B_COUNT = 28
BANK_B_LAST = BANK_B_FIRST + BANK_B_COUNT - 1


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


def slot_ref(data: bytes, disk: int) -> tuple[str, int, bytes] | None:
    """Resolve one runtime-approved E2 ID to its exact 128-byte DAT payload.

    Bank-A deliberately skips A9. V355 added Bank-B D1..EC at 0x4200 after a
    successful cold-boot probe; accepting any wider raw-ID range here would hide a
    real handler mismatch.
    """
    if 0x81 <= disk <= 0xA8:
        bank, slot, base = "A", disk - 0x81, SLOT_BASE
    elif 0xAA <= disk <= 0xD0:
        bank, slot, base = "A", disk - 0x82, SLOT_BASE
    elif BANK_B_FIRST <= disk <= BANK_B_LAST:
        bank, slot, base = "B", disk - BANK_B_FIRST, BANK_B_BASE
    else:
        return None
    start = base + slot * SLOT_SIZE
    end = start + SLOT_SIZE
    if end > len(data):
        return None
    return bank, slot, data[start:end]


# Two fragments are buried and cannot be dug out, because what they said is not known.
# They are listed rather than failed, so that a new one still fails. 0x82634 sits between
# 勝 and 能力 on the versus-record screen and is probably 敗, but DD CB is not in
# 05_docs/japanese_charmap_manual.csv; 0x8299C is monster skill name [2], one byte BF,
# with nothing around it to narrow it down.
KNOWN_BURIED = {0x82634, 0x8299C}


def drawn_rows(payload: bytes, data: bytes) -> list[list[bytes]]:
    """The rows a choice body actually draws.

    A span that begins with E2 draws the slot instead, and the rest of that span is
    skipped -- so its bytes contribute nothing to the row's width while the slot's do.
    Splitting on line breaks alone reads 204px where the game draws 258px.
    """
    out: list[list[bytes]] = []
    row: list[bytes] = []
    at_start, skipping = True, False
    for token in tokens(payload):
        if len(token) == 1 and token[0] == 0:
            break
        if token == LINEBREAK:
            out.append(row)
            row, at_start, skipping = [], True, False
            continue
        if token[0] == CHOICE:
            row.append(token)
            at_start, skipping = True, False
            continue
        if at_start and len(token) == 2 and token[0] == 0xE2:
            ref = slot_ref(data, token[1])
            if ref is not None:
                _bank, _slot, seg = ref
                if 0 in seg:
                    row.extend(tokens(seg[:seg.index(0)]))
            at_start, skipping = False, True
            continue
        at_start = False
        if not skipping:
            row.append(token)
    out.append(row)
    return out


def row_width(row: list[bytes]) -> int:
    while row and len(row[-1]) == 1 and row[-1][0] == 0x9C:
        row = row[:-1]
    return sum(advance(t) for t in row)


def buried_pointers(exe: bytes, pure: bytes) -> list[str]:
    """Pointers that began a string on the original disc and now land inside one.

    A string starts right after a terminator, so a target whose preceding byte is not
    zero begins in the middle of somebody else's text. That test alone is too loud --
    plenty of strings are preceded by binary rather than by another string, and those
    read perfectly well. What makes a hit real is that the run it landed in is itself
    something a pointer points at: two live strings claiming the same bytes, one of
    which was laid down over the other during the repack.
    """
    def targets(data: bytes) -> dict[int, list[int]]:
        low, high = RAM_TO_FILE, RAM_TO_FILE + len(data)
        out: dict[int, list[int]] = defaultdict(list)
        for at in range(0, len(data) - 4, 4):
            value = struct.unpack_from("<I", data, at)[0]
            if low <= value < high and 0 < value - low < len(data):
                out[value - low].append(at)
        return out

    def run_start(data: bytes, at: int) -> int:
        while at > 0 and data[at - 1]:
            at -= 1
        return at

    here, before = targets(exe), targets(pure)
    live = {s for s in here if s and exe[s - 1] == 0}
    out = []
    for start, ats in sorted(before.items()):
        if not start or pure[start - 1] != 0:
            continue
        if not 1 <= len(pure[start:start + 64].split(b"\0")[0]) <= 40:
            continue
        for at in ats:
            if at >= len(exe) - 4:
                continue
            value = struct.unpack_from("<I", exe, at)[0]
            if not (RAM_TO_FILE <= value < RAM_TO_FILE + len(exe)):
                continue
            now = value - RAM_TO_FILE
            if now == 0 or exe[now - 1] == 0:
                continue
            covering = run_start(exe, now)
            if covering in live and at not in KNOWN_BURIED:
                out.append(f"포인터 0x{at:X} -> 0x{now:X}, 0x{covering:X} 문자열 한가운데")
    return out


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

    if "PSX.EXE" in original:
        fail["실행파일 포인터가 다른 문자열 한가운데를 가리킴"] += buried_pointers(
            exe, original["PSX.EXE"])
        if not fail["실행파일 포인터가 다른 문자열 한가운데를 가리킴"]:
            del fail["실행파일 포인터가 다른 문자열 한가운데를 가리킴"]

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
                # Comparing widths against the original is not enough: the row holding
                # 적에게 피해를 입지 않으려면 was 258px against a Japanese row of 288px, so
                # that comparison called it fine while the game wrapped 다음 페이지 onto
                # the margin. Asking whether the row draws Hangul is not enough either --
                # some Japanese cells share a picture with a syllable. What separates them
                # is whether the row's bytes were rewritten at all: the 69 rows still over
                # 228px are untranslated and byte-identical to the disc.
                theirs = drawn_rows(raw, pure)
                for index, mine in enumerate(drawn_rows(here, data)):
                    width = row_width(mine)
                    if width <= ROW_PIXELS:
                        continue
                    if index < len(theirs) and mine == theirs[index]:
                        continue
                    fail["선택지 줄이 창을 넘음 (커서·다음 칸과 겹침)"].append(
                        f"{name} 0x{offset:X} 줄{index} {width}px")
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
                            ref = slot_ref(data, token[1])
                            if ref is None:
                                fail["선택지 E2의 슬롯 번호가 범위 밖"].append(f"{name} 0x{offset:X}")
                                continue
                            _bank, _slot, seg = ref
                            if not any(seg):
                                fail["선택지 E2가 빈 슬롯을 가리킴"].append(f"{name} 0x{offset:X}")
                            elif 0 not in seg[:SLOT_SIZE - 1]:
                                fail["선택지 슬롯에 종결자 없음"].append(f"{name} 0x{offset:X}")
                text = here
            elif here[:1] == b"\xE2" and has_slots:
                ref = slot_ref(data, here[1])
                if ref is None:
                    fail["E2의 슬롯 번호가 범위 밖"].append(f"{name} 0x{offset:X}")
                    continue
                bank, slot, seg = ref
                counts["E2 참조"] += 1
                if not any(seg):
                    fail["E2가 빈 슬롯을 가리킴"].append(f"{name} 0x{offset:X}")
                    continue
                if 0 not in seg[:SLOT_SIZE - 1]:
                    fail["슬롯에 종결자 없음"].append(
                        f"{name} 0x{offset:X} bank {bank} slot {slot}")
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
