"""Build 05_docs/choices_untranslated.csv -- every choice option still in Japanese.

    python 02_scripts/review_untranslated_choices.py

A choice body is a row of spans separated by E5 markers, and the earlier passes worked
body by body, so a body counted as translated can still hold Japanese spans. Walking the
spans finds 105 of them in the shipped build.

Each row carries what is needed to decide: the Japanese the span came from, a proposed
Korean, and where it would go. A span can stay where it is if the Korean fits its own
bytes; otherwise it needs a free slot in that file, and the E2 redirect documented on
2026-07-17 puts it there. Rows whose Japanese the extractor could not decode are marked
and left without a proposal -- 69 of them read as noise such as 解い装ま火, and writing
Korean over something not known to be text is how data gets overwritten.

The file is for reading and editing before anything is built, the same way
shorten_todo.csv and tightened.csv were used.
"""
from __future__ import annotations

import csv
import pickle
import re
import struct
import sys
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from plan_bulk_insertion import (  # noqa: E402
    CACHE, CHOICE, LOOKUP_N, LOOKUP_SRC, RAM_TO_FILE, SLOT_BASE, SLOT_COUNT, SLOT_SIZE,
    bitmap, build_encoder, drawable, encode, has_marker, tokens,
)

OUT = ROOT / "05_docs/choices_untranslated.csv"
LINEBREAK = b"\xE6\x01"

# The CSV already holds a translation for most of these spans -- they were written and
# simply never inserted -- and those are used first, because they are the ones that have
# been read and approved. 150人 is 150 there, not 150명, and ちゃいろ is 갈, not 갈색;
# both are already cut to fit. This table is only the fallback for spans the CSV leaves
# empty, and it follows wording the game already uses elsewhere where there is any.
PROPOSED = {
    "はい": "네",
    "まだです": "아직요",
    "よむ。": "읽는다",
    "よまない": "안 읽기",
    "召喚獣": "소환수",
    "次のページ": "다음 페이지",
    "リングの位置設定": "링 위치 설정",
    "やる": "한다",
    "150人": "150명",
    "200人": "200명",
    "250人": "250명",
    "ねばねば": "끈적끈적",
    "わけあつてちゃいろ": "사연이 있어 갈색",
    "復活の薬": "부활약",
    "ちからの実": "힘의 열매",
    "幻のこて": "환상의 건틀릿",
    "まだ戦い方がわからないや。": "아직 싸우는 법을 모르겠어.",
    "どうすれば強くなれるの？": "어떻게 해야 강해질까?",
}

# Used only where the wording above does not fit and the file has no free slot to send it
# to. 달라붙음 is seven bytes in a four-byte span; 끈적 is four and says the same thing.
# 幻のこて is deliberately absent: the game calls it 환상의 건틀릿 in the message that
# follows the choice, and a different name here would read as a different item. That one
# needs a slot freed in C2/SC0B6.DAT instead, so it stays on the list.
TIGHTER = {
    "ねばねば": "끈적",
}


def newest() -> Path:
    found = sorted((ROOT / "03_output").glob("arc1_v1*.zip"), key=lambda p: p.stat().st_mtime)
    if not found:
        raise SystemExit("03_output에 arc1_v1*.zip 이 없습니다")
    return found[-1]


def main() -> None:
    build = Path(sys.argv[1]) if len(sys.argv) > 1 else newest()
    archive = ZipFile(build)
    exe, font = archive.read("PSX.EXE"), archive.read("COMM.IMG")
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    lut = struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP_SRC - RAM_TO_FILE)
    table = build_encoder(exe, font)

    def spell(payload: bytes) -> str:
        out = []
        for token in tokens(payload):
            if len(token) == 1:
                index = token[0] - 1
            elif 0xDD <= token[0] <= 0xE8:
                index = (token[0] - 0xDD) * 255 + token[1] + 0xDB
            elif token[0] in (0xE9, 0xEA):
                slot = (token[0] - 0xE9) * 254 + token[1] - 1
                index = lut[slot] if 0 <= slot < LOOKUP_N else None
            else:
                index = None
            if index is None or not drawable(exe, index):
                out.append("·")
                continue
            bits = bitmap(exe, font, index)
            out.append(shapes.get(bits) or (" " if not any(bits) else "?"))
        return "".join(out)

    japanese: dict[tuple[str, int], str] = {}
    korean_csv: dict[tuple[str, int], str] = {}
    with (ROOT / "05_docs/script_translated_full.csv").open(
            encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            at = (row["source file"], int(row["offset"], 0))
            japanese[at] = row.get("japanese") or ""
            korean_csv[at] = row.get("korean") or ""

    with (ROOT / "05_docs/script_original_full.csv").open(
            encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
        items = [(r["source file"], int(r[key], 0),
                  bytes.fromhex(r["raw bytes as hex"].replace(" ", ""))) for r in reader]

    def byte_spans(payload: bytes) -> list[tuple[int, int]]:
        out, start, position = [], None, 0
        for token in tokens(payload):
            if len(token) == 1 and token[0] == 0:
                break
            if token[0] == CHOICE:
                if start is not None:
                    out.append((start, position))
                start = position + len(token)
            elif token == LINEBREAK and start is not None:
                out.append((start, position))
                start = None
            position += len(token)
        if start is not None:
            out.append((start, position))
        return out

    def options(text: str) -> list[str]:
        """The Japanese cut the way the bytes are: one piece per choice marker."""
        if not text:
            return []
        out = []
        for piece in re.split(r"<CTRL:E5:[0-9A-Fa-f]+>", text)[1:]:
            piece = re.split(r"<CTRL:E6:[0-9A-Fa-f]+>|\|", piece)[0]
            out.append(re.sub(r"<[^>]*>", "", piece).strip())
        return out

    cache: dict[str, bytes] = {}
    free: dict[str, int] = {}
    rows = []
    for name, offset, raw in items:
        if name not in archive.namelist() or not has_marker(raw, CHOICE):
            continue
        data = cache.setdefault(name, archive.read(name))
        here = data[offset:offset + len(raw)]
        if len(here) != len(raw):
            continue
        if name not in free:
            free[name] = sum(
                1 for s in range(SLOT_COUNT)
                if not any(data[SLOT_BASE + s * SLOT_SIZE:SLOT_BASE + (s + 1) * SLOT_SIZE]))
        pieces = options(japanese.get((name, offset), ""))
        # The CSV separates options with a bar and may start with an empty one where the
        # disc has a line break; line them up by count before trusting the pairing.
        written = [p.strip() for p in korean_csv.get((name, offset), "").split("|")]
        while written and not written[0]:
            written.pop(0)
        if len(written) != len(pieces):
            written = []
        for n, (a, b) in enumerate(byte_spans(here)):
            drawn = spell(here[a:b]).strip()
            if not drawn or any("가" <= c <= "힣" for c in drawn):
                continue
            source = pieces[n] if n < len(pieces) else ""
            from_csv = written[n] if n < len(written) else ""
            korean = from_csv or PROPOSED.get(source, "")
            cost, missing = (encode(korean, table, keep_breaks=False)
                             if korean else (b"", []))
            if korean and (missing or (len(cost) > b - a and not free[name])):
                if tighter := TIGHTER.get(source):
                    korean, from_csv = tighter, ""
                    cost, missing = encode(korean, table, keep_breaks=False)
            if not source:
                verdict = "원문 불명 - 손대지 말 것"
            elif not korean:
                verdict = "원문이 노이즈 - 손대지 말 것"
            elif missing:
                verdict = "없는 글자: " + " ".join(sorted(set(missing)))
            elif len(cost) <= b - a:
                verdict = "제자리"
            elif free[name] > 0:
                verdict = "슬롯 필요"
            else:
                verdict = "슬롯 없음 - 더 줄여야 함"
            rows.append({
                "행번호": len(rows) + 1,
                "파일": name,
                "오프셋": f"0x{offset:X}",
                "칸": n,
                "칸 바이트": b - a,
                "빈 슬롯": free[name],
                "원문": source,
                "지금 화면": drawn,
                "출처": "CSV" if from_csv else ("제안" if korean else ""),
                "수정제안": korean,
                "제안 바이트": len(cost) if korean else "",
                "상태": verdict,
            })

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    tally: dict[str, int] = {}
    for row in rows:
        tally[row["상태"]] = tally.get(row["상태"], 0) + 1
    print(f"기준 빌드: {build.name}")
    print(f"미번역 선택지 칸 {len(rows)}개 -> {OUT.relative_to(ROOT)}")
    for state, count in sorted(tally.items(), key=lambda kv: -kv[1]):
        print(f"  {state:28s} {count}")


if __name__ == "__main__":
    main()
