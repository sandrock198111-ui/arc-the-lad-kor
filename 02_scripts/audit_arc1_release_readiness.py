"""Two static checks that stand in for a full playthrough before a release.

The failures this project keeps hitting are silent: a glyph reference survives a
build, points at a cell that was emptied, and the renderer draws nothing.  No
crash, no log -- the word is simply gone.  Three of them turned up in one day
(○, 괜, 상승).  A player would have to walk into the exact line to notice.

Neither needs the emulator:

    orphaned references   a two-byte glyph code whose index has no pixels in
                          COMM.IMG and sits in none of the 48 conflict ranges at
                          0x801A74C0.  Nothing redirects it to the cache, so it
                          draws an empty cell.

    line growth           the rendered line count of every dialogue body,
                          compared with the original disc.  A row whose width
                          reaches ROW_PIXELS wraps once more -- that is what
                          pushed the options below the choice cursor in v197 --
                          and a body that grows past what the original ever used
                          risks running out of the window.

    python 02_scripts/audit_arc1_release_readiness.py <patch.zip>
"""
from __future__ import annotations

import collections
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

import build_arc1_v186_runtime_text_choice_fixes as v186  # noqa: E402

R2F = 0x8011A800
ROW_BYTES, IPR, CELL = 896, 84, 12
RANGES_RAM, RANGE_BYTES = 0x801A74C0, 96
DIALOGUE = ROOT / "05_docs/dialogue_all.csv"
ORIGINAL = ROOT / "00_original/arc.zip"


def members(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def inked(font: bytes, index: int) -> bool:
    row, col, plane = index // IPR, (index % IPR) // 4, index % 4
    bit = 1 << plane
    for dy in range(CELL):
        at = (row * CELL + dy) * ROW_BYTES + col * (CELL // 2)
        for byte in font[at:at + CELL // 2]:
            if (byte & 0x0F & bit) or ((byte >> 4) & bit):
                return True
    return False


def reachable(exe: bytes) -> set[int]:
    raw = exe[RANGES_RAM - R2F:RANGES_RAM - R2F + RANGE_BYTES]
    out = set()
    for i in range(RANGE_BYTES // 2):
        word = struct.unpack_from("<H", raw, i * 2)[0]
        start, length = word & 0x7FF, (word >> 11) + 1
        out.update(range(start, start + length))
    return out


def body(data: bytes, offset: int) -> bytes:
    end = offset
    while end < len(data) and data[end] and end - offset < 400:
        end += 1
    return data[offset:end]


def rendered_lines(data: bytes, offset: int) -> int:
    rows = v186.structural.drawn_rows(body(data, offset), data)
    total = 0
    for row in rows:
        width = v186.structural.row_width(row)
        total += 1 if width == 0 else (width // v186.ROW_PIXELS) + 1
    return total


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    built = members(Path(sys.argv[1]))
    stock = members(ORIGINAL)
    exe, font = built["PSX.EXE"], built["COMM.IMG"]

    covered = reachable(exe)
    orphan = {i for i in range(219, 1480) if not inked(font, i) and i not in covered}

    targets = []
    for row in csv.DictReader(open(DIALOGUE, encoding="utf-8-sig", errors="replace")):
        try:
            offset = int(row["오프셋"], 16)
        except Exception:
            continue
        name = row["파일"]
        if name in built and offset < len(built[name]):
            targets.append((name, offset, row.get("원문", "")))

    hits, seen = [], collections.Counter()
    for name, offset, source in targets:
        blob = body(built[name], offset)
        at, found = 0, []
        while at < len(blob):
            lead = blob[at]
            if 0xDD <= lead <= 0xE0 and at + 1 < len(blob):
                index = (lead - 0xDD) * 255 + blob[at + 1] + 219
                if index in orphan:
                    found.append(index)
                    seen[index] += 1
                at += 2
            elif 0xDD <= lead <= 0xEA and at + 1 < len(blob):
                at += 2
            else:
                at += 1
        if found:
            hits.append((name, offset, found, source[:30]))

    grew, shrank, ceiling = [], 0, collections.Counter()
    for name, offset, _source in targets:
        try:
            was, now = rendered_lines(stock[name], offset), rendered_lines(built[name], offset)
        except Exception:
            continue
        ceiling[now] += 1
        if now > was:
            grew.append((name, offset, was, now))
        elif now < was:
            shrank += 1
    stock_max = 0
    for name, offset, _source in targets:
        try:
            stock_max = max(stock_max, rendered_lines(stock[name], offset))
        except Exception:
            pass
    over = sum(count for lines, count in ceiling.items() if lines > stock_max)

    print(f"검사 대상 대사 {len(targets)}개\n")
    print(f"1) 고아 글리프를 가리키는 대사  {len(hits)}건, 참조 {sum(seen.values())}회")
    for name, offset, found, source in hits[:20]:
        print(f"     {name:16} 0x{offset:05X}  번호{found}  {source}")
    print(f"\n2) 표시 줄 수  원본보다 늘어난 {len(grew)}건, 줄어든 {shrank}건")
    print(f"   원본이 쓴 최대 {stock_max}줄, 그보다 많은 대사 {over}건")
    if hits or over:
        raise SystemExit(1)
    print("\n두 검사 모두 통과")


if __name__ == "__main__":
    main()
