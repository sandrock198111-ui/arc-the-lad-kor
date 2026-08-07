"""Find the line behind a report, from a fragment of what was on screen.

    python 02_scripts/find_line.py 물론이야
    python 02_scripts/find_line.py "戦闘になる"        원문으로도 찾습니다
    python 02_scripts/find_line.py 21/S2041 --file     파일로 좁혀 보기

A report arrives as a screenshot or a sentence. What is needed to act on it is the CSV
row, and finding that by hand means grepping three files and decoding bytes. This does
it in one step: it searches the Japanese, the Korean in the CSV, and the Korean the
newest build actually draws, then prints the row with everything needed to decide --
where it lives, whether it is in the game yet, and what it would cost to change.

The disc column is decoded from the build, so a line that reads correctly here but not
in game is a rendering problem, and a line that differs here was never inserted. That
distinction is the one that has cost the most time.
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

import re
import sys
import tkinter as tk

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "02_scripts"))
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]
                       / "06_tools" / "python_packages"))

from review_editor import Editor  # noqa: E402


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    by_file = "--file" in sys.argv
    if not args:
        raise SystemExit(__doc__)
    needle = " ".join(args)
    flat = re.sub(r"\s+", "", needle)

    root = tk.Tk()
    root.withdraw()
    editor = Editor(root)

    hits = []
    for line in editor.lines:
        if by_file:
            if needle.lower() in line.file.lower():
                hits.append(line)
            continue
        for field in (line.japanese, line.korean, line.disc):
            if flat and flat in re.sub(r"\s+", "", field or ""):
                hits.append(line)
                break

    print(f"기준 빌드: {editor.build_name}")
    print(f"'{needle}' → {len(hits)}줄\n")
    for line in hits[:20]:
        state = editor.state_of(line)
        m = editor.measure(line, line.proposal)
        print(f"행 {line.n}   {line.file} {line.offset}   [{state}]")
        print(f"   원문   : {(line.japanese or '').replace(chr(10), ' / ')[:90]}")
        print(f"   디스크 : {line.disc[:90]}")
        if re.sub(r"[|\s]+", "", line.disc) != re.sub(r"[|\s]+", "", line.korean):
            print(f"   CSV    : {line.korean[:90]}")
        note = []
        if m["missing"]:
            note.append("없는 글자 " + " ".join(m["missing"]))
        note.append(f"{m['need_rows']}/{m['window']}줄")
        note.append(f"{m['bytes']}B, 제자리 칸 {line.capacity}B")
        if line.is_choice:
            note.append("선택지")
        if state in ("슬롯부족", "빌드대기"):
            note.append(f"이 파일 빈 슬롯 {editor.free_slots.get(line.file, 0)}")
        print(f"   {' · '.join(note)}\n")
    if len(hits) > 20:
        print(f"... {len(hits) - 20}줄 더")
    root.destroy()


if __name__ == "__main__":
    main()
