"""Hand Codex a small slice instead of the whole script, then merge the result back.

Throughput collapsed from 337 rows a round to 3 even with a fresh session each time.
The cause is not the model: the file is 5,795 rows, and finding the untranslated ones
costs more as more of them fill in, so the run spends its budget reading and has none
left for output.

So the run never sees the big file. Each round writes out only untranslated rows, has
Codex fill in a Korean column, and merges by (source file, offset) so nothing else can
be disturbed -- a row that already had a translation is never rewritten, and a row the
slice does not mention is never touched.

    python 02_scripts/translate_slice.py [rounds] [rows-per-slice]
"""
from __future__ import annotations

import csv
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSV = ROOT / "05_docs/script_translated_full.csv"
WORK = ROOT / "01_work/translate_slice.csv"
CODEX = Path(r"C:\Users\Administrator\AppData\Local\OpenAI\Codex\bin"
             r"\d7e8094cfb76a267\codex.exe")
EXPECT_ROWS = 5795
ROUND_TIMEOUT = 1200

PROMPT = """Translate the Japanese into Korean in 01_work/translate_slice.csv.

That file is small and holds only untranslated lines. Fill the korean column of every
row, then save it. Change nothing else, add no rows, remove no rows, and do not touch
any other file.

Voice: this is Arc the Lad 1 for the PlayStation, and most of the script is already
translated elsewhere in this project. Match plain, natural Korean dialogue -- the
speech level each character would use, ordinary punctuation, no honorific inflation.

Translate fully. Do not shorten a line to make it fit and do not paraphrase for
smoothness; fitting is handled separately.

05_docs/terminology_decisions.csv is binding for any term it covers. Leave a row's
korean cell empty only if the japanese is not dialogue -- a filename, a control
sequence, debug text.

Work through the whole file. Do not stop to explain; when you are done, say only how
many rows you filled.
"""


def log(m):
    print(f"{datetime.now():%H:%M:%S}  {m}", flush=True)


def load(path):
    with path.open(encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        return r.fieldnames, list(r)


def cols(fields):
    return (next(c for c in fields if "korean" in c.lower()),
            next(c for c in fields if "japanese" in c.lower()),
            next((c for c in fields if "source of" in c.lower()), None),
            next(c for c in fields if "source file" in c.lower()),
            next(c for c in fields if "offset" in c.lower()))


def git(*a):
    return subprocess.run(["git", "-c", "user.name=sandrock198111-ui",
                           "-c", "user.email=sandrock@hanmail.net", *a],
                          cwd=ROOT, capture_output=True)


def main():
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    size = int(sys.argv[2]) if len(sys.argv) > 2 else 150
    WORK.parent.mkdir(parents=True, exist_ok=True)
    prev = -1

    for i in range(1, rounds + 1):
        fields, rows = load(CSV)
        ko, ja, src, sf, off = cols(fields)
        todo = [r for r in rows
                if "<G:" not in (r[ja] or "") and (r[ja] or "").strip()
                and not (r[ko] or "").strip()]
        done = sum(1 for r in rows if (r[ko] or "").strip())
        log(f"round {i}  translated={done}  remaining={len(todo)}")
        if not todo:
            log("DONE")
            return
        if done == prev:
            log(f"STALLED at {done}")
            return
        prev = done

        batch = todo[:size]
        with WORK.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=[sf, off, ja, ko])
            w.writeheader()
            for r in batch:
                w.writerow({sf: r[sf], off: r[off], ja: r[ja], ko: ""})

        subprocess.run(["taskkill", "/F", "/IM", "codex.exe"], capture_output=True)
        time.sleep(1)
        try:
            subprocess.run(
                [str(CODEX), "exec", "--model", "gpt-5.6-terra",
                 "-c", 'model_reasoning_effort="medium"',
                 "-c", 'approval_policy="never"',
                 "-c", 'sandbox_mode="workspace-write"', PROMPT],
                cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=ROUND_TIMEOUT)
        except subprocess.TimeoutExpired:
            log("  timed out")
            subprocess.run(["taskkill", "/F", "/IM", "codex.exe"], capture_output=True)

        # merge by key: only rows that were in the slice and are still empty
        try:
            wf, wrows = load(WORK)
            wko = next(c for c in wf if "korean" in c.lower())
            filled = {(r[sf], r[off]): (r[wko] or "").strip()
                      for r in wrows if (r[wko] or "").strip()}
        except Exception as e:
            log(f"  slice unreadable ({e})")
            continue
        if not filled:
            log("  nothing came back")
            continue

        fields, rows = load(CSV)
        if len(rows) != EXPECT_ROWS:
            log(f"  main file has {len(rows)} rows; restoring")
            git("checkout", "--", "05_docs/script_translated_full.csv")
            continue
        n = 0
        for r in rows:
            if (r[ko] or "").strip():
                continue
            v = filled.get((r[sf], r[off]))
            if v and "<G:" not in (r[ja] or ""):
                r[ko] = v
                if src:
                    r[src] = "new"
                n += 1
        with CSV.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)
        log(f"  merged {n}")
        if n:
            git("add", "05_docs/script_translated_full.csv")
            git("commit", "-q", "-m", f"번역 진행: {done} -> {done + n}")
    log("loop finished")


if __name__ == "__main__":
    main()
