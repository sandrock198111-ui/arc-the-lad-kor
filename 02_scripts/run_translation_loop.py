"""Drive Codex through the remaining translation, one run at a time.

Written in Python after the shell version broke twice: an unbounded wait that parked
round 1 behind a process that had stopped working, then a syntax error introduced while
patching that wait. Quoting and control flow in shell were the whole problem, so they
are gone.

Each round: clear any leftover Codex, run one, then check what came back. A run is only
accepted if the file still has all its rows -- a truncated write is discarded and the
file restored from git. Rows whose Japanese is still undecoded are cleared before they
can spread, and every accepted round is committed, so nothing can be lost and no
half-written file can be mistaken for one.

    python 02_scripts/run_translation_loop.py [rounds]
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
CODEX = Path(r"C:\Users\Administrator\AppData\Local\OpenAI\Codex\bin"
             r"\d7e8094cfb76a267\codex.exe")
PROMPT = Path(r"C:\Users\ADMINI~1\AppData\Local\Temp\claude\E--korean"
              r"\d4252d73-7384-4279-9adc-1eb7f9ddea73\scratchpad\loop_prompt.txt")
EXPECT_ROWS = 5795
ROUND_TIMEOUT = 1500


def log(msg):
    print(f"{datetime.now():%H:%M:%S}  {msg}", flush=True)


def read_rows():
    with CSV.open(encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        return r.fieldnames, list(r)


def cols(fields):
    ko = next(c for c in fields if "korean" in c.lower())
    ja = next(c for c in fields if "japanese" in c.lower())
    src = next((c for c in fields if "source of" in c.lower()), None)
    return ko, ja, src


def state():
    fields, rows = read_rows()
    ko, ja, _ = cols(fields)
    done = sum(1 for r in rows if (r[ko] or "").strip())
    todo = sum(1 for r in rows
               if "<G:" not in (r[ja] or "") and (r[ja] or "").strip()
               and not (r[ko] or "").strip())
    return len(rows), done, todo


def clear_undecoded():
    """A translation written against text nobody has decoded cannot be checked."""
    fields, rows = read_rows()
    ko, ja, src = cols(fields)
    n = 0
    for r in rows:
        if "<G:" in (r[ja] or "") and (r[ko] or "").strip():
            r[ko] = ""
            if src:
                r[src] = ""
            n += 1
    if n:
        with CSV.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)
    return n


def git(*args):
    return subprocess.run(["git", "-c", "user.name=sandrock198111-ui",
                           "-c", "user.email=sandrock@hanmail.net", *args],
                          cwd=ROOT, capture_output=True, text=True)


def kill_codex():
    subprocess.run(["taskkill", "/F", "/IM", "codex.exe"],
                   capture_output=True, text=True)


def main():
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    prev = -1
    for i in range(1, rounds + 1):
        n, done, todo = state()
        log(f"round {i}  rows={n}  translated={done}  remaining={todo}")
        if todo == 0:
            log("DONE")
            return
        if done == prev:
            log(f"STALLED at {done}")
            return
        prev = done

        kill_codex()
        time.sleep(2)
        try:
            with PROMPT.open("rb") as stdin:
                subprocess.run(
                    [str(CODEX), "exec", "--model", "gpt-5.6-terra",
                     "-c", 'model_reasoning_effort="medium"',
                     "-c", 'approval_policy="never"',
                     "-c", 'sandbox_mode="workspace-write"'],
                    cwd=ROOT, stdin=stdin, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=ROUND_TIMEOUT)
        except subprocess.TimeoutExpired:
            log("  run timed out")
            kill_codex()

        try:
            n2, done2, todo2 = state()
        except Exception as e:
            log(f"  unreadable after the run ({e}); restoring")
            git("checkout", "--", str(CSV.relative_to(ROOT)))
            continue
        if n2 != EXPECT_ROWS:
            log(f"  rejected: {n2} rows, expected {EXPECT_ROWS}; restoring")
            git("checkout", "--", str(CSV.relative_to(ROOT)))
            continue
        cleared = clear_undecoded()
        if cleared:
            log(f"  cleared {cleared} rows whose Japanese is still undecoded")
        _, done2, todo2 = state()
        if done2 > done:
            git("add", str(CSV.relative_to(ROOT)))
            git("commit", "-q", "-m", f"번역 진행: {done} -> {done2} (남은 {todo2})")
            log(f"  +{done2 - done} committed")
        else:
            log("  no progress this round")
    log("loop finished")


if __name__ == "__main__":
    main()
