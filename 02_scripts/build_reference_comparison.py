"""Pair our translation with an independent one, line by line, for reading side by side.

The reference is a blog retelling of the story, not a dump keyed to file offsets, so
nothing links the two but the words themselves. Each of our lines is matched to the
reference line it shares the most character bigrams with, which is enough to put the
same moment on the same row and cheap enough to run over the whole script.

The score is reported and never hidden. A high score means the two are the same line
and any difference is a wording choice worth looking at; a low one means no counterpart
was found, usually because the reference covers episodes 1-21 and we have the rest, or
because it summarises where the game has several short lines. Sort by score to read the
confident pairs first.
"""
from __future__ import annotations

import csv
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OURS = ROOT / "05_docs/script_translated_full.csv"
REFERENCE = Path.home() / "Downloads/아크더래드1_스토리번역_1-21.csv"
OUT = ROOT / "05_docs/review_against_reference.csv"
REPORT = ROOT / "01_work/analysis/reference_comparison.txt"

SPEAKER = re.compile(r"^\s*([^:：|]{1,10})\s*[:：]\s*")
NOISE = re.compile(r"[\s.,!?…·・\"'()\[\]「」『』~\-—|]+")
STRONG, WEAK = 0.45, 0.20


def strip_speaker(text: str) -> tuple[str, str]:
    m = SPEAKER.match(text)
    return (m.group(1).strip(), text[m.end():]) if m else ("", text)


def key(text: str) -> str:
    return NOISE.sub("", text)


def bigrams(text: str) -> set[str]:
    t = key(text)
    return {t[i:i + 2] for i in range(len(t) - 1)} or {t}


def main() -> None:
    if not REFERENCE.exists():
        raise SystemExit(f"reference not found: {REFERENCE}")
    ref = list(csv.DictReader(REFERENCE.read_text(encoding="utf-8-sig").splitlines()))
    ref_rows = []
    for r in ref:
        text = (r.get("text") or "").strip()
        if len(key(text)) < 4:
            continue
        ref_rows.append({"episode": r.get("episode", ""), "row_no": r.get("row_no", ""),
                         "speaker": (r.get("speaker") or "").strip(), "text": text,
                         "grams": bigrams(text)})

    index: dict[str, list[int]] = defaultdict(list)
    for i, r in enumerate(ref_rows):
        for g in r["grams"]:
            index[g].append(i)

    with OURS.open(encoding="utf-8-sig", newline="") as handle:
        ours = [r for r in csv.DictReader(handle)
                if any("가" <= c <= "힣" for c in (r.get("korean") or ""))]

    out = []
    for row in ours:
        korean = (row["korean"] or "").strip()
        speaker, body = strip_speaker(korean)
        grams = bigrams(body)
        hits: dict[int, int] = defaultdict(int)
        for g in grams:
            for i in index.get(g, ()):
                hits[i] += 1
        best, score = None, 0.0
        for i, shared in hits.items():
            union = len(grams | ref_rows[i]["grams"])
            s = shared / union if union else 0.0
            if s > score:
                best, score = i, s
        match = ref_rows[best] if best is not None and score >= WEAK else None
        out.append({
            "file": row["source file"], "offset": row["offset"],
            "score": f"{score:.2f}", "speaker": speaker,
            "ours": korean,
            "reference": match["text"] if match else "",
            "reference_speaker": match["speaker"] if match else "",
            "episode": match["episode"] if match else "",
            "japanese": (row.get("japanese") or "").replace("\n", " / "),
        })

    fields = ["file", "offset", "score", "speaker", "ours", "reference",
              "reference_speaker", "episode", "japanese"]
    with OUT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(sorted(out, key=lambda r: (r["file"], int(r["offset"], 0))))

    strong = sum(1 for r in out if float(r["score"]) >= STRONG)
    weak = sum(1 for r in out if WEAK <= float(r["score"]) < STRONG)
    none = len(out) - strong - weak
    lines = [
        "our translation against the reference retelling",
        "",
        f"our lines            {len(out)}",
        f"reference lines      {len(ref_rows)}   (episodes 1-21)",
        "",
        f"confident pair       {strong}   score >= {STRONG}",
        f"loose pair           {weak}   score {WEAK} to {STRONG}",
        f"no counterpart       {none}",
        "",
        "A confident pair is the same line in both translations, so any difference is a",
        "wording choice. A loose one may be the same moment phrased differently, or the",
        "reference summarising several game lines at once. No counterpart usually means",
        "the scene is outside episodes 1-21.",
        "",
        "Sort by score, descending, to read the pairs that are really comparable first.",
        "",
        f"-> {OUT.relative_to(ROOT)}",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
