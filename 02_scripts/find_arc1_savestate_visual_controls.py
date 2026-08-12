"""Rank older DuckStation states by thumbnail similarity to v163 controls.

Only the first Zstandard frame (the 256x192 thumbnail) is decompressed.  The
score samples an 8-pixel grid and averages the closest 70 percent of blocks so
dialogue boxes, glyph corruption, and animated sprites do not dominate the
background match.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from extract_duckstation_savestate import decompress  # noqa: E402


SAVE_DIR = Path(r"C:\Users\Administrator\AppData\Local\DuckStation\savestates")
TARGET_DIR = ROOT / "01_work/analysis/arc1_v163_runtime_states"
OUT = TARGET_DIR / "visual_control_candidates.csv"
TARGET_SLOTS = (1, 2, 5, 7, 8, 9, 10)
WIDTH, HEIGHT, STEP = 256, 192, 8


def feature(bgra: bytes) -> tuple[tuple[int, int, int], ...]:
    if len(bgra) != WIDTH * HEIGHT * 4:
        raise ValueError(f"thumbnail length differs: {len(bgra)}")
    points = []
    for y in range(STEP // 2, HEIGHT, STEP):
        for x in range(STEP // 2, WIDTH, STEP):
            at = (y * WIDTH + x) * 4
            points.append((bgra[at], bgra[at + 1], bgra[at + 2]))
    return tuple(points)


def robust_distance(left: tuple[tuple[int, int, int], ...],
                    right: tuple[tuple[int, int, int], ...]) -> float:
    errors = sorted(
        (lb - rb) ** 2 + (lg - rg) ** 2 + (lr - rr) ** 2
        for (lb, lg, lr), (rb, rg, rr) in zip(left, right)
    )
    keep = max(1, len(errors) * 7 // 10)
    return sum(errors[:keep]) / keep


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    targets = {
        slot: feature((TARGET_DIR / f"slot{slot}.capture.bin").read_bytes())
        for slot in TARGET_SLOTS
    }
    candidates = []
    failures = []
    for path in sorted(SAVE_DIR.glob("*.sav")):
        if path.name.startswith("HASH-5BBE776656FD02D7_"):
            continue
        try:
            capture = decompress(path, "first")
            candidates.append((path, feature(capture)))
        except Exception as exc:  # retain the exact unreadable-state count
            failures.append((path.name, type(exc).__name__))

    rows = []
    for slot, target in targets.items():
        ranked = sorted(
            ((robust_distance(target, candidate), path) for path, candidate in candidates),
            key=lambda item: item[0],
        )
        for rank, (score, path) in enumerate(ranked[:30], 1):
            rows.append({
                "target_slot": slot,
                "rank": rank,
                "score": f"{score:.3f}",
                "candidate": path.name,
                "last_write_time": path.stat().st_mtime,
                "bytes": path.stat().st_size,
            })
    with OUT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"states_scanned={len(candidates)}")
    print(f"states_unreadable={len(failures)}")
    for slot in TARGET_SLOTS:
        print(f"slot{slot}")
        for row in rows:
            if row["target_slot"] == slot and row["rank"] <= 8:
                print(f"  {row['rank']:2} score={row['score']:>10} {row['candidate']}")


if __name__ == "__main__":
    main()
