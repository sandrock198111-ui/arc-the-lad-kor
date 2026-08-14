"""Read-only audit for a transient V=255 dynamic-cache packet marker.

The v214 design marks only strictly identified cache SPRTs before the frame
routine, then rewrites them to real V=224/128 before DrawOT.  This audit proves
whether any existing active OT packet in the available save-state corpus would
already satisfy the frame routine's marker signature.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))

from extract_savestate_vram import load  # noqa: E402
from analyze_arc1_v163_runtime import trace_active_text_ot  # noqa: E402
import build_arc1_v171_ui_asset_recovery as v171  # noqa: E402


STATES = Path(r"C:\Users\Administrator\AppData\Local\DuckStation\savestates")
OUT_DIR = ROOT / "01_work/analysis/arc1_cache_marker_v255"
CSV_OUT = OUT_DIR / "marker_candidates.csv"
REPORT = OUT_DIR / "report.txt"

MARKER_V = 255
CACHE_U = tuple(v171.CACHE_U + 12 * cell for cell in range(v171.CACHE_CELLS))
FONT_MIN = v171.v166.FONT_CLUT_MIN


def main() -> None:
    files = sorted(STATES.glob("*.sav"))
    if not files:
        raise SystemExit("no DuckStation save states found")
    rows: list[dict[str, object]] = []
    failures: list[str] = []
    packets = 0
    sprts = 0
    loose_a = 0
    loose_a_not_12 = 0
    for index, path in enumerate(files, 1):
        try:
            ram, _vram = load(path)
            _context, _parity, active = trace_active_text_ot(ram)
        except Exception as exc:  # fail closed but finish the corpus report
            failures.append(f"{path.name}: {type(exc).__name__}: {exc}")
            continue
        packets += len(active)
        for packet in active:
            if packet["kind"] != "SPRT" or packet["dma_words"] != 4:
                continue
            sprts += 1
            u = int(packet["u"])
            v = int(packet["v"])
            clut = int(packet["clut"])
            signature = u in CACHE_U and FONT_MIN <= clut < FONT_MIN + 16
            if v == 224 and signature:
                loose_a += 1
                if int(packet["width"]) != 12 or int(packet["height"]) != 12:
                    loose_a_not_12 += 1
            if v != MARKER_V or not signature:
                continue
            rows.append({
                "state": path.name,
                "address": f"0x{int(packet['address']):08X}",
                "tpage": packet["tpage"],
                "u": u,
                "v": v,
                "width": packet["width"],
                "height": packet["height"],
                "clut": f"0x{clut:04X}",
            })
        if index % 50 == 0:
            print(f"scanned {index}/{len(files)}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fields = ["state", "address", "tpage", "u", "v", "width", "height", "clut"]
    with CSV_OUT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    lines = [
        f"savestates_total={len(files)}",
        f"savestates_decoded={len(files) - len(failures)}",
        f"savestates_failed={len(failures)}",
        f"active_packets={packets}",
        f"active_variable_sprts={sprts}",
        f"existing_marker_signature_V255={len(rows)}",
        f"existing_loose_V224_cache_signature={loose_a}",
        f"loose_V224_non12x12={loose_a_not_12}",
        *[f"failure={item}" for item in failures],
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(CSV_OUT)


if __name__ == "__main__":
    main()
