"""Corrected v214 instruction-execution cases.

The first development verifier expected a 13x12 non-cache packet at A to
leave the upload at A.  That expectation was wrong: strict classification must
leave the packet untouched *and* count it as an A reader, so the upload moves
to B.  This file records and runs the corrected expectation without changing
the generated build.
"""
from __future__ import annotations

from pathlib import Path
from zipfile import ZipFile

import build_arc1_v214_marked_ab_cache_selector as v214
from verify_arc1_v214_selector_execution import run_case


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    candidates = sorted((ROOT / "03_output").glob(
        "arc1_v214_marked_ab_cache_selector_TEST_ONLY_????????.zip"
    ))
    if len(candidates) != 1:
        raise SystemExit(f"expected one v214 archive, found {candidates}")
    with ZipFile(candidates[0]) as archive:
        exe = archive.read("PSX.EXE")

    tpage31 = {"count": 1, "cmd": 0xE1, "tpage": 31}
    tpage63 = {"count": 1, "cmd": 0xE1, "tpage": 63}
    font_a = {
        "count": 4, "cmd": 0x64, "u": 4, "v": 224,
        "clut": v214.build.v171.v166.FONT_CLUT_MIN, "width": 12, "height": 12,
    }
    font_b = dict(font_a, v=128)
    font_marker = dict(font_a, v=v214.MARKER_V)
    game_a = dict(font_a, u=0, v=160, clut=0x79C0, width=128, height=96)
    game_b = dict(font_a, v=128, clut=0x0010)
    bad_size = dict(font_a, width=13)
    both = dict(font_a, u=0, v=120, clut=0x79C0, width=128, height=128)

    cases = [
        ("A canonical", [tpage31, font_a], (224, [0, 255], 480)),
        ("B canonical", [tpage63, font_b], (224, [0, 255], 480)),
        ("marker persistent", [tpage31, font_marker], (224, [0, 255], 480)),
        ("A conflict chooses B", [tpage31, font_b, game_a], (128, [0, 255, 160], 384)),
        ("B conflict chooses A", [tpage31, game_b, font_a], (224, [0, 128, 255], 480)),
        ("simultaneous fallback A", [tpage31, both, font_a], (224, [0, 120, 255], 480)),
        ("wrong size untouched and counted as A reader",
         [tpage31, bad_size], (128, [0, 224], 384)),
    ]
    for name, specs, expected in cases:
        actual = run_case(exe, specs)
        if actual != expected:
            raise SystemExit(f"{name}: expected {expected}, got {actual}")
        print(f"PASS {name}: {actual}")
    print(f"archive={candidates[0].name}")
    print("selector_instruction_execution_corrected=PASS")


if __name__ == "__main__":
    main()
