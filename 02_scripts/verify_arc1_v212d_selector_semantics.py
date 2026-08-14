"""Independent semantic checks for the v212d selector and patched frame.

This verifier does not launch DuckStation and writes no game artifact.  It
loads the exact ZIP bytes, validates the selector graph and executes a compact
instruction-level model against synthetic OT chains for every required branch.
"""
from __future__ import annotations

import struct
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v212_ab_cache_selector as v212  # noqa: E402
import build_arc1_v212d_selector_exact_bounds as v212d  # noqa: E402


ZIP = ROOT / "03_output/arc1_v212d_ab_cache_selector_exact_bounds_TEST_ONLY_CA6CDDFD.zip"
EXPECTED_SHA = "CA6CDDFD2E15D8BC718A227E6793BCC47DD21CDF48C429AE8480D2032B0D77D3"


def run_case(name: str, packets: list[dict[str, int]], expected_v: int,
             expected_packet_v: list[int]) -> None:
    selected, packet_v = v212.selector_model(packets)
    if selected != expected_v or packet_v != expected_packet_v:
        raise SystemExit(
            f"{name}: selected={selected}, packet_v={packet_v}, "
            f"expected={expected_v}/{expected_packet_v}"
        )
    print(f"PASS {name:<28} selected V={selected} packets={packet_v}")


def main() -> None:
    if v212.digest(ZIP.read_bytes()) != EXPECTED_SHA:
        raise SystemExit("v212d ZIP SHA256 differs")
    with zipfile.ZipFile(ZIP) as archive:
        exe = archive.read("PSX.EXE")

    entry = v212d.exact_entry()
    at = v212.old.file_at(v212.SELECTOR_ENTRY)
    if exe[at:at + len(entry)] != entry:
        raise SystemExit("ZIP selector entry differs from v212d builder")

    tpage31 = {"cmd": 0xE1, "tpage": 31}
    tpage27 = {"cmd": 0xE1, "tpage": 27}
    font_a = {"cmd": 0x64, "u": 4, "v": 224, "w": 12, "h": 12,
              "clut": v212.v171.v166.FONT_CLUT_MIN}
    font_b = dict(font_a, v=128)
    font_a_2 = dict(font_a, u=76, clut=v212.v171.v166.FONT_CLUT_MIN + 3)

    game_a_small = {"cmd": 0x64, "u": 4, "v": 224, "w": 12, "h": 12,
                    "clut": 0x0010}
    game_a_large = {"cmd": 0x64, "u": 0, "v": 160, "w": 128, "h": 96,
                    "clut": 0x79C0}
    game_b_only = {"cmd": 0x64, "u": 4, "v": 128, "w": 12, "h": 12,
                   "clut": 0x0010}
    game_left = {"cmd": 0x64, "u": 0, "v": 224, "w": 4, "h": 12,
                 "clut": 0x0010}
    game_above = {"cmd": 0x64, "u": 4, "v": 212, "w": 12, "h": 12,
                  "clut": 0x0010}

    run_case("no packets", [], 224, [])
    run_case("canonical font A", [tpage31, font_a], 224, [224])
    run_case("persistent font B", [tpage31, font_b], 224, [224])
    run_case("two persistent fonts", [tpage31, font_b, font_a_2], 224, [224, 224])
    run_case("small measured A conflict", [tpage31, font_b, game_a_small], 128, [224, 224])
    run_case("large measured A conflict", [tpage31, font_b, game_a_large], 128, [224, 160])
    run_case("B-only game reader", [tpage31, game_b_only, font_a], 224, [128, 224])
    run_case("touching left edge", [tpage31, game_left, font_a], 224, [224, 224])
    run_case("touching top edge", [tpage31, game_above, font_a], 224, [212, 224])
    run_case("wrong tpage ignored", [tpage27, game_a_small, font_a], 224, [224, 224])

    # Verify exact low-level constants from the packaged code.
    words = struct.unpack(f"<{len(entry) // 4}I", entry)
    if words[5] != v212.old.i_type(0x0B, v212.T0, v212.T2, 1):
        raise SystemExit("link-zero instruction differs")
    if words[6] != v212.old.r_type(v212.ZERO, v212.T0, v212.T1, 21, 0x02):
        raise SystemExit("2 MiB link-bound instruction differs")
    if words[30] != v212.old.j(v212.SELECTOR_CHECK) or words[31] != 0:
        raise SystemExit("cross-cave continuation differs")
    print("PASS packaged selector constants")


if __name__ == "__main__":
    main()
