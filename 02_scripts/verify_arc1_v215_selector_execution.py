#!/usr/bin/env python3
"""Execute v215 selector MIPS with the real variable-SPRT packet layout."""
from __future__ import annotations

import struct
from pathlib import Path
from zipfile import ZipFile

import build_arc1_v215_correct_packet_layout_selector as v215
from verify_arc1_v214_selector_execution import (
    CONTEXT, PACKET0, Machine, put,
)


ROOT = Path(__file__).resolve().parents[1]


def packet(link: int, count: int, cmd: int, *, tpage: int = 0,
           u: int = 0, v: int = 0, clut: int = 0,
           width: int = 0, height: int = 0) -> bytearray:
    data = bytearray(20)
    struct.pack_into("<I", data, 0, ((count & 0xFF) << 24) | (link & 0xFFFFFF))
    struct.pack_into("<I", data, 4, ((cmd & 0xFF) << 24) | (tpage & 0xFFFF))
    data[12], data[13] = u & 0xFF, v & 0xFF
    struct.pack_into("<H", data, 14, clut & 0xFFFF)
    struct.pack_into("<H", data, 16, width & 0xFFFF)
    struct.pack_into("<H", data, 18, height & 0xFFFF)
    return data


def run_case(exe: bytes, specs: list[dict[str, int]]) -> tuple[int, list[int], int]:
    memory: dict[int, int] = {}
    addresses = [PACKET0 + i * 0x100 for i in range(len(specs))]
    put(memory, CONTEXT, struct.pack("<I", addresses[0] & 0xFFFFFF))
    for index, spec in enumerate(specs):
        link = addresses[index + 1] & 0xFFFFFF if index + 1 < len(specs) else 0
        put(memory, addresses[index], packet(link, **spec))
    machine = Machine(exe, memory)
    machine.run()
    vs = [machine.load(address + 13, 1) for address in addresses]
    rect = v215.parent.build.v190.resident_layout()[0]["upload_rect"][0]
    return machine.r[v215.parent.build.A1], vs, machine.load(rect + 2, 2)


def main() -> None:
    archives = sorted((ROOT / "03_output").glob(
        "arc1_v215_correct_packet_layout_selector_TEST_ONLY_????????.zip"
    ))
    if len(archives) != 1:
        raise SystemExit(f"expected one v215 archive, found {archives}")
    with ZipFile(archives[0]) as archive:
        exe = archive.read("PSX.EXE")

    build = v215.parent.build
    tpage = {"count": 1, "cmd": 0xE1, "tpage": 31}
    font_a = {
        "count": 4, "cmd": 0x65, "u": 4, "v": 224,
        "clut": build.v171.v166.FONT_CLUT_MIN, "width": 12, "height": 12,
    }
    font_b = dict(font_a, v=128)
    marker = dict(font_a, v=v215.parent.MARKER_V)
    game_a = dict(font_a, u=0, v=160, clut=0x79C0, width=128, height=96)
    game_b = dict(font_a, v=128, clut=0x0010)
    wrong_width = dict(font_a, width=13)
    wrong_height = dict(font_a, height=13)
    both = dict(font_a, u=0, v=120, clut=0x79C0, width=128, height=128)
    cases = [
        ("real 12x12 A", [tpage, font_a], (224, [0, 255], 480)),
        ("real 12x12 B", [tpage, font_b], (224, [0, 255], 480)),
        ("persistent marker", [tpage, marker], (224, [0, 255], 480)),
        ("A conflict chooses B", [tpage, font_a, game_a], (128, [0, 255, 160], 384)),
        ("B conflict chooses A", [tpage, game_b, font_a], (224, [0, 128, 255], 480)),
        ("simultaneous fallback A", [tpage, both, font_a], (224, [0, 120, 255], 480)),
        ("wrong width unmarked", [tpage, wrong_width], (128, [0, 224], 384)),
        ("wrong height unmarked", [tpage, wrong_height], (128, [0, 224], 384)),
    ]
    for name, specs, expected in cases:
        actual = run_case(exe, specs)
        if actual != expected:
            raise SystemExit(f"{name}: expected {expected}, got {actual}")
        print(f"PASS {name}: {actual}")
    print(f"archive={archives[0].name}")
    print("real_variable_SPRT_layout=PASS")


if __name__ == "__main__":
    main()
