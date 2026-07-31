#!/usr/bin/env python3
"""Extract text-sprite packets and matching RAM strings from DuckStation states.

This is a read-only helper for the Arc the Lad UI renderer.  It records the
12x12 glyph packets already queued by the game, which makes fixed-layout UI
failures reproducible without relying on screenshots alone.
"""

from __future__ import annotations

import argparse
import csv
import json
import struct
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VENDORED_PACKAGES = ROOT / "06_tools" / "python_packages"
if str(VENDORED_PACKAGES) not in sys.path:
    sys.path.insert(0, str(VENDORED_PACKAGES))
sys.path.insert(0, str(ROOT / "02_scripts"))

from map_savestate_script import load_ram  # noqa: E402
from extract_story_corpus import build_glyph_map  # noqa: E402


GLYPHS_PER_ROW = 84
STATE_RAM_OFFSET = 0x1262


@dataclass(frozen=True)
class GlyphPacket:
    state: str
    packet_offset: str
    x: int
    y: int
    u: int
    v: int
    clut: int
    physical_index: int
    source_code_hex: str
    char: str


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def physical_index(code: bytes) -> int:
    if len(code) == 1:
        if not 0x01 <= code[0] < 0xDD:
            raise ValueError(f"unsupported one-byte glyph code: {code.hex(' ')}")
        return code[0] - 1
    if len(code) != 2 or code[0] < 0xDD:
        raise ValueError(f"unsupported glyph code: {code.hex(' ')}")
    return (code[0] - 0xDD) * 255 + code[1] + 0xDB


def source_code(index: int) -> bytes:
    if index <= 0xDB:
        return bytes((index + 1,))
    number = index - 0xDB
    return bytes((0xDD + number // 255, number % 255))


def character_maps() -> tuple[dict[int, str], dict[int, bytes]]:
    legacy_chars, _ambiguity, _nearest, _rows = build_glyph_map()
    chars: dict[int, str] = dict(legacy_chars)
    codes: dict[int, bytes] = {}
    for map_name in ("korean_charmap.csv", "korean_charmap_extended.csv"):
        for row in read_csv(ROOT / "05_docs" / map_name):
            code = bytes.fromhex(row["code_hex"])
            try:
                index = physical_index(code)
            except ValueError:
                continue
            chars[index] = row["char"]
            codes[index] = code

    for row in read_csv(ROOT / "05_docs" / "ui_glyph_store_v42_map.csv"):
        index = int(row["physical_index"])
        chars[index] = row["char"]
        codes[index] = bytes.fromhex(row["virtual_code_hex"])
    return chars, codes


def signed16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def packets(state: str, ram: bytes, chars: dict[int, str]) -> list[GlyphPacket]:
    result: list[GlyphPacket] = []
    for offset in range(0, len(ram) - 15, 4):
        w0, w1, w2, w3 = struct.unpack_from("<IIII", ram, offset)
        if (w0 >> 24) not in (0x64, 0x65) or w3 != 0x000C000C:
            continue
        x = signed16(w1 & 0xFFFF)
        y = signed16(w1 >> 16)
        if not -64 <= x <= 384 or not -64 <= y <= 304:
            continue
        u = w2 & 0xFF
        v = (w2 >> 8) & 0xFF
        clut = (w2 >> 16) & 0xFFFF
        index = (v // 12) * GLYPHS_PER_ROW + (u // 12) * 4 + (clut & 3)
        result.append(
            GlyphPacket(
                state=state,
                packet_offset=f"0x{offset:X}",
                x=x,
                y=y,
                u=u,
                v=v,
                clut=clut,
                physical_index=index,
                source_code_hex=source_code(index).hex(" ").upper(),
                char=chars.get(index, ""),
            )
        )
    return result


def visual_rows(rows: list[GlyphPacket]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, int], list[GlyphPacket]] = defaultdict(list)
    for row in rows:
        grouped[(row.state, row.y)].append(row)

    output: list[dict[str, object]] = []
    for (state, y), glyphs in sorted(grouped.items()):
        # The command buffer can retain duplicate copies of a glyph packet.
        by_position: dict[tuple[int, int], GlyphPacket] = {}
        for glyph in glyphs:
            by_position[(glyph.x, glyph.physical_index)] = glyph
        ordered = sorted(by_position.values(), key=lambda item: (item.x, item.physical_index))
        text = "".join(item.char or f"<{item.physical_index}>" for item in ordered)
        output.append(
            {
                "state": state,
                "y": y,
                "x_min": min(item.x for item in ordered),
                "x_max": max(item.x for item in ordered),
                "glyph_count": len(ordered),
                "text": text,
                "physical_indices": " ".join(str(item.physical_index) for item in ordered),
                "source_codes_hex": " | ".join(item.source_code_hex for item in ordered),
            }
        )
    return output


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Read DuckStation save states and audit 12x12 UI glyph packets."
    )
    parser.add_argument("states", type=Path, nargs="+")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "01_work" / "analysis" / "ui_runtime_v43",
    )
    parser.add_argument("--state-ram-offset", type=lambda value: int(value, 0), default=STATE_RAM_OFFSET)
    args = parser.parse_args()

    chars, _codes = character_maps()
    all_packets: list[GlyphPacket] = []
    for path in args.states:
        ram = load_ram(path, args.state_ram_offset)
        all_packets.extend(packets(path.stem, ram, chars))

    packet_rows = [asdict(item) for item in all_packets]
    rows = visual_rows(all_packets)
    write_csv(args.output / "glyph_packets.csv", packet_rows)
    write_csv(args.output / "visual_rows.csv", rows)
    (args.output / "summary.json").write_text(
        json.dumps(
            {
                "states": [str(path) for path in args.states],
                "packet_count": len(all_packets),
                "visual_row_count": len(rows),
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {args.output}")
    print(f"packets={len(all_packets)} visual_rows={len(rows)}")


if __name__ == "__main__":
    main()
