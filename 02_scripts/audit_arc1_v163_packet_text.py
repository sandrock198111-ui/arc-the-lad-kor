"""Decode the live text-object packet identities in the supplied v163 states.

This is read-only.  It distinguishes a wrong text stream from a wrong bitmap: if the
packet identities already spell the visible nonsense, the fault is upstream of the
renderer; if they spell the intended Korean but the capture differs, the fault is in
atlas/CLUT rendering.
"""
from __future__ import annotations

import csv
import pickle
import struct
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from analyze_arc1_v163_runtime import (  # noqa: E402
    FONT_CLUT_MAX, FONT_CLUT_MIN, OWNERS, PLAN, RAM_DUMP_OFFSET, RAM_SIZE,
    find_text_objects, ram_at, trace_active_text_ot,
)
from plan_bulk_insertion import CACHE, CELL, IPR, PLANES  # noqa: E402

STATE_DIR = ROOT / "01_work/analysis/arc1_v163_runtime_states"
BUILD = ROOT / "03_output/arc1_v163_text_clut_classifier_773E3B82.zip"
OUT = STATE_DIR / "packet_text_audit.csv"
ROW_BYTES = 896


def bitmap(font: bytes, index: int) -> tuple[int, ...] | None:
    row, rem = divmod(index, IPR)
    col, plane = divmod(rem, PLANES)
    if row * CELL + CELL > 512 or col >= 21:
        return None
    result = []
    for dy in range(CELL):
        for dx in range(CELL):
            px = col * CELL + dx
            value = font[(row * CELL + dy) * ROW_BYTES + px // 2]
            nibble = value & 0x0F if px % 2 == 0 else value >> 4
            result.append((nibble >> plane) & 1)
    return tuple(result)


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    with zipfile.ZipFile(BUILD) as archive:
        font = archive.read("COMM.IMG")
    known_shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    assignments = list(csv.DictReader(
        (PLAN / "glyph_assignments.csv").open(encoding="utf-8-sig", newline="")
    ))
    static_chars = {
        int(row["physical_index"]): row["char"]
        for row in assignments if row.get("kind") == "static" and row.get("physical_index")
    }
    source_chars = {
        int(row["source_id"]): row["char"]
        for row in assignments if row.get("source_id")
    }
    # Bitmap identity is an independent decoder for static Hangul.  It catches a
    # table that says one character while the pixels at that physical index say another.
    bitmap_chars = {}
    for index in range(IPR * (512 // CELL)):
        bits = bitmap(font, index)
        if bits in known_shapes:
            bitmap_chars[index] = known_shapes[bits]

    rows = []
    for state_path in sorted(STATE_DIR.glob("slot*.state.bin"),
                             key=lambda p: int(p.name.split(".", 1)[0][4:])):
        state = state_path.read_bytes()
        ram = state[RAM_DUMP_OFFSET:RAM_DUMP_OFFSET + RAM_SIZE]
        owners = struct.unpack_from("<20H", ram, ram_at(OWNERS))
        for object_index, obj in enumerate(find_text_objects(ram)):
            declared = []
            pixels = []
            identities = []
            for glyph in obj["glyphs"]:
                slot = glyph["slot"]
                if slot is not None:
                    source_id = owners[int(slot)]
                    char = source_chars.get(source_id, f"<D:{source_id}>")
                    declared.append(char)
                    pixels.append(char)
                    identities.append(f"D{source_id}")
                else:
                    index = int(glyph["physical"])
                    declared.append(static_chars.get(index, f"<S:{index}>"))
                    pixels.append(bitmap_chars.get(index, f"<S:{index}>"))
                    identities.append(f"S{index}")
            rows.append({
                "state": state_path.stem,
                "object": object_index,
                "header": f"0x{int(obj['header']):08X}",
                "count": obj["count"],
                "source_pointer": f"0x{int(obj['source_pointer']):08X}",
                "assignment_text": "".join(declared),
                "bitmap_text": "".join(pixels),
                "assignment_equals_bitmap": int(declared == pixels),
                "identities": " ".join(identities),
            })

        # Decode every font SPRT in the current ordering table, including dialogue
        # systems whose object header does not use the common 68-byte layout.
        _, _, active_ot = trace_active_text_ot(ram)
        visible = []
        for packet in active_ot:
            if packet["kind"] != "SPRT":
                continue
            clut = packet["clut"]
            tpage = packet["tpage"]
            if not isinstance(clut, int) or not FONT_CLUT_MIN <= clut <= FONT_CLUT_MAX:
                continue
            address = ram_at(int(packet["address"]))
            x, y = struct.unpack_from("<hh", ram, address + 8)
            u, v = int(packet["u"]), int(packet["v"])
            char = None
            if tpage == 5:
                index = (v // CELL) * IPR + (u // CELL) * PLANES + ((clut - FONT_CLUT_MIN) & 3)
                char = bitmap_chars.get(index) or static_chars.get(index) or f"<S:{index}>"
            elif tpage == 31 and v == 224 and u in (4, 16, 28, 40, 52):
                cache_slot = (u - 4) // 12 * PLANES + ((clut - FONT_CLUT_MIN) & 3)
                source_id = owners[cache_slot]
                char = source_chars.get(source_id, f"<D:{source_id}>")
            if char is not None:
                visible.append((y, x, char, tpage, u, v, clut))

        # Group adjacent glyphs by screen baseline.  This is diagnostic text, not a
        # source reconstruction: spaces have no packet and are represented by gaps.
        line_groups: list[list[tuple[int, int, str, int, int, int, int]]] = []
        for item in sorted(visible):
            group = next((g for g in line_groups if abs(g[0][0] - item[0]) <= 1), None)
            (group if group is not None else line_groups.append([]) or line_groups[-1]).append(item)
        for line_number, group in enumerate(line_groups):
            group.sort(key=lambda item: item[1])
            text = ""
            previous_x = None
            for y, x, char, *_ in group:
                if previous_x is not None and x - previous_x > 13:
                    text += " "
                text += char
                previous_x = x
            rows.append({
                "state": state_path.stem,
                "object": f"OT{line_number}",
                "header": "",
                "count": len(group),
                "source_pointer": "",
                "assignment_text": text,
                "bitmap_text": text,
                "assignment_equals_bitmap": 1,
                "identities": " ".join(
                    f"xy{x},{y}:T{tpage}:U{u}:V{v}:C{clut:04X}:{char}"
                    for y, x, char, tpage, u, v, clut in group
                ),
            })

    with OUT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    for row in rows:
        print(
            f"{row['state']} obj{row['object']} count={row['count']} "
            f"map/pixels={row['assignment_equals_bitmap']}\n"
            f"  map    {row['assignment_text']}\n"
            f"  pixels {row['bitmap_text']}"
        )
    print(f"report={OUT}")


if __name__ == "__main__":
    main()
