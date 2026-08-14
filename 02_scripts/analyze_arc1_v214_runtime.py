#!/usr/bin/env python3
"""Read-only audit of v214 runtime cache ownership and glyph delivery.

The audit compares four independent layers in DuckStation save states:

* the dynamic source requested by each live text object;
* the source ID currently recorded in each of the 28 cache-owner slots;
* the 12x12 glyph bitmap actually present at destination A and B in VRAM;
* the cache packets reachable from the active GPU ordering table.

No save state, patch archive, or disc image is modified.
"""
from __future__ import annotations

import argparse
import csv
import struct
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import analyze_arc1_v163_runtime as legacy_runtime  # noqa: E402
import analyze_arc1_v165c_runtime as glyph_tools  # noqa: E402
import build_arc1_v190_dynamic_owner_repair as v190  # noqa: E402
import build_arc1_v213_strict_ab_cache_selector as selector  # noqa: E402
import plan_arc1_v190_dynamic_owner_repair as plan  # noqa: E402
from extract_savestate_vram import load  # noqa: E402


SAVE_DIR = Path(r"C:\Users\Administrator\AppData\Local\DuckStation\savestates")
DEFAULT_PREFIX = "HASH-DA2823B0BBB822CA"
RAM_SIZE = 2 * 1024 * 1024
VRAM_W = 1024
CACHE_N = v190.CACHE_N
CACHE_CELLS = v190.CACHE_CELLS
CACHE_U = tuple(selector.CACHE_U0 + 12 * cell for cell in range(CACHE_CELLS))
CACHE_X = 961
CACHE_A_Y, CACHE_A_V = selector.CACHE_A_Y, selector.CACHE_A_V
CACHE_B_Y, CACHE_B_V = selector.CACHE_B_Y, selector.CACHE_B_V
FONT_CLUT_MIN = selector.v171.v166.FONT_CLUT_MIN
DYNAMIC_TAG = selector.v171.plan.DYNAMIC_TAG
SPECIAL_STATIC_TAG = selector.v171.plan.SPECIAL_STATIC_TAG
SPECIAL_STATIC_VALUE = selector.v171.plan.SPECIAL_STATIC_VALUE


def ram_at(address: int) -> int:
    return address & 0x1FFFFF


def slot_number(path: Path) -> int:
    return int(path.stem.rsplit("_", 1)[1])


def cache_cell(vram: bytes, cell: int, y: int) -> bytes:
    x = CACHE_X + cell * 3
    return b"".join(
        vram[((y + row) * VRAM_W + x) * 2:
             ((y + row) * VRAM_W + x) * 2 + 6]
        for row in range(12)
    )


def configure_legacy(selected_y: int, selected_v: int) -> None:
    legacy_runtime.CACHE_SLOTS = CACHE_N
    legacy_runtime.CACHE_CELLS = CACHE_CELLS
    legacy_runtime.CACHE_X = CACHE_X
    legacy_runtime.CACHE_Y = selected_y
    legacy_runtime.CACHE_U = CACHE_U
    legacy_runtime.CACHE_V = selected_v
    legacy_runtime.CACHE_U_END = CACHE_U[0] + CACHE_CELLS * 12
    legacy_runtime.CACHE_V_END = selected_v + 12
    legacy_runtime.FONT_CLUT_MIN = FONT_CLUT_MIN
    legacy_runtime.FONT_CLUT_MAX = FONT_CLUT_MIN + 15


def source_chars() -> dict[int, str]:
    with plan.SOURCE_MANIFEST.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != plan.SOURCE_N:
        raise SystemExit(f"source manifest count differs: {len(rows)}")
    return {int(row["source_id"]): row["char"] for row in rows}


def runtime_sources(ram: bytes, layout: dict[str, tuple[int, int]]) -> list[tuple[int, ...]]:
    rows_at, rows_n = layout["huffman_rows"]
    stream_at, stream_n = layout["source_bitstream"]
    counts_at, counts_n = layout["huffman_counts"]
    rows = struct.unpack_from(f"<{rows_n // 2}H", ram, ram_at(rows_at))
    stream = ram[ram_at(stream_at):ram_at(stream_at) + stream_n]
    counts = ram[ram_at(counts_at):ram_at(counts_at) + counts_n]
    checkpoint_at = ram_at(selector.v171.HUFFMAN_CHECKPOINTS_RAM)
    checkpoint_n = (plan.SOURCE_N + plan.CHECKPOINT_GROUP - 1) // plan.CHECKPOINT_GROUP
    checkpoints = struct.unpack_from(f"<{checkpoint_n}H", ram, checkpoint_at)
    return [
        plan.old_plan.decode_huffman_source(
            source, tuple(rows), counts, tuple(checkpoints), stream
        )
        for source in range(plan.SOURCE_N)
    ]


def direct_ranges(ram: bytes) -> list[tuple[int, int, int]]:
    result: list[tuple[int, int, int]] = []
    cumulative = 0
    at = ram_at(selector.v171.RANGE_RAM)
    for ordinal in range(selector.v171.RANGE_N):
        value = struct.unpack_from("<H", ram, at + ordinal * 2)[0]
        start = value & 0x07FF
        encoded = value >> 11
        length = encoded + 1 if encoded != 31 else 39
        result.append((start, length, cumulative))
        cumulative += length
    if cumulative != selector.v171.plan.NEW_DIRECT_N:
        raise SystemExit(f"direct range source count differs: {cumulative}")
    return result


def direct_identity(index: int, ranges: list[tuple[int, int, int]]) -> tuple[str, int]:
    for start, length, source in ranges:
        if index < start:
            break
        if index < start + length:
            return "dynamic", source + index - start
    return "static", index


def packed_lookup(ram: bytes) -> list[int]:
    at = ram_at(selector.v171.PACKED_LOOKUP_RAM)
    blob = ram[at:at + 568]
    return selector.v171.plan.unpack_fixed(blob, plan.LOOKUP_N, plan.LOOKUP_BITS)


def token_identities(payload: bytes, lookup: list[int],
                     ranges: list[tuple[int, int, int]]) -> list[tuple[str, int]]:
    result: list[tuple[str, int]] = []
    cursor = 0
    while cursor < len(payload):
        lead = payload[cursor]
        width = 1 if lead < 0xDD else 2
        if cursor + width > len(payload):
            break
        if width == 1 and lead:
            result.append(direct_identity(lead - 1, ranges))
        elif width == 2:
            trail = payload[cursor + 1]
            if 0xDD <= lead <= 0xE8 and 1 <= trail <= 0xFE:
                index = (lead - 0xDD) * 255 + trail + 0xDB
                result.append(direct_identity(index, ranges))
            elif lead in (0xE9, 0xEA) and 1 <= trail <= 0xFE:
                virtual = (lead - 0xE9) * 254 + trail - 1
                if virtual < len(lookup):
                    value = lookup[virtual]
                    if value == SPECIAL_STATIC_TAG:
                        result.append(("static", SPECIAL_STATIC_VALUE))
                    elif value >= DYNAMIC_TAG:
                        result.append(("dynamic", value - DYNAMIC_TAG))
                    else:
                        result.append(("static", value))
        cursor += width
    return result


def identity_text(identity: tuple[str, int], chars: dict[int, str]) -> str:
    kind, value = identity
    if kind == "dynamic":
        return chars.get(value, f"<d:{value}>")
    return f"<s:{value}>"


def match_object(ram: bytes, obj: dict[str, object], owners: tuple[int, ...],
                 lookup: list[int], ranges: list[tuple[int, int, int]],
                 chars: dict[int, str]) -> dict[str, object] | None:
    pointer = int(obj["source_pointer"])
    start = ram_at(pointer)
    if pointer & 0xFFE00000 not in (0x80000000, 0xA0000000) or start >= RAM_SIZE:
        return None
    metadata: list[tuple[str, int]] = []
    for glyph in obj["glyphs"]:  # type: ignore[union-attr]
        slot = glyph["slot"]
        if slot is None:
            metadata.append(("static", int(glyph["physical"])))
        else:
            owner = owners[int(slot)]
            metadata.append(("dynamic", owner))

    best: dict[str, object] | None = None
    cursor = start
    limit = min(RAM_SIZE, start + 0x2000)
    candidates = 0
    while cursor < limit and candidates < 512:
        end = ram.find(b"\0", cursor, limit)
        if end < 0:
            break
        payload = ram[cursor:end]
        cursor = end + 1
        if not payload:
            continue
        candidates += 1
        expected = token_identities(payload, lookup, ranges)
        if len(expected) != len(metadata):
            continue
        exact = structural = 0
        stale: list[tuple[int, int, int]] = []
        for index, (want, have) in enumerate(zip(expected, metadata)):
            if want == have:
                exact += 1
                structural += 1
            elif want[0] == have[0] == "dynamic":
                structural += 1
                stale.append((index, want[1], have[1]))
        score = (structural, exact, -len(stale), -abs((end - len(payload)) - start))
        if best is None or score > best["score"]:
            best = {
                "score": score,
                "offset": 0x80000000 + end - len(payload),
                "expected": expected,
                "metadata": metadata,
                "stale": stale,
                "expected_text": "".join(identity_text(item, chars) for item in expected),
                "current_text": "".join(identity_text(item, chars) for item in metadata),
            }
    if best is None or best["score"][0] * 4 < len(metadata) * 3:
        return None
    return best


def write_csv(path: Path, rows: list[dict[str, object]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser()
    parser.add_argument("prefix", nargs="?", default=DEFAULT_PREFIX)
    args = parser.parse_args()
    states = sorted(
        (
            path for path in SAVE_DIR.glob(f"{args.prefix}_*.sav")
            if path.stem.rsplit("_", 1)[-1].isdigit()
        ),
        key=slot_number,
    )
    if not states:
        raise SystemExit("no matching save states")

    layout, _blobs, _code = v190.resident_layout()
    chars = source_chars()
    out = ROOT / "01_work/analysis" / f"arc1_v214_runtime_{args.prefix.removeprefix('HASH-')}"
    out.mkdir(parents=True, exist_ok=True)
    summaries: list[dict[str, object]] = []
    shape_rows: list[dict[str, object]] = []
    object_rows: list[dict[str, object]] = []
    packet_rows: list[dict[str, object]] = []

    for state in states:
        slot_no = slot_number(state)
        ram, vram = load(state)
        owners_at = ram_at(layout["owners"][0])
        owners = struct.unpack_from(f"<{CACHE_N}H", ram, owners_at)
        active = struct.unpack_from("<I", ram, ram_at(layout["active_mask"][0]))[0]
        next_slot = struct.unpack_from("<I", ram, ram_at(layout["next_slot"][0]))[0]
        rect = struct.unpack_from("<4H", ram, ram_at(layout["upload_rect"][0]))
        selected_y, selected_v = (
            (CACHE_A_Y, CACHE_A_V) if rect[1] == CACHE_A_Y
            else (CACHE_B_Y, CACHE_B_V) if rect[1] == CACHE_B_Y
            else (rect[1], -1)
        )
        if selected_v < 0:
            raise SystemExit(f"{state.name}: unexpected upload Y {rect[1]}")
        configure_legacy(selected_y, selected_v)
        sources = runtime_sources(ram, layout)
        ranges = direct_ranges(ram)
        lookup = packed_lookup(ram)

        owner_shape_selected = owner_shape_a = owner_shape_b = 0
        owner_used = 0
        for cache_slot, owner in enumerate(owners):
            if owner == 0xFFFF:
                continue
            owner_used += 1
            expected = glyph_tools.expected_shape(sources[owner])
            plane = cache_slot & 3
            cell = cache_slot // 4
            got_a = glyph_tools.selected_plane(cache_cell(vram, cell, CACHE_A_Y), plane)
            got_b = glyph_tools.selected_plane(cache_cell(vram, cell, CACHE_B_Y), plane)
            match_a, match_b = got_a == expected, got_b == expected
            match_selected = match_a if selected_v == CACHE_A_V else match_b
            owner_shape_a += int(match_a)
            owner_shape_b += int(match_b)
            owner_shape_selected += int(match_selected)
            shape_rows.append({
                "state": slot_no, "cache_slot": cache_slot,
                "source": owner, "char": chars.get(owner, "?"),
                "active": int(bool(active & (1 << cache_slot))),
                "selected": "A" if selected_v == CACHE_A_V else "B",
                "match_A": int(match_a), "match_B": int(match_b),
                "match_selected": int(match_selected),
            })

        objects = legacy_runtime.find_text_objects(ram)
        stale_packets = 0
        matched_objects = 0
        for obj in objects:
            match = match_object(ram, obj, owners, lookup, ranges, chars)
            if match is None:
                continue
            matched_objects += 1
            stale = match["stale"]
            stale_packets += len(stale)
            object_rows.append({
                "state": slot_no,
                "header": f"0x{int(obj['header']):08X}",
                "count": obj["count"],
                "source": f"0x{int(match['offset']):08X}",
                "expected": match["expected_text"],
                "current": match["current_text"],
                "stale_count": len(stale),
                "stale": " ".join(
                    f"i{index}:{chars.get(want, '?')}({want})->{chars.get(have, '?')}({have})"
                    for index, want, have in stale
                ),
            })

        _context, _parity, packets = legacy_runtime.trace_active_text_ot(ram)
        active_cache_slots: set[int] = set()
        for packet in packets:
            if not packet["text_cache"]:
                continue
            cache_slot = int(packet["slot"])
            active_cache_slots.add(cache_slot)
            address = int(packet["address"])
            at = ram_at(address)
            packet_rows.append({
                "state": slot_no, "order": packet["order"],
                "address": f"0x{address:08X}",
                "x": struct.unpack_from("<h", ram, at + 8)[0],
                "y": struct.unpack_from("<h", ram, at + 10)[0],
                "u": packet["u"], "v": packet["v"],
                "cache_slot": cache_slot, "owner": owners[cache_slot],
                "char": chars.get(owners[cache_slot], "?"),
            })
        ot_mask = sum(1 << cache_slot for cache_slot in active_cache_slots)
        summaries.append({
            "state": slot_no, "savestate": state.name,
            "destination": "A" if selected_v == CACHE_A_V else "B",
            "upload_rect": f"{rect[0]},{rect[1]},{rect[2]},{rect[3]}",
            "owners_used": owner_used, "active_count": active.bit_count(),
            "active_mask": f"0x{active:08X}", "next_slot": next_slot,
            "owner_shape_selected": f"{owner_shape_selected}/{owner_used}",
            "owner_shape_A": f"{owner_shape_a}/{owner_used}",
            "owner_shape_B": f"{owner_shape_b}/{owner_used}",
            "active_ot_cache_count": len([p for p in packet_rows if p["state"] == slot_no]),
            "active_ot_mask": f"0x{ot_mask:08X}",
            "active_ot_missing": f"0x{ot_mask & ~active:08X}",
            "matched_objects": matched_objects,
            "stale_packets": stale_packets,
        })

    write_csv(out / "state_summary.csv", summaries, list(summaries[0]))
    write_csv(out / "owner_shapes.csv", shape_rows, list(shape_rows[0]))
    write_csv(
        out / "text_objects.csv", object_rows,
        list(object_rows[0]) if object_rows else
        ["state", "header", "count", "source", "expected", "current", "stale_count", "stale"],
    )
    write_csv(
        out / "active_cache_packets.csv", packet_rows,
        list(packet_rows[0]) if packet_rows else
        ["state", "order", "address", "x", "y", "u", "v", "cache_slot", "owner", "char"],
    )
    lines = ["v214 runtime ownership audit", ""]
    for row in summaries:
        lines.append(
            "slot{state}: dest={destination} shapes={owner_shape_selected} "
            "active={active_count} OT={active_ot_cache_count} missing={active_ot_missing} "
            "matched_objects={matched_objects} stale_packets={stale_packets}".format(**row)
        )
    report = "\n".join(lines) + "\n"
    (out / "runtime_audit.txt").write_text(report, encoding="utf-8")
    print(report, end="")
    print(f"output={out}")


if __name__ == "__main__":
    main()
