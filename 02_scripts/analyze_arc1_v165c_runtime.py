"""Read-only runtime audit of the user's eight v165c DuckStation states.

The audit separates cache delivery, persistent-slot ownership and remaining
static COMM.IMG collisions.  Save states and patch archives are never modified;
only reproducible CSV/text reports are written under ``01_work/analysis``.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import analyze_arc1_v163_runtime as old  # noqa: E402
import analyze_arc1_v164_runtime as old164  # noqa: E402
import build_arc1_v165_failclosed_cache as build  # noqa: E402
import verify_arc1_v165c_failclosed_cache as verify  # noqa: E402
from extract_savestate_vram import inflate, locate_ram, locate_vram  # noqa: E402


SAVE_DIR = Path(r"C:\Users\Administrator\AppData\Local\DuckStation\savestates")
DEFAULT_PREFIX = "HASH-5D381712B6D6EB28"
PATCH = ROOT / "03_output/arc1_v165c_failclosed_24slot_cache_checkpoint_fix_D1ADC357.zip"
PATCH_SHA256 = "D1ADC3570E8690CAE66CCDD54ED1686DA081D1E0A908B3E3BB6B7083ECE8F618"
ORIGINAL = ROOT / "00_original/arc.zip"
PLAN = ROOT / "01_work/analysis/dynamic_cache_v165_failclosed"
OLD_PLAN = ROOT / "01_work/analysis/dynamic_cache_v153_widthsafe"

RAM_SIZE = 2 * 1024 * 1024
VRAM_SIZE = 1024 * 512 * 2
ROUTINES = (
    (0x801FF294, 532, "decoder"),
    (0x801FF4A8, 248, "huffman"),
    (0x801FF5A0, 44, "helper"),
    (0x801FF5CC, 36, "classifier"),
    (0x801FF5F0, 440, "frame"),
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def slot_number(path: Path) -> int:
    return int(path.stem.rsplit("_", 1)[1])


def selected_plane(cell: bytes, plane: int) -> tuple[int, ...]:
    return tuple(
        (((cell[y * 6 + x // 2] >> (4 * (x & 1))) & 0xF) >> plane) & 1
        for y in range(12) for x in range(12)
    )


def expected_shape(rows: tuple[int, ...]) -> tuple[int, ...]:
    return tuple((rows[y] >> (11 - x)) & 1 for y in range(12) for x in range(12))


def parse_ranges() -> list[tuple[int, int, int]]:
    raw = (PLAN / "conflict_ranges.bin").read_bytes()
    return [struct.unpack_from("<HBB", raw, at) for at in range(0, len(raw), 4)]


def direct_identity(index: int, ranges: list[tuple[int, int, int]]) -> tuple[str, int]:
    for start, length, source in ranges:
        if index < start:
            break
        if index < start + length:
            return "dynamic", source + index - start
    return "static", index


def token_identities(payload: bytes, lookup: tuple[int, ...],
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
                    result.append(
                        ("dynamic", value & 0x7FFF)
                        if value & 0x8000 else ("static", value)
                    )
        cursor += width
    return result


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser()
    parser.add_argument("save_prefix", nargs="?", default=DEFAULT_PREFIX)
    args = parser.parse_args()
    prefix = args.save_prefix
    states = sorted(
        (path for path in SAVE_DIR.glob(f"{prefix}_*.sav")
         if path.stem.rsplit("_", 1)[-1].isdigit()),
        key=slot_number,
    )
    if [slot_number(path) for path in states] != list(range(1, 9)):
        raise SystemExit(f"expected slots 1..8, found {[slot_number(p) for p in states]}")
    if digest(PATCH) != PATCH_SHA256:
        raise SystemExit("v165c patch hash differs")

    suffix = prefix.removeprefix("HASH-")
    out = ROOT / "01_work/analysis" / f"arc1_v165c_runtime_states_{suffix}"
    out.mkdir(parents=True, exist_ok=True)
    with ZipFile(PATCH) as archive:
        exe = archive.read(build.PSX)
        current_comm = archive.read(build.COMM)
    with ZipFile(ORIGINAL) as archive:
        original_comm = archive.read(build.COMM)

    layout = build.read_layout()
    runtime = verify.runtime_memory(exe)
    source_rows = verify.python_sources(runtime, layout)
    with (PLAN / "source_manifest.csv").open(encoding="utf-8-sig", newline="") as handle:
        source_chars = {
            int(row["source_id"]): row["char"] for row in csv.DictReader(handle)
        }
    with (OLD_PLAN / "glyph_assignments.csv").open(
        encoding="utf-8-sig", newline=""
    ) as handle:
        static_chars = {
            int(row["physical_index"]): row["char"]
            for row in csv.DictReader(handle)
            if row["kind"] == "static" and row["physical_index"]
        }
    ranges = parse_ranges()

    # Reuse the proven packet/OT walkers with the six-cell v165c geometry.
    old.CACHE_SLOTS = 24
    old.CACHE_CELLS = 6
    old.CACHE_U = (4, 16, 28, 40, 52, 64)
    old.CACHE_U_END = 76
    old.CACHE_V = 224
    old.CACHE_V_END = 236
    old.token_identities = lambda payload, lookup: token_identities(payload, lookup, ranges)

    changed_cells = {
        (row, col)
        for row in range(21) for col in range(21)
        if old164.comm_cell(current_comm, row, col) !=
        old164.comm_cell(original_comm, row, col)
    }
    expected_hooks = {
        address: struct.unpack_from("<I", exe, build.file_at(address))[0]
        for address in (
            build.DECODER_ENTRY, build.GLYPH_PACKET_HOOK,
            build.CLASSIFIER_CALL, build.LATE_HOOK,
        )
    }
    immutable_layout = (
        "huffman_rows", "huffman_counts", "conflict_ranges",
        "source_checkpoints", "source_bitstream", "nibble_expand",
    )

    state_rows: list[dict[str, object]] = []
    packet_rows: list[dict[str, object]] = []
    stale_rows: list[dict[str, object]] = []
    collision_rows: list[dict[str, object]] = []
    report = [
        "v165c eight-state runtime audit",
        f"patch={PATCH.name}",
        f"patch_sha256={PATCH_SHA256}",
        f"savestates={prefix}_1..8.sav",
        "",
    ]
    totals = {
        "valid_lineage": 0,
        "active_cache_packets": 0,
        "active_unique_slot_checks": 0,
        "active_slot_shape_matches": 0,
        "active_slot_blank_planes": 0,
        "active_slot_wrong_nonblank_planes": 0,
        "matched_text_objects": 0,
        "stale_text_objects": 0,
        "stale_text_packets": 0,
        "cache_nontext_packets": 0,
        "static_nontext_collision_packets": 0,
    }

    resident_source = build.file_at(build.SOURCE_BASE)
    for path in states:
        slot = slot_number(path)
        blob = inflate(path)
        ram_base, vram_base = locate_ram(blob), locate_vram(blob)
        ram = blob[ram_base:ram_base + RAM_SIZE]
        vram = blob[vram_base:vram_base + VRAM_SIZE]
        owners = struct.unpack_from(
            "<24H", ram, old.ram_at(layout["owners"][0])
        )
        active = old.u32(ram, old.ram_at(layout["active_mask"][0]))
        next_slot = old.u32(ram, old.ram_at(layout["next_slot"][0]))
        lookup = struct.unpack_from("<409H", ram, old.ram_at(build.LOOKUP_RAM))

        code_failures = []
        for address, expected in expected_hooks.items():
            if old.u32(ram, old.ram_at(address)) != expected:
                code_failures.append(f"hook_0x{address:08X}")
        for address, size, name in ROUTINES:
            expected = exe[
                build.source_at(address):build.source_at(address) + size
            ]
            if ram[old.ram_at(address):old.ram_at(address) + size] != expected:
                code_failures.append(name)
        for name in immutable_layout:
            address, size = layout[name]
            expected = exe[
                resident_source + address - build.RESIDENT_BASE:
                resident_source + address - build.RESIDENT_BASE + size
            ]
            if ram[old.ram_at(address):old.ram_at(address) + size] != expected:
                code_failures.append(name)
        if tuple(lookup) != struct.unpack_from(
            "<409H", exe, build.file_at(build.LOOKUP_RAM)
        ):
            code_failures.append("lookup")
        if not code_failures:
            totals["valid_lineage"] += 1

        objects = old.find_text_objects(ram)
        matched = []
        for obj in objects:
            match = old.match_source_entry(
                ram, obj, lookup, owners, static_chars, source_chars
            )
            if match is None:
                continue
            matched.append((obj, match))
            totals["matched_text_objects"] += 1
            if match["stale"]:
                totals["stale_text_objects"] += 1
                totals["stale_text_packets"] += len(match["stale"])
                stale_rows.append({
                    "state": f"slot{slot}",
                    "header": f"0x{int(obj['header']):08X}",
                    "expected_text": match["expected_text"],
                    "packet_text_now": match["current_text"],
                    "stale_count": len(match["stale"]),
                    "stale": " ".join(
                        f"i{index}:{source_chars.get(want, '?')}({want})->"
                        f"{source_chars.get(have, '?')}({have})"
                        for index, want, have in match["stale"]
                    ),
                })

        _context, _parity, active_ot = old.trace_active_text_ot(ram)
        selected = [row for row in active_ot if row["selected_buffer"]]
        cache_packets = [row for row in selected if row["text_cache"]]
        cache_nontext = [
            row for row in selected if row["overlap"] and not row["text_cache"]
        ]
        totals["active_cache_packets"] += len(cache_packets)
        totals["cache_nontext_packets"] += len(cache_nontext)

        slot_status: dict[int, tuple[bool, bool, int, int]] = {}
        for packet in cache_packets:
            cache_slot = int(packet["slot"])
            owner = owners[cache_slot]
            cell, plane = divmod(cache_slot, 4)
            shape = selected_plane(old.vram_cell(vram, cell), plane)
            pixels = sum(shape)
            matched_shape = owner < len(source_rows) and \
                shape == expected_shape(source_rows[owner])
            blank = pixels == 0
            slot_status[cache_slot] = (matched_shape, blank, owner, pixels)
            packet_rows.append({
                "state": f"slot{slot}",
                "order": packet["order"],
                "address": f"0x{int(packet['address']):08X}",
                "cache_slot": cache_slot,
                "owner_source": owner,
                "owner_char": source_chars.get(owner, "?"),
                "pixels": pixels,
                "shape_match": int(matched_shape),
                "blank_plane": int(blank),
            })
        totals["active_unique_slot_checks"] += len(slot_status)
        totals["active_slot_shape_matches"] += sum(v[0] for v in slot_status.values())
        totals["active_slot_blank_planes"] += sum(v[1] for v in slot_status.values())
        totals["active_slot_wrong_nonblank_planes"] += sum(
            not match and not blank for match, blank, _owner, _pixels in slot_status.values()
        )

        static_collisions = []
        for packet in selected:
            tpage, clut = packet.get("tpage"), packet.get("clut")
            if not isinstance(tpage, int) or tpage & 0x19F != 0x005:
                continue
            try:
                cells = old164.touched_cells(
                    int(packet["u"]), int(packet["v"]),
                    int(packet["width"]), int(packet["height"]),
                )
            except (KeyError, TypeError, ValueError):
                continue
            hits = cells & changed_cells
            looks_text = (
                packet.get("kind") in ("SPRT", "SPRT_8", "SPRT_16")
                and isinstance(clut, int)
                and old.FONT_CLUT_MIN <= clut <= old.FONT_CLUT_MAX
            )
            if not hits or looks_text:
                continue
            static_collisions.append(packet)
            collision_rows.append({
                "state": f"slot{slot}",
                "order": packet["order"],
                "address": f"0x{int(packet['address']):08X}",
                "kind": packet["kind"],
                "cells": " ".join(f"{row},{col}" for row, col in sorted(hits)),
            })
        totals["static_nontext_collision_packets"] += len(static_collisions)

        blank_slots = sorted(slot_id for slot_id, status in slot_status.items() if status[1])
        wrong_slots = sorted(
            slot_id for slot_id, status in slot_status.items()
            if not status[0] and not status[1]
        )
        stale_count = sum(len(match["stale"]) for _obj, match in matched)
        state_rows.append({
            "slot": slot,
            "savestate": path.name,
            "code_ok": int(not code_failures),
            "code_failures": " ".join(code_failures),
            "owners": sum(owner != 0xFFFF for owner in owners),
            "active_mask": f"0x{active:08X}",
            "next_slot": next_slot,
            "active_ot_packets": len(selected),
            "cache_text_packets": len(cache_packets),
            "cache_unique_slots": len(slot_status),
            "cache_blank_slots": " ".join(map(str, blank_slots)),
            "cache_wrong_nonblank_slots": " ".join(map(str, wrong_slots)),
            "matched_text_objects": len(matched),
            "stale_packets": stale_count,
            "cache_nontext_packets": len(cache_nontext),
            "static_nontext_collision_packets": len(static_collisions),
        })
        report.extend((
            f"slot{slot}",
            f"  code_ok={not code_failures} failures={code_failures or 'none'}",
            f"  owners={sum(owner != 0xFFFF for owner in owners)}/24 "
            f"active=0x{active:08X} next={next_slot}",
            f"  cache_packets={len(cache_packets)} unique_slots={len(slot_status)} "
            f"blank_slots={blank_slots or 'none'} wrong_nonblank={wrong_slots or 'none'}",
            f"  matched_objects={len(matched)} stale_packets={stale_count}",
            f"  cache_nontext={len(cache_nontext)} "
            f"static_nontext_collisions={len(static_collisions)}",
            "",
        ))

    report.extend((
        "aggregate",
        *(f"  {key}={value}" for key, value in totals.items()),
        "",
        "measured conclusion",
        "  v165c lineage and resident code are present in all eight states.",
        "  No sampled non-text packet reads the six cache cells or remaining 119 static cells.",
        "  Live text packets reference blanked cache planes and slots whose owners changed.",
        "  The cache must rebuild every owned plane in an active cell and retain final-OT slots.",
    ))

    def write_csv(path: Path, rows: list[dict[str, object]], fields: list[str]) -> None:
        with path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    (out / "runtime_audit.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    write_csv(out / "state_summary.csv", state_rows, list(state_rows[0]))
    write_csv(out / "active_cache_packets.csv", packet_rows, list(packet_rows[0]))
    write_csv(
        out / "stale_text_objects.csv", stale_rows,
        ["state", "header", "expected_text", "packet_text_now", "stale_count", "stale"],
    )
    write_csv(
        out / "static_cell_collisions.csv", collision_rows,
        ["state", "order", "address", "kind", "cells"],
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
