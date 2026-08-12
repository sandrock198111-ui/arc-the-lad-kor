"""Read-only runtime audit for the user's v168 DuckStation states.

The audit distinguishes cache capacity, final-OT protection, the bounded item
description guard, and every verified persistent text object.  Savestates and
patch archives are never modified; only reproducible reports are written below
``01_work/analysis``.
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

import analyze_arc1_v163_runtime as runtime  # noqa: E402
import analyze_arc1_v165c_runtime as legacy  # noqa: E402
import build_arc1_v165_failclosed_cache as old  # noqa: E402
import build_arc1_v168_item_description_slot_shift_fix as build  # noqa: E402
import verify_arc1_v165c_failclosed_cache as executor  # noqa: E402
import verify_arc1_v167_item_description_generation_guard as v167_verify  # noqa: E402
from extract_savestate_vram import inflate, locate_ram, locate_vram  # noqa: E402


PATCH = ROOT / "03_output/arc1_v168_item_description_slot_shift_fix_3B604507.zip"
PATCH_SHA256 = "3B6045078334ABCEC78D07A05F5B39C5368BB76D18A880878646279FF664A751"
SAVE_DIR = Path.home() / "AppData/Local/DuckStation/savestates"
DEFAULT_PREFIX = "HASH-124B7457BEE4A10F"
RAM_SIZE = 2 * 1024 * 1024
VRAM_SIZE = 1024 * 512 * 2
ITEM_DESCRIPTION_HEADER = build.ITEM_DESCRIPTION_HEADER


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def slot_number(path: Path) -> int:
    return int(path.stem.rsplit("_", 1)[1])


def configure_runtime() -> None:
    runtime.CACHE_SLOTS = 24
    runtime.CACHE_CELLS = 6
    runtime.CACHE_U = (4, 16, 28, 40, 52, 64)
    runtime.CACHE_U_END = 76
    runtime.CACHE_V = 224
    runtime.CACHE_V_END = 236


def metadata_mask(obj: dict[str, object]) -> int:
    mask = 0
    for glyph in obj["dynamic"]:  # type: ignore[union-attr]
        mask |= 1 << int(glyph["slot"])
    return mask


def selected_ot_mask(rows: list[dict[str, object]]) -> int:
    mask = 0
    for row in rows:
        if row["selected_buffer"] and row["text_cache"]:
            mask |= 1 << int(row["slot"])
    return mask


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser()
    parser.add_argument("save_prefix", nargs="?", default=DEFAULT_PREFIX)
    args = parser.parse_args()
    prefix = args.save_prefix

    if digest(PATCH) != PATCH_SHA256:
        raise SystemExit("v168 archive hash differs")
    states = sorted(
        (path for path in SAVE_DIR.glob(f"{prefix}_*.sav")
         if path.stem.rsplit("_", 1)[-1].isdigit()),
        key=slot_number,
    )
    slots = [slot_number(path) for path in states]
    if not states or slots != list(range(1, max(slots) + 1)):
        raise SystemExit(f"expected contiguous slots from 1, found {slots}")

    configure_runtime()
    v167_verify.build = build
    layout, blobs, routines = v167_verify.routine_layout()
    with ZipFile(PATCH) as archive:
        exe = archive.read(old.PSX)

    for name, (address, blob) in routines.items():
        if exe[old.source_at(address):old.source_at(address) + len(blob)] != blob:
            raise SystemExit(f"final v168 resident routine differs: {name}")
    expected_hooks = {
        address: struct.unpack_from("<I", exe, old.file_at(address))[0]
        for address in (
            old.DECODER_ENTRY, old.GLYPH_PACKET_HOOK,
            old.CLASSIFIER_CALL, old.LATE_HOOK,
        )
    }

    executor.plan.CHECKPOINT_GROUP = build.CHECKPOINT_GROUP
    expected_memory = executor.runtime_memory(exe)
    source_rows = executor.python_sources(expected_memory, layout)
    ranges = legacy.parse_ranges()
    with (legacy.PLAN / "source_manifest.csv").open(
        encoding="utf-8-sig", newline=""
    ) as handle:
        source_chars = {
            int(row["source_id"]): row["char"] for row in csv.DictReader(handle)
        }
    with (legacy.OLD_PLAN / "glyph_assignments.csv").open(
        encoding="utf-8-sig", newline=""
    ) as handle:
        static_chars = {
            int(row["physical_index"]): row["char"]
            for row in csv.DictReader(handle)
            if row["kind"] == "static" and row["physical_index"]
        }
    runtime.token_identities = lambda payload, lookup: legacy.token_identities(
        payload, lookup, ranges
    )

    immutable_layout = (
        "huffman_rows", "huffman_counts", "conflict_ranges",
        "source_checkpoints", "source_bitstream", "nibble_expand",
    )
    state_rows: list[dict[str, object]] = []
    object_rows: list[dict[str, object]] = []
    stale_rows: list[dict[str, object]] = []
    packet_rows: list[dict[str, object]] = []
    active_counts: list[int] = []
    valid_lineage = 0
    shape_checks = 0
    shape_matches = 0
    stale_by_header: dict[int, int] = {}

    for path in states:
        slot = slot_number(path)
        inflated = inflate(path)
        ram_base, vram_base = locate_ram(inflated), locate_vram(inflated)
        ram = inflated[ram_base:ram_base + RAM_SIZE]
        vram = inflated[vram_base:vram_base + VRAM_SIZE]
        if len(ram) != RAM_SIZE or len(vram) != VRAM_SIZE:
            raise SystemExit(f"incomplete RAM/VRAM in {path.name}")

        owners = struct.unpack_from(
            "<24H", ram, runtime.ram_at(layout["owners"][0])
        )
        active = runtime.u32(ram, runtime.ram_at(layout["active_mask"][0])) & 0xFFFFFF
        next_slot = runtime.u32(ram, runtime.ram_at(layout["next_slot"][0]))
        lookup = struct.unpack_from(
            "<409H", ram, runtime.ram_at(old.LOOKUP_RAM)
        )

        failures: list[str] = []
        for address, expected in expected_hooks.items():
            if runtime.u32(ram, runtime.ram_at(address)) != expected:
                failures.append(f"hook_0x{address:08X}")
        for name, (address, expected) in routines.items():
            got = ram[runtime.ram_at(address):runtime.ram_at(address) + len(expected)]
            if got != expected:
                failures.append(name)
        for name in immutable_layout:
            address, _size = layout[name]
            expected = blobs[name]
            got = ram[runtime.ram_at(address):runtime.ram_at(address) + len(expected)]
            if got != expected:
                failures.append(name)
        expected_lookup = struct.unpack_from(
            "<409H", exe, old.file_at(old.LOOKUP_RAM)
        )
        if tuple(lookup) != expected_lookup:
            failures.append("lookup")
        valid_lineage += int(not failures)

        for cache_slot, owner in enumerate(owners):
            if owner == 0xFFFF:
                continue
            shape_checks += 1
            got = legacy.selected_plane(
                runtime.vram_cell(vram, cache_slot // 4), cache_slot % 4
            )
            expected = legacy.expected_shape(source_rows[owner])
            shape_matches += int(got == expected)

        objects = runtime.find_text_objects(ram)
        item_object = next(
            (obj for obj in objects if int(obj["header"]) == ITEM_DESCRIPTION_HEADER),
            None,
        )
        item_mask = 0 if item_object is None else metadata_mask(item_object)
        matched_objects = 0
        stale_objects = 0
        stale_packets = 0
        for obj in objects:
            match = runtime.match_source_entry(
                ram, obj, lookup, owners, static_chars, source_chars
            )
            if match is None:
                continue
            matched_objects += 1
            stale = match["stale"]
            stale_n = len(stale)
            stale_objects += int(bool(stale))
            stale_packets += stale_n
            header = int(obj["header"])
            object_row = {
                "state": f"slot{slot}",
                "header": f"0x{header:08X}",
                "item_description": int(header == ITEM_DESCRIPTION_HEADER),
                "count": obj["count"],
                "dynamic_mask": f"0x{metadata_mask(obj):06X}",
                "expected_text": match["expected_text"],
                "current_owner_text": match["current_text"],
                "stale_count": stale_n,
                "stale": " ".join(
                    f"i{index}:{source_chars.get(want, '?')}({want})->"
                    f"{source_chars.get(have, '?')}({have})"
                    for index, want, have in stale
                ),
            }
            object_rows.append(object_row)
            if stale:
                stale_rows.append(object_row)
                stale_by_header[header] = stale_by_header.get(header, 0) + 1

        _context, _parity, active_ot = runtime.trace_active_text_ot(ram)
        selected = [row for row in active_ot if row["selected_buffer"]]
        ot_mask = selected_ot_mask(selected)
        for packet in selected:
            if not packet["text_cache"]:
                continue
            cache_slot = int(packet["slot"])
            packet_rows.append({
                "state": f"slot{slot}",
                "order": packet["order"],
                "address": f"0x{int(packet['address']):08X}",
                "cache_slot": cache_slot,
                "owner_source": owners[cache_slot],
                "owner_char": source_chars.get(owners[cache_slot], "?"),
            })

        expected_protection = ot_mask | item_mask
        active_counts.append(active.bit_count())
        state_rows.append({
            "slot": slot,
            "savestate": path.name,
            "lineage_ok": int(not failures),
            "lineage_failures": " ".join(failures),
            "owners_used": sum(owner != 0xFFFF for owner in owners),
            "active_slots": active.bit_count(),
            "active_mask": f"0x{active:06X}",
            "next_slot": next_slot,
            "selected_ot_mask": f"0x{ot_mask:06X}",
            "item_description_mask": f"0x{item_mask:06X}",
            "expected_protection_union": f"0x{expected_protection:06X}",
            "active_missing_current_union": f"0x{expected_protection & ~active:06X}",
            "matched_text_objects": matched_objects,
            "stale_text_objects": stale_objects,
            "stale_text_packets": stale_packets,
        })

    out = ROOT / "01_work/analysis" / (
        "arc1_v168_runtime_states_" + prefix.removeprefix("HASH-")
    )
    out.mkdir(parents=True, exist_ok=True)

    def write_csv(name: str, rows: list[dict[str, object]], fields: list[str]) -> None:
        with (out / name).open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    write_csv("state_summary.csv", state_rows, list(state_rows[0]))
    write_csv(
        "text_objects.csv", object_rows,
        list(object_rows[0]) if object_rows else [
            "state", "header", "item_description", "count", "dynamic_mask",
            "expected_text", "current_owner_text", "stale_count", "stale",
        ],
    )
    write_csv(
        "stale_text_objects.csv", stale_rows,
        list(object_rows[0]) if object_rows else [
            "state", "header", "item_description", "count", "dynamic_mask",
            "expected_text", "current_owner_text", "stale_count", "stale",
        ],
    )
    write_csv(
        "active_cache_packets.csv", packet_rows,
        list(packet_rows[0]) if packet_rows else [
            "state", "order", "address", "cache_slot", "owner_source", "owner_char",
        ],
    )

    lines = [
        "v168 runtime cache/object audit",
        f"patch={PATCH.name}",
        f"sha256={PATCH_SHA256}",
        f"savestates={prefix}_1..{slots[-1]}.sav",
        "",
        f"v168_lineage={valid_lineage}/{len(states)}",
        f"owner_shape_matches={shape_matches}/{shape_checks}",
        "active_slots_by_state=" + ",".join(map(str, active_counts)),
        f"active_slots_max={max(active_counts)}",
        f"captured_full_24_slot_masks={sum(n == 24 for n in active_counts)}",
        f"matched_text_objects={len(object_rows)}",
        f"stale_text_objects={len(stale_rows)}",
        "stale_headers=" + (
            ",".join(
                f"0x{header:08X}:{count}state"
                for header, count in sorted(stale_by_header.items())
            ) or "none"
        ),
        "",
        "state detail",
    ]
    for row in state_rows:
        lines.append(
            "  slot{slot}: active={active_slots} OT={selected_ot_mask} "
            "item={item_description_mask} missing={active_missing_current_union} "
            "stale_objects={stale_text_objects} stale_packets={stale_text_packets}"
            .format(**row)
        )
    lines.extend((
        "",
        "measured boundary",
        "  lineage, current owner glyph shapes, active pressure, final OT,",
        "  item-description metadata and all structurally matched text objects were audited.",
        "  A stale object outside 0x801F031C means the v168 one-object guard is too narrow;",
        "  it does not mean the 24-slot cache is full.",
    ))
    (out / "runtime_audit.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
