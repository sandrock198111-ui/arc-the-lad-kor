#!/usr/bin/env python3
"""Plan v190 without borrowing any COMM.IMG cell.

Four glyphs still referenced by current text owners have no live destination:
``R``, ``페``, ``큐`` and ``…``.  They are appended to the proven v171 Huffman
source library and reached through the formerly-invalid EA 9C..EA 9F lookup
slots.  The original 409 lookup entries and all 462 existing sources remain
bit-for-bit meaningful.

This file is analysis only.  It creates reproducible cache artifacts and an
owner-scoped repair manifest; it never writes a patch archive.
"""
from __future__ import annotations

import csv
import hashlib
import struct
import sys
import zipfile
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import audit_arc1_v189_text_glyph_ownership as owner_audit  # noqa: E402
import build_arc1_v171_ui_asset_recovery as v171  # noqa: E402
import build_arc1_v186_runtime_text_choice_fixes as v186  # noqa: E402
import plan_arc1_v171_ui_asset_recovery as old_plan  # noqa: E402
import plan_dynamic_cache_v165_failclosed as huffman  # noqa: E402
from plan_bulk_insertion import bitmap, tokens  # noqa: E402


BASE = owner_audit.BASE
BASE_SHA256 = owner_audit.BASE_SHA256
ORIGINAL = owner_audit.ORIGINAL
CONTROL = owner_audit.CONTROL
OUT = ROOT / "01_work/analysis/arc1_v190_dynamic_owner_repair"

SOURCE_MANIFEST = OUT / "source_manifest.csv"
HUFFMAN_ROWS = OUT / "huffman_rows.bin"
HUFFMAN_COUNTS = OUT / "huffman_counts.bin"
SOURCE_CHECKPOINTS = OUT / "source_checkpoints.bin"
SOURCE_BITSTREAM = OUT / "source_bitstream.bin"
LOOKUP_TABLE = OUT / "lookup_11bit_413.bin"
OWNER_REPAIRS = OUT / "owner_repairs.csv"
REPORT = OUT / "plan_report.txt"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
OLD_SOURCE_N = 462
SOURCE_N = 466
OLD_LOOKUP_N = 409
LOOKUP_N = 413
LOOKUP_BITS = 11
CHECKPOINT_GROUP = 16
ENCODED_ROWS = 11
DYNAMIC_TAG = old_plan.DYNAMIC_TAG
SPECIAL_STATIC_TAG = old_plan.SPECIAL_STATIC_TAG

# These four slots were outside the v189 decoder's 0..408 lookup domain.  No
# existing text or glyph loses a meaning when the decoder bound becomes 413.
TARGETS = (
    (462, "R", bytes.fromhex("EA 9C"), 732, "untouched original font"),
    (463, "큐", bytes.fromhex("EA 9D"), 4414, "v151 strip D"),
    (464, "페", bytes.fromhex("EA 9E"), 5299, "v151 strip B"),
    (465, "…", bytes.fromhex("EA 9F"), 992, "v151 glyph atlas"),
)
TARGET_CODE = {char: code for _source, char, code, _index, _where in TARGETS}
EXPECTED_ROWS = {
    "R": (0x000, 0x3E0, 0x210, 0x210, 0x210, 0x3E0,
          0x210, 0x210, 0x208, 0x208, 0x000, 0x000),
    "페": (0x7D4, 0x014, 0x294, 0x294, 0x2F4, 0x294,
          0x294, 0x294, 0x294, 0x7D4, 0x014, 0x000),
    "큐": (0x3FC, 0x004, 0x004, 0x3FC, 0x004, 0x008,
          0x000, 0x7FE, 0x108, 0x108, 0x108, 0x000),
    "…": (0x000, 0x000, 0x000, 0x222, 0x000, 0x000,
          0x000, 0x000, 0x000, 0x000, 0x000, 0x000),
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def decode_old_sources() -> tuple[list[tuple[int, ...]], list[dict[str, str]]]:
    rows_blob = old_plan.HUFFMAN_ROWS.read_bytes()
    rows = tuple(struct.unpack(f"<{len(rows_blob) // 2}H", rows_blob))
    counts = old_plan.HUFFMAN_COUNTS.read_bytes()
    checkpoints_blob = old_plan.SOURCE_CHECKPOINTS.read_bytes()
    checkpoints = tuple(struct.unpack(f"<{len(checkpoints_blob) // 2}H", checkpoints_blob))
    stream = old_plan.SOURCE_BITSTREAM.read_bytes()
    manifest = read_csv(old_plan.SOURCE_MANIFEST)
    if len(manifest) != OLD_SOURCE_N:
        raise SystemExit("v171 source manifest is not exactly 462 entries")
    decoded = [
        old_plan.decode_huffman_source(source, rows, counts, checkpoints, stream)
        for source in range(OLD_SOURCE_N)
    ]
    return decoded, manifest


def extracted_target_rows(
    original_exe: bytes,
    original_font: bytes,
    control_exe: bytes,
    control_font: bytes,
) -> list[tuple[int, ...]]:
    result: list[tuple[int, ...]] = []
    for _source, char, _code, index, location in TARGETS:
        if char == "R":
            bits = bitmap(original_exe, original_font, index)
        else:
            bits = bitmap(control_exe, control_font, index)
        if bits is None:
            raise SystemExit(f"target bitmap is unreachable: {char} index {index}")
        rows = old_plan.bitmap_rows(bits)
        if rows != EXPECTED_ROWS[char]:
            raise SystemExit(f"target bitmap readback differs: {char} from {location}")
        if rows[-1] != 0:
            raise SystemExit(f"target final row is not blank: {char}")
        result.append(rows)
    return result


def encode_sources(
    source_rows: list[tuple[int, ...]],
) -> tuple[bytes, bytes, bytes, bytes]:
    all_rows = [row for glyph in source_rows for row in glyph[:ENCODED_ROWS]]
    lengths = huffman.huffman_lengths(Counter(all_rows))
    canonical_rows, counts, codes = huffman.canonical_codes(lengths)
    writer = huffman.BitWriter()
    checkpoints: list[int] = []
    for source, glyph in enumerate(source_rows):
        if source % CHECKPOINT_GROUP == 0:
            checkpoints.append(writer.bit_length)
        for row in glyph[:ENCODED_ROWS]:
            code, width = codes[row]
            writer.write(code, width)
    row_blob = struct.pack(f"<{len(canonical_rows)}H", *canonical_rows)
    checkpoint_blob = struct.pack(f"<{len(checkpoints)}H", *checkpoints)
    stream = bytes(writer.data)
    if len(counts) > 13:
        raise SystemExit(f"Huffman count table grew beyond 13 bytes: {len(counts)}")
    if len(checkpoint_blob) > v171.PARSER_HELPER - v171.HUFFMAN_CHECKPOINTS_RAM:
        raise SystemExit("Huffman checkpoints overlap the parser helper")
    for source, expected in enumerate(source_rows):
        got = old_plan.decode_huffman_source(
            source, tuple(canonical_rows), counts, tuple(checkpoints), stream
        )
        if got != expected:
            raise SystemExit(f"Huffman readback differs at source {source}")
    return row_blob, counts, checkpoint_blob, stream


def repair_manifest(members: dict[str, bytes]) -> tuple[list[dict[str, str]], dict[str, bytes]]:
    # Recreate the ownership report against the exact v189 base so stale CSV
    # output can never silently become a build input.
    owner_audit.main()
    rows = read_csv(owner_audit.OUT / "repairs.csv")
    if len(rows) != 83:
        raise SystemExit(f"owner repair count is {len(rows)}, not 83")
    patched = dict(members)
    result: list[dict[str, str]] = []
    seen: set[tuple[str, int]] = set()
    for row in rows:
        member = PSX if row["owner_type"] == "ui" else row["owner"].split()[0]
        offset = int(row["file_offset"], 0)
        old = bytes.fromhex(row["old_hex"])
        if row["status"] == "repair":
            new = bytes.fromhex(row["new_hex"])
        else:
            new = TARGET_CODE.get(row["intended_char"], b"")
        if not new or len(new) != len(old):
            raise SystemExit(f"owner repair has no width-safe replacement: {row}")
        key = (member, offset)
        if key in seen:
            raise SystemExit(f"duplicate owner repair: {member} 0x{offset:X}")
        seen.add(key)
        data = bytearray(patched[member])
        if bytes(data[offset:offset + len(old)]) != old:
            raise SystemExit(f"owner guard differs: {member} 0x{offset:X}")
        data[offset:offset + len(old)] = new
        patched[member] = bytes(data)
        result.append({
            "member": member,
            "offset": f"0x{offset:X}",
            "owner_type": row["owner_type"],
            "owner": row["owner"],
            "char": row["intended_char"],
            "old_hex": old.hex(" ").upper(),
            "new_hex": new.hex(" ").upper(),
            "byte_changed": str(old != new),
        })
    return result, patched


def source_for_token(
    token: bytes,
    lookup: list[int],
    direct: dict[int, int],
) -> int | None:
    if len(token) == 2 and token[0] in (0xE9, 0xEA):
        slot = (token[0] - 0xE9) * 254 + token[1] - 1
        if not 0 <= slot < len(lookup):
            return None
        value = lookup[slot]
        return value - DYNAMIC_TAG if DYNAMIC_TAG <= value < SPECIAL_STATIC_TAG else None
    index = owner_audit.physical_index(token)
    return direct.get(index) if index is not None else None


def main() -> None:
    if digest(BASE) != BASE_SHA256:
        raise SystemExit("v189 base hash differs")
    with zipfile.ZipFile(BASE) as archive:
        members = {info.filename: archive.read(info.filename) for info in archive.infolist()}
    with zipfile.ZipFile(ORIGINAL) as archive:
        original_exe = archive.read(PSX)
        original_font = archive.read(COMM)
    with zipfile.ZipFile(CONTROL) as archive:
        control_exe = archive.read(PSX)
        control_font = archive.read(COMM)

    old_sources, old_manifest = decode_old_sources()
    target_rows = extracted_target_rows(
        original_exe, original_font, control_exe, control_font
    )
    sources = old_sources + target_rows
    if len(sources) != SOURCE_N or any(row[-1] for row in sources):
        raise SystemExit("final source count or omitted-row invariant differs")
    row_blob, counts, checkpoints, stream = encode_sources(sources)

    file_at = v171.old.file_at
    current_lookup_blob = members[PSX][
        file_at(v171.PACKED_LOOKUP_RAM):
        file_at(v171.PACKED_LOOKUP_RAM) + v171.PACKED_LOOKUP_BYTES
    ]
    current_lookup = old_plan.unpack_fixed(current_lookup_blob, OLD_LOOKUP_N, LOOKUP_BITS)
    lookup = current_lookup + [DYNAMIC_TAG + source for source in range(462, 466)]
    lookup_blob = old_plan.pack_fixed(lookup, LOOKUP_BITS)
    if len(lookup) != LOOKUP_N or len(lookup_blob) != 568:
        raise SystemExit("413-entry lookup does not occupy exactly 568 bytes")
    if old_plan.unpack_fixed(lookup_blob, LOOKUP_N, LOOKUP_BITS) != lookup:
        raise SystemExit("413-entry lookup roundtrip differs")
    if lookup[:OLD_LOOKUP_N] != current_lookup:
        raise SystemExit("one of the original 409 lookup entries changed")

    repairs, patched = repair_manifest(members)

    # Geometry is compared against v189 before/after at the same 357 bounded
    # bodies.  Glyph address changes must never create or move E5/E6 controls.
    choice_checked = 0
    for name, bodies in v186.choice_bodies().items():
        if name not in members:
            continue
        for offset, raw in bodies:
            before = members[name][offset:offset + len(raw)]
            after = patched[name][offset:offset + len(raw)]
            if v186.structural.markers(before) != v186.structural.markers(after):
                raise SystemExit(f"choice geometry changed: {name} 0x{offset:X}")
            choice_checked += 1
    if choice_checked != 357:
        raise SystemExit(f"choice body audit count is {choice_checked}, not 357")

    manifest = list(old_manifest)
    for source, char, code, index, location in TARGETS:
        manifest.append({
            "source_id": str(source),
            "char": char,
            "kind": "v190_missing_owner_glyph",
            "old_physical_index": str(index),
            "old_source_id": "",
            "code_hex": code.hex(" ").upper(),
            "provenance": location,
        })
    for row in manifest[:OLD_SOURCE_N]:
        row.setdefault("code_hex", "")
        row.setdefault("provenance", "v171 preserved source")

    direct = {
        int(row["old_physical_index"]): int(row["source_id"])
        for row in old_manifest if row["old_physical_index"]
    }
    working_sets: list[tuple[int, str]] = []
    units = (
        list(old_plan.body_units(patched, old_plan.source_ranges()))
        + list(old_plan.active_slot_units(patched, old_plan.source_ranges()))
        + list(old_plan.exe_units(patched))
    )
    for label, payload in units:
        active = {
            source for token in tokens(payload)
            if (source := source_for_token(token, lookup, direct)) is not None
        }
        if active:
            working_sets.append((len(active), label))
    working_sets.sort(reverse=True)
    maximum_working_set = working_sets[0][0] if working_sets else 0
    if maximum_working_set > v171.CACHE_N:
        raise SystemExit(
            f"bounded working set {maximum_working_set} exceeds {v171.CACHE_N}"
        )

    OUT.mkdir(parents=True, exist_ok=True)
    fields = [
        "source_id", "char", "kind", "old_physical_index", "old_source_id",
        "code_hex", "provenance",
    ]
    with SOURCE_MANIFEST.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(manifest)
    repair_fields = [
        "member", "offset", "owner_type", "owner", "char", "old_hex",
        "new_hex", "byte_changed",
    ]
    with OWNER_REPAIRS.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=repair_fields)
        writer.writeheader()
        writer.writerows(repairs)
    HUFFMAN_ROWS.write_bytes(row_blob)
    HUFFMAN_COUNTS.write_bytes(counts)
    SOURCE_CHECKPOINTS.write_bytes(checkpoints)
    SOURCE_BITSTREAM.write_bytes(stream)
    LOOKUP_TABLE.write_bytes(lookup_blob)

    character_counts = Counter(row["char"] for row in repairs)
    report = [
        "v190 dynamic-only owner repair plan",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        "COMM_IMG_changes=0 by design",
        f"old_sources={OLD_SOURCE_N}",
        f"new_sources={SOURCE_N}",
        "new_source_codes=" + " ".join(
            f"{char}:{code.hex(' ').upper()}" for _s, char, code, _i, _p in TARGETS
        ),
        f"lookup_entries={LOOKUP_N}",
        f"lookup_bytes={len(lookup_blob)}",
        "old_lookup_entries_preserved=409/409 PASS",
        f"huffman_row_symbols={len(row_blob) // 2}",
        f"huffman_rows_bytes={len(row_blob)}",
        f"huffman_counts_bytes={len(counts)}",
        f"huffman_checkpoint_bytes={len(checkpoints)}",
        f"huffman_bitstream_bytes={len(stream)}",
        f"huffman_readback={SOURCE_N}/{SOURCE_N} PASS",
        f"owner_repairs={len(repairs)}",
        f"owner_actual_byte_replacements={sum(r['byte_changed'] == 'True' for r in repairs)}",
        "owner_character_counts=" + repr(dict(character_counts)),
        f"choice_bodies_checked={choice_checked}",
        "choice_E5_E6_geometry=unchanged PASS",
        f"bounded_max_simultaneous_dynamic={maximum_working_set}",
        f"cache_slots={v171.CACHE_N}",
        "top_bounded_working_sets=" + " | ".join(
            f"{count}:{label}" for count, label in working_sets[:10]
        ),
        "analysis_only=PASS",
        "patch_built=NO",
    ]
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
