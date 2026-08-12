"""Prove and plan the v168 E1-control / Hangul-code collision fix.

This audit is intentionally read-only.  It replays the exact width-preserving
text rewrite used by v159 from the frozen v151 archive, then compares the result
with v168.  That replay gives provenance for every byte pair: a pair is eligible
for remapping only when v159 produced it from a glyph whose bitmap names a
Hangul syllable.  Existing E1..E8 commands are therefore never selected merely
because their bytes resemble one of the colliding glyph codes.

For each colliding Hangul the audit first reuses an existing E9/EA alias that
already resolves to the same glyph.  If none exists, it allocates an E9/EA slot
whose byte pair occurs nowhere in any v168 archive member.  Repointing such a
slot cannot alter an existing string, including text outside the bounded script
inventory.
"""
from __future__ import annotations

import csv
import hashlib
import pickle
import struct
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from audit_dynamic_cache_requirements import (  # noqa: E402
    active_slots,
    bitmap,
    glyph_index,
    read_lut,
    source_ranges,
)
from plan_bulk_insertion import (  # noqa: E402
    CACHE,
    SLOT_BASE,
    SLOT_SIZE,
    tokens,
)
from build_arc1_v161_bounded_exe_text import (  # noqa: E402
    pointer_records,
    string_span,
    target,
)


V151 = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
V151_SHA256 = "A4358FEE5FEA4964C9DD376B630894EB5EC133EFEEDD9E5E85BBC5FDD8CA1A46"
V168 = ROOT / "03_output/arc1_v168_item_description_slot_shift_fix_3B604507.zip"
V168_SHA256 = "3B6045078334ABCEC78D07A05F5B39C5368BB76D18A880878646279FF664A751"
ORIGINAL = ROOT / "00_original/arc.zip"
ORIGINAL_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"

ASSIGNMENTS = (
    ROOT / "01_work/analysis/dynamic_cache_v153_widthsafe/glyph_assignments.csv"
)
SOURCE_MANIFEST = ROOT / "01_work/analysis/dynamic_cache_v165_failclosed/source_manifest.csv"
PROTECTED_RELOCATIONS = (
    ROOT
    / "01_work/analysis/dynamic_cache_v153_widthsafe/protected_virtual_relocations.csv"
)

OUT = ROOT / "01_work/analysis/arc1_v168_control_glyph_collisions"
REPORT = OUT / "audit_report.txt"
OCCURRENCES = OUT / "collision_occurrences.csv"
ALIAS_PLAN = OUT / "safe_alias_plan.csv"
SLOT_INVENTORY = OUT / "e9_ea_slot_inventory.csv"
CONTROL_RESTORES = OUT / "native_e1_control_restores.csv"

PSX, COMM = "PSX.EXE", "COMM.IMG"
LOOKUP_RAM = 0x801A7520
RAM_TO_FILE = 0x8011A800
LOOKUP_N = 409
EXE_TEXT_START, EXE_TEXT_END = 0x78000, 0x83000
CONTROL_LEADS = frozenset(range(0xE1, 0xE9))


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def load_archive(path: Path, expected_sha256: str) -> tuple[list[str], dict[str, bytes]]:
    raw = path.read_bytes()
    actual = digest(raw)
    if actual != expected_sha256:
        raise SystemExit(f"archive hash differs: {path.name} {actual}")
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        return names, {name: archive.read(name) for name in names}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def virtual_code(slot: int) -> bytes:
    if not 0 <= slot < LOOKUP_N:
        raise ValueError(slot)
    return bytes((0xE9 + slot // 254, slot % 254 + 1))


def virtual_slot(code: bytes) -> int | None:
    if len(code) != 2 or code[0] not in (0xE9, 0xEA) or not 1 <= code[1] <= 0xFE:
        return None
    slot = (code[0] - 0xE9) * 254 + code[1] - 1
    return slot if 0 <= slot < LOOKUP_N else None


def token_offsets(payload: bytes):
    cursor = 0
    for token in tokens(payload):
        yield cursor, token
        cursor += len(token)
    if cursor != len(payload):
        raise SystemExit("token walker did not consume the payload")


def count_pair(data: bytes, pair: bytes) -> int:
    count = start = 0
    while True:
        at = data.find(pair, start)
        if at < 0:
            return count
        count += 1
        start = at + 1


def main() -> None:
    v151_names, v151 = load_archive(V151, V151_SHA256)
    v168_names, v168 = load_archive(V168, V168_SHA256)
    original_names, original = load_archive(ORIGINAL, ORIGINAL_SHA256)
    if v151_names != v168_names:
        raise SystemExit("v151/v168 archive member order differs")
    if not set(v168_names) <= set(original_names):
        raise SystemExit("one v168 patch member is absent from the untouched archive")

    assignments = read_csv(ASSIGNMENTS)
    source_rows = read_csv(SOURCE_MANIFEST)
    relocation_rows = read_csv(PROTECTED_RELOCATIONS)
    ranges = source_ranges()
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())

    old_exe, old_font = v151[PSX], v151[COMM]
    old_lut = read_lut(old_exe)
    if len(old_lut) < LOOKUP_N:
        raise SystemExit("v151 lookup is shorter than the runtime namespace")
    lookup_at = LOOKUP_RAM - RAM_TO_FILE
    current_lut = struct.unpack_from(f"<{LOOKUP_N}H", v168[PSX], lookup_at)

    code_by_width: dict[tuple[str, int], bytes] = {}
    index_char: dict[int, str] = {}
    risky_code_char: dict[bytes, str] = {}
    risky_rows: list[dict[str, str]] = []
    for row in assignments:
        char = row["char"]
        if row["code_1byte"]:
            code_by_width[(char, 1)] = bytes.fromhex(row["code_1byte"])
        if row["code_2byte"]:
            code = bytes.fromhex(row["code_2byte"])
            code_by_width[(char, 2)] = code
            if code[0] in CONTROL_LEADS:
                if code in risky_code_char and risky_code_char[code] != char:
                    raise SystemExit(f"colliding assignment code {code.hex()}")
                risky_code_char[code] = char
                risky_rows.append(row)
        if row["physical_index"]:
            index_char[int(row["physical_index"])] = char

    source_char = {int(row["source_id"]): row["char"] for row in source_rows}
    source_ids_by_char: dict[str, list[int]] = defaultdict(list)
    for source_id, char in source_char.items():
        source_ids_by_char[char].append(source_id)

    # Replay the exact v159 text rewrite.  The mutable copy is also a strong
    # lineage check: all DAT members and the EXE text pool must become v168.
    simulated = {name: bytearray(data) for name, data in v151.items()}
    traced: dict[tuple[str, int], dict[str, object]] = {}
    touched: dict[str, set[int]] = defaultdict(set)

    def rewrite_region(name: str, offset: int, size: int, label: str) -> None:
        data = simulated[name]
        before = bytes(data[offset:offset + size])
        out = bytearray()
        for relative, token in token_offsets(before):
            index = glyph_index(token, old_lut)
            bits = bitmap(old_exe, old_font, index) if index is not None else None
            char = shapes.get(bits) if bits else None
            code = code_by_width.get((char, len(token)), token)
            if len(code) != len(token):
                raise SystemExit(f"width changed while replaying {label}")
            absolute = offset + relative
            if code in risky_code_char:
                key = (name, absolute)
                record = {
                    "member": name,
                    "offset": absolute,
                    "label": label,
                    "char": char,
                    "old_code": token.hex(" ").upper(),
                    "risky_code": code.hex(" ").upper(),
                    "old_lead_is_control": int(bool(token and token[0] in CONTROL_LEADS)),
                }
                previous = traced.get(key)
                if previous and (
                    previous["char"] != record["char"]
                    or previous["risky_code"] != record["risky_code"]
                ):
                    raise SystemExit(f"overlap changed glyph provenance at {name}:0x{absolute:X}")
                traced[key] = record
            out += code
        if len(out) != size:
            raise SystemExit(f"replay length differs for {label}")
        data[offset:offset + size] = out
        touched[name].update(range(offset, offset + size))

    by_file: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for name, offset, size in ranges:
        by_file[name].append((offset, size))
    assigned = active_slots(v151, ranges)
    for name, member_ranges in by_file.items():
        if name not in simulated:
            continue
        for offset, size in member_ranges:
            rewrite_region(name, offset, size, f"body:{name}:0x{offset:X}")
        for slot in assigned.get(name, ()):
            at = SLOT_BASE + slot * SLOT_SIZE
            block = bytes(simulated[name][at:at + SLOT_SIZE])
            end = block.find(b"\0")
            if end <= 0:
                raise SystemExit(f"invalid active slot {name}:{slot}")
            rewrite_region(name, at, end, f"slot:{name}:{slot}")

    exe_spans: dict[tuple[int, int], list[str]] = defaultdict(list)
    for pointer, label in sorted(pointer_records().items()):
        span = string_span(old_exe, target(old_exe, pointer))
        exe_spans[span].append(label)
    for (start, end), labels in sorted(exe_spans.items()):
        rewrite_region(PSX, start, end - start, f"exe:{labels[0]}:0x{start:X}")

    # Translation lineage must be exact.  Later cache builds changed only EXE
    # code/data and COMM.IMG; every other member must equal the replayed v159 bytes.
    unexpected_members = [
        name
        for name in v151_names
        if name not in (PSX, COMM) and bytes(simulated[name]) != v168[name]
    ]
    if unexpected_members:
        raise SystemExit(
            "v168 translation members differ from the v159 replay: "
            + ", ".join(unexpected_members[:12])
        )
    if bytes(simulated[PSX][EXE_TEXT_START:EXE_TEXT_END]) != v168[PSX][EXE_TEXT_START:EXE_TEXT_END]:
        raise SystemExit("v168 EXE text pool differs from the v159 replay")

    for (name, offset), record in traced.items():
        code = bytes.fromhex(str(record["risky_code"]))
        if v168[name][offset:offset + 2] != code:
            raise SystemExit(f"traced bytes differ in v168 at {name}:0x{offset:X}")

    occurrence_counts = Counter(str(record["char"]) for record in traced.values())
    traced_chars = set(occurrence_counts)
    assigned_risky_chars = {row["char"] for row in risky_rows}
    if traced_chars != assigned_risky_chars:
        missing = sorted(assigned_risky_chars - traced_chars)
        extra = sorted(traced_chars - assigned_risky_chars)
        raise SystemExit(f"risky assignment coverage differs: missing={missing}, extra={extra}")

    # Name every current lookup entry by its actual destination.
    def target_char(value: int) -> str | None:
        return source_char.get(value & 0x7FFF) if value & 0x8000 else index_char.get(value)

    aliases_by_char: dict[str, list[int]] = defaultdict(list)
    for slot, value in enumerate(current_lut):
        if char := target_char(value):
            aliases_by_char[char].append(slot)

    # Bounded use is recorded for diagnosis.  Allocation is stricter: a new
    # alias slot must have zero raw occurrences in the *entire* archive.
    bounded_slot_use: Counter[int] = Counter()

    def collect_slots(payload: bytes) -> None:
        for token in tokens(payload):
            if (slot := virtual_slot(token)) is not None:
                bounded_slot_use[slot] += 1

    for name, member_ranges in by_file.items():
        if name not in v168:
            continue
        for offset, size in member_ranges:
            collect_slots(v168[name][offset:offset + size])
    for name, slots in active_slots(v168, ranges).items():
        for slot in slots:
            at = SLOT_BASE + slot * SLOT_SIZE
            block = v168[name][at:at + SLOT_SIZE]
            end = block.find(b"\0")
            if end <= 0:
                raise SystemExit(f"invalid v168 active slot {name}:{slot}")
            collect_slots(block[:end])
    for start, end in exe_spans:
        collect_slots(v168[PSX][start:end])

    raw_counts: dict[int, int] = {}
    for slot in range(LOOKUP_N):
        pair = virtual_code(slot)
        raw_counts[slot] = sum(count_pair(data, pair) for data in v168.values())

    protected_slots = {int(row["virtual_slot"]) for row in relocation_rows}
    zero_raw_slots = [
        slot
        for slot in range(LOOKUP_N)
        if raw_counts[slot] == 0 and slot not in protected_slots
    ]

    # Evaluate the data-remap alternative.  Existing same-character aliases keep
    # their lookup word.  New aliases would be acceptable only when their byte pair
    # is globally absent.  If that strict pool is too small, record the alternative
    # as infeasible instead of weakening the evidence rule.
    alias_plan: list[dict[str, object]] = []
    consumed_new_slots: set[int] = set()
    new_alias_need = sum(not aliases_by_char.get(row["char"]) for row in risky_rows)
    strict_alias_feasible = len(zero_raw_slots) >= new_alias_need
    for row in sorted(risky_rows, key=lambda item: bytes.fromhex(item["code_2byte"])):
        char = row["char"]
        existing = aliases_by_char.get(char, [])
        if existing:
            slot = existing[0]
            target_value = current_lut[slot]
            kind = "existing_same_glyph_alias"
            safe_code = virtual_code(slot)
            lookup_before = f"0x{current_lut[slot]:04X}"
            lookup_after = f"0x{target_value:04X}"
            raw_before: int | str = raw_counts[slot]
        elif not strict_alias_feasible:
            slot = -1
            target_value = -1
            kind = "unallocated_strict_pool_insufficient"
            safe_code = b""
            lookup_before = ""
            lookup_after = ""
            raw_before = ""
        else:
            candidates = [slot for slot in zero_raw_slots if slot not in consumed_new_slots]
            if not candidates:
                raise SystemExit("not enough globally absent E9/EA codes")
            slot = candidates[-1]  # high, globally absent slots first
            consumed_new_slots.add(slot)
            source_ids = source_ids_by_char.get(char, [])
            physical = int(row["physical_index"]) if row["physical_index"] else None
            if len(source_ids) == 1:
                target_value = 0x8000 | source_ids[0]
            elif not source_ids and physical is not None:
                target_value = physical
            else:
                raise SystemExit(
                    f"cannot choose one lookup target for {char!r}: sources={source_ids}"
                )
            kind = "new_globally_absent_alias"
            safe_code = virtual_code(slot)
            lookup_before = f"0x{current_lut[slot]:04X}"
            lookup_after = f"0x{target_value:04X}"
            raw_before = raw_counts[slot]
        if target_value >= 0 and target_char(target_value) != char:
            raise SystemExit(f"alias target does not resolve to {char!r}")
        alias_plan.append({
            "char": char,
            "risky_code": row["code_2byte"],
            "safe_code": safe_code.hex(" ").upper(),
            "virtual_slot": slot if slot >= 0 else "",
            "allocation": kind,
            "lookup_before": lookup_before,
            "lookup_after": lookup_after,
            "occurrences": occurrence_counts[char],
            "raw_safe_code_occurrences_before": raw_before,
        })

    safe_by_char = {
        str(row["char"]): bytes.fromhex(str(row["safe_code"]))
        for row in alias_plan if row["safe_code"]
    }
    for record in traced.values():
        code = safe_by_char.get(str(record["char"]), b"")
        record["safe_code"] = code.hex(" ").upper()

    # Ensure every current risky token in the rewritten regions has replay
    # provenance.  Any difference would be an ambiguous control and blocks a build.
    current_risky_positions: set[tuple[str, int]] = set()

    def collect_risky_positions(name: str, offset: int, size: int) -> None:
        payload = v168[name][offset:offset + size]
        for relative, token in token_offsets(payload):
            if token in risky_code_char:
                current_risky_positions.add((name, offset + relative))

    for name, member_ranges in by_file.items():
        if name not in v168:
            continue
        for offset, size in member_ranges:
            collect_risky_positions(name, offset, size)
    for name, slots in active_slots(v168, ranges).items():
        for slot in slots:
            at = SLOT_BASE + slot * SLOT_SIZE
            block = v168[name][at:at + SLOT_SIZE]
            end = block.find(b"\0")
            collect_risky_positions(name, at, end)
    for start, end in exe_spans:
        collect_risky_positions(PSX, start, end - start)
    if current_risky_positions != set(traced):
        unproved = sorted(current_risky_positions - set(traced))
        missing = sorted(set(traced) - current_risky_positions)
        raise SystemExit(
            f"risky token provenance differs: unproved={unproved[:8]} missing={missing[:8]}"
        )

    # Find native E1 controls independently from the untouched archive.  This is
    # the counterexample the v159 bitmap-based rewrite missed: a real command can
    # land on a cell that currently contains a Hangul picture.
    def bounded_e1_positions(members: dict[str, bytes]) -> dict[tuple[str, int], bytes]:
        result: dict[tuple[str, int], bytes] = {}

        def collect(name: str, offset: int, payload: bytes) -> None:
            for relative, token in token_offsets(payload):
                if len(token) == 2 and token[0] == 0xE1:
                    result[(name, offset + relative)] = token

        for name, offset, size in ranges:
            if name in members and offset + size <= len(members[name]):
                collect(name, offset, members[name][offset:offset + size])
        for name, slots in active_slots(members, ranges).items():
            for slot in slots:
                at = SLOT_BASE + slot * SLOT_SIZE
                block = members[name][at:at + SLOT_SIZE]
                end = block.find(b"\0")
                if end > 0:
                    collect(name, at, block[:end])
        exe = members[PSX]
        seen: set[tuple[int, int]] = set()
        for pointer in pointer_records():
            span = string_span(exe, target(exe, pointer))
            if span in seen:
                continue
            seen.add(span)
            collect(PSX, span[0], exe[span[0]:span[1]])
        return result

    original_e1 = bounded_e1_positions(original)
    v151_e1 = bounded_e1_positions(v151)
    v168_e1 = bounded_e1_positions(v168)
    original_e1_args = Counter(code[1] for code in original_e1.values())
    v151_e1_args = Counter(code[1] for code in v151_e1.values())
    v168_e1_args = Counter(code[1] for code in v168_e1.values())
    if original_e1_args != Counter({1: 1}):
        raise SystemExit(f"untouched bounded E1 controls differ: {original_e1_args}")
    if set(v168_e1) != current_risky_positions:
        raise SystemExit("every v168 E1 token is not a proven colliding glyph")
    risky_leads = {code[0] for code in risky_code_char}
    risky_trails = {code[1] for code in risky_code_char}
    if risky_leads != {0xE1} or min(risky_trails) != 0xBE or max(risky_trails) != 0xF0:
        raise SystemExit(
            f"risky E1 assignment interval differs: leads={risky_leads}, "
            f"trail={min(risky_trails):02X}..{max(risky_trails):02X}"
        )

    control_restores: list[dict[str, object]] = []
    for (name, offset), code in sorted(original_e1.items()):
        before = v151[name][offset:offset + 2]
        current = v168[name][offset:offset + 2]
        if before != code:
            raise SystemExit(f"v151 changed a native E1 control at {name}:0x{offset:X}")
        if current == code:
            raise SystemExit(f"native E1 control unexpectedly survived at {name}:0x{offset:X}")
        control_restores.append({
            "member": name,
            "offset": offset,
            "original_code": code.hex(" ").upper(),
            "v151_code": before.hex(" ").upper(),
            "v168_code": current.hex(" ").upper(),
            "planned_code": code.hex(" ").upper(),
        })

    OUT.mkdir(parents=True, exist_ok=True)
    occurrence_fields = [
        "member", "offset", "label", "char", "old_code", "risky_code",
        "safe_code", "old_lead_is_control",
    ]
    with OCCURRENCES.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=occurrence_fields)
        writer.writeheader()
        for (_name, _offset), record in sorted(traced.items()):
            writer.writerow(record)

    alias_fields = [
        "char", "risky_code", "safe_code", "virtual_slot", "allocation",
        "lookup_before", "lookup_after", "occurrences",
        "raw_safe_code_occurrences_before",
    ]
    with ALIAS_PLAN.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=alias_fields)
        writer.writeheader()
        writer.writerows(alias_plan)

    with SLOT_INVENTORY.open("w", encoding="utf-8-sig", newline="") as handle:
        fields = [
            "slot", "code", "lookup_value", "target_char", "bounded_occurrences",
            "raw_archive_occurrences", "protected", "globally_absent_candidate",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for slot, value in enumerate(current_lut):
            writer.writerow({
                "slot": slot,
                "code": virtual_code(slot).hex(" ").upper(),
                "lookup_value": f"0x{value:04X}",
                "target_char": target_char(value) or "",
                "bounded_occurrences": bounded_slot_use[slot],
                "raw_archive_occurrences": raw_counts[slot],
                "protected": int(slot in protected_slots),
                "globally_absent_candidate": int(
                    raw_counts[slot] == 0 and slot not in protected_slots
                ),
            })

    with CONTROL_RESTORES.open("w", encoding="utf-8-sig", newline="") as handle:
        fields = [
            "member", "offset", "original_code", "v151_code", "v168_code",
            "planned_code",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(control_restores)

    old_control_lead_occurrences = sum(
        int(record["old_lead_is_control"]) for record in traced.values()
    )
    existing_aliases = sum(
        row["allocation"] == "existing_same_glyph_alias" for row in alias_plan
    )
    new_aliases = sum(row["allocation"] == "new_globally_absent_alias" for row in alias_plan)
    unallocated_aliases = sum(
        row["allocation"] == "unallocated_strict_pool_insufficient" for row in alias_plan
    )
    lookup_changes = sum(
        bool(row["lookup_before"])
        and row["lookup_before"] != row["lookup_after"]
        for row in alias_plan
    )
    by_member = Counter(str(record["member"]) for record in traced.values())
    lines = [
        "v168 E1..E8 control/glyph collision audit",
        "",
        f"v151_sha256={V151_SHA256}",
        f"v168_sha256={V168_SHA256}",
        "v159_translation_replay=PASS",
        "v168_DAT_members_match_replay=PASS",
        "v168_EXE_text_pool_matches_replay=PASS",
        "risky_token_provenance=PASS",
        "",
        f"control_leading_assignment_codes={len(risky_rows)}",
        f"affected_hangul={len(traced_chars)}",
        f"proven_glyph_occurrences={len(traced)}",
        f"occurrences_whose_old_v151_token_also_led_with_E1_E8={old_control_lead_occurrences}",
        f"existing_same_glyph_aliases={existing_aliases}",
        f"new_globally_absent_aliases={new_aliases}",
        f"strict_alias_unallocated={unallocated_aliases}",
        f"strict_alias_plan_feasible={str(strict_alias_feasible).lower()}",
        f"lookup_entries_changed={lookup_changes}",
        f"globally_absent_unprotected_alias_codes={len(zero_raw_slots)}",
        f"globally_absent_alias_codes_remaining={max(0, len(zero_raw_slots) - new_aliases)}",
        f"protected_virtual_slots={len(protected_slots)}",
        f"untouched_bounded_E1_controls={len(original_e1)}",
        "untouched_bounded_E1_arguments="
        + ",".join(f"{arg:02X}:{count}" for arg, count in sorted(original_e1_args.items())),
        f"v151_bounded_E1_tokens={len(v151_e1)}",
        "v151_bounded_E1_arguments="
        + ",".join(f"{arg:02X}:{count}" for arg, count in sorted(v151_e1_args.items())),
        f"v168_bounded_E1_tokens={len(v168_e1)}",
        "v168_E1_assignment_interval=BE..F0",
        f"native_E1_controls_to_restore={len(control_restores)}",
        "",
        "occurrences_by_member:",
        *(f"  {name}={count}" for name, count in by_member.most_common()),
        "",
        f"occurrences_csv={OCCURRENCES.relative_to(ROOT)}",
        f"alias_plan_csv={ALIAS_PLAN.relative_to(ROOT)}",
        f"slot_inventory_csv={SLOT_INVENTORY.relative_to(ROOT)}",
        f"control_restores_csv={CONTROL_RESTORES.relative_to(ROOT)}",
        "result=PASS_ANALYSIS_ONLY",
        "patch_built=NO",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
