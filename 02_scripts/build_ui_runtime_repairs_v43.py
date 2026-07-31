#!/usr/bin/env python3
"""Repair v0.42 common UI pointers without moving accepted UI table data.

v0.42 repacked the 503 item/equipment/skill/location strings after clearing
the shared native string pools.  Seventy-one inherited common/system pointers
were left pointing at the cleared bytes.  This builder restores only those
pointers and payloads in the remaining holes, restores the accepted compact
HUD LV source, and verifies that every v0.42 table record remains byte exact.
"""

from __future__ import annotations

import csv
import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

import build_ui_guide_repairs_v42 as v42  # noqa: E402
import build_ui_safe_v39 as v39  # noqa: E402
from build_story_sf0b1_return_full import get_pixel, set_pixel  # noqa: E402
from build_ui_full_v26 import PSX_LOAD_BASE, raw_string  # noqa: E402


BASE = ROOT / "03_output" / "ui_guide_terms_v42_v39_repairs_cumulative_patch_only.zip"
BASE_HASH = "0CEF485BD82D2C7C72EA4F0326D804AC07282773731CD02AF1D6DA83FCFD5EFC"
BASE_PSX_HASH = "24C004F8718AAF3A2AA760E58D42E4991724DD43A3E9BF572064F357EDF3CCD1"
BASE_COMM_HASH = "AEFEE1EDD4FB2B00DF1533C745C0E8AE3A78A96D5CD0C7302F65B2456E8626F6"

V39 = ROOT / "03_output" / "ui_safe_v39_cumulative_patch_only.zip"
V39_HASH = "0778FE435820409F190579D179F8B36FFFCEB02B5F2004FC1E3ACE58741D5DC3"
V39_COMM_HASH = "CC06EE234F61416FE4C52829F54E078E33D83BD9DFD243B3D39C35C5667F0388"

TABLE_MANIFEST = ROOT / "05_docs" / "ui_full_v42.csv"
SYSTEM_MANIFESTS = (
    ("system", ROOT / "05_docs" / "ui_system_v39.csv"),
    ("nonstory_system", ROOT / "05_docs" / "ui_nonstory_system_v39.csv"),
)

OUTPUT = ROOT / "03_output" / "ui_runtime_repairs_v43_cumulative_patch_only.zip"
MANIFEST = ROOT / "05_docs" / "ui_runtime_repairs_v43.csv"
ANALYSIS = ROOT / "01_work" / "analysis" / "ui_runtime_repairs_v43"
READBACK = ANALYSIS / "readback.csv"
ALLOCATION = ANALYSIS / "pool_allocation.csv"
REGRESSION = ANALYSIS / "regression_audit.txt"
REPORT = ANALYSIS / "build_report.txt"

PSX_TARGET = "PSX.EXE"
COMM_TARGET = "COMM.IMG"
HUD_POINTERS = (0x823AC, 0x823B0, 0x823B4, 0x823B8, 0x823BC)
HUD_SOURCES = (0x82154, 0x82158, 0x8215C, 0x82160, 0x82164)
HUD_PAYLOADS = (
    bytes.fromhex("6C 00 00 00"),
    bytes.fromhex("00 00 00 00"),
    bytes.fromhex("DD B2 00 00"),
    bytes.fromhex("01 DE 4F 00"),
    bytes.fromhex("DD 90 00 00"),
)

# The original configuration label is wider than the value column permits in
# Korean and visibly collides with the right-hand state text. Re-encode only
# this label with the already installed v0.42 E9/EA map; no new glyph is added.
CONFIG_OVERRIDES = {
    0x825D8: "몬스터 도감",
}

CIRCLE_REFERENCE = (24, 130)
CIRCLE_DESTINATION = (180, 228)
X_DESTINATION = (192, 228)
ICON_WIDTH = 12
ICON_HEIGHT = 12


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, data: list[dict[str, object]]) -> None:
    if not data:
        raise SystemExit(f"refusing to write empty CSV: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fields: list[str] = []
    for row in data:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)


def v42_virtual_mapping() -> dict[str, bytes]:
    return {
        row["char"]: bytes.fromhex(row["virtual_code_hex"])
        for row in rows(v42.GLYPH_MAP)
    }


def pointer_target(data: bytes | bytearray, pointer_offset: int) -> int:
    return struct.unpack_from("<I", data, pointer_offset)[0] - PSX_LOAD_BASE


def in_pool(offset: int) -> bool:
    return any(start <= offset < end for start, end in v42.pool_segments())


def add_occupied(occupied: list[tuple[int, int]], start: int, size: int) -> None:
    if size <= 0 or not in_pool(start):
        return
    end = start + size
    if not any(pool_start <= start and end <= pool_end for pool_start, pool_end in v42.pool_segments()):
        raise SystemExit(f"occupied string crosses pool boundary: 0x{start:X}-0x{end:X}")
    occupied.append((start, end))


def merge_intervals(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[list[int]] = []
    for start, end in sorted(intervals):
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)
    return [(start, end) for start, end in merged]


def free_intervals(occupied: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged = merge_intervals(occupied)
    result: list[tuple[int, int]] = []
    for pool_start, pool_end in v42.pool_segments():
        cursor = pool_start
        for start, end in merged:
            if end <= pool_start or start >= pool_end:
                continue
            if cursor < start:
                result.append((cursor, start))
            cursor = max(cursor, end)
        if cursor < pool_end:
            result.append((cursor, pool_end))
    return result


def rectangle(data: bytes | bytearray, origin: tuple[int, int]) -> tuple[int, ...]:
    x, y = origin
    return tuple(
        get_pixel(data, x + dx, y + dy)
        for dy in range(ICON_HEIGHT)
        for dx in range(ICON_WIDTH)
    )


def write_rectangle(data: bytearray, origin: tuple[int, int], pixels: tuple[int, ...]) -> None:
    x, y = origin
    for dy in range(ICON_HEIGHT):
        for dx in range(ICON_WIDTH):
            set_pixel(data, x + dx, y + dy, pixels[dy * ICON_WIDTH + dx])


def diff_ranges(before: bytes, after: bytes) -> list[tuple[int, int]]:
    if len(before) != len(after):
        raise ValueError("cannot diff differently sized files")
    ranges: list[tuple[int, int]] = []
    start: int | None = None
    for offset, (old, new) in enumerate(zip(before, after)):
        if old != new and start is None:
            start = offset
        elif old == new and start is not None:
            ranges.append((start, offset))
            start = None
    if start is not None:
        ranges.append((start, len(before)))
    return ranges


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("v0.42 base ZIP hash differs")
    if digest(V39.read_bytes()) != V39_HASH:
        raise SystemExit("v0.39 reference ZIP hash differs")

    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        files = {info.filename: archive.read(info.filename) for info in infos}
    with ZipFile(V39) as archive:
        v39_comm = archive.read(COMM_TARGET)

    if digest(files[PSX_TARGET]) != BASE_PSX_HASH:
        raise SystemExit("v0.42 PSX.EXE hash differs")
    if digest(files[COMM_TARGET]) != BASE_COMM_HASH:
        raise SystemExit("v0.42 COMM.IMG hash differs")
    if digest(v39_comm) != V39_COMM_HASH:
        raise SystemExit("v0.39 COMM.IMG hash differs")

    before_files = dict(files)
    before_exe = files[PSX_TARGET]
    before_comm = files[COMM_TARGET]
    executable = bytearray(before_exe)
    comm = bytearray(before_comm)
    legacy_mapping = v42.load_mapping()
    virtual_mapping = v42_virtual_mapping()

    table_rows = rows(TABLE_MANIFEST)
    if len(table_rows) != 503:
        raise SystemExit(f"v0.42 table manifest count differs: {len(table_rows)}")

    occupied: list[tuple[int, int]] = []
    payload_locations: dict[bytes, int] = {}
    table_snapshots: list[tuple[int, int, bytes]] = []
    table_payload_by_pointer: dict[int, bytes] = {}
    for row in table_rows:
        pointer = int(row["pointer_offset"], 16)
        target = int(row["string_offset"], 16)
        payload = bytes.fromhex(row["encoded_hex"])
        if pointer_target(executable, pointer) != target:
            raise SystemExit(f"v0.42 table pointer differs: {row['table_key']}[{row['index']}]")
        if raw_string(executable, target) != payload:
            raise SystemExit(f"v0.42 table payload differs: {row['table_key']}[{row['index']}]")
        if executable[target + len(payload)] != 0:
            raise SystemExit(f"v0.42 table terminator differs: {row['table_key']}[{row['index']}]")
        table_snapshots.append((pointer, target, payload))
        table_payload_by_pointer[pointer] = payload
        payload_locations.setdefault(payload, target)
        add_occupied(occupied, target, len(payload) + 1)

    manifest_rows: list[dict[str, object]] = []
    repair_rows: list[dict[str, object]] = []
    seen_pointers: dict[int, bytes] = {}
    for category, path in SYSTEM_MANIFESTS:
        for row in rows(path):
            pointer = int(row["pointer_offset"], 16)
            korean = CONFIG_OVERRIDES.get(pointer, row["korean"])
            payload = (
                v42.encode_text(korean, legacy_mapping, virtual_mapping)
                if pointer in CONFIG_OVERRIDES
                else bytes.fromhex(row.get("encoded_hex", ""))
            )
            previous = seen_pointers.setdefault(pointer, payload)
            if previous != payload:
                raise SystemExit(f"conflicting system manifests at 0x{pointer:X}")
            if pointer in HUD_POINTERS:
                continue
            # v0.42 intentionally replaced this shared legacy pointer as part
            # of the accepted 503-record table.  The v0.42 table is authoritative.
            if pointer in table_payload_by_pointer:
                continue
            target = pointer_target(executable, pointer)
            current = raw_string(executable, target)
            exact = current == payload
            if exact:
                payload_locations.setdefault(payload, target)
                add_occupied(occupied, target, len(payload) + 1)
            else:
                repair_rows.append(
                    {
                        "category": category,
                        "pointer_offset": pointer,
                        "korean": korean,
                        "payload": payload,
                        "old_target": target,
                        "old_hex": current.hex(" ").upper(),
                    }
                )

    initial_free = free_intervals(occupied)
    initial_free_bytes = sum(end - start for start, end in initial_free)

    missing_payloads = {
        row["payload"] for row in repair_rows if row["payload"] not in payload_locations
    }
    required_bytes = sum(len(payload) + 1 for payload in missing_payloads)
    free = list(initial_free)
    allocation_rows: list[dict[str, object]] = []
    for payload in sorted(missing_payloads, key=lambda item: (-(len(item) + 1), item)):
        required = len(payload) + 1
        candidates = [
            (end - start - required, slot, start, end)
            for slot, (start, end) in enumerate(free)
            if end - start >= required
        ]
        if not candidates:
            raise SystemExit(
                f"v0.43 pool allocation failed: need={required}, free={sum(e-s for s,e in free)}"
            )
        _, slot, start, end = min(candidates)
        executable[start : start + len(payload)] = payload
        executable[start + len(payload)] = 0
        payload_locations[payload] = start
        free[slot] = (start + required, end)
        allocation_rows.append(
            {
                "string_offset": f"0x{start:X}",
                "encoded_bytes": len(payload),
                "required_bytes_with_terminator": required,
                "encoded_hex": payload.hex(" ").upper(),
            }
        )

    for row in repair_rows:
        pointer = int(row["pointer_offset"])
        payload = row["payload"]
        target = payload_locations[payload]
        struct.pack_into("<I", executable, pointer, PSX_LOAD_BASE + target)
        manifest_rows.append(
            {
                "category": row["category"],
                "pointer_offset": f"0x{pointer:X}",
                "korean": row["korean"],
                "old_target": f"0x{int(row['old_target']):X}",
                "new_target": f"0x{target:X}",
                "encoded_bytes": len(payload),
                "encoded_hex": payload.hex(" ").upper(),
                "action": "repoint_existing" if not any(
                    item["encoded_hex"] == payload.hex(" ").upper() for item in allocation_rows
                ) else "allocate_and_repoint",
            }
        )

    for pointer, source, payload in zip(HUD_POINTERS, HUD_SOURCES, HUD_PAYLOADS):
        executable[source : source + len(payload)] = payload
        struct.pack_into("<I", executable, pointer, PSX_LOAD_BASE + source)

    # Keep the working X icon exact and refresh the circle from the verified
    # v0.39 copy.  The copy is intentionally idempotent when v0.42 is already
    # byte-identical, which prevents collateral font changes.
    x_snapshot = rectangle(comm, X_DESTINATION)
    circle = rectangle(v39_comm, CIRCLE_REFERENCE)
    write_rectangle(comm, CIRCLE_DESTINATION, circle)
    if rectangle(comm, CIRCLE_DESTINATION) != circle:
        raise SystemExit("v0.43 circle icon readback differs")
    if rectangle(comm, X_DESTINATION) != x_snapshot:
        raise SystemExit("v0.43 X icon regressed")
    if v39.plane(v39_comm, b"\x6C") != v39.plane(bytes(comm), b"\x6C"):
        raise SystemExit("v0.43 compact LV glyph differs from accepted v0.39")

    # Full readback for both common UI manifests, including the explicit HUD.
    readback_rows: list[dict[str, object]] = []
    mismatch_count = 0
    for category, path in SYSTEM_MANIFESTS:
        for row in rows(path):
            pointer = int(row["pointer_offset"], 16)
            korean = CONFIG_OVERRIDES.get(pointer, row["korean"])
            payload = (
                v42.encode_text(korean, legacy_mapping, virtual_mapping)
                if pointer in CONFIG_OVERRIDES
                else bytes.fromhex(row.get("encoded_hex", ""))
            )
            target = pointer_target(executable, pointer)
            actual = raw_string(executable, target)
            if pointer in table_payload_by_pointer:
                expected = table_payload_by_pointer[pointer]
                exact = actual == expected
                mismatch_count += not exact
                readback_rows.append(
                    {
                        "category": category,
                        "pointer_offset": f"0x{pointer:X}",
                        "korean": korean,
                        "target": f"0x{target:X}",
                        "expected_hex": expected.hex(" ").upper(),
                        "actual_hex": actual.hex(" ").upper(),
                        "status": "v42_table_authoritative_exact" if exact else "mismatch",
                    }
                )
                continue
            exact = actual == payload
            mismatch_count += not exact
            readback_rows.append(
                {
                    "category": category,
                    "pointer_offset": f"0x{pointer:X}",
                    "korean": korean,
                    "target": f"0x{target:X}",
                    "expected_hex": payload.hex(" ").upper(),
                    "actual_hex": actual.hex(" ").upper(),
                    "status": "exact" if exact else "mismatch",
                }
            )
    if mismatch_count:
        raise SystemExit(f"v0.43 common UI readback mismatches: {mismatch_count}")

    # The accepted 503 table pointers and payloads are immutable in this build.
    for pointer, target, payload in table_snapshots:
        if pointer_target(executable, pointer) != target:
            raise SystemExit(f"v0.43 moved accepted table pointer 0x{pointer:X}")
        if raw_string(executable, target) != payload:
            raise SystemExit(f"v0.43 changed accepted table payload at 0x{target:X}")

    files[PSX_TARGET] = bytes(executable)
    files[COMM_TARGET] = bytes(comm)
    changed_members = [name for name in files if files[name] != before_files[name]]
    if any(name not in (PSX_TARGET, COMM_TARGET) for name in changed_members):
        raise SystemExit(f"unexpected changed ZIP members: {changed_members}")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    temporary = OUTPUT.with_suffix(".tmp")
    with ZipFile(temporary, "w", ZIP_DEFLATED, compresslevel=9) as archive:
        for info in infos:
            archive.writestr(info, files[info.filename])
    temporary.replace(OUTPUT)
    with ZipFile(OUTPUT) as archive:
        for name, expected in files.items():
            if archive.read(name) != expected:
                raise SystemExit(f"v0.43 ZIP readback differs: {name}")

    # The raw v0.39 comparison has 71 mismatches. One is superseded by the
    # accepted v0.42 consumable table and one is the separately repaired HUD.
    # The compact configuration label is one deliberate additional repoint.
    if len(repair_rows) != 69 + len(CONFIG_OVERRIDES):
        raise SystemExit(f"documented repair pointer count differs: {len(repair_rows)}")

    final_free_bytes = sum(end - start for start, end in free)
    psx_ranges = diff_ranges(before_exe, files[PSX_TARGET])
    comm_ranges = diff_ranges(before_comm, files[COMM_TARGET])
    regression_lines = [
        "ui_runtime_repairs_v43 regression audit",
        "accepted_v42_table_records=503 exact",
        "accepted_v42_table_pointers=503 unchanged",
        "story_members=unchanged",
        f"changed_members={','.join(changed_members)}",
        "psx_changed_ranges=" + ",".join(f"0x{s:X}-0x{e-1:X}" for s, e in psx_ranges),
        "comm_changed_ranges=" + (
            ",".join(f"0x{s:X}-0x{e-1:X}" for s, e in comm_ranges) or "none_idempotent_icon_refresh"
        ),
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    write_csv(MANIFEST, manifest_rows)
    write_csv(READBACK, readback_rows)
    write_csv(ALLOCATION, allocation_rows)
    REGRESSION.write_text("\n".join(regression_lines) + "\n", encoding="utf-8")

    report_lines = [
        "UI runtime repairs v0.43",
        f"base_zip_sha256={BASE_HASH}",
        f"output_zip_sha256={digest(OUTPUT.read_bytes())}",
        f"output_psx_sha256={digest(files[PSX_TARGET])}",
        f"output_comm_sha256={digest(files[COMM_TARGET])}",
        "base_runtime_status=V42_USER_REPORTED_POINTER_REGRESSION",
        "story_e2_members_unchanged=true",
        "accepted_v42_table_records_unchanged=503",
        f"repaired_common_ui_pointers={len(repair_rows)}",
        f"compact_config_labels={len(CONFIG_OVERRIDES)}",
        f"new_unique_payloads={len(missing_payloads)}",
        f"required_pool_bytes={required_bytes}",
        f"initial_pool_free_bytes={initial_free_bytes}",
        f"final_pool_free_bytes={final_free_bytes}",
        "battle_hud_lv=accepted_v39_compact_6C",
        "confirm_icon=verified_v39_circle_refresh",
        "cancel_icon=v42_exact_preserved",
        f"changed_members={','.join(changed_members)}",
        "runtime_status=UNVERIFIED_CANDIDATE",
    ]
    REPORT.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    print("\n".join(report_lines))


if __name__ == "__main__":
    main()
