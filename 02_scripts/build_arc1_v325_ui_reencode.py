#!/usr/bin/env python3
"""Build V325: re-encode every pointer-proven PSX.EXE UI string for Hanme16.

V324 made the E9/EA lookup entirely static and moved the skill-range cursor to
persistent RAM, but its executable string pools still contain V241-era codes.
Those codes predate the current 16px physical atlas: legacy 0x9C spaces render
as ')', high direct indices fail closed, and several low direct indices name a
different physical glyph.

This build does not scan the mixed executable data as text.  It rebuilds only
the 666 unique pointer records proven by the accepted 503 UI-table, system,
common/non-story, and world-name manifests.  Five HUD micro-pointers keep their
special binary payloads byte exact.  Five missing glyphs are placed in physical
planes whose every known text use lies inside the rebuilt strings and whose
509-state cell audit has zero non-text readers.
"""

from __future__ import annotations

import csv
import hashlib
import json
import pickle
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import build_arc1_v320_hanme_static_recovery as v320  # noqa: E402
import build_arc1_v320c_hanme_official_beol as v320c  # noqa: E402
import build_arc1_v324_static_ui_cursor_recovery as v324  # noqa: E402
import build_ui_guide_repairs_v42 as v42  # noqa: E402
from build_arc1_v231_static_promotion_restored162 import text_regions  # noqa: E402


BASE = ROOT / "03_output/arc1_v324_static_ui_cursor_recovery_TEST_ONLY_06F7C289.zip"
BASE_SHA256 = "06F7C289B593AB2767BA3D3ABC256ACCFD21781F60DF46A18F1D3FF58D67FD4B"
BASE_PSX_SHA256 = "DD6EDADA703BAF7294C762ED787978FAA83CAD1B7AA552806265827FD4681900"
BASE_COMM_SHA256 = "C81F48B805F3FF973C08DE14DE232DD2620612483FC0778A79BA2D2DC26E185B"

TABLE_MANIFEST = ROOT / "05_docs/ui_full_v42.csv"
TABLE_MANIFEST_SHA256 = "D3C691FA3F097B299D25CDDE6D7689983444DA32CEAEC23EE10BDD4AF7A52950"
SYSTEM_MANIFEST = ROOT / "05_docs/ui_system_v39.csv"
SYSTEM_MANIFEST_SHA256 = "C6D84C490DB9D6F9A420CC942F78F7D774A63D9E7048AF2CF433C5C9250EB053"
NONSTORY_MANIFEST = ROOT / "05_docs/ui_nonstory_system_v39.csv"
NONSTORY_MANIFEST_SHA256 = "250C16F06961EF7F03B800DD3FD244109E441EEF93E4504A10815D7B1840E5DB"
WORLD_MANIFEST = ROOT / "05_docs/ui_world_name_v39.csv"
WORLD_MANIFEST_SHA256 = "6898B0D63C4426CD2CBCFFFE10126EEBC86D0245943F0F1ED14D755CB2BA3969"

ASSIGNMENTS = ROOT / "01_work/analysis/arc1_v320_hanme_static_recovery/character_assignments.csv"
ASSIGNMENTS_SHA256 = "933BDAC4BC4C39D33DB134D2FF836902B5053B93725C96E19DED714CB7DE98A4"
ATLAS = ROOT / "01_work/analysis/arc1_v319_pilgi16_integration/atlas_mapping.csv"
ATLAS_SHA256 = "9553E7643621CC80C23355067611EAE7650FEF7CB547DC9115B62157DB0C3122"
PIECES = ROOT / "01_work/analysis/hangul_johab_16px/pieces_1bpp.bin"
PIECES_SHA256 = "409ABA72F4BA2282AA5C4E4982A9EEA16FBD14FB0413A40E151537A6653E2904"
ASCII = ROOT / "01_work/analysis/hangul_johab_16px/ascii_16px.pkl"
ASCII_SHA256 = "36BBEF684D730517042E2174E5D6D12A639D9DDD60E40529E2AEE29C7AE141BB"
CELL_AUDIT = ROOT / "01_work/analysis/font_cell_audit_full/cell_consumers.csv"
CELL_AUDIT_SHA256 = "63EF327777CC8A4E072AF68B8A1FE2B2EF4DFD8570D6176980157B7BBF7D5A73"

OUTPUT_STEM = "arc1_v325_ui_reencode_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v324"
ANALYSIS = ROOT / "01_work/analysis/arc1_v325_ui_reencode"

PSX, COMM = "PSX.EXE", "COMM.IMG"
RAM_TO_FILE = 0x8011A800
STATIC_LIMIT = 960
POOL_SEGMENTS = (
    (0x80224, 0x804A4),
    (0x805A4, 0x80A94),
    (0x80B94, 0x80C9C),
    (0x80D1C, 0x80F14),
    (0x80F94, 0x811C0),
    (0x812AC, 0x81708),
    (0x817F4, 0x81B4C),
    (0x81CFC, 0x81E38),
    (0x81F04, 0x82134),
)
POOL_BYTES = 6076

MANIFEST_SPECS = (
    ("table", TABLE_MANIFEST, "korean", 503),
    ("system", SYSTEM_MANIFEST, "korean", 40),
    ("nonstory", NONSTORY_MANIFEST, "korean", 128),
    ("world", WORLD_MANIFEST, "korean_target", 7),
)
PRIORITY = {"table": 0, "system": 1, "nonstory": 2, "world": 3}

# These five pointers are packed binary HUD fragments, not normal strings.
HUD_POINTERS = (0x823AC, 0x823B0, 0x823B4, 0x823B8, 0x823BC)
CONFIG_OVERRIDES = {0x825D8: "몬스터 도감"}
ICON_TOKENS = {"{결정버튼}": b"\xE7\x02", "{취소버튼}": b"\xE7\x03"}

# Each target is direct-code encodable, nontext-safe, and absent outside the
# 666 rebuilt pointer strings.  Physical 819 is also the value stored in
# lookup slot 230, but E9 E7 has zero occurrences in all 8,448 text regions;
# the five live uses of 819 are direct DF 5A tokens inside rebuilt UI strings.
NEW_GLYPHS = {"%": 403, "뱀": 762, "센": 819, "첩": 823, "탑": 865}
EXPECTED_INSIDE_USES = {403: 0, 762: 1, 819: 5, 823: 2, 865: 5}

EXPECTED_SOURCE_ROWS = 678
EXPECTED_UNIQUE_POINTERS = 671
EXPECTED_CONFLICT_POINTERS = {0x80F1C}
EXPECTED_REBUILT_POINTERS = 666
EXPECTED_UNIQUE_PAYLOADS = 561
EXPECTED_REQUIRED_POOL_BYTES = 5590
EXPECTED_POOL_FREE_BYTES = 486
EXPECTED_ALIGNED_POOL_POINTERS = 497


class BuildError(RuntimeError):
    pass


@dataclass(frozen=True)
class TextRecord:
    pointer: int
    category: str
    source_text: str
    text: str
    categories: tuple[str, ...]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def raw_string(data: bytes | bytearray, offset: int) -> bytes:
    end = data.find(0, offset, min(len(data), offset + 513))
    if end < 0:
        raise BuildError(f"unterminated executable string at 0x{offset:X}")
    return bytes(data[offset:end])


def pointer_target(exe: bytes | bytearray, pointer: int) -> int:
    value = struct.unpack_from("<I", exe, pointer)[0]
    target = value - RAM_TO_FILE
    if not 0 <= target < len(exe):
        raise BuildError(f"pointer target outside PSX.EXE: 0x{pointer:X}->0x{value:08X}")
    return target


def in_pool(offset: int) -> bool:
    return any(start <= offset < end for start, end in POOL_SEGMENTS)


def resolve_token(exe: bytes | bytearray, token: bytes) -> int | None:
    slot = v320.virtual_slot(token)
    if slot is not None:
        if slot >= v320.LOOKUP_SLOTS:
            return None
        return v320.lookup_get(exe, slot)
    return v320.direct_index(token)


def normalize_text(text: str) -> str:
    replacements = (
        ("LV +1", "레벨 1"),
        ("LV 1", "레벨 1"),
        ("LV 상승", "레벨 상승"),
        ("레벨 +1", "레벨 1"),
    )
    for old, new in replacements:
        text = text.replace(old, new)
    return text


def semantic_characters(text: str) -> str:
    for marker in ICON_TOKENS:
        text = text.replace(marker, "")
    return text


def load_records() -> dict[int, TextRecord]:
    gathered: dict[int, list[tuple[str, str]]] = defaultdict(list)
    source_rows = 0
    for category, path, text_field, expected_count in MANIFEST_SPECS:
        records = csv_rows(path)
        if len(records) != expected_count:
            raise BuildError(f"{category} manifest row drift: {len(records)}/{expected_count}")
        source_rows += len(records)
        for row in records:
            pointer = int(row["pointer_offset"], 0)
            gathered[pointer].append((category, row[text_field]))
    if source_rows != EXPECTED_SOURCE_ROWS or len(gathered) != EXPECTED_UNIQUE_POINTERS:
        raise BuildError(f"manifest census drift: {source_rows}/{len(gathered)}")
    conflicts = {
        pointer
        for pointer, values in gathered.items()
        if len({text for _category, text in values}) > 1
    }
    if conflicts != EXPECTED_CONFLICT_POINTERS:
        raise BuildError(f"manifest conflict set drift: {sorted(conflicts)}")

    result: dict[int, TextRecord] = {}
    for pointer, values in gathered.items():
        if pointer in HUD_POINTERS:
            continue
        category, source_text = min(values, key=lambda item: PRIORITY[item[0]])
        text = CONFIG_OVERRIDES.get(pointer, source_text)
        text = normalize_text(text)
        result[pointer] = TextRecord(
            pointer=pointer,
            category=category,
            source_text=source_text,
            text=text,
            categories=tuple(sorted({item[0] for item in values}, key=PRIORITY.get)),
        )
    if len(result) != EXPECTED_REBUILT_POINTERS:
        raise BuildError(f"rebuilt pointer count drift: {len(result)}")
    if result[0x80F1C].category != "table" or result[0x80F1C].text != "레벨 1 상승":
        raise BuildError("table/system conflict precedence drift")
    return result


def merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)
    return [(start, end) for start, end in merged]


def prove_new_glyph_targets(
    files: dict[str, bytes], records: dict[int, TextRecord]
) -> list[dict[str, object]]:
    exe, comm = files[PSX], files[COMM]
    spans = []
    for pointer in records:
        start = pointer_target(exe, pointer)
        spans.append((start, start + len(raw_string(exe, start))))
    merged = merge_spans(spans)

    def covered(offset: int) -> bool:
        return any(start <= offset < end for start, end in merged)

    regions = list(text_regions(files))
    if len(regions) != v320.REGION_COUNT or v320.region_fingerprint(regions) != v320.REGION_SHA256:
        raise BuildError("8,448-region text catalogue drift")
    inside: Counter[int] = Counter()
    outside: Counter[int] = Counter()
    lookup_occurrences: Counter[int] = Counter()
    targets = set(NEW_GLYPHS.values())
    for name, start, end in regions:
        data = files[name]
        offset = start
        while offset < end:
            if v320.is_control(data, offset):
                offset += 2
                continue
            width = v320.token_width(data[offset])
            token = data[offset : offset + width]
            slot = v320.virtual_slot(token)
            if slot is not None:
                lookup_occurrences[slot] += 1
            physical = resolve_token(exe, token)
            if physical in targets:
                bucket = inside if name == PSX and covered(offset) else outside
                bucket[physical] += 1
            offset += width
    if dict(inside) != {key: value for key, value in EXPECTED_INSIDE_USES.items() if value}:
        raise BuildError(f"new-glyph inside-use census drift: {dict(inside)}")
    if any(outside[index] for index in targets):
        raise BuildError(f"new-glyph target has use outside rebuilt UI: {dict(outside)}")

    lookup_targets: dict[int, list[int]] = defaultdict(list)
    for slot in range(v320.LOOKUP_SLOTS):
        lookup_targets[v320.lookup_get(exe, slot)].append(slot)
    audit = {
        (int(row["row"]), int(row["col"])): int(row["nontext_reads"])
        for row in csv_rows(CELL_AUDIT)
    }
    rows: list[dict[str, object]] = []
    for char, physical in NEW_GLYPHS.items():
        code = v320.encode_index(physical)
        if code is None or len(code) != 2 or resolve_token(exe, code) != physical:
            raise BuildError(f"new glyph lacks stable direct code: {char}/{physical}")
        lookup_slots = lookup_targets.get(physical, [])
        live_lookup_slots = [slot for slot in lookup_slots if lookup_occurrences[slot]]
        if live_lookup_slots:
            raise BuildError(
                f"new glyph target has live lookup destinations: {physical}/{live_lookup_slots}"
            )
        if not v320.safe_geometry(physical, audit):
            raise BuildError(f"new glyph target has a nontext reader: {physical}")
        rows.append(
            {
                "char": char,
                "unicode": f"U+{ord(char):04X}",
                "physical_index": physical,
                "code_hex": code.hex(" ").upper(),
                "inside_rebuilt_uses_before": inside[physical],
                "outside_rebuilt_uses_before": outside[physical],
                "before_plane_sha256": sha256_bytes(struct.pack(">16H", *v320.read_plane(comm, physical))),
                "safe_nontext": 1,
                "lookup_slots": " ".join(str(slot) for slot in lookup_slots),
                "lookup_occurrences": sum(lookup_occurrences[slot] for slot in lookup_slots),
            }
        )
    return rows


def audit_aligned_pool_pointers(exe: bytes, records: dict[int, TextRecord]) -> None:
    found: set[int] = set()
    for offset in range(0, len(exe) - 3, 4):
        target = struct.unpack_from("<I", exe, offset)[0] - RAM_TO_FILE
        if in_pool(target):
            found.add(offset)
    unknown = found - set(records) - set(HUD_POINTERS)
    if unknown or len(found) != EXPECTED_ALIGNED_POOL_POINTERS:
        raise BuildError(
            f"aligned pool-pointer audit drift: found={len(found)} unknown={sorted(unknown)[:8]}"
        )


def build_code_map(
    exe: bytes, comm: bytes, records: dict[int, TextRecord]
) -> tuple[dict[str, bytes], dict[str, int], tuple[tuple[int, ...], ...], dict[str, list[int]]]:
    pieces = v320c.load_pieces(PIECES.read_bytes())
    candidates: dict[str, set[tuple[bytes, int]]] = defaultdict(set)

    assignment_rows = csv_rows(ASSIGNMENTS)
    if len(assignment_rows) != 750:
        raise BuildError(f"assignment row count drift: {len(assignment_rows)}")
    final_identity: dict[int, str] = {}
    atlas_rows = csv_rows(ATLAS)
    if len(atlas_rows) != 728:
        raise BuildError(f"atlas row count drift: {len(atlas_rows)}")
    for row in atlas_rows:
        if row["char"]:
            final_identity[int(row["index"])] = row["char"]
    for row in assignment_rows:
        char = row["char"]
        physical = int(row["physical_index"])
        token = bytes.fromhex(row["code_hex"])
        if resolve_token(exe, token) == physical:
            candidates[char].add((token, physical))
        final_identity[physical] = char
    final_identity[170] = "괄"
    candidates["괄"].add((b"\xAB", 170))

    for physical, char in final_identity.items():
        token = v320.encode_index(physical)
        if token is not None and resolve_token(exe, token) == physical:
            candidates[char].add((token, physical))
    for char, physical in NEW_GLYPHS.items():
        token = v320.encode_index(physical)
        if token is None:
            raise BuildError(f"new glyph direct code missing: {char}")
        candidates[char].add((token, physical))

    candidates[" "] = {(b"\xA1", 160)}
    if resolve_token(exe, b"\xA1") != 160 or any(v320.read_plane(comm, 160)):
        raise BuildError("verified half-width space A1/physical160 drift")

    required_chars = {
        char
        for record in records.values()
        for char in semantic_characters(record.text)
    }
    code_map: dict[str, bytes] = {}
    physical_map: dict[str, int] = {}
    candidate_manifest: dict[str, list[int]] = {}
    for char in sorted(required_chars, key=ord):
        available = set(candidates.get(char, set()))
        if 0xAC00 <= ord(char) <= 0xD7A3 and char not in NEW_GLYPHS:
            expected = v320c.compose(pieces, char, official=True)
            available = {
                (token, physical)
                for token, physical in available
                if v320.read_plane(comm, physical) == expected
            }
        if not available:
            raise BuildError(f"no verified 16px glyph/code for {char!r} U+{ord(char):04X}")
        token, physical = min(available, key=lambda item: (len(item[0]), item[0], item[1]))
        if len(token) == 1 and token[0] == 0x9C:
            raise BuildError(f"legacy space/right-parenthesis code selected for {char!r}")
        code_map[char] = token
        physical_map[char] = physical
        candidate_manifest[char] = sorted({item[1] for item in available})
    return code_map, physical_map, pieces, candidate_manifest


def encode_text(text: str, code_map: dict[str, bytes]) -> bytes:
    output = bytearray()
    index = 0
    while index < len(text):
        for marker, token in ICON_TOKENS.items():
            if text.startswith(marker, index):
                output.extend(token)
                index += len(marker)
                break
        else:
            char = text[index]
            try:
                output.extend(code_map[char])
            except KeyError as exc:
                raise BuildError(f"missing encoder entry for {char!r} in {text!r}") from exc
            index += 1
            continue
        continue
    payload = bytes(output)
    # Empty table entries are intentional and encode as the allocator's lone
    # trailing 0x00.  Only embedded terminators/sentinels are forbidden.
    if b"\x00" in payload or b"\xFF" in payload:
        raise BuildError(f"unsafe encoded UI payload: {text!r} {payload.hex(' ')}")
    return payload


def allocate_payloads(
    exe: bytearray, payloads: dict[int, bytes]
) -> tuple[dict[bytes, int], list[tuple[int, int]], int]:
    unique = set(payloads.values())
    required = sum(len(payload) + 1 for payload in unique)
    if len(unique) != EXPECTED_UNIQUE_PAYLOADS or required != EXPECTED_REQUIRED_POOL_BYTES:
        raise BuildError(f"payload census drift: {len(unique)}/{required}")
    for start, end in POOL_SEGMENTS:
        exe[start:end] = bytes(end - start)
    free = list(POOL_SEGMENTS)
    locations: dict[bytes, int] = {}
    for payload in sorted(unique, key=lambda item: (-len(item), item)):
        size = len(payload) + 1
        candidates = [
            (end - start - size, slot, start, end)
            for slot, (start, end) in enumerate(free)
            if end - start >= size
        ]
        if not candidates:
            raise BuildError(f"UI pool allocation failed: need={size} free={sum(e-s for s,e in free)}")
        _waste, slot, start, end = min(candidates)
        exe[start : start + len(payload)] = payload
        exe[start + len(payload)] = 0
        locations[payload] = start
        free[slot] = (start + size, end)
    remaining = sum(end - start for start, end in free)
    if remaining != EXPECTED_POOL_FREE_BYTES:
        raise BuildError(f"UI pool free-byte drift: {remaining}")
    return locations, free, required


def write_new_glyphs(
    before: bytes, pieces: tuple[tuple[int, ...], ...]
) -> tuple[bytes, dict[str, tuple[int, ...]]]:
    with ASCII.open("rb") as handle:
        ascii_glyphs = pickle.load(handle)
    if not isinstance(ascii_glyphs, dict) or set(ascii_glyphs) != {
        chr(code) for code in range(0x20, 0x7F)
    }:
        raise BuildError("ASCII 16px artifact structure drift")
    comm = bytearray(before)
    rows_by_char: dict[str, tuple[int, ...]] = {}
    for char, physical in NEW_GLYPHS.items():
        rows = (
            v320.validate_rows(ascii_glyphs[char], f"ASCII {char}")
            if ord(char) < 0x80
            else v320c.compose(pieces, char, official=True)
        )
        rows_by_char[char] = rows
        v320.put_plane(comm, physical, rows)
        if v320.read_plane(comm, physical) != rows:
            raise BuildError(f"new glyph readback failed: {char}/{physical}")
    targets = set(NEW_GLYPHS.values())
    for physical in range(STATIC_LIMIT):
        if physical not in targets and v320.read_plane(comm, physical) != v320.read_plane(before, physical):
            raise BuildError(f"COMM neighboring plane changed: {physical}")
    for y in range(512):
        start = y * v320.ROW_BYTES + 120
        end = (y + 1) * v320.ROW_BYTES
        if comm[start:end] != before[start:end]:
            raise BuildError(f"COMM x>=240 changed on row {y}")
    return bytes(comm), rows_by_char


def changed_offsets(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise BuildError("member size changed")
    return {offset for offset, (old, new) in enumerate(zip(before, after, strict=True)) if old != new}


def allowed_comm_offsets(physical: int) -> set[int]:
    cell, _plane = divmod(physical, v320.PLANES)
    col, row = cell % v320.COLS, cell // v320.COLS
    return {
        (row * v320.CELL + y) * v320.ROW_BYTES + col * (v320.CELL // 2) + x // 2
        for y in range(v320.CELL)
        for x in range(v320.CELL)
    }


def main() -> None:
    fixed_inputs = (
        (BASE, BASE_SHA256, "V324 base"),
        (TABLE_MANIFEST, TABLE_MANIFEST_SHA256, "UI table manifest"),
        (SYSTEM_MANIFEST, SYSTEM_MANIFEST_SHA256, "system manifest"),
        (NONSTORY_MANIFEST, NONSTORY_MANIFEST_SHA256, "nonstory manifest"),
        (WORLD_MANIFEST, WORLD_MANIFEST_SHA256, "world manifest"),
        (ASSIGNMENTS, ASSIGNMENTS_SHA256, "character assignments"),
        (ATLAS, ATLAS_SHA256, "atlas mapping"),
        (PIECES, PIECES_SHA256, "Hanme pieces"),
        (ASCII, ASCII_SHA256, "Hanme ASCII"),
        (CELL_AUDIT, CELL_AUDIT_SHA256, "509-state cell audit"),
    )
    for path, expected, label in fixed_inputs:
        if not path.is_file() or v324.sha256_file(path) != expected:
            raise BuildError(f"{label} hash mismatch: {path}")
    if tuple(v42.pool_segments()) != POOL_SEGMENTS or sum(end - start for start, end in POOL_SEGMENTS) != POOL_BYTES:
        raise BuildError("verified UI pool geometry drift")

    infos, before = v324.read_archive(BASE)
    if sha256_bytes(before[PSX]) != BASE_PSX_SHA256 or sha256_bytes(before[COMM]) != BASE_COMM_SHA256:
        raise BuildError("V324 member hash drift")
    records = load_records()
    audit_aligned_pool_pointers(before[PSX], records)
    glyph_audit = prove_new_glyph_targets(before, records)
    code_map, physical_map, pieces, candidate_manifest = build_code_map(
        before[PSX], before[COMM], records
    )

    # Snapshot every V324 subsystem that this UI-only build must preserve.
    preserved_ranges = {
        "resident_source": (v324.SOURCE_FILE, v324.SOURCE_FILE + v324.COPY_SIZE),
        "lookup": (
            v324.file_offset(v324.LOOKUP_RAM),
            v324.file_offset(v324.LOOKUP_RAM) + v324.LOOKUP_BYTES,
        ),
        "range_descriptor": (v324.DESCRIPTOR_FILE, v324.DESCRIPTOR_FILE + v324.DESCRIPTOR_SIZE),
        "range_uv": (v324.UV_FILE, v324.UV_FILE + v324.UV_SIZE),
        "discarded_v323_cave": (
            v324.BAD_V323_CAVE_FILE,
            v324.BAD_V323_CAVE_FILE + v324.BAD_V323_CAVE_SIZE,
        ),
    }
    preserved_hashes = {
        name: sha256_bytes(before[PSX][start:end])
        for name, (start, end) in preserved_ranges.items()
    }
    hud_snapshots = {
        pointer: (
            bytes(before[PSX][pointer : pointer + 4]),
            pointer_target(before[PSX], pointer),
            raw_string(before[PSX], pointer_target(before[PSX], pointer)),
        )
        for pointer in HUD_POINTERS
    }

    payloads = {
        pointer: encode_text(record.text, code_map)
        for pointer, record in records.items()
    }
    exe = bytearray(before[PSX])
    locations, free, required = allocate_payloads(exe, payloads)
    ui_rows: list[dict[str, object]] = []
    for pointer, record in sorted(records.items()):
        payload = payloads[pointer]
        target = locations[payload]
        struct.pack_into("<I", exe, pointer, RAM_TO_FILE + target)
        if pointer_target(exe, pointer) != target or raw_string(exe, target) != payload:
            raise BuildError(f"UI pointer/payload readback failed: 0x{pointer:X}")
        space_count = record.text.count(" ")
        ui_rows.append(
            {
                "pointer_offset": f"0x{pointer:X}",
                "categories": "+".join(record.categories),
                "selected_category": record.category,
                "source_text": record.source_text,
                "korean": record.text,
                "string_offset": f"0x{target:X}",
                "encoded_bytes": len(payload),
                "space_count": space_count,
                "space_code": "A1" if space_count else "",
                "encoded_hex": payload.hex(" ").upper(),
            }
        )

    comm, new_rows = write_new_glyphs(before[COMM], pieces)
    final = dict(before)
    final[PSX] = bytes(exe)
    final[COMM] = comm

    for name, (start, end) in preserved_ranges.items():
        if sha256_bytes(final[PSX][start:end]) != preserved_hashes[name]:
            raise BuildError(f"V324 preserved subsystem changed: {name}")
    for pointer, (pointer_bytes, target, payload) in hud_snapshots.items():
        if final[PSX][pointer : pointer + 4] != pointer_bytes:
            raise BuildError(f"HUD pointer changed: 0x{pointer:X}")
        if pointer_target(final[PSX], pointer) != target or raw_string(final[PSX], target) != payload:
            raise BuildError(f"HUD payload changed: 0x{pointer:X}")

    changed_members = [name for name in before if before[name] != final[name]]
    if set(changed_members) != {COMM, PSX} or len(changed_members) != 2:
        raise BuildError(f"changed member set drift: {changed_members}")
    if any(len(before[name]) != len(final[name]) for name in before):
        raise BuildError("archive member size drift")

    psx_changes = changed_offsets(before[PSX], final[PSX])
    allowed_psx = {
        offset for start, end in POOL_SEGMENTS for offset in range(start, end)
    } | {
        offset for pointer in records for offset in range(pointer, pointer + 4)
    }
    if not psx_changes or not psx_changes <= allowed_psx:
        raise BuildError(f"PSX Expected-Write violation: {sorted(psx_changes - allowed_psx)[:8]}")
    comm_changes = changed_offsets(before[COMM], final[COMM])
    allowed_comm = set().union(*(allowed_comm_offsets(index) for index in NEW_GLYPHS.values()))
    if not comm_changes or not comm_changes <= allowed_comm:
        raise BuildError(f"COMM Expected-Write violation: {sorted(comm_changes - allowed_comm)[:8]}")

    output_path, output_hash = v324.write_archive(OUTPUT_STEM, infos, final, None)
    delta_path, delta_hash = v324.write_archive(DELTA_STEM, infos, final, {COMM, PSX})
    with ZipFile(output_path) as archive:
        names = [info.filename for info in archive.infolist() if not info.is_dir()]
        expected_names = [info.filename for info in infos if not info.is_dir()]
        if names != expected_names or any(archive.read(name) != final[name] for name in final):
            raise BuildError("full ZIP round-trip/topology mismatch")
    with ZipFile(delta_path) as archive:
        if set(archive.namelist()) != {COMM, PSX}:
            raise BuildError("delta ZIP member set mismatch")
        if any(archive.read(name) != final[name] for name in (COMM, PSX)):
            raise BuildError("delta ZIP payload mismatch")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    with (ANALYSIS / "ui_reencode.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(ui_rows[0]))
        writer.writeheader()
        writer.writerows(ui_rows)
    for row in glyph_audit:
        char = str(row["char"])
        row["after_plane_sha256"] = sha256_bytes(struct.pack(">16H", *new_rows[char]))
        row["code_candidates"] = ",".join(map(str, candidate_manifest.get(char, [])))
    with (ANALYSIS / "glyph_allocations.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(glyph_audit[0]))
        writer.writeheader()
        writer.writerows(glyph_audit)
    with (ANALYSIS / "expected_writes.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("member", "offset", "before", "after", "region"))
        for member, offsets in ((PSX, psx_changes), (COMM, comm_changes)):
            for offset in sorted(offsets):
                if member == PSX:
                    region = "ui_pool" if in_pool(offset) else "ui_pointer"
                else:
                    region = "new_ui_glyph_plane"
                writer.writerow(
                    (
                        member,
                        f"0x{offset:X}",
                        f"{before[member][offset]:02X}",
                        f"{final[member][offset]:02X}",
                        region,
                    )
                )

    manifest = {
        "build": "V325 TEST_ONLY pointer-proven UI re-encode for Hanme16",
        "base": {"path": str(BASE), "sha256": BASE_SHA256},
        "output": {"path": str(output_path), "sha256": output_hash},
        "delta": {"path": str(delta_path), "sha256": delta_hash},
        "changed_members": changed_members,
        "changed_bytes": {PSX: len(psx_changes), COMM: len(comm_changes)},
        "ui": {
            "source_rows": EXPECTED_SOURCE_ROWS,
            "unique_manifest_pointers": EXPECTED_UNIQUE_POINTERS,
            "rebuilt_pointers": len(records),
            "hud_binary_pointers_preserved": len(HUD_POINTERS),
            "unique_payloads": len(set(payloads.values())),
            "pool_bytes": POOL_BYTES,
            "required_bytes": required,
            "free_bytes": sum(end - start for start, end in free),
            "space": "A1 -> physical160 blank/half-width; legacy literal 9C forbidden",
            "normalizations": ["LV -> 레벨", "레벨 +1 -> 레벨 1"],
        },
        "glyphs": {
            char: {
                "physical_index": physical,
                "code_hex": v320.encode_index(physical).hex(" ").upper(),
                "source": "ascii_16px.pkl" if ord(char) < 0x80 else "official Hanme 8x4x4 composition",
            }
            for char, physical in NEW_GLYPHS.items()
        },
        "preserved": {
            "V324_resident_lookup_cursor": preserved_hashes,
            "HUD_binary_pointers": [f"0x{pointer:X}" for pointer in HUD_POINTERS],
            "all_DAT": "byte exact",
        },
        "runtime": "PENDING user cold boot; load/save, equipment, item, skill, battle prompts",
        "release_status": "DIAGNOSTIC; DO NOT DISTRIBUTE",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V325 TEST ONLY - pointer-proven Hanme16 UI re-encode",
        f"base={BASE.name}",
        f"output={output_path.name}",
        f"sha256={output_hash}",
        f"delta={delta_path.name}",
        f"delta_sha256={delta_hash}",
        f"changed_members={','.join(changed_members)}",
        f"changed_bytes={PSX}:{len(psx_changes)},{COMM}:{len(comm_changes)}",
        f"ui_records={len(records)}; unique_payloads={len(set(payloads.values()))}",
        f"pool={required}/{POOL_BYTES}B; free={sum(end-start for start,end in free)}B",
        "space=A1/physical160 half-width; legacy literal 9C removed at character boundaries",
        "new_glyphs=" + ",".join(f"{char}:{physical}" for char, physical in NEW_GLYPHS.items()),
        "V324 resident lookup/range cursor/HUD binary pointers=byte exact",
        "all DAT=byte exact",
        "runtime=PENDING cold boot and UI traversal; TEST_ONLY",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
