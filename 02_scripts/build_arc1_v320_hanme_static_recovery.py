#!/usr/bin/env python3
"""Build V320: Hanme rollback plus source-aligned, cache-free 16px text.

V319R proved that the 15-column 16px renderer, E2 slots and broad V241
content all run, but it also exposed two inherited V240 defects:

* direct codes that still fall in the V153 cache range table are diverted to
  dead cache slots even though V318 disabled cache uploads; their wrapped V
  coordinates read unrelated low-page glyphs (마->뜨, 전->료, ...), and
* V240 identified E9/EA through a stale flat lookup address, so many otherwise
  known virtual characters were rewritten to a blank.

This builder keeps V319R's verified geometry and all 164 cumulative members,
rolls COMM.IMG back to the exact V318 Hanme atlas, and re-encodes text from the
V238 raw tokens with two independent identity sources:

1. code_map_voted.pkl (alignment evidence, authoritative on conflicts), and
2. the live V238 packed 11-bit E9/EA table plus the V190 source manifest.

Every replacement keeps its original byte width.  Direct codes bypass the
dynamic range/cache path.  A missing two-byte spelling reuses the same E9/EA
slot whose historical semantic is that character; its lookup entry becomes a
static physical index.  Only characters with no such virtual slot get a new
direct two-byte cell.  No unrelated virtual slot is repurposed.

The output is TEST_ONLY until a cold boot covers dialogue, UI, battle and the
world-map transition.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import pickle
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from build_arc1_v231_static_promotion_restored162 import text_regions  # noqa: E402


V238 = ROOT / "03_output/arc1_v238_glyph_16px_TEST_ONLY_8816AF49.zip"
V238_SHA256 = "8816AF49683A8529E5C0B29CAF0676A32029DA283613F89605A759A383F8FFE5"
V318 = ROOT / "03_output/arc1_v318_v241_nocache_recovery_TEST_ONLY_50B30D67.zip"
V318_SHA256 = "50B30D67FC5856B548A986EB17470AF179EC0E3CFAF595F2291C225F1EF8DFBF"
BASE = ROOT / "03_output/arc1_v319_pilgi16_integration_TEST_ONLY_07418C00.zip"
BASE_SHA256 = "07418C0024C4059C550E1584FC29340C6B97D9CF9B9DE778CA1FE38ACCB74A49"

ART = ROOT / "01_work/analysis/hangul_johab_16px"
VOTED_MAP = ART / "code_map_voted.pkl"
VOTED_MAP_SHA256 = "514ACCDB7329A0D18BB547F2C09E115A8A3E34DD412672BE85826BC54259866A"
CODE_TO_CHAR = ART / "code_to_char.pkl"
CODE_TO_CHAR_SHA256 = "D2FB3A64C3E2203A1012590BEE24A36EAB30D0B5A9691A86BAC518B97A158E23"
PIECES = ART / "pieces_1bpp.bin"
PIECES_SHA256 = "409ABA72F4BA2282AA5C4E4982A9EEA16FBD14FB0413A40E151537A6653E2904"
ASCII = ART / "ascii_16px.pkl"
ASCII_SHA256 = "36BBEF684D730517042E2174E5D6D12A639D9DDD60E40529E2AEE29C7AE141BB"
CACHE_GLYPHS = ROOT / "01_work/analysis/cache_glyphs/glyphs.pkl"
CACHE_GLYPHS_SHA256 = "7A3EC1747B4592985368D97B869CDF41464266F189B221C1D9192D6B7940F1E5"
SOURCE_MANIFEST = ROOT / "01_work/analysis/arc1_v190_dynamic_owner_repair/source_manifest.csv"
SOURCE_MANIFEST_SHA256 = "A629A8C2010C1C34CB40B6667A2279AB5EB5BE78F3AE8750768C3A42E1D68B00"
ATLAS_MAPPING = ROOT / "01_work/analysis/arc1_v319_pilgi16_integration/atlas_mapping.csv"
ATLAS_MAPPING_SHA256 = "9553E7643621CC80C23355067611EAE7650FEF7CB547DC9115B62157DB0C3122"
CELL_AUDIT = ROOT / "01_work/analysis/font_cell_audit_full/cell_consumers.csv"
CELL_AUDIT_SHA256 = "63EF327777CC8A4E072AF68B8A1FE2B2EF4DFD8570D6176980157B7BBF7D5A73"

OUTPUT_DIR = ROOT / "03_output"
ANALYSIS_DIR = ROOT / "01_work/analysis/arc1_v320_hanme_static_recovery"
OUTPUT_STEM = "arc1_v320_hanme_static_recovery_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v319"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
RAM_TO_FILE = 0x8011A800
ROW_BYTES = 896
CELL = 16
COLS = 15
PLANES = 4
FULL_ROWS = 512 // CELL
ONE_BYTE_LIMIT = 220
EXPECTED_MEMBERS = 164
EXPECTED_HANME_COMM_SHA256 = "D0A59E8315A7886A4A5E375D5DBF7E2ABD6B99D7F75A45EF1180E48CE8AE597B"

LOOKUP_RAM = 0x801A7520
LOOKUP_SLOTS = 0x19D
CACHE_MARK = 0x600
SLOT_BASE = 0x45000
SLOT_SIZE = 0x80

# Runtime copy destination 0x801FF348 is sourced uniquely from this EXE block.
DECODER_SOURCE = 0x8EE70
DECODER_SOURCE_SIZE = 512
DECODER_SOURCE_SHA256 = "1D3A492607DAF934697975A38C64573787761701C0A4391B3FABB7067CBCB20B"
DECODER_PATCHES = {
    DECODER_SOURCE + 0x14: (0x1500000D, 0x1500002F),  # one-byte -> local stock trampoline
    DECODER_SOURCE + 0x1C: (0x2C6800E9, 0x0805ACFC),  # every non-E9/EA 2B -> stock decoder
    DECODER_SOURCE + 0x20: (0x1100002A, 0x00000000),  # jump delay slot
}
SPACE_COMPARE_RAM = 0x8016B524
SPACE_COMPARE_WORDS = (0x3409009B, 0x340900A0)  # old index 155 -> V240 blank index 160

REGION_COUNT = 8448
REGION_SHA256 = "74AB263AD491EF64405E42D1306FBCA062ED016D3505FB491A4F7495413431F5"
EXPECTED_VOTED_CODES = 643
EXPECTED_DERIVED_CODES = 399
EXPECTED_DERIVED_CONFLICTS = {bytes.fromhex("E98E"), bytes.fromhex("E99E")}
EXPECTED_EFFECTIVE_CODES = 892
EXPECTED_KNOWN_OCCURRENCES = 97_080
# ``text_regions`` deliberately stops at a run-ending orphan lead/control
# byte.  Those EXE-pool tails are not runtime tokens and must not influence
# allocation safety or the reproducible occurrence census.
EXPECTED_UNKNOWN_OCCURRENCES = 35_032
EXPECTED_CONTROL_TOKENS = 5_634
EXPECTED_CHAR_WIDTH_PAIRS = 750
EXPECTED_UNKNOWN_VIRTUAL_OCCURRENCES = 48
EXPECTED_UNKNOWN_DIRECT_OCCURRENCES = 34_984
EXPECTED_UNKNOWN_DYNAMIC_OCCURRENCES = 0
EXPECTED_DIRECT_REUSE = 555
EXPECTED_MISSING_ONE = 7
EXPECTED_MISSING_TWO = 188
EXPECTED_VIRTUAL_ALIASES = 176
EXPECTED_DIRECT_NEW_TWO = 12
EXPECTED_NEW_PHYSICAL_ONE = 7
EXPECTED_NEW_PHYSICAL_TWO = 85

V240_JUNG_GROUP = (
    0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 3, 1, 2, 3, 3, 3, 2, 1, 3, 0,
)


class BuildError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def file_offset(address: int) -> int:
    return address - RAM_TO_FILE


def word(blob: bytes | bytearray, address: int) -> int:
    return struct.unpack_from("<I", blob, file_offset(address))[0]


def clone_zipinfo(info: ZipInfo) -> ZipInfo:
    clone = ZipInfo(info.filename, info.date_time)
    for attribute in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(clone, attribute, getattr(info, attribute))
    return clone


def read_archive(path: Path) -> tuple[list[ZipInfo], dict[str, bytes]]:
    with ZipFile(path) as archive:
        infos = archive.infolist()
        if len({info.filename for info in infos}) != len(infos):
            raise BuildError(f"duplicate member in {path}")
        members = {info.filename: archive.read(info.filename) for info in infos if not info.is_dir()}
    return infos, members


def write_archive(
    stem: str,
    infos: list[ZipInfo],
    members: dict[str, bytes],
    selected: set[str] | None,
) -> tuple[Path, str]:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    temporary = OUTPUT_DIR / f".{stem}.{os.getpid()}.building.zip"
    if temporary.exists():
        raise BuildError(f"temporary output exists: {temporary}")
    try:
        with ZipFile(temporary, "w", ZIP_DEFLATED, compresslevel=1) as archive:
            for info in infos:
                if info.is_dir():
                    if selected is None:
                        archive.writestr(clone_zipinfo(info), b"")
                    continue
                if selected is None or info.filename in selected:
                    archive.writestr(clone_zipinfo(info), members[info.filename])
        digest = sha256_file(temporary)
        final = OUTPUT_DIR / f"{stem}_{digest[:8]}.zip"
        if final.exists():
            if sha256_file(final) != digest:
                raise BuildError(f"existing output differs: {final}")
            temporary.unlink()
        else:
            temporary.replace(final)
        return final, digest
    finally:
        if temporary.exists():
            temporary.unlink()


def encode_index(index: int) -> bytes | None:
    if 0 <= index < ONE_BYTE_LIMIT:
        return bytes((index + 1,))
    lead_delta, trail = divmod(index - 0xDB, 255)
    if 0 <= lead_delta <= 3 and 1 <= trail <= 0xFE:
        return bytes((0xDD + lead_delta, trail))
    return None


def direct_index(token: bytes) -> int | None:
    if len(token) == 1:
        return token[0] - 1 if 0x01 <= token[0] <= 0xDC else None
    if len(token) != 2:
        return None
    lead, trail = token
    if lead in (0xE9, 0xEA) or not (lead >= 0xDD and 1 <= trail <= 0xFE):
        return None
    return (lead - 0xDD) * 255 + trail + 0xDB


def virtual_token(slot: int) -> bytes:
    if not 0 <= slot < 508:
        raise BuildError(f"virtual slot outside E9/EA space: {slot}")
    return bytes((0xE9 + slot // 254, slot % 254 + 1))


def virtual_slot(token: bytes) -> int | None:
    if len(token) != 2 or token[0] not in (0xE9, 0xEA) or not 1 <= token[1] <= 0xFE:
        return None
    return (token[0] - 0xE9) * 254 + token[1] - 1


def lookup_get(exe: bytes | bytearray, slot: int) -> int:
    if not 0 <= slot < LOOKUP_SLOTS:
        raise BuildError(f"lookup slot out of live range: {slot}")
    bit = slot * 11
    byte_index, shift = divmod(bit, 8)
    at = file_offset(LOOKUP_RAM) + byte_index
    value = exe[at] | (exe[at + 1] << 8) | (exe[at + 2] << 16)
    return (value >> shift) & 0x7FF


def lookup_set(exe: bytearray, slot: int, value: int) -> None:
    if not 0 <= value < 0x800:
        raise BuildError(f"lookup value outside 11-bit range: {value}")
    bit = slot * 11
    byte_index, shift = divmod(bit, 8)
    at = file_offset(LOOKUP_RAM) + byte_index
    packed = exe[at] | (exe[at + 1] << 8) | (exe[at + 2] << 16)
    packed = (packed & ~(0x7FF << shift)) | (value << shift)
    exe[at] = packed & 0xFF
    exe[at + 1] = (packed >> 8) & 0xFF
    exe[at + 2] = (packed >> 16) & 0xFF


def is_control(data: bytes | bytearray, offset: int) -> bool:
    value = data[offset]
    return value == 0xE2 or 0xE3 <= value <= 0xE8


def token_width(value: int) -> int:
    return 1 if value < 0xDD else 2


def region_fingerprint(regions: list[tuple[str, int, int]]) -> str:
    digest = hashlib.sha256()
    for name, start, end in regions:
        digest.update(name.encode("utf-8"))
        digest.update(struct.pack("<II", start, end))
    return digest.hexdigest().upper()


def validate_rows(rows: object, label: str) -> tuple[int, ...]:
    if not isinstance(rows, (list, tuple)) or len(rows) != CELL:
        raise BuildError(f"{label}: expected 16 rows")
    values = tuple(int(value) for value in rows)
    if any(value < 0 or value >= 1 << CELL for value in values):
        raise BuildError(f"{label}: row outside 16-bit range")
    return values


def read_plane(buf: bytes | bytearray, index: int) -> tuple[int, ...]:
    if not 0 <= index < COLS * FULL_ROWS * PLANES:
        raise BuildError(f"physical index outside 16px low page: {index}")
    cell, plane = divmod(index, PLANES)
    col, row = cell % COLS, cell // COLS
    bit = 1 << plane
    rows = []
    for y in range(CELL):
        value = 0
        base = (row * CELL + y) * ROW_BYTES + col * (CELL // 2)
        for x in range(CELL):
            at = base + x // 2
            shift = 0 if x % 2 == 0 else 4
            if ((buf[at] >> shift) & 0x0F) & bit:
                value |= 1 << (CELL - 1 - x)
        rows.append(value)
    return tuple(rows)


def put_plane(buf: bytearray, index: int, rows: tuple[int, ...]) -> None:
    validate_rows(rows, f"put index {index}")
    cell, plane = divmod(index, PLANES)
    col, row = cell % COLS, cell // COLS
    bit = 1 << plane
    for y, source in enumerate(rows):
        base = (row * CELL + y) * ROW_BYTES + col * (CELL // 2)
        for x in range(CELL):
            at = base + x // 2
            shift = 0 if x % 2 == 0 else 4
            nibble = (buf[at] >> shift) & 0x0F
            if (source >> (CELL - 1 - x)) & 1:
                nibble |= bit
            else:
                nibble &= ~bit & 0x0F
            keep = 0xF0 if shift == 0 else 0x0F
            buf[at] = (buf[at] & keep) | (nibble << shift)


def load_pieces(raw: bytes) -> tuple[tuple[int, ...], ...]:
    if len(raw) != 360 * CELL * 2:
        raise BuildError(f"piece blob size drift: {len(raw)}")
    pieces = tuple(
        tuple(struct.unpack_from(">16H", raw, index * CELL * 2))
        for index in range(360)
    )
    expected_blank = (
        {beol * 20 for beol in range(8)}
        | {160 + beol * 22 for beol in range(4)}
        | {248 + beol * 28 for beol in range(4)}
    )
    actual_blank = {index for index, rows in enumerate(pieces) if not any(rows)}
    if actual_blank != expected_blank:
        raise BuildError("historical piece layout drift")
    return pieces


def compose_hangul(pieces: tuple[tuple[int, ...], ...], ch: str) -> tuple[int, ...]:
    codepoint = ord(ch)
    if not 0xAC00 <= codepoint <= 0xD7A3:
        raise BuildError(f"not Hangul: U+{codepoint:04X}")
    value = codepoint - 0xAC00
    cho, remainder = divmod(value, 588)
    jung, jong = divmod(remainder, 28)
    group = V240_JUNG_GROUP[jung]
    indices = [
        (group + (4 if jong else 0)) * 20 + cho + 1,
        160 + ((1 if cho in (0, 15) else 0) + (2 if jong else 0)) * 22 + jung + 1,
    ]
    if jong:
        indices.append(248 + group * 28 + jong)
    rows = tuple(
        pieces[indices[0]][y]
        | pieces[indices[1]][y]
        | (pieces[indices[2]][y] if jong else 0)
        for y in range(CELL)
    )
    if not any(rows):
        raise BuildError(f"blank Hangul synthesis: {ch}")
    return rows


def safe_geometry(index: int, audit: dict[tuple[int, int], int]) -> bool:
    cell = index // PLANES
    x0 = (cell % COLS) * CELL
    y0 = (cell // COLS) * CELL
    if x0 + CELL > 252 or y0 + CELL > 256:
        return False
    overlaps = {
        (y // 12, x // 12)
        for y in range(y0, y0 + CELL)
        for x in range(x0, x0 + CELL)
    }
    return all(audit.get(cell_key, -1) == 0 for cell_key in overlaps)


def slot_from_disk_id(value: int) -> int | None:
    if 0x81 <= value <= 0xA8:
        return value - 0x81
    if 0xAA <= value <= 0xD0:
        return value - 0x82
    return None


def main() -> None:
    fixed_inputs = (
        (V238, V238_SHA256, "V238 source"),
        (V318, V318_SHA256, "V318 Hanme"),
        (BASE, BASE_SHA256, "V319R base"),
        (VOTED_MAP, VOTED_MAP_SHA256, "voted map"),
        (CODE_TO_CHAR, CODE_TO_CHAR_SHA256, "old physical map"),
        (PIECES, PIECES_SHA256, "Hanme pieces"),
        (ASCII, ASCII_SHA256, "Hanme ASCII"),
        (CACHE_GLYPHS, CACHE_GLYPHS_SHA256, "historical cache glyphs"),
        (SOURCE_MANIFEST, SOURCE_MANIFEST_SHA256, "dynamic source manifest"),
        (ATLAS_MAPPING, ATLAS_MAPPING_SHA256, "V319 atlas mapping"),
        (CELL_AUDIT, CELL_AUDIT_SHA256, "509-state cell audit"),
    )
    for path, expected, label in fixed_inputs:
        if not path.is_file() or sha256_file(path) != expected:
            raise BuildError(f"{label} hash mismatch: {path}")

    infos, before = read_archive(BASE)
    source_infos, source = read_archive(V238)
    hanme_infos, hanme = read_archive(V318)
    names = [info.filename for info in infos if not info.is_dir()]
    if len(before) != EXPECTED_MEMBERS:
        raise BuildError(f"base member count drift: {len(before)}")
    if names != [info.filename for info in source_infos if not info.is_dir()]:
        raise BuildError("V238 member order/topology drift")
    if names != [info.filename for info in hanme_infos if not info.is_dir()]:
        raise BuildError("V318 member order/topology drift")
    if any(len(before[name]) != len(source[name]) or len(before[name]) != len(hanme[name]) for name in names):
        raise BuildError("historical member size drift")
    if sha256_bytes(hanme[COMM]) != EXPECTED_HANME_COMM_SHA256:
        raise BuildError("V318 Hanme COMM hash drift")

    regions_source = list(text_regions(source))
    regions_base = list(text_regions(before))
    if regions_source != regions_base:
        raise BuildError("V238/V319 text-region topology differs")
    if len(regions_source) != REGION_COUNT or region_fingerprint(regions_source) != REGION_SHA256:
        raise BuildError("text-region catalog drift")

    with VOTED_MAP.open("rb") as handle:
        voted = pickle.load(handle)
    with CODE_TO_CHAR.open("rb") as handle:
        code_to_char = pickle.load(handle)
    with ASCII.open("rb") as handle:
        ascii_glyphs = pickle.load(handle)
    with CACHE_GLYPHS.open("rb") as handle:
        cache_glyphs = pickle.load(handle)
    if not isinstance(voted, dict) or len(voted) != EXPECTED_VOTED_CODES:
        raise BuildError("voted map shape drift")
    if any(not isinstance(token, bytes) or len(token) not in (1, 2) or not isinstance(ch, str) or len(ch) != 1 for token, ch in voted.items()):
        raise BuildError("invalid voted map entry")

    manifest: dict[int, str] = {}
    with SOURCE_MANIFEST.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            source_id = int(row["source_id"])
            ch = row["char"]
            if source_id in manifest:
                raise BuildError(f"invalid source manifest row: {row}")
            if len(ch) == 1:
                manifest[source_id] = ch
            elif not (ch.startswith("<VIRTUAL:") and ch.endswith(">")):
                raise BuildError(f"invalid source manifest row: {row}")

    source_exe = source[PSX]
    base_exe = before[PSX]
    if [lookup_get(source_exe, slot) for slot in range(LOOKUP_SLOTS)] != [
        lookup_get(base_exe, slot) for slot in range(LOOKUP_SLOTS)
    ]:
        raise BuildError("V238/V319 packed lookup table differs")

    derived: dict[bytes, str] = {}
    derived_slot_by_char: dict[str, int] = {}
    for slot in range(LOOKUP_SLOTS):
        value = lookup_get(source_exe, slot)
        ch = manifest.get(value - CACHE_MARK) if value >= CACHE_MARK else code_to_char.get(value)
        if isinstance(ch, str) and len(ch) == 1:
            token = virtual_token(slot)
            derived[token] = ch
            # The live table contains two historical spellings for U+C64A.
            # Keep both token meanings in ``derived`` while choosing the
            # lowest slot deterministically when a new spelling needs one.
            derived_slot_by_char.setdefault(ch, slot)
    if len(derived) != EXPECTED_DERIVED_CODES:
        raise BuildError(f"derived E9/EA map drift: {len(derived)}")
    conflicts = {token for token in voted.keys() & derived.keys() if voted[token] != derived[token]}
    if conflicts != EXPECTED_DERIVED_CONFLICTS:
        raise BuildError(f"voted/lookup conflict set drift: {[x.hex() for x in conflicts]}")
    effective = dict(voted)
    for token, ch in derived.items():
        effective.setdefault(token, ch)
    if len(effective) != EXPECTED_EFFECTIVE_CODES:
        raise BuildError(f"effective source map drift: {len(effective)}")

    atlas_records: list[dict[str, str]] = []
    atlas_by_char: dict[str, list[int]] = defaultdict(list)
    with ATLAS_MAPPING.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            index = int(row["index"])
            if index != len(atlas_records):
                raise BuildError("atlas mapping index/order drift")
            atlas_records.append(row)
            if row["char"]:
                atlas_by_char[row["char"]].append(index)
    if len(atlas_records) != 728:
        raise BuildError(f"atlas mapping row count drift: {len(atlas_records)}")

    audit: dict[tuple[int, int], int] = {}
    with CELL_AUDIT.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            audit[(int(row["row"]), int(row["col"]))] = int(row["nontext_reads"])

    pair_uses: Counter[tuple[str, int]] = Counter()
    known_occurrences = unknown_occurrences = control_tokens = 0
    current_known_uses: Counter[int] = Counter()
    current_unknown_uses: Counter[int] = Counter()
    current_unknown_virtual_dynamic = False
    unknown_virtual_occurrences = 0
    unknown_direct_occurrences = 0
    unknown_dynamic_occurrences = 0

    def current_target(token: bytes) -> int | None:
        slot = virtual_slot(token)
        if slot is not None:
            if slot >= LOOKUP_SLOTS:
                return None
            value = lookup_get(base_exe, slot)
            return value if value < CACHE_MARK else None
        return direct_index(token)

    for name, start, end in regions_source:
        old = source[name]
        cur = before[name]
        offset = start
        while offset < end:
            if is_control(old, offset):
                if offset + 2 > end:
                    break
                if cur[offset : offset + 2] != old[offset : offset + 2]:
                    raise BuildError(f"control drift at {name}:0x{offset:X}")
                control_tokens += 1
                offset += 2
                continue
            width = token_width(old[offset])
            if offset + width > end:
                break
            if token_width(cur[offset]) != width:
                raise BuildError(f"token-width drift at {name}:0x{offset:X}")
            old_token = old[offset : offset + width]
            cur_token = cur[offset : offset + width]
            target = current_target(cur_token)
            ch = effective.get(old_token)
            if ch is None:
                unknown_occurrences += 1
                if virtual_slot(old_token) is None:
                    unknown_direct_occurrences += 1
                else:
                    unknown_virtual_occurrences += 1
                if target is not None:
                    current_unknown_uses[target] += 1
                slot = virtual_slot(cur_token)
                if slot is not None and slot < LOOKUP_SLOTS and lookup_get(base_exe, slot) >= CACHE_MARK:
                    current_unknown_virtual_dynamic = True
                    unknown_dynamic_occurrences += 1
            else:
                known_occurrences += 1
                pair_uses[(ch, width)] += 1
                if target is not None:
                    current_known_uses[target] += 1
            offset += width

    census = (
        known_occurrences, unknown_occurrences, control_tokens, len(pair_uses),
    )
    expected_census = (
        EXPECTED_KNOWN_OCCURRENCES, EXPECTED_UNKNOWN_OCCURRENCES,
        EXPECTED_CONTROL_TOKENS, EXPECTED_CHAR_WIDTH_PAIRS,
    )
    if census != expected_census:
        raise BuildError(f"token census drift: {census} != {expected_census}")
    unresolved_census = (
        unknown_virtual_occurrences,
        unknown_direct_occurrences,
        unknown_dynamic_occurrences,
    )
    expected_unresolved_census = (
        EXPECTED_UNKNOWN_VIRTUAL_OCCURRENCES,
        EXPECTED_UNKNOWN_DIRECT_OCCURRENCES,
        EXPECTED_UNKNOWN_DYNAMIC_OCCURRENCES,
    )
    if unresolved_census != expected_unresolved_census:
        raise BuildError(
            f"unresolved-token census drift: {unresolved_census} != "
            f"{expected_unresolved_census}"
        )
    if Counter(width for _ch, width in pair_uses) != Counter({1: 129, 2: 621}):
        raise BuildError("character-width census drift")

    assignments: dict[tuple[str, int], dict[str, object]] = {}
    used_physical: set[int] = set()
    for ch, width in sorted(pair_uses, key=lambda item: (item[1], ord(item[0]))):
        key = (ch, width)
        if ch == " ":
            index = 160 if width == 1 else 724
            code = encode_index(index)
            if code is None or len(code) != width or any(read_plane(hanme[COMM], index)):
                raise BuildError(f"space target invalid for width {width}")
            assignments[key] = {"mode": "space", "code": code, "physical": index, "slot": None}
            used_physical.add(index)
            continue
        candidates = [
            index for index in atlas_by_char.get(ch, [])
            if (code := encode_index(index)) is not None and len(code) == width
        ]
        if candidates:
            index = min(candidates)
            code = encode_index(index)
            assignments[key] = {"mode": "direct_existing", "code": code, "physical": index, "slot": None}
            used_physical.add(index)

    if len(assignments) != EXPECTED_DIRECT_REUSE:
        raise BuildError(f"direct reuse census drift: {len(assignments)}")
    missing_one = [key for key in pair_uses if key not in assignments and key[1] == 1]
    missing_two = [key for key in pair_uses if key not in assignments and key[1] == 2]
    if (len(missing_one), len(missing_two)) != (EXPECTED_MISSING_ONE, EXPECTED_MISSING_TWO):
        raise BuildError("missing width-specific glyph census drift")

    static_lookup_targets = {
        lookup_get(base_exe, slot)
        for slot in range(LOOKUP_SLOTS)
        if lookup_get(base_exe, slot) < CACHE_MARK
    }
    if current_unknown_virtual_dynamic:
        # A dynamic cache return aliases to the low-page indices 480..507 after
        # row*16 is stored through an 8-bit V field.  Never allocate there.
        current_unknown_uses.update({index: 1 for index in range(480, 508)})

    one_candidates = [
        index for index in range(ONE_BYTE_LIMIT)
        if index not in used_physical
        and index not in static_lookup_targets
        and current_unknown_uses[index] == 0
        and safe_geometry(index, audit)
    ]
    one_candidates.sort(key=lambda index: (current_known_uses[index], index))
    if len(one_candidates) != 14:
        raise BuildError(f"safe one-byte candidate census drift: {len(one_candidates)}")
    missing_one.sort(key=lambda key: (-pair_uses[key], ord(key[0])))
    allocated_rows: dict[int, tuple[int, ...]] = {}
    allocation_char: dict[int, str] = {}
    for key, index in zip(missing_one, one_candidates, strict=False):
        ch, width = key
        code = encode_index(index)
        if code is None or len(code) != width:
            raise BuildError(f"no one-byte encoding for allocation {index}")
        assignments[key] = {"mode": "direct_new", "code": code, "physical": index, "slot": None}
        used_physical.add(index)
        allocation_char[index] = ch
    if len(allocation_char) != EXPECTED_NEW_PHYSICAL_ONE:
        raise BuildError("one-byte allocation count drift")

    missing_two_with_virtual = [key for key in missing_two if key[0] in derived_slot_by_char]
    missing_two_direct = [key for key in missing_two if key[0] not in derived_slot_by_char]
    if (len(missing_two_with_virtual), len(missing_two_direct)) != (
        EXPECTED_VIRTUAL_ALIASES, EXPECTED_DIRECT_NEW_TWO,
    ):
        raise BuildError("virtual/direct two-byte split drift")

    # A virtual alias can point at an existing picture regardless of its direct
    # code width.  Only characters absent from the atlas need a new plane.
    needs_new_physical = {
        ch for ch, _width in missing_two_with_virtual if ch not in atlas_by_char
    } | {ch for ch, _width in missing_two_direct}
    if len(needs_new_physical) != EXPECTED_NEW_PHYSICAL_TWO:
        raise BuildError(f"new two-byte physical census drift: {len(needs_new_physical)}")

    two_candidates = [
        index for index in range(728, 960)
        if (code := encode_index(index)) is not None
        and len(code) == 2
        and index not in static_lookup_targets
        and current_unknown_uses[index] == 0
        and safe_geometry(index, audit)
    ]
    two_candidates.sort(key=lambda index: (any(read_plane(hanme[COMM], index)), index))
    if len(two_candidates) != EXPECTED_NEW_PHYSICAL_TWO:
        raise BuildError(
            f"safe two-byte capacity no longer closes: {len(two_candidates)} != "
            f"{EXPECTED_NEW_PHYSICAL_TWO}"
        )
    for ch, index in zip(sorted(needs_new_physical, key=ord), two_candidates, strict=True):
        allocation_char[index] = ch
        used_physical.add(index)

    physical_for_new_char = {ch: index for index, ch in allocation_char.items() if index >= 728}
    alias_slots: dict[int, tuple[str, int]] = {}
    for key in sorted(missing_two_with_virtual, key=lambda item: ord(item[0])):
        ch, _width = key
        slot = derived_slot_by_char[ch]
        if ch in atlas_by_char:
            physical = min(atlas_by_char[ch])
        else:
            physical = physical_for_new_char[ch]
        assignments[key] = {
            "mode": "virtual_static_new" if ch not in atlas_by_char else "virtual_static_existing",
            "code": virtual_token(slot),
            "physical": physical,
            "slot": slot,
        }
        if slot in alias_slots:
            raise BuildError(f"virtual slot assigned twice: {slot}")
        alias_slots[slot] = (ch, physical)

    for key in sorted(missing_two_direct, key=lambda item: ord(item[0])):
        ch, width = key
        physical = physical_for_new_char[ch]
        code = encode_index(physical)
        if code is None or len(code) != width:
            raise BuildError(f"new direct two-byte target is not encodable: {physical}")
        assignments[key] = {"mode": "direct_new", "code": code, "physical": physical, "slot": None}

    if len(assignments) != len(pair_uses):
        raise BuildError(f"unassigned character-width pairs: {set(pair_uses) - set(assignments)}")
    code_owner: dict[bytes, tuple[str, int]] = {}
    for key, assignment in assignments.items():
        code = assignment["code"]
        if not isinstance(code, bytes) or len(code) != key[1]:
            raise BuildError(f"bad code assignment for {key}")
        previous = code_owner.setdefault(code, key)
        if previous != key:
            raise BuildError(f"code collision: {code.hex()} {previous} {key}")

    pieces = load_pieces(PIECES.read_bytes())
    glyph_cache: dict[str, tuple[int, ...]] = {}

    def glyph_rows(ch: str) -> tuple[int, ...]:
        if ch in glyph_cache:
            return glyph_cache[ch]
        existing_shapes = {
            read_plane(hanme[COMM], index)
            for index in atlas_by_char.get(ch, [])
            if any(read_plane(hanme[COMM], index))
        }
        if len(existing_shapes) > 1:
            raise BuildError(f"multiple historical shapes for {ch!r}")
        if existing_shapes:
            rows = next(iter(existing_shapes))
        elif 0xAC00 <= ord(ch) <= 0xD7A3:
            rows = compose_hangul(pieces, ch)
        elif ch in ascii_glyphs:
            rows = validate_rows(ascii_glyphs[ch], f"ASCII {ch!r}")
        else:
            slot = derived_slot_by_char.get(ch)
            cached = cache_glyphs.get(slot) if slot is not None else None
            if not isinstance(cached, list) or len(cached) != 12:
                raise BuildError(f"no reproducible glyph source for U+{ord(ch):04X}")
            rows = tuple(((int(value) << 4) & 0xFFFF) for value in cached) + (0, 0, 0, 0)
        if not any(rows):
            raise BuildError(f"blank glyph source for U+{ord(ch):04X}")
        glyph_cache[ch] = rows
        return rows

    comm = bytearray(hanme[COMM])
    for index, ch in allocation_char.items():
        rows = glyph_rows(ch)
        put_plane(comm, index, rows)
        allocated_rows[index] = rows

    for index in range(COLS * FULL_ROWS * PLANES):
        actual = read_plane(comm, index)
        if index in allocated_rows:
            if actual != allocated_rows[index]:
                raise BuildError(f"allocated COMM plane readback differs: {index}")
        elif actual != read_plane(hanme[COMM], index):
            raise BuildError(f"unallocated Hanme plane changed: {index}")
    for y in range(512):
        if bytes(comm[y * ROW_BYTES + 120 : (y + 1) * ROW_BYTES]) != hanme[COMM][
            y * ROW_BYTES + 120 : (y + 1) * ROW_BYTES
        ]:
            raise BuildError(f"COMM changed right of x=239 on row {y}")

    members = {name: bytearray(data) for name, data in before.items()}
    expected_text_offsets: dict[str, set[int]] = defaultdict(set)
    replaced_occurrences = 0
    for name, start, end in regions_source:
        old = source[name]
        cur_before = before[name]
        out = members[name]
        offset = start
        while offset < end:
            if is_control(old, offset):
                if offset + 2 > end:
                    break
                if bytes(out[offset : offset + 2]) != old[offset : offset + 2]:
                    raise BuildError(f"control changed before rewrite at {name}:0x{offset:X}")
                offset += 2
                continue
            width = token_width(old[offset])
            if offset + width > end:
                break
            old_token = old[offset : offset + width]
            ch = effective.get(old_token)
            if ch is not None:
                code = assignments[(ch, width)]["code"]
                if not isinstance(code, bytes) or len(code) != width:
                    raise BuildError(f"width change at {name}:0x{offset:X}")
                out[offset : offset + width] = code
                expected_text_offsets[name].update(range(offset, offset + width))
                replaced_occurrences += 1
            elif bytes(out[offset : offset + width]) != cur_before[offset : offset + width]:
                raise BuildError(f"unknown token changed at {name}:0x{offset:X}")
            offset += width
    if replaced_occurrences != EXPECTED_KNOWN_OCCURRENCES:
        raise BuildError(f"replacement occurrence drift: {replaced_occurrences}")

    exe = members[PSX]
    if len(exe) != 587_776:
        raise BuildError(f"unexpected executable size: {len(exe)}")
    if sha256_bytes(bytes(exe[DECODER_SOURCE : DECODER_SOURCE + DECODER_SOURCE_SIZE])) != DECODER_SOURCE_SHA256:
        raise BuildError("resident decoder source block hash drift")
    prefix = bytes(exe[DECODER_SOURCE : DECODER_SOURCE + 64])
    if bytes(exe).count(prefix) != 1:
        raise BuildError("resident decoder source signature is not unique")
    for offset, (expected, replacement) in DECODER_PATCHES.items():
        actual = struct.unpack_from("<I", exe, offset)[0]
        if actual != expected:
            raise BuildError(f"decoder source word drift at file 0x{offset:X}: {actual:08X}")
        struct.pack_into("<I", exe, offset, replacement)

    if word(exe, SPACE_COMPARE_RAM) != SPACE_COMPARE_WORDS[0]:
        raise BuildError("space comparison word drift")
    struct.pack_into("<I", exe, file_offset(SPACE_COMPARE_RAM), SPACE_COMPARE_WORDS[1])

    lookup_before = [lookup_get(base_exe, slot) for slot in range(LOOKUP_SLOTS)]
    for slot, (_ch, physical) in alias_slots.items():
        lookup_set(exe, slot, physical)
    lookup_after = [lookup_get(exe, slot) for slot in range(LOOKUP_SLOTS)]
    for slot, (left, right) in enumerate(zip(lookup_before, lookup_after)):
        if slot in alias_slots:
            if right != alias_slots[slot][1] or right >= CACHE_MARK:
                raise BuildError(f"static alias table write failed at slot {slot}")
        elif right != left:
            raise BuildError(f"unselected lookup slot changed: {slot}")
    if len(alias_slots) != EXPECTED_VIRTUAL_ALIASES:
        raise BuildError(f"alias slot census drift: {len(alias_slots)}")

    # Frozen V319R geometry and cache-upload shutdown.
    frozen_words = {
        0x8016B150: 0xAE200008,
        0x8016B154: 0xA2200010,
        0x8016B15C: 0xAE20000C,
        0x8016B160: 0x3402000E,
        0x8016B168: 0x34020010,
        0x8016B16C: 0xA222000E,
        0x8016B174: 0xA222000F,
        0x8016B394: 0x3404000E,
        0x8016B398: 0x34050010,
        0x8016B39C: 0x34060002,
        0x8016B3A4: 0x00003821,
        0x8016B3D4: 0x08069D2E,
        0x8016B530: 0x3402003C,
        0x8016B5CC: 0x90C3000D,
        0x8016B5D0: 0x90C1000F,
        0x8016B5D4: 0x90C2000E,
        0x8016B5D8: 0x00611821,
        0x8016B5DC: 0xA0A3002A,
        0x8016B5E0: 0xA0A2002B,
        0x8016BEF4: 0x25080008,
        0x8016BEFC: 0x25290008,
        0x8011C860: 0x0C05DB87,
        0x8016B764: 0x27BDFFD0,
        # The E9/EA unpacker must continue reading the packed table patched
        # above, not a stale flat address from an intermediate experiment.
        0x801A780C: 0x3C0D801A,
        0x801A7810: 0x35AD7520,
    }
    for address, expected in frozen_words.items():
        if word(exe, address) != expected:
            raise BuildError(f"frozen V319 geometry drift at 0x{address:08X}")
    text_size = struct.unpack_from("<I", exe, 0x1C)[0]
    cache_upload_jal = struct.pack("<I", 0x0C07FD9A)
    if bytes(exe[0x800 : 0x800 + text_size]).count(cache_upload_jal):
        raise BuildError("dynamic cache upload JAL returned")

    members[COMM] = bytearray(comm)
    final_members = {name: bytes(data) for name, data in members.items()}
    if any(len(final_members[name]) != len(before[name]) for name in before):
        raise BuildError("a member changed size")

    lookup_byte_start = file_offset(LOOKUP_RAM)
    lookup_byte_end = lookup_byte_start + (LOOKUP_SLOTS * 11 + 7) // 8 + 2
    allowed_psx_extra = set(range(file_offset(SPACE_COMPARE_RAM), file_offset(SPACE_COMPARE_RAM) + 4))
    for offset in DECODER_PATCHES:
        allowed_psx_extra.update(range(offset, offset + 4))
    allowed_psx_extra.update(range(lookup_byte_start, lookup_byte_end))
    for name in before:
        if name == COMM:
            continue
        actual_diffs = {
            offset for offset, (left, right) in enumerate(zip(before[name], final_members[name]))
            if left != right
        }
        allowed = set(expected_text_offsets.get(name, set()))
        if name == PSX:
            allowed |= allowed_psx_extra
        if not actual_diffs <= allowed:
            first = min(actual_diffs - allowed)
            raise BuildError(f"unexpected write in {name} at 0x{first:X}")

    # Exhaustive semantic readback: mapped old occurrences must decode to their
    # assigned character; unknown occurrences and every control remain V319R.
    final_exe = final_members[PSX]
    for name, start, end in regions_source:
        old = source[name]
        base_data = before[name]
        out = final_members[name]
        offset = start
        while offset < end:
            if is_control(old, offset):
                if offset + 2 > end:
                    break
                if out[offset : offset + 2] != old[offset : offset + 2]:
                    raise BuildError(f"control readback failed at {name}:0x{offset:X}")
                offset += 2
                continue
            width = token_width(old[offset])
            if offset + width > end:
                break
            old_token = old[offset : offset + width]
            new_token = out[offset : offset + width]
            ch = effective.get(old_token)
            if ch is None:
                if new_token != base_data[offset : offset + width]:
                    raise BuildError(f"unknown readback changed at {name}:0x{offset:X}")
            elif new_token != assignments[(ch, width)]["code"]:
                raise BuildError(f"semantic readback code mismatch at {name}:0x{offset:X}")
            offset += width

    final_index_char = {
        int(row["index"]): row["char"] for row in atlas_records if row["char"]
    }
    final_index_char.update({index: ch for index, ch in allocation_char.items()})

    def resolve_final(token: bytes) -> int | None:
        slot = virtual_slot(token)
        if slot is not None:
            if slot >= LOOKUP_SLOTS:
                return None
            value = lookup_get(final_exe, slot)
            return value if value < CACHE_MARK else None
        return direct_index(token)

    code_to_char_final = {assignment["code"]: key[0] for key, assignment in assignments.items()}

    def decode_visible(name: str, site: int) -> str:
        data = final_members[name]
        start = site
        if data[start] == 0xE2:
            slot = slot_from_disk_id(data[start + 1])
            if slot is None:
                raise BuildError(f"invalid E2 id at {name}:0x{site:X}")
            start = SLOT_BASE + slot * SLOT_SIZE
            end = data.index(0, start, start + SLOT_SIZE)
        else:
            matches = [(s, e) for n, s, e in regions_source if n == name and s == site]
            if len(matches) != 1:
                raise BuildError(f"site region not unique: {name}:0x{site:X}")
            start, end = matches[0]
        result: list[str] = []
        offset = start
        while offset < end:
            if is_control(data, offset):
                if offset + 2 > end:
                    break
                if data[offset] == 0xE6 and data[offset + 1] == 1:
                    result.append("\n")
                offset += 2
                continue
            width = token_width(data[offset])
            if offset + width > end:
                break
            token = data[offset : offset + width]
            ch = code_to_char_final.get(token)
            if ch is None:
                index = resolve_final(token)
                ch = final_index_char.get(index, "�")
            result.append(ch)
            offset += width
        return "".join(result).rstrip()

    phrase_checks = {
        ("1/S1071.DAT", 0x47932): (
            "약속대로 이 마을에서", "정말로 자유롭게 해 줄 거지?",
        ),
        ("1/S1071.DAT", 0x4798E): (
            "촌장: 아아, 물론이지.", "하지만 그 전에", "봉인의 불꽃을...",
        ),
        ("1/S1011.DAT", 0x478AA): (
            "3천 년이나 계속 타오르는 정령의 산, 시온의 불꽃.",
        ),
        ("1/S1011.DAT", 0x47954): (
            "그런 걸 신경 쓰고 있을 때가 아니야!",
        ),
        ("1/S1011.DAT", 0x4799E): (
            "새해가 오면 팔렌시아 성에서", "나를 데리러 와.", "우리 일족의 규율이야.",
        ),
    }
    visible_samples: dict[str, str] = {}
    for (name, site), needles in phrase_checks.items():
        visible = decode_visible(name, site)
        flat = visible.replace("\n", "")
        for needle in needles:
            if needle not in flat:
                raise BuildError(
                    f"visible phrase guard failed at {name}:0x{site:X}: "
                    f"{needle!r} not in {flat!r}"
                )
        visible_samples[f"{name}:0x{site:X}"] = visible

    changed_members = [name for name in names if final_members[name] != before[name]]
    if PSX not in changed_members or COMM not in changed_members:
        raise BuildError("PSX/COMM did not change")
    output_path, output_hash = write_archive(OUTPUT_STEM, infos, final_members, None)
    delta_path, delta_hash = write_archive(DELTA_STEM, infos, final_members, set(changed_members))
    with ZipFile(output_path) as archive:
        if [info.filename for info in archive.infolist() if not info.is_dir()] != names:
            raise BuildError("output ZIP topology drift")
        for name in names:
            if archive.read(name) != final_members[name]:
                raise BuildError(f"output round-trip differs: {name}")
    with ZipFile(delta_path) as archive:
        if set(archive.namelist()) != set(changed_members):
            raise BuildError("delta member set drift")

    ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
    assignment_rows = []
    for key in sorted(assignments, key=lambda item: (item[1], ord(item[0]))):
        ch, width = key
        assignment = assignments[key]
        physical = int(assignment["physical"])
        assignment_rows.append(
            {
                "char": ch,
                "unicode": f"U+{ord(ch):04X}",
                "width": width,
                "occurrences": pair_uses[key],
                "mode": assignment["mode"],
                "code_hex": assignment["code"].hex(" ").upper(),
                "physical_index": physical,
                "virtual_slot": "" if assignment["slot"] is None else assignment["slot"],
                "new_physical_plane": int(physical in allocation_char),
                "target_was_blank_in_v318": int(not any(read_plane(hanme[COMM], physical))),
            }
        )
    with (ANALYSIS_DIR / "character_assignments.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=assignment_rows[0].keys())
        writer.writeheader()
        writer.writerows(assignment_rows)

    with (ANALYSIS_DIR / "physical_allocations.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        fieldnames = ("physical_index", "char", "unicode", "was_blank_v318", "safe_nontext")
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for index in sorted(allocation_char):
            ch = allocation_char[index]
            writer.writerow(
                {
                    "physical_index": index,
                    "char": ch,
                    "unicode": f"U+{ord(ch):04X}",
                    "was_blank_v318": int(not any(read_plane(hanme[COMM], index))),
                    "safe_nontext": int(safe_geometry(index, audit)),
                }
            )

    manifest_json = {
        "build": "V320 TEST_ONLY Hanme static recovery",
        "inputs": {
            "v238": V238_SHA256,
            "v318": V318_SHA256,
            "v319": BASE_SHA256,
            "voted_map": VOTED_MAP_SHA256,
            "source_manifest": SOURCE_MANIFEST_SHA256,
            "cell_audit": CELL_AUDIT_SHA256,
        },
        "source_identity": {
            "voted_codes": len(voted),
            "lookup_derived_codes": len(derived),
            "conflicts_voted_wins": [token.hex().upper() for token in sorted(conflicts)],
            "effective_codes": len(effective),
            "known_occurrences": known_occurrences,
            "unknown_occurrences_preserved": unknown_occurrences,
            "unknown_virtual_occurrences_preserved": unknown_virtual_occurrences,
            "unknown_direct_occurrences_preserved": unknown_direct_occurrences,
            "unknown_dynamic_occurrences": unknown_dynamic_occurrences,
            "control_tokens_preserved": control_tokens,
        },
        "atlas": {
            "font": "V318 historical Hanme 16px rollback",
            "new_one_byte_planes": EXPECTED_NEW_PHYSICAL_ONE,
            "new_two_byte_planes": EXPECTED_NEW_PHYSICAL_TWO,
            "new_planes_total": len(allocation_char),
            "virtual_aliases_static": len(alias_slots),
            "space_physical_index": 160,
            "space_advance": 6,
        },
        "runtime": {
            "direct_cache_range_bypass": True,
            "E9_EA_static_alias_path_preserved": True,
            "packet": [16, 16],
            "advance": 14,
            "line_pitch": 16,
            "cache_upload_direct_calls": 0,
        },
        "visible_samples": visible_samples,
        "output": {
            "path": str(output_path),
            "sha256": output_hash,
            "delta_path": str(delta_path),
            "delta_sha256": delta_hash,
            "changed_members": changed_members,
        },
        "runtime_status": "PENDING user cold boot",
        "known_limits": [
            "14px advance still overlaps adjacent 16px sprites by 2px",
            f"{unknown_direct_occurrences} unresolved direct occurrences retain V319R bytes and use the stock decoder",
            f"{unknown_virtual_occurrences} unresolved E9/EA occurrences retain static V319R targets; dynamic uses are zero",
            "final production reconstruction from pristine arc.zip remains future work",
        ],
    }
    (ANALYSIS_DIR / "build_manifest.json").write_text(
        json.dumps(manifest_json, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    report = [
        "V320 TEST ONLY - Hanme rollback and source-aligned static 16px recovery",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output_path.name}",
        f"sha256={output_hash}",
        f"delta_from_v319={delta_path.name}",
        f"delta_sha256={delta_hash}",
        f"changed_members={len(changed_members)}/{len(names)}",
        f"source_map=voted {len(voted)} + lookup-derived {len(derived)} -> effective {len(effective)}",
        f"occurrences=known {known_occurrences:,}; unknown preserved {unknown_occurrences:,}; controls {control_tokens:,}",
        f"assignments={len(assignments)} char/width pairs; direct reuse {EXPECTED_DIRECT_REUSE}; virtual static {len(alias_slots)}",
        f"new_physical_planes=one-byte {EXPECTED_NEW_PHYSICAL_ONE}; two-byte {EXPECTED_NEW_PHYSICAL_TWO}; total {len(allocation_char)}",
        "font=V318 historical Hanme 16px (Pilgi removed)",
        "decoder=direct DD/non-E9EA codes bypass the dynamic range/cache path",
        "E9_EA=historical same-character slots retained and pointed at static physical glyphs",
        "space=index160, 6px advance; packet 16x16; glyph advance14; line pitch16",
        "five_uploaded_state_phrases=STATIC PASS from final disk member bytes",
        "runtime=PENDING user cold boot",
        "known_limit=14px advance overlaps 16px glyphs by 2px",
        f"unknown_preserved=direct {unknown_direct_occurrences:,}; E9/EA {unknown_virtual_occurrences}; dynamic 0",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
    ]
    (ANALYSIS_DIR / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
