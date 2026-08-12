#!/usr/bin/env python3
"""Audit v189 text owners for references to superseded glyph addresses.

This script deliberately does *not* scan arbitrary DAT bytes.  Story ownership
comes only from ``script_original_full.csv`` and executable ownership comes only
from pointer manifests.  That boundary prevents binary script data from being
mistaken for text.

The report is also the input contract for the following repair build: every
proposed byte replacement has an owner, an exact byte offset, an intended
character and a same-width canonical replacement.
"""
from __future__ import annotations

import csv
import hashlib
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v171_ui_asset_recovery as v171  # noqa: E402
import plan_arc1_v171_ui_asset_recovery as v171_plan  # noqa: E402
import verify_arc1_v171_ui_asset_recovery as v171_verify  # noqa: E402


BASE = ROOT / "03_output/arc1_v189_dialogue_timing_choice_rows_DA219F8F.zip"
BASE_SHA256 = "DA219F8F46C5E3C537C5B8D4928EB4FAA5D0009CA6C916B772C94D423A3F67B6"
CONTROL = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
ORIGINAL = ROOT / "00_original/arc.zip"
ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"
TRANSLATED_CSV = ROOT / "05_docs/script_translated_full.csv"
UI_CSV = ROOT / "05_docs/ui_full_v42.csv"
SYSTEM_CSV = ROOT / "01_work/analysis/arc1_v171_native_ui_assets_28slot_cache/system_string_readback.csv"
RUNTIME_UI_CSV = ROOT / "05_docs/ui_runtime_repairs_v43.csv"
ASSIGNMENTS = ROOT / "01_work/analysis/dynamic_cache_v153_widthsafe/glyph_assignments.csv"
SOURCE_DIR = ROOT / "01_work/analysis/arc1_v171_ui_asset_recovery"
CELL_SAFETY = ROOT / "01_work/analysis/comm_physical_cell_safety/cells.csv"
OUT = ROOT / "01_work/analysis/arc1_v189_text_glyph_ownership_audit"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
R2F = 0x8011A800
ROW_BYTES = 896
CELL = 12
IPR = 84
PLANES = 4
SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT_COUNT = 79
FILLER = 0x9C


@dataclass(frozen=True)
class GlyphToken:
    offset: int
    raw: bytes
    index: int | None
    current: str | None
    legacy: str | None
    declared: str | None

    @property
    def candidates(self) -> frozenset[str]:
        return frozenset(x for x in (self.current, self.legacy, self.declared) if x)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def plane_bitmap(font: bytes, index: int) -> tuple[int, ...]:
    row, rem = divmod(index, IPR)
    col, plane = divmod(rem, PLANES)
    bit = 1 << plane
    result: list[int] = []
    for y in range(CELL):
        at = (row * CELL + y) * ROW_BYTES + col * (CELL // 2)
        line = 0
        for pair, value in enumerate(font[at:at + CELL // 2]):
            if (value & 0x0F) & bit:
                line |= 1 << (11 - pair * 2)
            if (value >> 4) & bit:
                line |= 1 << (10 - pair * 2)
        result.append(line)
    return tuple(result)


def physical_code(index: int) -> bytes | None:
    if 0 <= index < 220:
        return bytes((index + 1,))
    value = index - 219
    lead, trail = 0xDD + value // 255, value % 255
    if lead <= 0xE0 or (lead == 0xE1 and 190 <= trail <= 240):
        return bytes((lead, trail))
    return None


def physical_index(raw: bytes) -> int | None:
    if len(raw) == 1 and 0x01 <= raw[0] <= 0xDC:
        return raw[0] - 1
    if len(raw) == 2 and 0xDD <= raw[0] <= 0xE0:
        return (raw[0] - 0xDD) * 255 + raw[1] + 219
    if len(raw) == 2 and raw[0] == 0xE1 and 190 <= raw[1] <= 240:
        return (raw[0] - 0xDD) * 255 + raw[1] + 219
    return None


def raw_tokens(blob: bytes):
    at = 0
    while at < len(blob):
        lead = blob[at]
        if lead == 0:
            break
        width = 1 if lead < 0xDD else 2
        if at + width > len(blob):
            break
        yield at, blob[at:at + width]
        at += width


def slot_from_disk_id(value: int) -> int | None:
    if 0x81 <= value <= 0xA8:
        return value - 0x81
    if 0xAA <= value <= 0xD0:
        return value - 0x82
    return None


def visible_story_segments(data: bytes, offset: int, length: int):
    """Yield runtime-visible bytes with their real file offsets.

    An E2 body first draws its external slot and resumes at ``2 + completion``.
    Keeping the two pieces separate preserves exact ownership for repair output.
    """
    body = data[offset:offset + length]
    cursor = segment_start = 0
    while cursor < len(body):
        lead = body[cursor]
        width = 1 if lead < 0xDD else 2
        if lead == 0xE2 and cursor + 1 < len(body):
            slot = slot_from_disk_id(body[cursor + 1])
            if slot is not None and slot < SLOT_COUNT:
                if segment_start < cursor:
                    yield "body", offset + segment_start, body[segment_start:cursor]
                start = SLOT_BASE + slot * SLOT_SIZE
                stored = data[start:start + SLOT_SIZE]
                end = stored.find(b"\0")
                if end < 0:
                    raise SystemExit(f"external slot {slot} has no terminator")
                yield "slot", start, stored[:end]
                cursor = min(len(body), cursor + 2 + stored[-1])
                segment_start = cursor
                continue
        cursor += width
    if segment_start < len(body):
        yield "body", offset + segment_start, body[segment_start:]


def decode_dynamic_sources() -> tuple[list[tuple[int, ...]], dict[int, str]]:
    rows_blob = (SOURCE_DIR / "huffman_rows.bin").read_bytes()
    rows = tuple(struct.unpack(f"<{len(rows_blob) // 2}H", rows_blob))
    counts = (SOURCE_DIR / "huffman_counts.bin").read_bytes()
    checkpoints_blob = (SOURCE_DIR / "source_checkpoints.bin").read_bytes()
    checkpoints = tuple(struct.unpack(f"<{len(checkpoints_blob) // 2}H", checkpoints_blob))
    stream = (SOURCE_DIR / "source_bitstream.bin").read_bytes()
    manifest = read_csv(SOURCE_DIR / "source_manifest.csv")
    names = {int(row["source_id"]): row["char"] for row in manifest if row["char"]}
    sources = [
        v171_plan.decode_huffman_source(i, rows, counts, checkpoints, stream)
        for i in range(len(manifest))
    ]
    return sources, names


def canonical_tables(exe: bytes, font: bytes, original_font: bytes):
    rows = read_csv(ASSIGNMENTS)
    char_to_code: dict[str, bytes] = {}
    char_to_codes: dict[str, list[bytes]] = defaultdict(list)
    static_by_index: dict[int, str] = {}
    for row in rows:
        char = row["char"]
        encodings = [row["code_1byte"], row["code_2byte"]]
        for encoded in encodings:
            if char and encoded:
                code = bytes.fromhex(encoded)
                if code not in char_to_codes[char]:
                    char_to_codes[char].append(code)
        if char and char_to_codes[char]:
            char_to_code[char] = char_to_codes[char][0]
        if row["kind"] == "static" and row["physical_index"]:
            static_by_index[int(row["physical_index"])] = char

    # These are the only verified low ASCII positions.  Do not extend the rule.
    for index in range(26):
        char = chr(index + 32)
        code = bytes((index + 1,))
        char_to_code.setdefault(char, code)
        char_to_codes[char].append(code)
    char_to_code[" "] = bytes((FILLER,))
    char_to_codes[" "].append(bytes((FILLER,)))
    punctuation = {
        ":": bytes.fromhex("DF 80"),
        "?": bytes.fromhex("E0 47"),
        ".": bytes.fromhex("E0 60"),
        "!": bytes.fromhex("DF E3"),
    }
    char_to_code.update(punctuation)
    for char, code in punctuation.items():
        char_to_codes[char].append(code)

    # H/L/M/P are named by exact bitmap equality with the untouched disc.
    # R intentionally has no current twin and is handled by the candidate audit.
    original_latin = {"H": 469, "L": 825, "M": 553, "P": 363, "R": 732}
    current_shapes: dict[tuple[int, ...], list[int]] = defaultdict(list)
    for index in range(1480):
        shape = plane_bitmap(font, index)
        if any(shape):
            current_shapes[shape].append(index)
    for char, original_index in original_latin.items():
        for index in current_shapes.get(plane_bitmap(original_font, original_index), ()):
            code = physical_code(index)
            if code is not None and code not in char_to_codes[char]:
                char_to_codes[char].append(code)
        if char_to_codes[char]:
            char_to_code[char] = char_to_codes[char][0]

    inverse = {
        code: char for char, codes in char_to_codes.items() for code in codes
    }

    sources, source_names = decode_dynamic_sources()
    direct = v171_verify.direct_ranges(exe)
    lookup = v171_verify.packed_lookup(exe)

    def current_char(raw: bytes) -> str | None:
        if raw in inverse:
            return inverse[raw]
        index = physical_index(raw)
        if index is not None:
            source = direct.get(index)
            return source_names.get(source) if source is not None else static_by_index.get(index)
        if len(raw) == 2 and raw[0] in (0xE9, 0xEA):
            virtual = (raw[0] - 0xE9) * 254 + raw[1] - 1
            if 0 <= virtual < len(lookup):
                value = lookup[virtual]
                return source_names.get(value - 1536) if value >= 1536 else static_by_index.get(value)
        return None

    def current_shape(raw: bytes) -> tuple[int, ...] | None:
        index = physical_index(raw)
        if index is None:
            return None
        source = direct.get(index)
        return sources[source] if source is not None else plane_bitmap(font, index)

    return char_to_code, char_to_codes, current_char, current_shape, sources, source_names, direct


def declared_ui_intents() -> dict[bytes, str]:
    votes: dict[bytes, Counter[str]] = defaultdict(Counter)
    for row in read_csv(UI_CSV):
        payload = bytes.fromhex(row["encoded_hex"])
        tokens = [raw for _, raw in raw_tokens(payload)]
        chars = list(row["korean"])
        if len(tokens) != len(chars):
            continue
        for raw, char in zip(tokens, chars):
            votes[raw][char] += 1
    result: dict[bytes, str] = {}
    for raw, counts in votes.items():
        [(char, n), *rest] = counts.most_common()
        if not rest or n > rest[0][1]:
            result[raw] = char
    return result


def legacy_map(control_font: bytes, current_font: bytes, exe: bytes,
               char_to_code: dict[str, bytes], current_shape, sources,
               source_names: dict[int, str]) -> dict[bytes, str]:
    shapes: dict[tuple[int, ...], set[str]] = defaultdict(set)
    for char, code in char_to_code.items():
        index = physical_index(code)
        if index is not None:
            shape = current_shape(code)
            if shape and any(shape):
                shapes[shape].add(char)
    for source, shape in enumerate(sources):
        if source in source_names and any(shape):
            shapes[shape].add(source_names[source])

    result: dict[bytes, str] = {}
    for index in range(0, 1480):
        raw = physical_code(index)
        if raw is None:
            continue
        old_shape = plane_bitmap(control_font, index)
        if not any(old_shape) or len(shapes.get(old_shape, ())) != 1:
            continue
        if current_shape(raw) == old_shape:
            continue
        result[raw] = next(iter(shapes[old_shape]))
    return result


def make_tokens(blob: bytes, base: int, current_char, legacy: dict[bytes, str],
                declared: dict[bytes, str]) -> list[GlyphToken]:
    result: list[GlyphToken] = []
    for relative, raw in raw_tokens(blob):
        # E2..E8 are runtime controls at token boundaries, not glyphs.
        if len(raw) == 2 and 0xE2 <= raw[0] <= 0xE8:
            continue
        index = physical_index(raw)
        current = current_char(raw)
        old = legacy.get(raw)
        intent = declared.get(raw)
        if current is None and old is None and intent is None \
                and index is None and not (len(raw) == 2 and raw[0] in (0xE9, 0xEA)):
            continue
        result.append(GlyphToken(base + relative, raw, index, current, old, intent))
    return result


def align(tokens: list[GlyphToken], desired_text: str):
    desired = [c for c in desired_text if c not in "|\r\n"]
    n, m = len(tokens), len(desired)
    score = [[0] * (m + 1) for _ in range(n + 1)]
    prev = [[""] * (m + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        score[i][0] = score[i - 1][0] - (1 if " " in tokens[i - 1].candidates else 4)
        prev[i][0] = "T"
    for j in range(1, m + 1):
        score[0][j] = score[0][j - 1] - (1 if desired[j - 1] == " " else 4)
        prev[0][j] = "C"
    for i in range(1, n + 1):
        token = tokens[i - 1]
        for j in range(1, m + 1):
            char = desired[j - 1]
            if char in token.candidates:
                bonus = 12 if token.current == char else 10
            else:
                bonus = -8
            choices = (
                (score[i - 1][j - 1] + bonus, "M"),
                (score[i - 1][j] - (1 if " " in token.candidates else 4), "T"),
                (score[i][j - 1] - (1 if char == " " else 4), "C"),
            )
            score[i][j], prev[i][j] = max(choices, key=lambda x: x[0])
    pairs: list[tuple[GlyphToken, str]] = []
    i, j = n, m
    while i or j:
        step = prev[i][j]
        if step == "M":
            pairs.append((tokens[i - 1], desired[j - 1]))
            i -= 1
            j -= 1
        elif step == "T":
            i -= 1
        else:
            j -= 1
    pairs.reverse()
    substantive = [c for c in desired if c != " "]
    matched = sum(1 for token, char in pairs if char != " " and char in token.candidates)
    ratio = matched / len(substantive) if substantive else 0.0
    return pairs, ratio


def pointer_payload(exe: bytes, pointer_offset: int) -> tuple[int, bytes] | None:
    if pointer_offset < 0 or pointer_offset + 4 > len(exe):
        return None
    target = struct.unpack_from("<I", exe, pointer_offset)[0]
    offset = target - R2F
    if not 0 <= offset < len(exe):
        return None
    end = exe.find(b"\0", offset, min(len(exe), offset + 512))
    if end < 0:
        return None
    return offset, exe[offset:end]


def main() -> None:
    if digest(BASE) != BASE_SHA256:
        raise SystemExit("v189 base hash differs")
    with ZipFile(BASE) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    with ZipFile(CONTROL) as archive:
        control_font = archive.read(COMM)
    with ZipFile(ORIGINAL) as archive:
        original_font = archive.read(COMM)

    exe, font = members[PSX], members[COMM]
    char_to_code, char_to_codes, current_char, current_shape, sources, source_names, direct = \
        canonical_tables(exe, font, original_font)
    declared = declared_ui_intents()
    legacy = legacy_map(
        control_font, font, exe, char_to_code, current_shape, sources, source_names
    )

    original_rows = {
        (row["source file"], row["byte offset"]): row for row in read_csv(ORIGINAL_CSV)
    }
    translated = read_csv(TRANSLATED_CSV)
    repairs: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []
    owner_indices: Counter[int] = Counter()
    original_indices: Counter[int] = Counter()

    # Original text-plane use is counted at token boundaries, never by raw substring.
    for row in original_rows.values():
        for _, raw in raw_tokens(bytes.fromhex(row["raw bytes as hex"])):
            index = physical_index(raw)
            if index is not None:
                original_indices[index] += 1

    def inspect(owner_type: str, owner: str, desired: str,
                segments: list[tuple[str, int, bytes]]) -> None:
        tokens: list[GlyphToken] = []
        for _, base, payload in segments:
            part = make_tokens(payload, base, current_char, legacy, declared)
            tokens.extend(part)
            for token in part:
                if token.index is not None:
                    owner_indices[token.index] += 1
        pairs, ratio = align(tokens, desired)
        if ratio < 0.65:
            skipped.append({
                "owner_type": owner_type, "owner": owner, "desired": desired,
                "match_ratio": f"{ratio:.4f}", "reason": "current payload is not this translation",
            })
            return
        for token, intended in pairs:
            old_intent = token.legacy or token.declared
            inferred = old_intent is None and token.current is None and ratio >= 0.85
            if (old_intent != intended and not inferred) or token.current == intended:
                continue
            replacement = next(
                (code for code in char_to_codes.get(intended, ()) if len(code) == len(token.raw)),
                None,
            )
            status = "repair"
            reason = "superseded glyph address"
            if intended == "R" and replacement is None:
                status, reason = "needs_R_cell", "R bitmap has no current code"
            elif replacement is None:
                status, reason = "blocked", "no canonical current code"
            elif len(replacement) != len(token.raw):
                status, reason = "blocked", "replacement changes byte width"
            repairs.append({
                "status": status,
                "owner_type": owner_type,
                "owner": owner,
                "file_offset": f"0x{token.offset:X}",
                "intended_char": intended,
                "old_hex": token.raw.hex(" ").upper(),
                "old_current_char": token.current or "",
                "new_hex": replacement.hex(" ").upper() if replacement else "",
                "reason": reason,
            })

    for row in translated:
        desired = row.get("korean", "")
        if not desired or "<G:" in row.get("japanese", ""):
            continue
        key = (row["source file"], row["offset"])
        original_row = original_rows.get(key)
        if original_row is None or key[0] not in members:
            continue
        offset = int(row["offset"], 0)
        length = int(original_row["length"])
        segments = list(visible_story_segments(members[key[0]], offset, length))
        inspect("story", f"{key[0]} {key[1]}", desired, segments)

    # Current pointer value, not a stale target_offset column, proves UI ownership.
    pointer_owners: dict[int, tuple[str, str]] = {}
    for source, path, pointer_column, text_column in (
        ("ui_full_v42", UI_CSV, "pointer_offset", "korean"),
        ("v171_system", SYSTEM_CSV, "pointer_offset", "korean"),
        ("ui_runtime_v43", RUNTIME_UI_CSV, "pointer_offset", "korean"),
    ):
        for row in read_csv(path):
            pointer = int(row[pointer_column], 0)
            text = row[text_column]
            pointer_owners[pointer] = (source, text)
    for pointer, (source, desired) in sorted(pointer_owners.items()):
        located = pointer_payload(exe, pointer)
        if located is None:
            continue
        offset, payload = located
        inspect("ui", f"{source} pointer=0x{pointer:X}", desired,
                [("pointer", offset, payload)])

    # Exact duplicates arise when two manifests own the same payload.  One write is enough.
    unique: dict[tuple[str, str, str], dict[str, object]] = {}
    for row in repairs:
        key = (row["owner"].split(" ")[0] if row["owner_type"] == "story" else PSX,
               row["file_offset"], row["old_hex"])
        unique.setdefault(key, row)
    repairs = sorted(unique.values(), key=lambda r: (
        r["status"], r["owner_type"], r["owner"], int(str(r["file_offset"]), 0)
    ))

    # R candidate: every plane in the physical cell must be proven original text,
    # no current owner may reference the candidate, no dynamic direct range may own
    # it, and no savestate may have identified the cell as non-text.
    safety = {(int(r["row"]), int(r["col"])): r for r in read_csv(CELL_SAFETY)}
    assigned = {
        int(r["physical_index"]) for r in read_csv(ASSIGNMENTS)
        if r["physical_index"]
    }
    native_cells = {
        (int(r["row"]), int(r["col"]))
        for r in read_csv(SOURCE_DIR / "restore_ui_cells.csv")
    }
    candidates: list[dict[str, object]] = []
    for index in range(220, 1480):
        code = physical_code(index)
        if code is None or index in assigned or index in direct or owner_indices[index]:
            continue
        row, rem = divmod(index, IPR)
        col, plane = divmod(rem, PLANES)
        cell = (row, col)
        if cell in native_cells:
            continue
        evidence = safety.get(cell, {})
        if evidence.get("status", "").startswith("rejected"):
            continue
        planes = [row * IPR + col * PLANES + p for p in range(PLANES)]
        if not all(original_indices[p] for p in planes):
            continue
        candidates.append({
            "index": index, "code_hex": code.hex(" ").upper(),
            "row": row, "col": col, "plane": plane,
            "original_uses": original_indices[index],
            "current_owner_uses": owner_indices[index],
            "cell_classification": evidence.get("status", ""),
            "cell_runtime_nontext_states": evidence.get("runtime_nontext_states", ""),
        })

    OUT.mkdir(parents=True, exist_ok=True)
    repair_fields = [
        "status", "owner_type", "owner", "file_offset", "intended_char",
        "old_hex", "old_current_char", "new_hex", "reason",
    ]
    with (OUT / "repairs.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=repair_fields)
        writer.writeheader()
        writer.writerows(repairs)
    with (OUT / "skipped_rows.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=["owner_type", "owner", "desired", "match_ratio", "reason"]
        )
        writer.writeheader()
        writer.writerows(skipped)
    candidate_fields = [
        "index", "code_hex", "row", "col", "plane", "original_uses",
        "current_owner_uses", "cell_classification", "cell_runtime_nontext_states",
    ]
    with (OUT / "r_candidates.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=candidate_fields)
        writer.writeheader()
        writer.writerows(candidates)

    statuses = Counter(str(row["status"]) for row in repairs)
    owners = Counter(str(row["owner_type"]) for row in repairs)
    report = [
        "v189 text/glyph ownership audit",
        f"base={BASE.name}",
        f"base_sha256={digest(BASE)}",
        f"story_rows_considered={sum(1 for r in translated if r.get('korean'))}",
        f"pointer_owners_considered={len(pointer_owners)}",
        f"legacy_codes_identified_by_bitmap={len(legacy)}",
        f"repair_records={len(repairs)}",
        f"status_counts={dict(statuses)}",
        f"owner_counts={dict(owners)}",
        f"skipped_unaligned_owners={len(skipped)}",
        f"R_safe_candidate_planes={len(candidates)}",
        "arbitrary_DAT_scan=0",
        "emulator_run=0",
    ]
    (OUT / "report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))
    for row in repairs[:80]:
        print(
            f"{row['status']:12} {row['owner']:30} {row['file_offset']:>9} "
            f"{row['intended_char']} {row['old_hex']} -> {row['new_hex']}"
        )
    print("R candidates (first 20):")
    for row in candidates[:20]:
        print(row)


if __name__ == "__main__":
    main()
