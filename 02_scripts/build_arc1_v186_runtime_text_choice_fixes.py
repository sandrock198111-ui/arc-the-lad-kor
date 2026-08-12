#!/usr/bin/env python3
"""Build v186 from v185 using only runtime-proven text repairs.

The user's six v185 savestates prove four independent defects:

* S1031 slot 0 still contains the old pre-cache encoding of ``엄마...``.
* SD011's extended body at 0x47B60 redirects to slot 10, but that slot is empty.
* v184 replaced the working ``번 그라운드`` bytes with stale virtual codes.
* Two translated choice rows exceed 228 pixels.  Their E5/E6 geometry is sound,
  so only the already redirected secondary strings are shortened.

Every write has an old-byte guard.  Choice markers are audited over all 357
extracted choice bodies before and after the edit.  The 46 over-width rows in
``choices_untranslated.csv`` are known undecoded source noise and are reported,
not guessed at or modified.
"""
from __future__ import annotations

import csv
import hashlib
import struct
import sys
from collections import defaultdict
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))

import build_arc1_v171_ui_asset_recovery as v171  # noqa: E402
import check_build as structural  # noqa: E402
import verify_arc1_v171_ui_asset_recovery as v171_verify  # noqa: E402
from plan_bulk_insertion import (  # noqa: E402
    CHOICE, SLOT_BASE, SLOT_COUNT, SLOT_SIZE, has_marker, tokens,
)
from review_editor import ROW_PIXELS  # noqa: E402


BASE = ROOT / "03_output/arc1_v185_acquisition_closing_bracket_fix.zip"
BASE_SHA256 = "AAC5C9F6396925FBBA5E6DCF129E97C2D3C197DE164B0A86CA53027133C11A32"
PRISTINE = ROOT / "00_original/arc.zip"
ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"
UNRESOLVED_CHOICES = ROOT / "05_docs/choices_untranslated.csv"
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v186_runtime_text_choice_fixes"
ANALYSIS = ROOT / "01_work/analysis" / OUT_STEM

PSX = "PSX.EXE"
S1031 = "1/S1031.DAT"
SD011 = "D/SD011.DAT"
S1023 = "1/S1023.DAT"

SKILL_OFFSET = 0x80DC9
STALE_SKILL = bytes.fromhex("E9 71 9C E9 19 E9 3F E9 B2 E9 3B 00")
WORKING_SKILL = bytes.fromhex("DF 97 9C E9 19 DE 74 E9 B2 DF 41 00")

S1031_SLOT = 0
S1031_OLD_PAYLOAD = bytes.fromhex("DE DB E0 9E E0 60 E0 60 E0 60")
S1031_COMPLETION = 7

SD011_SLOT = 10
SD011_COMPLETION = 27
SD011_BODY = 0x47B60
SD011_REDIRECT = bytes.fromhex("E2 8B")

S1023_QUESTION_SLOT = 0
S1023_QUESTION_COMPLETION = 18
S1023_OLD_QUESTION = bytes.fromhex(
    "95 A8 72 8F 9C E0 2C E9 53 9C E0 1B 72 8F 9C 53 84 AD 9C "
    "DF 16 4E 9C E9 3A DE A8 E0 47"
)
S1023_NEXT_SLOT = 2
S1023_NEXT_COMPLETION = 5
S1023_OLD_NEXT = bytes.fromhex("78 C6 9C EA 9E E0 BD 72")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    result = ZipInfo(info.filename, info.date_time)
    for attr in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(result, attr, getattr(info, attr))
    return result


def encode_text(text: str, mapping: dict[str, bytes]) -> bytes:
    punctuation = {
        ".": bytes.fromhex("E0 60"),
        "?": bytes.fromhex("E0 47"),
        "!": bytes.fromhex("DF E3"),
    }
    result = bytearray()
    for char in text:
        if char == " ":
            result.append(0x9C)
        elif char.isascii() and char.isdigit():
            result.append(0x11 + int(char))
        elif char in punctuation:
            result.extend(punctuation[char])
        elif char in mapping:
            result.extend(mapping[char])
        else:
            raise SystemExit(f"no current glyph code for {char!r} in {text!r}")
    if not result or 0 in result:
        raise SystemExit(f"invalid encoded text: {text!r}")
    return bytes(result)


def write_slot(
    data: bytearray,
    slot: int,
    expected_payload: bytes,
    expected_completion: int,
    new_payload: bytes,
) -> None:
    if not 0 <= slot < SLOT_COUNT or len(new_payload) > SLOT_SIZE - 2:
        raise SystemExit(f"slot {slot} payload does not fit")
    start = SLOT_BASE + slot * SLOT_SIZE
    old = bytes(data[start:start + SLOT_SIZE])
    term = old.find(b"\0")
    if term < 0:
        raise SystemExit(f"slot {slot} has no terminator")
    if old[:term] != expected_payload or old[-1] != expected_completion:
        raise SystemExit(
            f"slot {slot} guard differs: payload={old[:term].hex(' ')} "
            f"completion={old[-1]}"
        )
    if any(old[term:SLOT_SIZE - 1]):
        raise SystemExit(f"slot {slot} has nonzero bytes after its terminator")
    replacement = bytearray(SLOT_SIZE)
    replacement[:len(new_payload)] = new_payload
    replacement[len(new_payload)] = 0
    replacement[-1] = expected_completion
    data[start:start + SLOT_SIZE] = replacement


def current_decoder(exe: bytes):
    ranges = v171_verify.direct_ranges(exe)
    lookup = v171_verify.packed_lookup(exe)
    with (ROOT / "01_work/analysis/arc1_v171_ui_asset_recovery/source_manifest.csv").open(
        encoding="utf-8-sig", newline=""
    ) as handle:
        dynamic = {int(row["source_id"]): row["char"] for row in csv.DictReader(handle)}
    with (ROOT / "01_work/analysis/dynamic_cache_v153_widthsafe/glyph_assignments.csv").open(
        encoding="utf-8-sig", newline=""
    ) as handle:
        static = {
            int(row["physical_index"]): row["char"]
            for row in csv.DictReader(handle)
            if row["kind"] == "static" and row["physical_index"]
        }
    static.update({155: " ", 1055: "?", 1080: "."})

    def decode(payload: bytes) -> str:
        result: list[str] = []
        for token in tokens(payload):
            if len(token) == 1:
                index = token[0] - 1
                source = ranges.get(index)
                result.append(dynamic[source] if source is not None else static[index])
                continue
            lead, trail = token
            if 0xDD <= lead <= 0xE8:
                index = (lead - 0xDD) * 255 + trail + 0xDB
                source = ranges.get(index)
                result.append(dynamic[source] if source is not None else static[index])
                continue
            if lead in (0xE9, 0xEA):
                virtual = (lead - 0xE9) * 254 + trail - 1
                if not 0 <= virtual < len(lookup):
                    raise SystemExit(f"lookup token outside table: {token.hex(' ')}")
                value = lookup[virtual]
                result.append(dynamic[value - 1536] if value >= 1536 else static[value])
                continue
            raise SystemExit(f"unexpected token in runtime decode: {token.hex(' ')}")
        return "".join(result)

    return decode


def choice_bodies() -> dict[str, list[tuple[int, bytes]]]:
    result: dict[str, list[tuple[int, bytes]]] = defaultdict(list)
    with ORIGINAL_CSV.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
        for row in reader:
            raw = bytes.fromhex(row["raw bytes as hex"].replace(" ", ""))
            if has_marker(raw, CHOICE):
                result[row["source file"]].append((int(row[key], 0), raw))
    return result


def unresolved_choice_keys() -> set[tuple[str, int]]:
    result: set[tuple[str, int]] = set()
    with UNRESOLVED_CHOICES.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        next(reader)
        for row in reader:
            result.add((row[1], int(row[2], 0)))
    return result


def choice_audit(
    members: dict[str, bytes], pristine: dict[str, bytes], phase: str
) -> tuple[list[dict[str, object]], dict[str, int]]:
    bodies = choice_bodies()
    unresolved = unresolved_choice_keys()
    rows: list[dict[str, object]] = []
    counts = {
        "bodies": 0,
        "marker_matches": 0,
        "overflow_rows": 0,
        "known_unresolved_overflow_rows": 0,
        "translated_overflow_rows": 0,
    }
    for name, items in bodies.items():
        if name not in members or name not in pristine:
            continue
        data, original = members[name], pristine[name]
        for offset, raw in items:
            counts["bodies"] += 1
            current = data[offset:offset + len(raw)]
            marker_ok = structural.markers(current) == structural.markers(raw)
            counts["marker_matches"] += int(marker_ok)
            original_rows = structural.drawn_rows(raw, original)
            for row_number, row in enumerate(structural.drawn_rows(current, data)):
                width = structural.row_width(row)
                unchanged = row_number < len(original_rows) and row == original_rows[row_number]
                over = width > ROW_PIXELS and not unchanged
                known = (name, offset) in unresolved
                if over:
                    counts["overflow_rows"] += 1
                    counts["known_unresolved_overflow_rows"] += int(known)
                    counts["translated_overflow_rows"] += int(not known)
                rows.append({
                    "phase": phase,
                    "source_file": name,
                    "offset": f"0x{offset:X}",
                    "row": row_number,
                    "width_px": width,
                    "marker_geometry_matches_original": int(marker_ok),
                    "row_unchanged_from_original": int(unchanged),
                    "known_unresolved_source": int(known),
                    "translated_overflow": int(over and not known),
                })
    return rows, counts


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v185 base archive hash differs")
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}
    with ZipFile(PRISTINE) as archive:
        pristine = {
            name: archive.read(name) for name in archive.namelist() if name in members
        }

    required = {PSX, S1031, SD011, S1023}
    if not required <= members.keys():
        raise SystemExit(f"base archive lacks {sorted(required - members.keys())}")

    before_members = dict(members)
    before_rows, before = choice_audit(before_members, pristine, "before")
    if before != {
        "bodies": 357,
        "marker_matches": 357,
        "overflow_rows": 48,
        "known_unresolved_overflow_rows": 46,
        "translated_overflow_rows": 2,
    }:
        raise SystemExit(f"v185 choice control group differs: {before}")

    mapping = v171.current_char_mapping()
    replacements = {
        "s1031": ("엄마...", encode_text("엄마...", mapping)),
        "sd011": (
            "그 불을 줘. 내가 다시 붙이고 올게.",
            encode_text("그 불을 줘. 내가 다시 붙이고 올게.", mapping),
        ),
        "question": (
            "아버지가 남긴 편지가 있는데 읽어볼래?",
            encode_text("아버지가 남긴 편지가 있는데 읽어볼래?", mapping),
        ),
        "next": ("다음", encode_text("다음", mapping)),
    }

    exe = bytearray(members[PSX])
    if bytes(exe[SKILL_OFFSET:SKILL_OFFSET + len(STALE_SKILL)]) != STALE_SKILL:
        raise SystemExit("v185 skill-name guard differs")
    exe[SKILL_OFFSET:SKILL_OFFSET + len(WORKING_SKILL)] = WORKING_SKILL
    members[PSX] = bytes(exe)

    s1031 = bytearray(members[S1031])
    write_slot(
        s1031, S1031_SLOT, S1031_OLD_PAYLOAD, S1031_COMPLETION,
        replacements["s1031"][1],
    )
    members[S1031] = bytes(s1031)

    sd011 = bytearray(members[SD011])
    if bytes(sd011[SD011_BODY:SD011_BODY + 2]) != SD011_REDIRECT:
        raise SystemExit("SD011 live extended redirect guard differs")
    write_slot(
        sd011, SD011_SLOT, b"", 0, replacements["sd011"][1],
    )
    # The body has 29 writable bytes.  Completion 27 resumes at its boundary.
    sd011[SLOT_BASE + SD011_SLOT * SLOT_SIZE + SLOT_SIZE - 1] = SD011_COMPLETION
    members[SD011] = bytes(sd011)

    s1023 = bytearray(members[S1023])
    write_slot(
        s1023, S1023_QUESTION_SLOT, S1023_OLD_QUESTION,
        S1023_QUESTION_COMPLETION, replacements["question"][1],
    )
    write_slot(
        s1023, S1023_NEXT_SLOT, S1023_OLD_NEXT,
        S1023_NEXT_COMPLETION, replacements["next"][1],
    )
    members[S1023] = bytes(s1023)

    decoder = current_decoder(members[PSX])
    for name, (text, payload) in replacements.items():
        got = decoder(payload)
        if got != text:
            raise SystemExit(f"current-runtime decode differs for {name}: {got!r}")
    if decoder(WORKING_SKILL[:-1]) != "번 그라운드":
        raise SystemExit("working skill-name bytes do not decode as 번 그라운드")

    after_rows, after = choice_audit(members, pristine, "after")
    if after != {
        "bodies": 357,
        "marker_matches": 357,
        "overflow_rows": 46,
        "known_unresolved_overflow_rows": 46,
        "translated_overflow_rows": 0,
    }:
        raise SystemExit(f"v186 choice audit differs: {after}")

    changed = sorted(name for name in members if members[name] != before_members[name])
    if changed != sorted(required):
        raise SystemExit(f"unexpected changed archive members: {changed}")
    for name in members:
        if len(members[name]) != len(before_members[name]):
            raise SystemExit(f"member size changed: {name}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    temporary = OUT_DIR / f"{OUT_STEM}_building.zip"
    if temporary.exists():
        raise SystemExit(f"refusing to overwrite {temporary}")
    with ZipFile(temporary, "w", ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    with ZipFile(temporary) as archive:
        if archive.namelist() != [info.filename for info in infos]:
            raise SystemExit("archive member order changed")
        if any(archive.read(name) != members[name] for name in archive.namelist()):
            raise SystemExit("archive readback differs")

    output_hash = digest(temporary.read_bytes())
    output = OUT_DIR / f"{OUT_STEM}_{output_hash[:8]}.zip"
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {output}")
    temporary.replace(output)

    audit_rows = before_rows + after_rows
    with (ANALYSIS / "choice_width_audit.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(audit_rows[0]))
        writer.writeheader()
        writer.writerows(audit_rows)

    report = [
        "v186 runtime text and choice fixes",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output.name}",
        f"output_sha256={output_hash}",
        "",
        "runtime-proven writes",
        "  PSX.EXE 0x80DC9: stale v184 virtual codes -> v183 working 번 그라운드",
        "  1/S1031.DAT slot 0: old pre-cache bytes -> current-code 엄마...",
        "  D/SD011.DAT slot 10: empty -> 그 불을 줘. 내가 다시 붙이고 올게.",
        "  1/S1023.DAT slot 0: 읽어 볼래? -> 읽어볼래? (234px -> 228px)",
        "  1/S1023.DAT slot 2: stale 다음 페이지 -> current-code 다음",
        "",
        f"choice_bodies={after['bodies']}",
        f"choice_marker_geometry={after['marker_matches']}/{after['bodies']} PASS",
        f"translated_choice_overflow={before['translated_overflow_rows']} -> "
        f"{after['translated_overflow_rows']}",
        f"known_unresolved_noise_overflow={after['known_unresolved_overflow_rows']} "
        "(unchanged by policy)",
        "",
        "decoder 0x801FF30C / 568 bytes",
        "frame routine 0x801FF634 / 636 bytes",
        "changed_members=" + ",".join(changed),
        "member_sizes=unchanged",
        "runtime_decode_readback=PASS",
        "cold_boot=NOT RUN (user test required)",
        "rollback=v185",
    ]
    (ANALYSIS / "build_report.txt").write_text(
        "\n".join(report) + "\n", encoding="utf-8"
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
