#!/usr/bin/env python3
"""Build v187 from v186 using the user's six fresh runtime states.

The fixes are intentionally separated by subsystem:

* SD011 keeps the original E4/E6 controls and redirects only the four text spans.
* PSX.EXE keeps the dynamic skill-name table, restores the skill closer, and
  repoints the confirmed empty ``合体`` system string to current-code ``합체``.
* S1023 shortens the live question slot and rewrites option 3 in place.  No E5
  or E6 byte moves and no option text is sent through E2, avoiding v147's
  one-row cursor regression.

Every binary write is guarded against the exact v186 base and all changed
members retain their original size.
"""
from __future__ import annotations

import csv
import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))

import build_arc1_v171_ui_asset_recovery as v171  # noqa: E402
import build_arc1_v186_runtime_text_choice_fixes as v186  # noqa: E402
import check_build as structural  # noqa: E402
from plan_bulk_insertion import (  # noqa: E402
    SLOT_BASE, SLOT_COUNT, SLOT_SIZE,
)


BASE = ROOT / "03_output/arc1_v186_runtime_text_choice_fixes_0D144525.zip"
BASE_SHA256 = "0D144525001BA1FE6284DE7D823D6C68FEC26AC733B51D69E9AFB9A679B67BB5"
PRISTINE = ROOT / "00_original/arc.zip"
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v187_control_skill_choice_repair"
ANALYSIS = ROOT / "01_work/analysis" / OUT_STEM

PSX = "PSX.EXE"
SD011 = "D/SD011.DAT"
S1023 = "1/S1023.DAT"
RAM_TO_FILE = 0x8011A800

# Pointer tables and the live, proven string-pool allocation.
ITEM_CLOSE_PTR = 0x82474
SKILL_CLOSE_PTR = 0x82554
FUSION_PTR = 0x829B8
SKILL_TABLE = (0x811C0, 59 * 4)
WORKING_SKILL_AT = 0x80DC9
WORKING_SKILL = bytes.fromhex("DF 97 9C E9 19 DE 74 E9 B2 DF 41 00")
POOL_START = 0x828CC
POOL_END = 0x82938

# SD011 bodies and the four external slots used by their text-only spans.
SD_BODY_A = (0x47B60, 29)
SD_BODY_B = (0x47D58, 25)
SD_BODY_C = (0x47D78, 8)
SD_SLOTS = (10, 11, 12, 0)

# S1023 live menu locations.
QUESTION_SLOT = 0
QUESTION_COMPLETION = 18
QUESTION_BODY = (0x47952, 47)
HELP_BODY = (0x47AB0, 55)
HELP_OPTION3 = (28, 46)  # body-relative text span; next E5 begins at 46

LINEBREAK = bytes.fromhex("E6 01")
CHOICE = bytes.fromhex("E5 03")
FILLER = 0x9C


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


def pointer_target(exe: bytes, at: int) -> int:
    value = struct.unpack_from("<I", exe, at)[0]
    target = value - RAM_TO_FILE
    if not 0 <= target < len(exe):
        raise SystemExit(f"0x{at:X} is not an in-image pointer: 0x{value:08X}")
    return target


def c_string(data: bytes, start: int, limit: int = 200) -> bytes:
    end = data.find(b"\0", start, min(len(data), start + limit))
    if end < 0:
        raise SystemExit(f"unterminated string at 0x{start:X}")
    return data[start:end]


def encode_text(text: str, mapping: dict[str, bytes]) -> bytes:
    punctuation = {
        ".": bytes.fromhex("E0 60"),
        "?": bytes.fromhex("E0 47"),
        "!": bytes.fromhex("DF E3"),
    }
    result = bytearray()
    for char in text:
        if char == " ":
            result.append(FILLER)
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


def disk_id(slot: int) -> int:
    if not 0 <= slot < SLOT_COUNT:
        raise SystemExit(f"invalid external slot {slot}")
    return slot + 0x81 if slot < 40 else slot + 0x82


def slot_bytes(data: bytes, slot: int) -> bytes:
    start = SLOT_BASE + slot * SLOT_SIZE
    return data[start:start + SLOT_SIZE]


def write_slot(data: bytearray, slot: int, payload: bytes, completion: int) -> None:
    if len(payload) > SLOT_SIZE - 2 or not 0 <= completion <= 0xFF:
        raise SystemExit(f"slot {slot} payload/completion does not fit")
    start = SLOT_BASE + slot * SLOT_SIZE
    replacement = bytearray(SLOT_SIZE)
    replacement[:len(payload)] = payload
    replacement[len(payload)] = 0
    replacement[-1] = completion
    data[start:start + SLOT_SIZE] = replacement


def control_positions(payload: bytes) -> list[tuple[int, bytes]]:
    return structural.markers(payload)


def original_lengths() -> dict[tuple[str, int], int]:
    result: dict[tuple[str, int], int] = {}
    with (ROOT / "05_docs/script_original_full.csv").open(
        encoding="utf-8-sig", newline=""
    ) as handle:
        reader = csv.DictReader(handle)
        key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
        for row in reader:
            if row["source file"] in (SD011, S1023):
                result[(row["source file"], int(row[key], 0))] = len(
                    bytes.fromhex(row["raw bytes as hex"].replace(" ", ""))
                )
    return result


def prove_pool(exe: bytes, original: bytes, needed: int) -> None:
    """Require current zeros inside a range that held pointer-referenced original text."""
    if needed > POOL_END - POOL_START or any(exe[POOL_START:POOL_START + needed]):
        raise SystemExit("proven string-pool allocation is not empty or is too small")

    claimed = bytearray(len(exe))
    low, high = RAM_TO_FILE, RAM_TO_FILE + len(exe)
    for at in range(0, len(exe) - 4, 4):
        value = struct.unpack_from("<I", exe, at)[0]
        if not low <= value < high:
            continue
        start = value - low
        end = start
        while end < len(exe) and exe[end] and end - start < 200:
            end += 1
        claimed[start:min(end + 1, len(exe))] = b"\1" * (min(end + 1, len(exe)) - start)
    if any(claimed[POOL_START:POOL_START + needed]):
        raise SystemExit("new string-pool allocation overlaps a current live string")

    was_text: set[int] = set()
    original_high = RAM_TO_FILE + len(original)
    for at in range(0, len(original) - 4, 4):
        value = struct.unpack_from("<I", original, at)[0]
        if not RAM_TO_FILE <= value < original_high:
            continue
        start = value - RAM_TO_FILE
        if not 0 < start < len(original) or original[start - 1] != 0:
            continue
        end = start
        while end < len(original) and original[end] and end - start < 60:
            end += 1
        if 1 <= end - start <= 40:
            was_text.update(range(start, end + 1))
    if not was_text.intersection(range(POOL_START, POOL_START + needed)):
        raise SystemExit("allocation is not in a range proven as original live text")


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v186 base archive hash differs")
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}
    with ZipFile(PRISTINE) as archive:
        pristine = {name: archive.read(name) for name in (PSX, SD011, S1023)}

    before = dict(members)
    mapping = v171.current_char_mapping()
    decoder = v186.current_decoder(members[PSX])
    lengths = original_lengths()

    # ------------------------------------------------------------------ SD011
    sd = bytearray(members[SD011])
    original_sd = pristine[SD011]
    expected_current = {
        SD_BODY_A: bytes.fromhex(
            "E2 8B E6 01 A4 A8 AC 94 " + "9C " * 21
        ),
        SD_BODY_B: bytes.fromhex(
            "E2 8C E6 01 A4 A8 AC B0 94 " + "9C " * 16
        ),
        SD_BODY_C: bytes.fromhex("95 9E 0F 0F 0F 9C 9C 9C"),
    }
    for (offset, size), expected in expected_current.items():
        if len(expected) != size or bytes(sd[offset:offset + size]) != expected:
            raise SystemExit(f"SD011 v186 body guard differs at 0x{offset:X}")

    # Slot 10 contains v186's whole combined sentence; the other selected slots are free.
    old10 = slot_bytes(sd, 10)
    end10 = old10.find(b"\0")
    if end10 < 0 or old10[-1] != 27 or decoder(old10[:end10]) != "그 불을 줘. 내가 다시 붙이고 올게.":
        raise SystemExit("SD011 slot 10 no longer contains the v186 combined sentence")
    for slot in (0, 11, 12):
        if any(slot_bytes(sd, slot)):
            raise SystemExit(f"SD011 slot {slot} is no longer free")

    sd_texts = (
        (10, "그 불을 줘.", 10),
        (11, "내가 다시 붙이고 올게.", 9),
        (12, "안심해.", 4),
        (0, "불은 내가 다시 붙이고 올게.", 11),
    )
    for slot, text, completion in sd_texts:
        payload = encode_text(text, mapping)
        if decoder(payload) != text:
            raise SystemExit(f"runtime decode differs for SD011 slot {slot}")
        write_slot(sd, slot, payload, completion)

    a_at, a_size = SD_BODY_A
    body_a = bytearray((FILLER,) * a_size)
    body_a[0:2] = bytes((0xE2, disk_id(10)))
    body_a[12:16] = original_sd[a_at + 12:a_at + 16]
    body_a[16:18] = bytes((0xE2, disk_id(11)))
    body_a[27:29] = original_sd[a_at + 27:a_at + 29]
    sd[a_at:a_at + a_size] = body_a

    b_at, b_size = SD_BODY_B
    body_b = bytearray((FILLER,) * b_size)
    body_b[0:2] = bytes((0xE2, disk_id(12)))
    body_b[6:10] = original_sd[b_at + 6:b_at + 10]
    body_b[10:12] = bytes((0xE2, disk_id(0)))
    body_b[23:25] = original_sd[b_at + 23:b_at + 25]
    sd[b_at:b_at + b_size] = body_b

    c_at, c_size = SD_BODY_C
    # 0x0F is the one-byte dot already used by v186's visible "아크...".
    body_c = bytes.fromhex("95 9E 0F 0F 0F 9C") + original_sd[c_at + 6:c_at + 8]
    sd[c_at:c_at + c_size] = body_c

    # Only text spans may differ; every original E4/E6 control is back at its old offset.
    for offset, size in (SD_BODY_A, SD_BODY_B, SD_BODY_C):
        original_controls = [
            (i, original_sd[offset + i:offset + i + 2])
            for i in range(size - 1)
            if original_sd[offset + i] in (0xE4, 0xE6)
        ]
        result_controls = [
            (i, bytes(sd[offset + i:offset + i + 2]))
            for i in range(size - 1)
            if sd[offset + i] in (0xE4, 0xE6)
        ]
        if result_controls != original_controls:
            raise SystemExit(f"SD011 E4/E6 geometry differs at 0x{offset:X}")
    # Completion arithmetic: command + two bytes + completion = next original control.
    resumes = ((a_at, 10, a_at + 12), (a_at + 16, 9, a_at + 27),
               (b_at, 4, b_at + 6), (b_at + 10, 11, b_at + 23))
    if any(command + 2 + completion != target for command, completion, target in resumes):
        raise SystemExit("SD011 E2 completion arithmetic differs")
    members[SD011] = bytes(sd)

    # --------------------------------------------------------------- PSX.EXE
    exe = bytearray(members[PSX])
    original_exe = pristine[PSX]
    skill_table_before = bytes(exe[SKILL_TABLE[0]:SKILL_TABLE[0] + SKILL_TABLE[1]])
    if bytes(exe[WORKING_SKILL_AT:WORKING_SKILL_AT + len(WORKING_SKILL)]) != WORKING_SKILL:
        raise SystemExit("working dynamic skill-name entry differs from v186")

    item_close = c_string(exe, pointer_target(exe, ITEM_CLOSE_PTR))
    skill_close_at = pointer_target(exe, SKILL_CLOSE_PTR)
    skill_close = c_string(exe, skill_close_at)
    if not item_close or item_close[0] != 0x5A or skill_close.startswith(b"\x5A"):
        raise SystemExit("skill/item closer control group differs")
    new_skill_close = item_close[:1] + skill_close

    fusion_old_at = pointer_target(exe, FUSION_PTR)
    if fusion_old_at != 0x82821 or exe[fusion_old_at] != 0:
        raise SystemExit("the confirmed empty 合体 pointer target differs")
    fusion = encode_text("합체", mapping)
    if decoder(fusion) != "합체":
        raise SystemExit("current runtime does not decode the 合体 replacement as 합체")

    needed = len(new_skill_close) + 1 + len(fusion) + 1
    prove_pool(exe, original_exe, needed)
    cursor = POOL_START
    skill_close_new_at = cursor
    exe[cursor:cursor + len(new_skill_close)] = new_skill_close
    exe[cursor + len(new_skill_close)] = 0
    cursor += len(new_skill_close) + 1
    fusion_new_at = cursor
    exe[cursor:cursor + len(fusion)] = fusion
    exe[cursor + len(fusion)] = 0
    cursor += len(fusion) + 1
    struct.pack_into("<I", exe, SKILL_CLOSE_PTR, RAM_TO_FILE + skill_close_new_at)
    struct.pack_into("<I", exe, FUSION_PTR, RAM_TO_FILE + fusion_new_at)

    if bytes(exe[SKILL_TABLE[0]:SKILL_TABLE[0] + SKILL_TABLE[1]]) != skill_table_before:
        raise SystemExit("dynamic skill-name pointer table changed")
    if c_string(exe, pointer_target(exe, SKILL_CLOSE_PTR)) != new_skill_close:
        raise SystemExit("skill closer pointer readback differs")
    if c_string(exe, pointer_target(exe, FUSION_PTR)) != fusion:
        raise SystemExit("합체 pointer readback differs")
    members[PSX] = bytes(exe)

    # ---------------------------------------------------------------- S1023
    s1023 = bytearray(members[S1023])
    original_s1023 = pristine[S1023]
    question = encode_text("아버지 편지가 있는데 읽어볼래?", mapping)
    if decoder(question) != "아버지 편지가 있는데 읽어볼래?":
        raise SystemExit("question runtime decode differs")
    old_question = slot_bytes(s1023, QUESTION_SLOT)
    old_question_end = old_question.find(b"\0")
    if old_question_end < 0 or old_question[-1] != QUESTION_COMPLETION or \
            decoder(old_question[:old_question_end]) != "아버지가 남긴 편지가 있는데 읽어볼래?":
        raise SystemExit("S1023 v186 question slot guard differs")
    write_slot(s1023, QUESTION_SLOT, question, QUESTION_COMPLETION)

    help_at, help_size = HELP_BODY
    help_before = bytes(s1023[help_at:help_at + help_size])
    original_help = original_s1023[help_at:help_at + help_size]
    if control_positions(help_before) != control_positions(original_help):
        raise SystemExit("S1023 v186 help control geometry differs from original")
    span_start, span_end = HELP_OPTION3
    if help_before[span_end:span_end + 2] != CHOICE:
        raise SystemExit("S1023 option 3 does not end at its original E5 marker")
    option = encode_text("피해 줄이기 1", mapping)
    if decoder(option[:-1]) != "피해 줄이기 " or option[-1] != 0x12 \
            or len(option) > span_end - span_start:
        raise SystemExit("S1023 option 3 does not fit its original span")
    s1023[help_at + span_start:help_at + span_end] = option.ljust(
        span_end - span_start, bytes((FILLER,))
    )

    # Whole-game choice control group: all 357 bodies retain byte-exact E5/E6 positions.
    choice_bodies = v186.choice_bodies()
    checked = 0
    for name, bodies in choice_bodies.items():
        if name not in members:
            continue
        data = s1023 if name == S1023 else members[name]
        original = pristine[S1023] if name == S1023 else None
        for offset, raw in bodies:
            current = bytes(data[offset:offset + len(raw)])
            if control_positions(current) != control_positions(raw):
                raise SystemExit(f"choice geometry changed: {name} 0x{offset:X}")
            checked += 1
    if checked != 357:
        raise SystemExit(f"expected 357 choice bodies, checked {checked}")

    members[S1023] = bytes(s1023)
    q_at, q_size = QUESTION_BODY
    widths: dict[str, list[int]] = {}
    for label, offset, size in (
        ("question", q_at, q_size), ("help_page_1", help_at, help_size),
        ("help_page_2", 0x47B30, lengths[(S1023, 0x47B30)]),
    ):
        rows = structural.drawn_rows(bytes(s1023[offset:offset + size]), bytes(s1023))
        widths[label] = [structural.row_width(row) for row in rows]
    if max(widths["question"]) > 228 or max(widths["help_page_1"]) > 228 \
            or max(widths["help_page_2"]) > 228:
        raise SystemExit(f"S1023 menu still exceeds 228px: {widths}")

    # ----------------------------------------------------------- archive checks
    changed = sorted(name for name in members if members[name] != before[name])
    if changed != sorted((PSX, SD011, S1023)):
        raise SystemExit(f"unexpected changed archive members: {changed}")
    for name in members:
        if len(members[name]) != len(before[name]):
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
        for name in archive.namelist():
            if archive.read(name) != members[name]:
                raise SystemExit(f"archive readback differs: {name}")

    output_hash = digest(temporary.read_bytes())
    output = OUT_DIR / f"{OUT_STEM}_{output_hash[:8]}.zip"
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {output}")
    temporary.replace(output)

    report = [
        "v187 control, system text and choice repair",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output.name}",
        f"output_sha256={output_hash}",
        "",
        "SD011",
        "  0x47B60: two text spans; original E4/E6 controls restored",
        "  0x47D58: 안심해. + second text span; original E4/E6 controls restored",
        "  0x47D78: 아크... visual bytes retained; final E4 97 restored",
        "  E2 completion targets=4/4 exact next original controls",
        "",
        "PSX.EXE",
        "  dynamic skill-name table=byte-identical to v186",
        "  learned-skill closer=closing bracket + existing 를 배웠다.",
        "  合体 empty pointer=합체",
        f"  live string pool=0x{POOL_START:X}..0x{cursor:X}",
        "",
        "S1023",
        "  question=아버지 편지가 있는데 읽어볼래?",
        "  option 3=피해 줄이기 1 (written in place, padded to original E5)",
        f"  widths={widths}",
        f"  choice_marker_geometry={checked}/357 PASS",
        "",
        "decoder 0x801FF30C / 568 bytes",
        "frame routine 0x801FF634 / 636 bytes",
        f"changed_members={','.join(changed)}",
        "member_sizes=unchanged",
        "cold_boot=NOT RUN (user test required)",
        "rollback=v186",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
