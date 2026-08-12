#!/usr/bin/env python3
"""Build v192: merge every choice speaker label with its question.

The choice engine keeps cursor geometry separately from the visible text.  v191
removed the first line break from two Choppin menus; runtime testing proved that
the option text moved up while the cursor kept its old row.  This build instead
keeps the complete v190 E5/E6 geometry and the complete option tail.

Only the twelve choice bodies whose original first row is a speaker label are
changed.  The merged prompt occupies row 0, row 1 is deliberately left blank,
and both option rows remain at their original coordinates.  Four other two-line
prompts are ordinary sentence wrapping, not speaker labels, and remain untouched.
"""
from __future__ import annotations

import csv
import hashlib
import re
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v171_ui_asset_recovery as v171  # noqa: E402
import build_arc1_v186_runtime_text_choice_fixes as v186  # noqa: E402
import build_arc1_v191_yagun_choice_local_fixes as v191  # noqa: E402
import verify_arc1_v191_yagun_choice_local_fixes as v191_verify  # noqa: E402


BASE = ROOT / "03_output/arc1_v191_yagun_choice_local_fixes_682EC28A.zip"
BASE_SHA256 = "682EC28A565FAD7E66C4D70A79D66B6F63C227FA079047C9903CB1B808325690"
GEOMETRY_BASE = ROOT / "03_output/arc1_v190_dynamic_owner_repair_4AC51D4F.zip"
GEOMETRY_SHA256 = "4AC51D4F38F38B65782DBD5AAE5A7DA03369A57D6E7DBF3F437E4EDB29556619"
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v192_choice_speaker_rows"
ANALYSIS = ROOT / "01_work/analysis" / OUT_STEM
REPORT = ANALYSIS / "build_report.txt"
AUDIT = ANALYSIS / "choice_speaker_audit.csv"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
FILLER = 0x9C
E2 = 0xE2
E5 = bytes.fromhex("E5 03")
E6 = bytes.fromhex("E6 01")

SLOT_BASE = v186.SLOT_BASE
SLOT_SIZE = v186.SLOT_SIZE
SLOT_COUNT = v186.SLOT_COUNT


# Slot choices are owned per DAT file.  ``rewrite`` means an existing question
# slot is reused; ``free`` means the exact v191 slot must be all-zero and have no
# E2 owner.  Two S7028 prompts share one file and therefore use different slots.
TARGETS = (
    {
        "member": "1/S1023.DAT", "offset": 0x47952, "slot": 0,
        "slot_mode": "rewrite", "old_ref_rel": 9,
        "speaker": "어머니", "question": "아버지가 남긴 편지를 읽을래?",
    },
    {
        "member": "21/S2042.DAT", "offset": 0x47FF0, "slot": 11,
        "slot_mode": "free", "old_ref_rel": None,
        "speaker": "초핀", "question": "더 도와드릴까요?",
    },
    {
        "member": "31/S3012.DAT", "offset": 0x47FF0, "slot": 0,
        "slot_mode": "rewrite", "old_ref_rel": 0,
        "speaker": "초핀", "question": "제가 도와드릴 일이 있습니까?",
    },
    {
        "member": "31/S3022.DAT", "offset": 0x48822, "slot": 35,
        "slot_mode": "free", "old_ref_rel": None,
        "speaker": "병사", "question": "출발하시겠습니까?",
    },
    {
        "member": "7/S7021.DAT", "offset": 0x48D26, "slot": 7,
        "slot_mode": "free", "old_ref_rel": None,
        "speaker": "대회 위원", "question": "출전하시겠습니까?",
    },
    {
        "member": "7/S7022.DAT", "offset": 0x489B6, "slot": 7,
        "slot_mode": "free", "old_ref_rel": None,
        "speaker": "대회 위원", "question": "1회전 준비됐습니까?",
    },
    {
        "member": "7/S7023.DAT", "offset": 0x48A4E, "slot": 7,
        "slot_mode": "free", "old_ref_rel": None,
        "speaker": "대회 위원", "question": "2회전 준비됐습니까?",
    },
    {
        "member": "7/S7024.DAT", "offset": 0x48AAE, "slot": 7,
        "slot_mode": "free", "old_ref_rel": None,
        "speaker": "대회 위원", "question": "준결승 준비됐습니까?",
    },
    {
        "member": "7/S7025.DAT", "offset": 0x48AC2, "slot": 7,
        "slot_mode": "free", "old_ref_rel": None,
        "speaker": "대회 위원", "question": "결승 준비됐습니까?",
    },
    {
        "member": "7/S7026.DAT", "offset": 0x48D28, "slot": 7,
        "slot_mode": "free", "old_ref_rel": None,
        "speaker": "대회 위원", "question": "오브 쟁탈전 준비됐습니까?",
    },
    {
        "member": "7/S7028.DAT", "offset": 0x48028, "slot": 14,
        "slot_mode": "free", "old_ref_rel": None,
        "speaker": "대회 위원", "question": "출전하시겠습니까?",
    },
    {
        "member": "7/S7028.DAT", "offset": 0x48B70, "slot": 15,
        "slot_mode": "free", "old_ref_rel": None,
        "speaker": "대회 위원", "question": "정말 출전하시겠습니까?",
    },
)

# These were the other entries in the historical 15-body two-row audit.  Their
# first row is part of the sentence, not a speaker label.
SENTENCE_WRAPS = {
    ("4/S4033.DAT", 0x47CDC),
    ("4/S4034.DAT", 0x47D30),
    ("4/S4035.DAT", 0x47D30),
    ("4/S4036.DAT", 0x47CDC),
}


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


def disk_id(slot: int) -> int:
    return slot + 0x81 if slot < 40 else slot + 0x82


def slot_bytes(data: bytes, slot: int) -> bytes:
    start = SLOT_BASE + slot * SLOT_SIZE
    return data[start:start + SLOT_SIZE]


def write_slot(data: bytearray, slot: int, payload: bytes, completion: int) -> None:
    if not 0 <= slot < SLOT_COUNT:
        raise SystemExit(f"slot outside bank: {slot}")
    if not payload or len(payload) > SLOT_SIZE - 2 or 0 in payload:
        raise SystemExit(f"slot {slot} payload does not fit")
    replacement = bytearray(SLOT_SIZE)
    replacement[:len(payload)] = payload
    replacement[len(payload)] = 0
    replacement[-1] = completion
    start = SLOT_BASE + slot * SLOT_SIZE
    data[start:start + SLOT_SIZE] = replacement


def translated_rows() -> dict[tuple[str, int], dict[str, str]]:
    result: dict[tuple[str, int], dict[str, str]] = {}
    source = ROOT / "05_docs/script_translated_full.csv"
    with source.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            result[(row["source file"], int(row["offset"], 0))] = row
    return result


def discovered_speaker_choices(
    translations: dict[tuple[str, int], dict[str, str]],
) -> set[tuple[str, int]]:
    """Find the speaker-only prompt shape independently of TARGETS.

    Original choice text has its speaker and question as two text rows before
    the first E5.  Speaker labels in this corpus are at most eight Japanese
    characters and contain no sentence-ending punctuation.  The complete set is
    written to the audit and asserted against the manually reviewed target set.
    """
    choice_keys = {
        (member, offset)
        for member, bodies in v186.choice_bodies().items()
        for offset, _raw in bodies
    }
    found: set[tuple[str, int]] = set()
    for key in choice_keys:
        row = translations.get(key)
        if not row:
            continue
        pieces = [part.strip() for part in row["japanese"].replace("\n", "|").split("|")]
        prompt_rows: list[str] = []
        for part in pieces:
            if "<CTRL:E5" in part:
                break
            if part:
                prompt_rows.append(part)
        if len(prompt_rows) >= 2 and len(prompt_rows[0]) <= 8 \
                and not re.search(r"[。？！?!]", prompt_rows[0]):
            found.add(key)
    return found


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v191 base archive hash differs")
    if digest(GEOMETRY_BASE.read_bytes()) != GEOMETRY_SHA256:
        raise SystemExit("v190 geometry archive hash differs")
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}
    with ZipFile(GEOMETRY_BASE) as archive:
        geometry = {name: archive.read(name) for name in archive.namelist()}
    before = dict(members)

    targets = {(str(item["member"]), int(item["offset"])) for item in TARGETS}
    translations = translated_rows()
    discovered = discovered_speaker_choices(translations)
    if discovered != targets:
        missing = sorted(discovered - targets)
        extra = sorted(targets - discovered)
        raise SystemExit(f"speaker-choice census differs: missing={missing}, extra={extra}")

    bodies = {
        (member, offset): raw
        for member, items in v186.choice_bodies().items()
        for offset, raw in items
    }
    mapping = v171.current_char_mapping()
    mapping[":"] = bytes.fromhex("DF 80")
    runtime_decode = v191_verify.runtime_decoder(members[PSX])

    def decode(payload: bytes) -> str:
        # The v191 verifier intentionally covers the Korean runtime tables but
        # not the two native digit tokens used by these tournament prompts.
        # Preserve those proven one-byte tokens and use the runtime decoder for
        # every other token.
        result: list[str] = []
        for token in v186.tokens(payload):
            if token == b"\x12":
                result.append("1")
            elif token == b"\x13":
                result.append("2")
            else:
                result.append(runtime_decode(token))
        return "".join(result)

    result_rows: dict[tuple[str, int], dict[str, object]] = {}
    for item in TARGETS:
        member = str(item["member"])
        offset = int(item["offset"])
        slot = int(item["slot"])
        key = (member, offset)
        raw = bodies.get(key)
        if raw is None:
            raise SystemExit(f"declared target is not a choice body: {member} 0x{offset:X}")
        if member not in members or member not in geometry:
            raise SystemExit(f"declared target member is absent: {member}")

        data = bytearray(members[member])
        current = bytes(data[offset:offset + len(raw)])
        stock = geometry[member][offset:offset + len(raw)]
        stock_markers = v186.structural.markers(stock)
        e6_positions = [position for position, token in stock_markers if token == E6]
        e5_positions = [position for position, token in stock_markers if token == E5]
        if len(e6_positions) < 3 or len(e5_positions) != 2:
            raise SystemExit(f"target geometry differs: {member} 0x{offset:X}")
        first_break, second_break = e6_positions[:2]
        if first_break < 2 or second_break <= first_break + 2:
            raise SystemExit(f"target prompt rows are malformed: {member} 0x{offset:X}")

        old_slot = slot_bytes(data, slot)
        old_refs = v191.slot_references(data, slot)
        if item["slot_mode"] == "free":
            if any(old_slot) or old_refs:
                raise SystemExit(f"declared free slot is owned: {member} slot {slot}")
        else:
            expected_ref = offset + int(item["old_ref_rel"])
            if old_refs != [expected_ref]:
                raise SystemExit(
                    f"rewrite slot ownership differs: {member} slot {slot} refs={old_refs}"
                )

        prompt = f'{item["speaker"]}: {item["question"]}'
        payload = v186.encode_text(prompt, mapping)
        if decode(payload) != prompt:
            raise SystemExit(f"runtime prompt readback differs: {member} 0x{offset:X}")
        prompt_width = v186.structural.row_width(list(v186.tokens(payload)))
        if prompt_width > v186.ROW_PIXELS:
            raise SystemExit(
                f"merged prompt exceeds one row: {member} 0x{offset:X} {prompt_width}px"
            )

        completion = first_break - 2
        write_slot(data, slot, payload, completion)

        # Keep both original line breaks.  The second prompt row is blank, so the
        # options and their cursor markers retain the exact runtime-proven rows.
        made = bytearray(current)
        made[:second_break] = bytes((FILLER,)) * second_break
        made[:2] = bytes((E2, disk_id(slot)))
        made[first_break:first_break + 2] = E6
        made[second_break:] = stock[second_break:]
        data[offset:offset + len(raw)] = made

        if v191.slot_references(data, slot) != [offset]:
            raise SystemExit(f"new slot ownership differs: {member} slot {slot}")
        stored = slot_bytes(data, slot)
        if stored[:len(payload)] != payload or stored[len(payload)] != 0 \
                or stored[-1] != completion:
            raise SystemExit(f"new slot readback differs: {member} slot {slot}")
        if v186.structural.markers(bytes(made)) != stock_markers:
            raise SystemExit(f"E5/E6 geometry changed: {member} 0x{offset:X}")
        if bytes(made[second_break:]) != stock[second_break:]:
            raise SystemExit(f"option tail changed: {member} 0x{offset:X}")

        rows = v186.structural.drawn_rows(bytes(made), bytes(data))
        widths = [v186.structural.row_width(row) for row in rows]
        if len(rows) != 4 or widths[0] != prompt_width or widths[1] != 0:
            raise SystemExit(f"four-row speaker layout differs: {member} 0x{offset:X} {widths}")
        stock_rows = v186.structural.drawn_rows(stock, geometry[member])
        stock_widths = [v186.structural.row_width(row) for row in stock_rows]
        if widths[2:] != stock_widths[2:]:
            raise SystemExit(f"option row widths changed: {member} 0x{offset:X}")

        members[member] = bytes(data)
        result_rows[key] = {
            "prompt": prompt,
            "slot": slot,
            "prompt_width": prompt_width,
            "widths": widths,
            "e5": "|".join(str(value) for value in e5_positions),
            "e6": "|".join(str(value) for value in e6_positions),
        }

    # Whole-game control group: all 357 choices are compared with v190.  Exactly
    # twelve text bodies change, while every E5/E6 marker stays byte-for-byte at
    # its original offset.  The four sentence-wrap cases must remain untouched.
    checked = 0
    changed_choices = 0
    untouched = 0
    audit_rows: list[dict[str, object]] = []
    for member, items in v186.choice_bodies().items():
        if member not in members or member not in geometry:
            continue
        for offset, raw in items:
            key = (member, offset)
            old = geometry[member][offset:offset + len(raw)]
            new = members[member][offset:offset + len(raw)]
            marker_ok = v186.structural.markers(new) == v186.structural.markers(old)
            if not marker_ok:
                raise SystemExit(f"choice marker regression: {member} 0x{offset:X}")
            changed = new != old
            if key in targets:
                if not changed:
                    raise SystemExit(f"declared speaker choice did not change: {member} 0x{offset:X}")
                changed_choices += 1
                classification = "speaker_prompt_merged"
            elif key in SENTENCE_WRAPS:
                if changed:
                    raise SystemExit(f"sentence wrap changed: {member} 0x{offset:X}")
                untouched += 1
                classification = "sentence_wrap_preserved"
            else:
                # v191 already contains unrelated accepted data changes.  Compare
                # its non-target choice bodies with v190 to make sure this build
                # introduces no additional choice mutation.
                if new != before[member][offset:offset + len(raw)]:
                    raise SystemExit(f"undeclared choice changed: {member} 0x{offset:X}")
                untouched += 1
                classification = "other_choice_unchanged"
            row = translations.get(key, {})
            details = result_rows.get(key, {})
            audit_rows.append({
                "source_file": member,
                "offset": f"0x{offset:X}",
                "classification": classification,
                "japanese": row.get("japanese", "").replace("\n", " / "),
                "canonical_korean": row.get("korean", "").replace("\n", " / "),
                "v192_prompt": details.get("prompt", ""),
                "slot": details.get("slot", ""),
                "row_widths_px": "|".join(str(value) for value in details.get("widths", [])),
                "e5_positions": details.get("e5", ""),
                "e6_positions": details.get("e6", ""),
                "marker_geometry_matches_v190": int(marker_ok),
            })
            checked += 1
    if (checked, changed_choices, untouched) != (357, 12, 345):
        raise SystemExit(
            f"choice census differs: checked={checked}, changed={changed_choices}, "
            f"untouched={untouched}"
        )

    changed_members = sorted(name for name in members if members[name] != before[name])
    expected_changed = sorted({str(item["member"]) for item in TARGETS})
    if changed_members != expected_changed:
        raise SystemExit(f"unexpected changed members: {changed_members}")
    if members[PSX] != before[PSX] or members[COMM] != before[COMM]:
        raise SystemExit("PSX.EXE or COMM.IMG changed")
    if any(len(members[name]) != len(before[name]) for name in members):
        raise SystemExit("archive member length changed")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    with AUDIT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(audit_rows[0]))
        writer.writeheader()
        writer.writerows(audit_rows)

    temporary = OUT_DIR / f"{OUT_STEM}_building.zip"
    if temporary.exists():
        raise SystemExit(f"refusing to overwrite {temporary}")
    with ZipFile(temporary, "w", ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    with ZipFile(temporary) as archive:
        if archive.namelist() != [info.filename for info in infos]:
            raise SystemExit("archive member order changed")
        for name, expected in members.items():
            if archive.read(name) != expected:
                raise SystemExit(f"archive readback differs: {name}")
    output_hash = digest(temporary.read_bytes())
    output = OUT_DIR / f"{OUT_STEM}_{output_hash[:8]}.zip"
    if output.exists():
        if digest(output.read_bytes()) != output_hash:
            raise SystemExit(f"existing output content differs: {output}")
        temporary.unlink()
    else:
        temporary.replace(output)

    report = [
        "v192 all choice-speaker rows merged with cursor geometry preserved",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"geometry_base={GEOMETRY_BASE.name}",
        f"geometry_sha256={GEOMETRY_SHA256}",
        f"output={output.name}",
        f"sha256={output_hash}",
        "choice_bodies_checked=357",
        "speaker_prompt_candidates=12/12",
        "speaker_prompts_changed=12",
        "sentence_wrap_prompts_preserved=4/4",
        "other_choices_unchanged=341/341",
        "choice_E5_E6_geometry=v190 exact 357/357 PASS",
        "target_option_tails=v190 byte-identical 12/12 PASS",
        "target_layout=prompt|blank|option1|option2 12/12 PASS",
        "target_prompt_width_max_px=" + str(max(int(row["prompt_width"]) for row in result_rows.values())),
        "PSX.EXE=v191 byte-identical PASS",
        "COMM.IMG=v191 byte-identical PASS",
        "decoder 0x801FF348 / 568 bytes",
        "frame routine 0x801FF668 / 584 bytes",
        "huffman 0x801FF580 / 232 bytes",
        "resident_used=5356/5356",
        "resident_free=0",
        "heap_boundary=0x801FF8B0 unchanged",
        "startup_copy=5356 unchanged",
        f"changed_members={','.join(changed_members)}",
        "archive_member_order=PASS",
        "archive_member_lengths=PASS",
        "archive_roundtrip=PASS",
        "emulator_run=NO",
        "runtime=PENDING user cold boot",
        "rollback=v190 for choice layout; v191 for Yagun wording",
    ]
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))
    print(REPORT)


if __name__ == "__main__":
    main()
