#!/usr/bin/env python3
"""Build v189 from the runtime-working v188 archive.

The four changes in this build are deliberately data-only:

* Restore the two original E4 controls at S1072 0x47996/0x479F4.  The Korean
  pixels already seen in v188 are copied byte-for-byte into free external
  slots, whose completion bytes resume exactly at those controls.
* Put S1023's ``next`` and page-two option 2 on their own visual rows.  The E5
  choice markers never move; two existing filler bytes immediately before each
  marker become E6 01.
* Change SD011's approved wording from ``안심해.`` to ``걱정 마.`` without
  changing the slot's completion metadata or the surrounding controls.

PSX.EXE, COMM.IMG and the dynamic-cache implementation are not modified.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))

import build_arc1_v171_ui_asset_recovery as v171  # noqa: E402
import build_arc1_v186_runtime_text_choice_fixes as v186  # noqa: E402
import build_arc1_v187_control_skill_choice_repair as v187  # noqa: E402
import check_build as structural  # noqa: E402
from plan_bulk_insertion import SLOT_BASE, SLOT_COUNT, SLOT_SIZE  # noqa: E402


BASE = ROOT / "03_output/arc1_v188_safe_string_slot_repair_5A999CAC.zip"
BASE_SHA256 = "5A999CACB3FBDD65CAC7CC93099B494D69F3F2F9BF5D41C576392C87AA7D2383"
PRISTINE = ROOT / "00_original/arc.zip"
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v189_dialogue_timing_choice_rows"
ANALYSIS = ROOT / "01_work/analysis" / OUT_STEM

PSX = "PSX.EXE"
SD011 = "D/SD011.DAT"
S1072 = "1/S1072.DAT"
S1023 = "1/S1023.DAT"

FILLER = 0x9C
E2 = 0xE2
E4 = 0xE4
E5 = bytes.fromhex("E5 03")
E6 = bytes.fromhex("E6 01")

# Runtime-proven v188 bodies.  The Korean text bytes themselves are retained.
S1072_BODY_A = (0x47996, bytes.fromhex(
    "C9 CE DF 80 9C B1 95 DF AF A7 52 0F 0F 0F "
    "9C 9C 9C 9C 9C 9C 9C 9C 9C"
))
S1072_BODY_B = (0x479F4, bytes.fromhex(
    "C9 CE DF 80 9C 75 0D 9C 69 78 BD 51 9C 53 91 BE 0F 9C"
))
S1072_TEXT_A_LEN = 15
S1072_TEXT_B_LEN = 17
S1072_SLOT_A = 2
S1072_SLOT_B = 3
S1072_CONTROL_A_REL = 21
S1072_CONTROL_B_REL = 16

# These are filler bytes immediately before the following E5 marker.
S1023_PAGE1 = (0x47AB0, 55)
S1023_PAGE2 = (0x47B30, 40)
S1023_PAGE1_BREAK_REL = 44
S1023_PAGE2_BREAK_REL = 18


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


def slot_bytes(data: bytes, slot: int) -> bytes:
    start = SLOT_BASE + slot * SLOT_SIZE
    return data[start:start + SLOT_SIZE]


def write_slot(data: bytearray, slot: int, payload: bytes, completion: int) -> None:
    if not 0 <= slot < SLOT_COUNT or len(payload) > SLOT_SIZE - 2:
        raise SystemExit(f"slot {slot} payload does not fit")
    replacement = bytearray(SLOT_SIZE)
    replacement[:len(payload)] = payload
    replacement[len(payload)] = 0
    replacement[-1] = completion
    start = SLOT_BASE + slot * SLOT_SIZE
    data[start:start + SLOT_SIZE] = replacement


def disk_id(slot: int) -> int:
    return slot + 0x81 if slot < 40 else slot + 0x82


def current_slot_references(data: bytes, slot: int) -> list[int]:
    """Find current E2 references outside the external-slot bank."""
    result: list[int] = []
    wanted = bytes((E2, disk_id(slot)))
    bank_end = SLOT_BASE + SLOT_COUNT * SLOT_SIZE
    at = bank_end
    while True:
        at = data.find(wanted, at)
        if at < 0:
            return result
        result.append(at)
        at += 2


def install_timed_body(
    data: bytearray,
    original: bytes,
    offset: int,
    current: bytes,
    text_length: int,
    slot: int,
    control_rel: int,
) -> tuple[bytes, int]:
    if bytes(data[offset:offset + len(current)]) != current:
        raise SystemExit(f"S1072 v188 body guard differs at 0x{offset:X}")
    if any(slot_bytes(data, slot)) or current_slot_references(data, slot):
        raise SystemExit(f"S1072 external slot {slot} is not unowned and empty")
    if original[offset + control_rel:offset + control_rel + 2] != bytes(
        (E4, original[offset + control_rel + 1])
    ):
        raise SystemExit(f"S1072 original E4 guard differs at 0x{offset + control_rel:X}")

    payload = current[:text_length]
    completion = control_rel - 2
    if 0 in payload or completion < 0:
        raise SystemExit(f"S1072 invalid timed payload at 0x{offset:X}")
    write_slot(data, slot, payload, completion)

    body = bytearray((FILLER,) * len(current))
    body[:2] = bytes((E2, disk_id(slot)))
    body[control_rel:control_rel + 2] = original[
        offset + control_rel:offset + control_rel + 2
    ]
    data[offset:offset + len(current)] = body
    if offset + 2 + completion != offset + control_rel:
        raise SystemExit(f"S1072 completion arithmetic differs at 0x{offset:X}")
    return payload, completion


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v188 base archive hash differs")
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}
    with ZipFile(PRISTINE) as archive:
        original = {name: archive.read(name) for name in (SD011, S1072, S1023)}
    before = dict(members)

    # ------------------------------------------------------------- SD011 wording
    sd = bytearray(members[SD011])
    old_slot = slot_bytes(sd, 12)
    old_end = old_slot.find(b"\0")
    decoder = v186.current_decoder(members[PSX])
    if old_end < 0 or old_slot[-1] != 4 or decoder(old_slot[:old_end]) != "안심해.":
        raise SystemExit("SD011 slot 12 v188 wording/completion guard differs")
    new_wording = v187.encode_text("걱정 마.", v171.current_char_mapping())
    if decoder(new_wording) != "걱정 마.":
        raise SystemExit("current runtime decoder does not read the new SD011 wording")
    write_slot(sd, 12, new_wording, 4)
    if slot_bytes(sd, 12)[-1] != old_slot[-1]:
        raise SystemExit("SD011 slot 12 completion changed")
    members[SD011] = bytes(sd)

    # ----------------------------------------------------- S1072 timed dialogues
    s1072 = bytearray(members[S1072])
    payload_a, completion_a = install_timed_body(
        s1072, original[S1072], S1072_BODY_A[0], S1072_BODY_A[1],
        S1072_TEXT_A_LEN, S1072_SLOT_A, S1072_CONTROL_A_REL,
    )
    payload_b, completion_b = install_timed_body(
        s1072, original[S1072], S1072_BODY_B[0], S1072_BODY_B[1],
        S1072_TEXT_B_LEN, S1072_SLOT_B, S1072_CONTROL_B_REL,
    )
    # The exact pixels/text bytes seen in v188 must survive in the slots.
    for slot, payload, completion in (
        (S1072_SLOT_A, payload_a, completion_a),
        (S1072_SLOT_B, payload_b, completion_b),
    ):
        stored = slot_bytes(s1072, slot)
        if stored[:len(payload)] != payload or stored[len(payload)] != 0 \
                or stored[-1] != completion:
            raise SystemExit(f"S1072 slot {slot} readback differs")
    members[S1072] = bytes(s1072)

    # ------------------------------------------------------- S1023 choice rows
    s1023 = bytearray(members[S1023])
    base_target_markers: dict[int, list[tuple[int, bytes]]] = {}
    expected_target_markers: dict[int, list[tuple[int, bytes]]] = {}
    for (offset, size), break_rel in (
        (S1023_PAGE1, S1023_PAGE1_BREAK_REL),
        (S1023_PAGE2, S1023_PAGE2_BREAK_REL),
    ):
        body = bytes(s1023[offset:offset + size])
        base_target_markers[offset] = structural.markers(body)
        if body[break_rel:break_rel + 2] != bytes((FILLER, FILLER)):
            raise SystemExit(f"S1023 filler guard differs at 0x{offset + break_rel:X}")
        if body[break_rel + 2:break_rel + 4] != E5:
            raise SystemExit(f"S1023 following E5 guard differs at 0x{offset + break_rel + 2:X}")
        s1023[offset + break_rel:offset + break_rel + 2] = E6
        after_body = bytes(s1023[offset:offset + size])
        expected = sorted(base_target_markers[offset] + [(break_rel, E6)])
        if structural.markers(after_body) != expected:
            raise SystemExit(f"S1023 target marker readback differs at 0x{offset:X}")
        expected_target_markers[offset] = expected

    # All four/three choices remain distinct rows, within the 228px text window.
    expected_rows = {S1023_PAGE1[0]: 4, S1023_PAGE2[0]: 3}
    choice_widths: dict[int, list[int]] = {}
    for offset, size in (S1023_PAGE1, S1023_PAGE2):
        body = bytes(s1023[offset:offset + size])
        rows = structural.drawn_rows(body, bytes(s1023))
        widths = [structural.row_width(row) for row in rows]
        if len(rows) != expected_rows[offset] or max(widths) > 228:
            raise SystemExit(f"S1023 vertical layout differs at 0x{offset:X}: {widths}")
        if sum(body.count(marker) for marker in (E5,)) != expected_rows[offset]:
            raise SystemExit(f"S1023 E5 count differs at 0x{offset:X}")
        choice_widths[offset] = widths

    # Whole-game control group: only the two declared bodies may gain one E6.
    checked = 0
    target_changes = 0
    for name, bodies in v186.choice_bodies().items():
        if name not in members:
            continue
        source = s1023 if name == S1023 else members[name]
        for offset, raw in bodies:
            current = bytes(source[offset:offset + len(raw)])
            markers = structural.markers(current)
            if name == S1023 and offset in expected_target_markers:
                if markers != expected_target_markers[offset]:
                    raise SystemExit(f"declared S1023 geometry differs at 0x{offset:X}")
                target_changes += 1
            elif markers != structural.markers(raw):
                raise SystemExit(f"undeclared choice geometry changed: {name} 0x{offset:X}")
            checked += 1
    if checked != 357 or target_changes != 2:
        raise SystemExit(
            f"choice control audit count differs: checked={checked}, targets={target_changes}"
        )
    members[S1023] = bytes(s1023)

    # ----------------------------------------------------------- archive checks
    changed = sorted(name for name in members if members[name] != before[name])
    expected_changed = sorted((SD011, S1072, S1023))
    if changed != expected_changed:
        raise SystemExit(f"unexpected changed archive members: {changed}")
    for name in members:
        if len(members[name]) != len(before[name]):
            raise SystemExit(f"member size changed: {name}")
    if members[PSX] != before[PSX] or members["COMM.IMG"] != before["COMM.IMG"]:
        raise SystemExit("dynamic-cache executable/font changed")

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
        "v189 dialogue timing and choice-row repair",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output.name}",
        f"output_sha256={output_hash}",
        "",
        "dynamic_cache=byte-identical to v188 (PSX.EXE and COMM.IMG unchanged)",
        "decoder 0x801FF30C / 568 bytes",
        "frame routine 0x801FF634 / 636 bytes",
        "",
        "D/SD011.DAT",
        "  slot 12: 안심해. -> 걱정 마.",
        "  completion: 4 -> 4",
        "",
        "1/S1072.DAT",
        "  0x47996: v188 Korean bytes -> external slot 2; original E4 79 restored",
        f"  slot 2 completion={completion_a}; resume=0x{S1072_BODY_A[0] + S1072_CONTROL_A_REL:X}",
        "  0x479F4: v188 Korean bytes -> external slot 3; original E4 5B restored",
        f"  slot 3 completion={completion_b}; resume=0x{S1072_BODY_B[0] + S1072_CONTROL_B_REL:X}",
        "",
        "1/S1023.DAT",
        "  0x47AB0: filler at +44 -> E6 01; 다음 moves to row 4",
        "  0x47B30: filler at +18 -> E6 01; 전투 요령 moves to row 2",
        f"  page1 widths={choice_widths[S1023_PAGE1[0]]}",
        f"  page2 widths={choice_widths[S1023_PAGE2[0]]}",
        f"  choice_bodies_checked={checked}; declared_E6_additions={target_changes}",
        "  E5 marker offsets and counts unchanged",
        "",
        f"changed_members={','.join(changed)}",
        "cold_boot=NOT RUN (user test required)",
        "rollback=v188",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
