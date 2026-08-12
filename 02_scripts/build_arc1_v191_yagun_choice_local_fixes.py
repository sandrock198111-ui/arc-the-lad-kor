#!/usr/bin/env python3
"""Build v191: local Yagun register and duplicated Choppin-choice repairs.

This is deliberately a post-v190 surgical build.  It does not rerun the
whole-story translator or the whole-choice generator.  Four owned E2 slots
and the two copies of one Choppin menu are the complete mutation scope.
"""
from __future__ import annotations

import csv
import hashlib
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v171_ui_asset_recovery as v171  # noqa: E402
import build_arc1_v186_runtime_text_choice_fixes as v186  # noqa: E402
import build_arc1_v189_dialogue_timing_choice_rows as v189  # noqa: E402


BASE = ROOT / "03_output/arc1_v190_dynamic_owner_repair_4AC51D4F.zip"
BASE_SHA256 = "4AC51D4F38F38B65782DBD5AAE5A7DA03369A57D6E7DBF3F437E4EDB29556619"
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v191_yagun_choice_local_fixes"
ANALYSIS = ROOT / "01_work/analysis" / OUT_STEM
REPORT = ANALYSIS / "build_report.txt"
YAGUN_AUDIT = ANALYSIS / "yagun_tone_audit.csv"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
S3012 = "31/S3012.DAT"
S2042 = "21/S2042.DAT"
S3031 = "31/S3031.DAT"
S3032 = "31/S3032.DAT"

SLOT_BASE = v186.SLOT_BASE
SLOT_SIZE = v186.SLOT_SIZE
FILLER = 0x9C
E2 = 0xE2
E5 = bytes.fromhex("E5 03")
E6 = bytes.fromhex("E6 01")

CHOICE_OFFSET = 0x47FF0
CHOICE_SIZE = 53
FIRST_CHOICE_ROW = 25

S3012_OLD_BODY = bytes.fromhex(
    "6E 71 9C 9C 9C E6 01 E2 81 9C 9C 9C 9C 9C 9C 9C 9C 9C "
    "9C 9C 9C 9C 9C 9C 9C E6 01 E5 03 A1 4E 9C 9C 9C 9C 9C "
    "E6 01 E5 03 DF AB 9C AA 4E 8A 51 9C DF 24 4E 9C 9C"
)
S2042_OLD_BODY = bytes.fromhex(
    "6E 71 9C 9C 9C E6 01 E1 C1 9C 5E B7 DF 41 E1 D5 6D 8B "
    "E0 47 9C 9C 9C 9C 9C E6 01 E5 03 DF 85 DF ED 95 9C 9C "
    "E6 01 E5 03 A9 52 68 9C E1 C1 9C 9C 9C 9C 9C 9C 9C"
)
S3012_OLD_SLOT0 = bytes.fromhex(
    "96 DF 78 8F 9C B4 8F 9C 5E DF 17 DE 3C 9C DF 44 9C 9D "
    "DE 3C 9C 53 61 45 6D E0 47"
)

# Existing v190 payloads are guarded byte-for-byte.  New payloads are encoded
# with the same v171+ runtime map already used by the accepted v186-v190 line.
YAGUN_TARGETS = (
    {
        "member": S3031,
        "offset": "0x47C40",
        "slot": 37,
        "completion": 36,
        "old_text": "야군: 하지만 그건 아이들에게는 무리입니다. 너무 위험해요.",
        "new_text": "야군: 하지만 그건 아이들에게는 무리입니다. 너무 위험합니다.",
        "old_hex": (
            "E0 DA E0 C5 DF 80 9C E0 C4 E0 A2 E0 49 9C E0 29 E0 41 9C "
            "E0 9C E0 BD E0 3B E0 9F E0 14 E0 C2 9C E0 E7 E0 98 E0 C9 "
            "E0 35 E0 C1 0F 9C E0 32 E0 E7 9C E0 69 E0 E8 E0 88 E0 66 0F"
        ),
    },
    {
        "member": S3031,
        "offset": "0x4810A",
        "slot": 40,
        "completion": 28,
        "old_text": "야군: 최근에는 이 근처에도 몬스터가 나타나오.",
        "new_text": "야군: 최근에는 이 근처에도 몬스터가 나타나고 있습니다.",
        "old_hex": (
            "79 9B DF 80 9C DF A4 E9 59 46 84 9C DE 3C 9C E9 59 DF 0C "
            "46 5E 9C AB 6F 8D 8F 9C 52 E0 1A 52 75 0F"
        ),
    },
    {
        "member": S3032,
        "offset": "0x479EE",
        "slot": 7,
        "completion": 30,
        "old_text": "야군: 다만 저곳은 우리도 애를 먹고 있는 곳이오.",
        "new_text": "야군: 다만 저곳은 우리도 애를 먹고 있는 곳입니다.",
        "old_hex": (
            "79 9B DF 80 9C 78 68 9C DF 37 DE B0 56 9C 88 BD 5E 9C DF FE "
            "65 9C E9 58 51 9C 53 84 9C DE B0 DE 3C 75 0F"
        ),
    },
    {
        "member": S3032,
        "offset": "0x47A40",
        "slot": 6,
        "completion": 32,
        "old_text": "야군: 만일 무슨 일이 있어도 우리는 책임을 지지 않겠소.",
        "new_text": "야군: 만일 무슨 일이 있어도 우리는 책임을 지지 않습니다.",
        "old_hex": (
            "79 9B DF 80 9C 68 9D 9C 96 E1 C0 9C 9D DE 3C 9C 53 4E 5E 9C "
            "88 BD 84 9C EA 6F E1 CE D5 9C 72 72 9C AE C4 DE 83 0F"
        ),
    },
)

YAGUN_CONTEXT = {
    (S3031, "0x47AB0"): "혼잣말",
    (S3031, "0x47BDC"): "아크 일행",
    (S3031, "0x47C40"): "아크 일행",
    (S3031, "0x47C98"): "아크 일행",
    (S3031, "0x47E08"): "아크 일행",
    (S3031, "0x47E54"): "아크 일행",
    (S3031, "0x47EBE"): "아크 일행",
    (S3031, "0x47F1A"): "아크 일행",
    (S3031, "0x47F8C"): "아크 일행",
    (S3031, "0x480B0"): "아크 일행",
    (S3031, "0x4810A"): "아크 일행",
    (S3031, "0x4815A"): "아크 일행",
    (S3031, "0x481B6"): "아크 일행",
    (S3031, "0x48246"): "부하 병사",
    (S3031, "0x482A2"): "부하 병사",
    (S3031, "0x48308"): "아크 일행",
    (S3031, "0x4836C"): "아크 일행",
    (S3031, "0x483BC"): "아크 일행",
    (S3031, "0x4841E"): "부하 병사",
    (S3032, "0x47994"): "아크 일행",
    (S3032, "0x479EE"): "아크 일행",
    (S3032, "0x47A40"): "아크 일행",
    (S3032, "0x47B62"): "혼잣말",
    (S3032, "0x47BBA"): "혼잣말",
    (S3032, "0x47C8E"): "부하 몬스터",
    (S3032, "0x47CDC"): "부하 몬스터",
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


def encode(text: str, mapping: dict[str, bytes]) -> bytes:
    return v186.encode_text(text, mapping)


def slot_bytes(data: bytes, slot: int) -> bytes:
    start = SLOT_BASE + slot * SLOT_SIZE
    return data[start:start + SLOT_SIZE]


def guarded_slot_write(
    data: bytearray,
    slot: int,
    old_payload: bytes,
    completion: int,
    new_payload: bytes,
) -> None:
    old = slot_bytes(data, slot)
    end = old.find(b"\0")
    if end < 0 or old[:end] != old_payload or old[-1] != completion:
        raise SystemExit(f"slot {slot} payload/completion guard differs")
    if any(old[end:SLOT_SIZE - 1]):
        raise SystemExit(f"slot {slot} has nonzero tail")
    if not new_payload or len(new_payload) > SLOT_SIZE - 2 or 0 in new_payload:
        raise SystemExit(f"slot {slot} new payload is invalid")
    replacement = bytearray(SLOT_SIZE)
    replacement[:len(new_payload)] = new_payload
    replacement[len(new_payload)] = 0
    replacement[-1] = completion
    start = SLOT_BASE + slot * SLOT_SIZE
    data[start:start + SLOT_SIZE] = replacement


def disk_id(slot: int) -> int:
    return slot + 0x81 if slot < 40 else slot + 0x82


def slot_references(data: bytes, slot: int) -> list[int]:
    wanted = bytes((E2, disk_id(slot)))
    result: list[int] = []
    at = SLOT_BASE + v186.SLOT_COUNT * SLOT_SIZE
    while True:
        at = data.find(wanted, at)
        if at < 0:
            return result
        result.append(at)
        at += 2


def write_yagun_audit(new_text_by_key: dict[tuple[str, str], str]) -> None:
    source = ROOT / "05_docs/script_translated_full.csv"
    rows: list[dict[str, str]] = []
    with source.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            key = (row["source file"], row["offset"])
            if key not in YAGUN_CONTEXT:
                continue
            rows.append({
                "file": key[0],
                "offset": key[1],
                "audience": YAGUN_CONTEXT[key],
                "japanese": row["japanese"].replace("\n", " / "),
                "before": row["korean"],
                "after": new_text_by_key.get(key, row["korean"]),
                "decision": "수정" if key in new_text_by_key else "유지",
            })
    if len(rows) != 26 or sum(row["decision"] == "수정" for row in rows) != 4:
        raise SystemExit(f"Yagun audit scope differs: {len(rows)} rows")
    with YAGUN_AUDIT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v190 base archive hash differs")
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}
    before = dict(members)
    required = {PSX, COMM, S3012, S2042, S3031, S3032}
    if not required <= members.keys():
        raise SystemExit(f"v190 lacks required members: {sorted(required - members.keys())}")

    mapping = v171.current_char_mapping()
    mapping[":"] = bytes.fromhex("DF 80")
    new_text_by_key: dict[tuple[str, str], str] = {}
    changed_slots: list[str] = []

    for item in YAGUN_TARGETS:
        member = str(item["member"])
        slot = int(item["slot"])
        completion = int(item["completion"])
        old_payload = bytes.fromhex(str(item["old_hex"]))
        new_text = str(item["new_text"])
        new_payload = encode(new_text, mapping)
        data = bytearray(members[member])
        guarded_slot_write(data, slot, old_payload, completion, new_payload)
        if slot_bytes(data, slot)[-1] != completion:
            raise SystemExit(f"completion changed: {member} slot {slot}")
        members[member] = bytes(data)
        new_text_by_key[(member, str(item["offset"]))] = new_text
        changed_slots.append(f"{member}:slot{slot} -> {new_text}")

    # S3012: move its unique slot-0 redirect to the beginning of the body.  The
    # slot completion resumes at the original E6 immediately before choice 1.
    s3012 = bytearray(members[S3012])
    old = bytes(s3012[CHOICE_OFFSET:CHOICE_OFFSET + CHOICE_SIZE])
    if old != S3012_OLD_BODY or slot_references(s3012, 0) != [CHOICE_OFFSET + 7]:
        raise SystemExit("S3012 Choppin body/ownership guard differs")
    prompt_3012 = encode("초핀: 제가 도와드릴 일이 있습니까?", mapping)
    guarded_slot_write(s3012, 0, S3012_OLD_SLOT0, 16, prompt_3012)
    body = bytearray(old)
    body[:FIRST_CHOICE_ROW] = bytes((FILLER,)) * FIRST_CHOICE_ROW
    body[:2] = bytes((E2, disk_id(0)))
    s3012[CHOICE_OFFSET:CHOICE_OFFSET + CHOICE_SIZE] = body
    # The redirect starts at +0 and must resume at +25: 0 + 2 + 23 = 25.
    slot0 = bytearray(slot_bytes(s3012, 0))
    slot0[-1] = FIRST_CHOICE_ROW - 2
    s3012[SLOT_BASE:SLOT_BASE + SLOT_SIZE] = slot0
    if slot_references(s3012, 0) != [CHOICE_OFFSET]:
        raise SystemExit("S3012 slot-0 redirect did not move exactly once")
    members[S3012] = bytes(s3012)

    # S2042 is the inline duplicate.  Only its first visual row is rewritten;
    # the original E6/E5 choice tail from +25 remains byte-identical.
    s2042 = bytearray(members[S2042])
    old = bytes(s2042[CHOICE_OFFSET:CHOICE_OFFSET + CHOICE_SIZE])
    if old != S2042_OLD_BODY:
        raise SystemExit("S2042 Choppin body guard differs")
    prompt_2042 = encode("초핀: 더 도와드릴까요?", mapping)
    if len(prompt_2042) > FIRST_CHOICE_ROW:
        raise SystemExit("S2042 inline prompt does not fit its proven row")
    body = bytearray(old)
    body[:FIRST_CHOICE_ROW] = bytes((FILLER,)) * FIRST_CHOICE_ROW
    body[:len(prompt_2042)] = prompt_2042
    s2042[CHOICE_OFFSET:CHOICE_OFFSET + CHOICE_SIZE] = body
    members[S2042] = bytes(s2042)

    # The two option tails are immutable.
    for member, old_body in ((S3012, S3012_OLD_BODY), (S2042, S2042_OLD_BODY)):
        made = members[member][CHOICE_OFFSET:CHOICE_OFFSET + CHOICE_SIZE]
        if made[FIRST_CHOICE_ROW:] != old_body[FIRST_CHOICE_ROW:]:
            raise SystemExit(f"choice option tail changed: {member}")
        if [p for p, token in v186.structural.markers(made) if token == E5] != [27, 38]:
            raise SystemExit(f"E5 positions changed: {member}")
        if [p for p, token in v186.structural.markers(made) if token == E6] != [25, 36]:
            raise SystemExit(f"E6 target positions differ: {member}")

    # Whole-game control group.  Exactly two bodies lose only the obsolete
    # speaker-only E6 at +5.  The other 355 bodies are byte-identical.
    choice_checked = 0
    choice_changed = 0
    target_keys = {(S3012, CHOICE_OFFSET), (S2042, CHOICE_OFFSET)}
    for member, bodies in v186.choice_bodies().items():
        if member not in members:
            continue
        for offset, raw in bodies:
            left = before[member][offset:offset + len(raw)]
            right = members[member][offset:offset + len(raw)]
            if (member, offset) in target_keys:
                if left == right:
                    raise SystemExit(f"declared choice did not change: {member}")
                choice_changed += 1
            elif left != right:
                raise SystemExit(f"undeclared choice body changed: {member} 0x{offset:X}")
            choice_checked += 1
    if (choice_checked, choice_changed) != (357, 2):
        raise SystemExit(f"choice control count differs: {choice_checked}/{choice_changed}")

    choice_widths: dict[str, list[int]] = {}
    for member in (S3012, S2042):
        data = members[member]
        body = data[CHOICE_OFFSET:CHOICE_OFFSET + CHOICE_SIZE]
        rows = v186.structural.drawn_rows(body, data)
        widths = [v186.structural.row_width(row) for row in rows]
        if len(rows) != 3 or max(widths) > v186.ROW_PIXELS:
            raise SystemExit(f"choice layout differs: {member} rows={widths}")
        choice_widths[member] = widths

    changed = sorted(member for member in members if members[member] != before[member])
    expected_changed = sorted((S3012, S2042, S3031, S3032))
    if changed != expected_changed:
        raise SystemExit(f"unexpected changed members: {changed}")
    if members[PSX] != before[PSX] or members[COMM] != before[COMM]:
        raise SystemExit("dynamic-cache executable or font changed")
    if any(len(members[name]) != len(before[name]) for name in members):
        raise SystemExit("archive member length changed")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    write_yagun_audit(new_text_by_key)
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
    stamp = digest(temporary.read_bytes())
    output = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    if output.exists():
        raise SystemExit(f"refusing to overwrite {output}")
    temporary.replace(output)

    report = [
        "v191 local Yagun register and Choppin-choice repair",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output.name}",
        f"sha256={stamp}",
        "Yagun_direct_lines_audited=26",
        "Yagun_lines_changed=4",
        *changed_slots,
        "choice_bodies_checked=357",
        "choice_bodies_changed=2",
        "choice_other_bodies_byte_identical=355/355 PASS",
        f"S3012_choice_widths={choice_widths[S3012]}",
        f"S2042_choice_widths={choice_widths[S2042]}",
        "choice_E5_positions=27,38 unchanged",
        "choice_option_tail_from_+25=byte-identical PASS",
        "PSX.EXE=v190 byte-identical PASS",
        "COMM.IMG=v190 byte-identical PASS",
        "decoder 0x801FF348 / 568 bytes",
        "frame routine 0x801FF668 / 584 bytes",
        "huffman 0x801FF580 / 232 bytes",
        "resident_used=5356/5356",
        "resident_free=0",
        "heap_boundary=0x801FF8B0 unchanged",
        "startup_copy=5356 unchanged",
        f"changed_members={','.join(changed)}",
        "archive_member_order=PASS",
        "archive_member_lengths=PASS",
        "archive_roundtrip=PASS",
        "emulator_run=NO",
        "runtime=PENDING user cold boot",
        "rollback=v190",
    ]
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))
    print(REPORT)


if __name__ == "__main__":
    main()
