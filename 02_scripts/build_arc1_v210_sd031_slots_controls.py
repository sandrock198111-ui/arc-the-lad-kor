#!/usr/bin/env python3
"""Build v210: repair SD031 wording, slot ownership, and final-message controls.

The v208 scene used every external slot, but four slots were still owned by
lines that fit safely in their original bodies.  This build writes those four
lines inline and reassigns the recovered slots to the four remaining lines
that cannot fit.  No file grows and no new text storage is introduced.

The final two Gogen messages restore the control bytes found on the pristine
disc.  Their exact semantic names are intentionally not guessed here.
"""
from __future__ import annotations

import csv
import hashlib
import sys
import zipfile
from pathlib import Path
from zipfile import ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v171_ui_asset_recovery as v171  # noqa: E402
import build_arc1_v186_runtime_text_choice_fixes as v186  # noqa: E402


BASE = ROOT / "03_output/arc1_v208_gogen_scene.zip"
BASE_SHA256 = "F7A5B5FD46F0CCD66B0286B7E576F7894FDEE94502A75F14FABC332F18FD8140"
PRISTINE = ROOT / "00_original/arc.zip"
MANIFEST = ROOT / "01_work/analysis/arc1_v190_dynamic_owner_repair/source_manifest.csv"
ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"
OUT = ROOT / "03_output/arc1_v210_sd031_slots_controls.zip"
REPORT = ROOT / "03_output/arc1_v210_sd031_slots_controls_report.txt"

MEMBER = "D/SD031.DAT"
SLOT_BASE = v186.SLOT_BASE
SLOT_SIZE = v186.SLOT_SIZE
SLOT_COUNT = v186.SLOT_COUNT
PAD = 0x9C
E2 = 0xE2
E6_BREAK = bytes.fromhex("E6 01")
E4_1F = bytes.fromhex("E4 1F")
E4_3D = bytes.fromhex("E4 3D")


# Strings that fit in their pristine body.  Bytes objects preserve the exact
# original control layout; strings are encoded through the current manifest.
INLINE_JOBS: dict[int, tuple[str | bytes, ...]] = {
    0x459BC: ("할아버지, 누구야?",),
    0x45AAA: ("너희들, 고대의 기록을", E6_BREAK, "찾아왔겠지?"),
    0x45AFE: ("그럼, 당신이?",),
    0x45B3E: ("그렇다", E6_BREAK, "너희를 이끌 살아 있는 기록이지."),
    0x45B96: ("후훗, 후훗, 후훗.",),
    0x45C48: ("내가 다시 깨어난 건 정령들에게 이변이 생겼다는 거겠지.",),
    0x45CA4: ("세계를 이루는 5대 정령부터 구해야 하네.",),
    0x45D88: ("땅, 물, 불, 바람, 빛의 5요소를 관장하는 정령이니라.",),
    0x45F8E: ("그건 어디서 왔는가?",),
    0x46018: ("아주 먼 데서 왔구나.",),
    0x46130: ("에?", E6_BREAK, "할아버지도 따라와!?"),
    0x4637E: ("오랜만에", E6_BREAK, "힘을 쓰겠군."),
    0x463DA: ("어라?", E4_1F, E6_BREAK, "이 돌은 뭐였더라", E4_3D),
    0x463FC: ("로맨싱 스톤을 지녔다!", E4_3D),
}


# slot, body offset, payload.  The final control is part of the slot payload,
# exactly as it was in the pristine body.
SLOT_JOBS: tuple[tuple[int, int, tuple[str | bytes, ...]], ...] = (
    (0, 0x45CF4, ("5대 정령?",)),
    (6, 0x4699E, ("굉장한 아이템을 빼앗아 들었다!", E4_1F)),
    (9, 0x46A2A, ("굉장한 아이템이 부서져 날아갔다!", E4_1F)),
    (14, 0x46A88, ("부서진 아이템을 알아차리지 못했다.", E4_1F)),
)

OLD_SLOT_OWNERS = {0: 0x45C48, 6: 0x45CA4, 9: 0x45D88, 14: 0x46130}


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


def mapping() -> dict[str, bytes]:
    table = dict(v171.current_char_mapping())
    with MANIFEST.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            if row.get("code_hex"):
                table.setdefault(row["char"], bytes.fromhex(row["code_hex"].replace(" ", "")))
    table.update({
        " ": bytes((PAD,)), ",": bytes((0x0D,)), ".": bytes((0x0F,)),
        "!": bytes((0x02,)), "?": bytes.fromhex("E0 47"),
    })
    for value in range(10):
        table[str(value)] = bytes((0x11 + value,))
    return table


def encode_parts(parts: tuple[str | bytes, ...], table: dict[str, bytes]) -> bytes:
    output = bytearray()
    for part in parts:
        if isinstance(part, bytes):
            output.extend(part)
            continue
        missing = sorted({char for char in part if char not in table})
        if missing:
            raise SystemExit(f"missing glyphs for {part!r}: {missing}")
        for char in part:
            output.extend(table[char])
    if 0 in output:
        raise SystemExit(f"encoded payload contains NUL: {parts!r}")
    return bytes(output)


def body_end(data: bytes, offset: int) -> int:
    end = data.find(b"\0", offset)
    if end < 0:
        raise SystemExit(f"unterminated body at 0x{offset:X}")
    return end


def dialogue_offsets() -> list[int]:
    with ORIGINAL_CSV.open(encoding="utf-8-sig", newline="") as handle:
        return [
            int(row["byte offset"], 16)
            for row in csv.DictReader(handle)
            if row["source file"] == MEMBER
        ]


def refs_at_bodies(data: bytes, slot: int, offsets: list[int]) -> list[int]:
    wanted = bytes((E2, disk_id(slot)))
    return [offset for offset in offsets if data[offset:offset + 2] == wanted]


def write_inline(
    data: bytearray,
    stock: bytes,
    offset: int,
    parts: tuple[str | bytes, ...],
    table: dict[str, bytes],
) -> tuple[int, int]:
    end = body_end(stock, offset)
    room = end - offset
    payload = encode_parts(parts, table)
    if len(payload) > room:
        raise SystemExit(f"0x{offset:X}: payload {len(payload)} exceeds room {room}")
    data[offset:end] = payload + bytes((PAD,)) * (room - len(payload))
    data[end] = 0
    return room, len(payload)


def write_slot(
    data: bytearray,
    stock: bytes,
    slot: int,
    offset: int,
    parts: tuple[str | bytes, ...],
    table: dict[str, bytes],
) -> tuple[int, int]:
    end = body_end(stock, offset)
    room = end - offset
    payload = encode_parts(parts, table)
    if not payload or len(payload) > SLOT_SIZE - 2:
        raise SystemExit(f"slot {slot}: invalid payload length {len(payload)}")

    block = bytearray(SLOT_SIZE)
    block[:len(payload)] = payload
    block[len(payload)] = 0
    block[-1] = room - 2
    start = SLOT_BASE + slot * SLOT_SIZE
    data[start:start + SLOT_SIZE] = block

    # Runtime-proven slot bodies keep their pristine tail behind the redirect.
    data[offset:end] = stock[offset:end]
    data[offset:offset + 2] = bytes((E2, disk_id(slot)))
    data[end] = 0
    return room, len(payload)


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v208 base SHA256 differs; refusing to build")

    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        before = {info.filename: archive.read(info.filename) for info in infos}
    with ZipFile(PRISTINE) as archive:
        stock = archive.read(MEMBER)

    if len(before[MEMBER]) != len(stock):
        raise SystemExit("SD031 size differs from pristine")

    offsets = dialogue_offsets()
    data = bytearray(before[MEMBER])
    table = mapping()
    report: list[str] = []

    for slot, owner in OLD_SLOT_OWNERS.items():
        refs = refs_at_bodies(bytes(data), slot, offsets)
        if refs != [owner]:
            raise SystemExit(f"slot {slot} old owner differs: {refs}")

    for offset, parts in INLINE_JOBS.items():
        room, used = write_inline(data, stock, offset, parts, table)
        report.append(f"inline  0x{offset:05X}  {used:3}/{room:3}  {''.join(p for p in parts if isinstance(p, str))}")

    # v208 left translated dead bytes behind slot 4.  Keep the valid redirect,
    # but return its ignored body tail to the pristine sequence.
    slot4_owner = 0x45E42
    slot4_end = body_end(stock, slot4_owner)
    if data[slot4_owner:slot4_owner + 2] != bytes((E2, disk_id(4))):
        raise SystemExit("slot 4 redirect differs")
    data[slot4_owner + 2:slot4_end] = stock[slot4_owner + 2:slot4_end]

    for slot, offset, parts in SLOT_JOBS:
        room, used = write_slot(data, stock, slot, offset, parts, table)
        report.append(f"slot {slot:02}  0x{offset:05X}  {used:3}/{SLOT_SIZE - 2:3}  {''.join(p for p in parts if isinstance(p, str))}")

    for slot, offset, _parts in SLOT_JOBS:
        refs = refs_at_bodies(bytes(data), slot, offsets)
        if refs != [offset]:
            raise SystemExit(f"slot {slot} new owner differs: {refs}")
        end = body_end(stock, offset)
        if data[offset + 2:end] != stock[offset + 2:end]:
            raise SystemExit(f"slot {slot} body tail differs from pristine")
        block = data[SLOT_BASE + slot * SLOT_SIZE:SLOT_BASE + (slot + 1) * SLOT_SIZE]
        if block[-1] != end - offset - 2:
            raise SystemExit(f"slot {slot} completion differs")

    # Exact guards for the bugs this build is intended to remove.
    if data[0x459BC:body_end(stock, 0x459BC)].endswith(bytes((0x3C,))):
        raise SystemExit("old one-byte question code remains at 0x459BC")
    final_a = encode_parts(INLINE_JOBS[0x463DA], table)
    final_b = encode_parts(INLINE_JOBS[0x463FC], table)
    if data[0x463DA:0x463DA + len(final_a)] != final_a:
        raise SystemExit("first final-message controls differ")
    if data[0x463FC:0x463FC + len(final_b)] != final_b:
        raise SystemExit("second final-message controls differ")
    if E4_1F not in final_a or E6_BREAK not in final_a or not final_a.endswith(E4_3D):
        raise SystemExit("first final-message control layout incomplete")
    if not final_b.endswith(E4_3D):
        raise SystemExit("second final-message E4 3D missing")

    members = dict(before)
    members[MEMBER] = bytes(data)
    changed = [name for name in members if members[name] != before[name]]
    if changed != [MEMBER]:
        raise SystemExit(f"unexpected changed members: {changed}")
    if len(members[MEMBER]) != len(before[MEMBER]):
        raise SystemExit("SD031 length changed")

    with ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])

    occupied = 0
    for slot in range(SLOT_COUNT):
        start = SLOT_BASE + slot * SLOT_SIZE
        block = data[start:start + SLOT_SIZE]
        if any(block) or refs_at_bodies(bytes(data), slot, offsets):
            occupied += 1
    if occupied != SLOT_COUNT:
        raise SystemExit(f"occupied slots differ: {occupied}/{SLOT_COUNT}")

    lines = [
        "Arc the Lad 1 Korean patch v210 - SD031 slot/control repair",
        f"base_sha256={BASE_SHA256}",
        f"output_sha256={digest(OUT.read_bytes())}",
        f"changed_members={','.join(changed)}",
        f"sd031_size={len(data)}",
        f"occupied_slots={occupied}/{SLOT_COUNT}",
        "",
        *report,
        "",
        "final_0x463DA=E4 1F + E6 01 + E4 3D restored from pristine layout",
        "final_0x463FC=E4 3D restored from pristine layout",
        "new_E2_storage=none; slots 0,6,9,14 reassigned",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"output={OUT}")


if __name__ == "__main__":
    main()
