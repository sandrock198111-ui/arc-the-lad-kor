"""Translate the Gogen scene in full, using external slots instead of shortening.

v208 squeezed these ten lines into the original Japanese byte counts, which cost
most of their wording.  It did not have to: 1,449 bodies in this project already
take their text from an external slot, where 126 bytes are available.

v198 tried that and broke a scene, and I blamed the missing E6 marker.  That was
wrong -- 347 slot-backed bodies have no E6 at all.  The real difference is in
build_arc1_v192_choice_speaker_rows, which does this and is runtime-proven:

    disk_id(slot) = slot + 0x81 if slot < 40 else slot + 0x82
    made[second_break:] = stock[second_break:]      # body tail back to original

v198 left our own Korean in the body behind the E2 reference.  Every healthy
slot-backed body carries the original run there instead.

These ten lines are still the untouched original, so only the first two bytes
change: E2 + disk_id.  Everything after stays exactly as the disc shipped it,
and the completion byte keeps the value the engine expects, len(body) - 2.
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
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import build_arc1_v171_ui_asset_recovery as v171  # noqa: E402
import build_arc1_v186_runtime_text_choice_fixes as v186  # noqa: E402
import build_arc1_v191_yagun_choice_local_fixes as v191  # noqa: E402

BASE = ROOT / "03_output/arc1_v207_move_stub_strings.zip"
OUT = ROOT / "03_output/arc1_v209_gogen_scene_slots.zip"
ORIGINAL = ROOT / "00_original/arc.zip"
MANIFEST = ROOT / "01_work/analysis/arc1_v190_dynamic_owner_repair/source_manifest.csv"

MEMBER = "D/SD031.DAT"
SLOT_BASE, SLOT_SIZE, SLOT_COUNT = v186.SLOT_BASE, v186.SLOT_SIZE, v186.SLOT_COUNT
E2 = 0xE2

JOBS = (
    (0x459BC, "영감님, 당신 누구요?"),
    (0x45AFE, "그럼, 당신이……?"),
    (0x45B96, "허허허 허허허 허허허 허허허 허허허 허허허"),
    (0x45C4B, "다시 깨어났다는 건, 정령들에게 이변이 일어나고 있다는 뜻이지."),
    (0x45E45, "다섯 개를 모아 시온 산의 봉인을 풀어라."),
    (0x45F8E, "그건 어디서 난 것인고?"),
    (0x45FDA, "아라라토스에서다!"),
    (0x46190, "이 녀석!!"),
    (0x46226, "그럼, 굉장한 마법을 쓸 수 있다는 거네."),
    (0x462BC, "왠지 못 미더운데……"),
)


def disk_id(slot: int) -> int:
    return slot + 0x81 if slot < 40 else slot + 0x82


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system",
                 "create_version", "extract_version", "flag_bits", "volume",
                 "internal_attr", "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def mapping() -> dict:
    table = dict(v171.current_char_mapping())
    with open(MANIFEST, encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            if row.get("code_hex"):
                table.setdefault(row["char"], bytes.fromhex(row["code_hex"].replace(" ", "")))
    table.update({",": bytes((0x0D,)), " ": bytes((0x9C,)), "!": bytes((0x02,)),
                  ".": bytes((0x0F,)), "?": bytes((0x3C,))})
    return table


def spell(text: str, table: dict) -> bytes:
    missing = [c for c in text if c not in table]
    if missing:
        raise SystemExit(f"{text} 에 없는 글자 {missing}")
    return b"".join(table[c] for c in text)


def main() -> None:
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        before = {i.filename: archive.read(i.filename) for i in infos}
    with ZipFile(ORIGINAL) as archive:
        stock = archive.read(MEMBER)

    table = mapping()
    data = bytearray(before[MEMBER])

    taken = set()
    for slot in range(SLOT_COUNT):
        block = data[SLOT_BASE + slot * SLOT_SIZE:SLOT_BASE + (slot + 1) * SLOT_SIZE]
        if any(block) or v191.slot_references(bytes(data), slot):
            taken.add(slot)
    free = [s for s in range(SLOT_COUNT) if s not in taken]
    if len(free) < len(JOBS):
        raise SystemExit(f"빈 슬롯이 {len(free)}개뿐이다")

    report = []
    for (offset, text), slot in zip(JOBS, free):
        end = offset
        while data[end]:
            end += 1
        body = bytes(data[offset:end])
        if body != stock[offset:end]:
            raise SystemExit(f"0x{offset:X} 가 원본이 아니다. 이미 손댔다")

        payload = spell(text, table)
        if not payload or len(payload) > SLOT_SIZE - 2 or 0 in payload:
            raise SystemExit(f"0x{offset:X} 의 번역이 슬롯에 안 맞는다 ({len(payload)}B)")

        completion = len(body) - 2
        block = bytearray(SLOT_SIZE)
        block[:len(payload)] = payload
        block[-1] = completion
        data[SLOT_BASE + slot * SLOT_SIZE:SLOT_BASE + (slot + 1) * SLOT_SIZE] = block

        # only the reference changes; the rest of the body stays the original run
        data[offset] = E2
        data[offset + 1] = disk_id(slot)
        if bytes(data[offset + 2:end]) != stock[offset + 2:end]:
            raise SystemExit(f"0x{offset:X} 본문 꼬리가 원본과 다르다")
        report.append((offset, slot, len(body), len(payload), text))

    if len(data) != len(before[MEMBER]):
        raise SystemExit("길이가 변했다")
    members = dict(before)
    members[MEMBER] = bytes(data)

    for offset, slot, size, _n, _t in report:
        if v191.slot_references(members[MEMBER], slot) != [offset]:
            raise SystemExit(f"슬롯{slot} 참조가 {v191.slot_references(members[MEMBER], slot)} 다")
        block = members[MEMBER][SLOT_BASE + slot * SLOT_SIZE:SLOT_BASE + (slot + 1) * SLOT_SIZE]
        if block[-1] != size - 2:
            raise SystemExit(f"슬롯{slot} 완료값이 {block[-1]} 다")

    changed = sorted(n for n in members if members[n] != before[n])
    if changed != [MEMBER]:
        raise SystemExit(f"바뀐 멤버가 {changed} 다")

    with ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])

    print("v209  고겐 장면 열 줄, 축약 없이 외부 슬롯으로")
    print(f"  base    {BASE.name}")
    for offset, slot, size, n, text in report:
        print(f"    0x{offset:X}  본문 {size:2}B -> E2 {disk_id(slot):02X}   슬롯{slot:2} {n:2}B   {text}")
    print(f"\n  본문 꼬리 전부 원본 그대로,  완료값 = 본문길이-2")
    print(f"  바뀐 멤버  {changed}")
    print(f"  output  {OUT.name}")
    print(f"  sha256  {hashlib.sha256(OUT.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
