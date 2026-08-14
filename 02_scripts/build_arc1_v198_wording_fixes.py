"""Seven wording fixes the user asked for after the v197 test build shipped.

    잘됐군      ->  비참하군
    개조        ->  재정비        three lines in the Palencia jail scene
    결행        ->  집행
    동생분들    ->  동생들
    다운타운    ->  마을

v197 is already out, so nothing may regress.  This build touches only the byte
runs that spell those words.

Two mechanisms hold dialogue.  A body either spells its own text, or it starts
with `E2 (0x81 + slot)` and takes the text from an external 128-byte slot whose
last byte is `len(body) - 2`.  Slot text has room to spare, so a line that grows
past its own body is moved into a free slot rather than shortened -- the wording
stays exactly as asked.  Lines already on a slot only have their slot rewritten.

Words are found and replaced as byte runs built from the live character mapping,
so punctuation and spacing are never re-encoded and the rest of the line is
copied through untouched.
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

BASE = ROOT / "03_output/arc1_v197_prompt_width_off_by_one.zip"
BASE_SHA256 = "E8D9BA745A2F0F1776C0B52A22E05D1D52205D8B274914716187A4E86A4DBE3B"
OUT = ROOT / "03_output/arc1_v198_wording_fixes.zip"
MANIFEST = ROOT / "01_work/analysis/arc1_v190_dynamic_owner_repair/source_manifest.csv"

SLOT_BASE, SLOT_SIZE, SLOT_COUNT = v186.SLOT_BASE, v186.SLOT_SIZE, v186.SLOT_COUNT
E2 = 0xE2

JOBS = (
    ("4/S4021.DAT", 0x47992, "잘됐군", "비참하군"),
    ("4/S4021.DAT", 0x47AFA, "개조", "재정비"),
    ("4/S4021.DAT", 0x47B8E, "개조", "재정비"),
    ("4/S4022.DAT", 0x47A0C, "개조", "재정비"),
    ("4/S4022.DAT", 0x47D34, "결행", "집행"),
    ("4/S4022.DAT", 0x47E1E, "동생분들", "동생들"),
    ("F/SF081.DAT", 0x479EC, "다운타운", "마을"),
)


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system",
                 "create_version", "extract_version", "flag_bits", "volume",
                 "internal_attr", "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def mapping() -> dict[str, bytes]:
    table = dict(v171.current_char_mapping())
    with open(MANIFEST, encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            if row.get("code_hex"):
                table.setdefault(row["char"], bytes.fromhex(row["code_hex"].replace(" ", "")))
    return table


def spell(word: str, table: dict[str, bytes]) -> bytes:
    missing = [c for c in word if c not in table]
    if missing:
        raise SystemExit(f"{word} 에 없는 글자 {missing}")
    return b"".join(table[c] for c in word)


def run(data: bytes, at: int) -> bytes:
    end = at
    while end < len(data) and data[end]:
        end += 1
    return data[at:end]


def slot_of(body: bytes) -> int | None:
    if len(body) >= 2 and body[0] == E2 and 0x81 <= body[1] < 0x81 + SLOT_COUNT:
        return body[1] - 0x81
    return None


def block_of(data, slot: int) -> bytes:
    return bytes(data[SLOT_BASE + slot * SLOT_SIZE:SLOT_BASE + (slot + 1) * SLOT_SIZE])


def put_block(data, slot: int, text: bytes, completion: int) -> None:
    block = bytearray(SLOT_SIZE)
    block[:len(text)] = text
    block[-1] = completion
    data[SLOT_BASE + slot * SLOT_SIZE:SLOT_BASE + (slot + 1) * SLOT_SIZE] = block


def free_slot(data, taken: set) -> int:
    for slot in range(SLOT_COUNT):
        if slot in taken:
            continue
        if not any(block_of(data, slot)) and not v191.slot_references(bytes(data), slot):
            return slot
    raise SystemExit("빈 슬롯이 없다")


def main() -> None:
    if hashlib.sha256(BASE.read_bytes()).hexdigest().upper() != BASE_SHA256:
        raise SystemExit("base 아카이브 해시가 다르다")
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        before = {i.filename: archive.read(i.filename) for i in infos}
    members = dict(before)
    table = mapping()

    edited: dict = {}
    claimed: dict = {}
    report = []
    for member, offset, was, now in JOBS:
        data = edited.setdefault(member, bytearray(members[member]))
        taken = claimed.setdefault(member, set())
        old, new = spell(was, table), spell(now, table)
        body = run(bytes(data), offset)
        completion = len(body) - 2
        slot = slot_of(body)

        if slot is None:
            text = body
        else:
            block = block_of(data, slot)
            if block[-1] != completion:
                raise SystemExit(f"{member} 슬롯{slot} 완료값 {block[-1]} != {completion}")
            text = block[:block.find(b"\0")]

        if text.count(old) != 1:
            raise SystemExit(f"{member} 0x{offset:X} 안에 {was} 가 {text.count(old)}번 있다")
        fresh = text.replace(old, new)
        if len(fresh) > SLOT_SIZE - 2:
            raise SystemExit(f"{member} 0x{offset:X} 가 슬롯 한계를 넘는다")

        if slot is not None:
            put_block(data, slot, fresh, completion)
            how = f"슬롯{slot} 내용 교체 {len(text)}B -> {len(fresh)}B"
        elif len(fresh) <= len(body):
            data[offset:offset + len(fresh)] = fresh
            for k in range(offset + len(fresh), offset + len(body)):
                data[k] = 0
            how = f"본문 직접 {len(body)}B -> {len(fresh)}B"
        else:
            slot = free_slot(data, taken)
            taken.add(slot)
            put_block(data, slot, fresh, completion)
            data[offset] = E2
            data[offset + 1] = 0x81 + slot
            how = f"슬롯{slot} 로 옮김 {len(fresh)}B"
        report.append((member, offset, was, now, how))

    for member, data in edited.items():
        if len(data) != len(members[member]):
            raise SystemExit(f"{member} 길이가 변했다")
        members[member] = bytes(data)

    changed = sorted(n for n in members if members[n] != before[n])
    if changed != sorted({m for m, *_ in JOBS}):
        raise SystemExit(f"바뀐 멤버가 {changed} 다")
    if members["PSX.EXE"] != before["PSX.EXE"] or members["COMM.IMG"] != before["COMM.IMG"]:
        raise SystemExit("PSX.EXE 또는 COMM.IMG 가 변했다")

    with ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])

    print("v198  문구 일곱 곳 수정")
    print(f"  base    {BASE.name}")
    for member, offset, was, now, how in report:
        print(f"    {member:14} 0x{offset:X}  {was} -> {now}   {how}")
    print(f"\n  바뀐 멤버  {changed}")
    print("  PSX.EXE 와 COMM.IMG  v197 과 동일")
    print(f"  output  {OUT.name}")
    print(f"  sha256  {hashlib.sha256(OUT.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
