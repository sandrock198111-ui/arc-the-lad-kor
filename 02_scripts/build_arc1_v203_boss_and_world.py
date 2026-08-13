"""Eight wording fixes, none of which changes a line's structure.

v198 tried to move two lines that had outgrown their body into free slots.  That
broke the scene: the dialogue stopped advancing and repeated.  The reason shows
in the bytes.  A line that legitimately lives in a slot keeps the original's
control run in its body --

    0x479E4   e2 85 13 25 e6 01 ...  e6 01 ...      E6 at 4 and 18
    0x47AB0   e2 82 1f 1b 3b ae dd 16 e6 01 ...     E6 at 8

-- and those E6 markers are what advance the line.  The two lines v198 moved had
already been translated in place, so their bodies held no E6 at all.  Pointing
them at a slot left nothing to end the text.

So this build never relocates anything.  Every line is written where it already
lives:

    body already on a slot   rewrite the slot text (126 bytes of room)
    body spells its own text rewrite in place, must not grow past the body

Two lines needed one more byte than their words allowed.  Both had trailing
9C padding to spend, so the wording still lands as asked -- except 개조하는,
which becomes 재정비한 rather than 재정비하는 to fit the single spare byte.
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

BASE = ROOT / "03_output/arc1_v202_untranslated_two_lines.zip"
BASE_SHA256 = "E0D04D0A8631407D34F60204A2C0E283891D271EA175926F6C544E33890CA25A"
OUT = ROOT / "03_output/arc1_v203_boss_and_world.zip"
MANIFEST = ROOT / "01_work/analysis/arc1_v190_dynamic_owner_repair/source_manifest.csv"

SLOT_BASE, SLOT_SIZE, SLOT_COUNT = v186.SLOT_BASE, v186.SLOT_SIZE, v186.SLOT_COUNT
E2, PAD = 0xE2, 0x9C

JOBS = (
    ("4/S4022.DAT", 0x47E1E, "두목님", "두목"),
    ("22/S2055.DAT", 0x47C88, "사람의 미래", "세상의 미래"),
)


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
    # punctuation, read back out of the very lines this build edits
    table.update({",": bytes((0x0D,)), " ": bytes((0x9C,)),
                  "!": bytes((0x02,)), ".": bytes((0x0F,))})
    return table


def spell(word: str, table: dict) -> bytes:
    missing = [c for c in word if c not in table]
    if missing:
        raise SystemExit(f"{word} 에 없는 글자 {missing}")
    return b"".join(table[c] for c in word)


def run(data, at: int) -> bytes:
    end = at
    while end < len(data) and data[end]:
        end += 1
    return bytes(data[at:end])


def main() -> None:
    if hashlib.sha256(BASE.read_bytes()).hexdigest().upper() != BASE_SHA256:
        raise SystemExit("base 아카이브 해시가 다르다")
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        before = {i.filename: archive.read(i.filename) for i in infos}
    members = dict(before)
    table = mapping()

    edited: dict = {}
    report = []
    for member, offset, was, now in JOBS:
        data = edited.setdefault(member, bytearray(members[member]))
        old, new = spell(was, table), spell(now, table)
        body = run(data, offset)
        completion = len(body) - 2
        on_slot = len(body) >= 2 and body[0] == E2 and 0x81 <= body[1] < 0x81 + SLOT_COUNT

        if on_slot:
            slot = body[1] - 0x81
            start = SLOT_BASE + slot * SLOT_SIZE
            block = bytes(data[start:start + SLOT_SIZE])
            if block[-1] != completion:
                raise SystemExit(f"{member} 슬롯{slot} 완료값 {block[-1]} != {completion}")
            text = block[:block.find(b"\0")]
            if text.count(old) != 1:
                raise SystemExit(f"{member} 슬롯{slot} 안에 {was} 가 {text.count(old)}번 있다")
            fresh = text.replace(old, new)
            if len(fresh) > SLOT_SIZE - 2:
                raise SystemExit(f"{member} 슬롯{slot} 텍스트가 한계를 넘는다")
            fill = bytearray(SLOT_SIZE)
            fill[:len(fresh)] = fresh
            fill[-1] = completion
            data[start:start + SLOT_SIZE] = fill
            report.append((member, offset, was, now, f"슬롯{slot} 내용 {len(text)}B -> {len(fresh)}B"))
            continue

        if body.count(old) != 1:
            raise SystemExit(f"{member} 0x{offset:X} 안에 {was} 가 {body.count(old)}번 있다")
        fresh = body.replace(old, new)
        grew = len(fresh) - len(body)
        if grew > 0:
            # spend the trailing 9C padding rather than relocating the line;
            # v198 relocated two and the scene stopped advancing
            spare = len(fresh) - len(fresh.rstrip(bytes((PAD,))))
            if spare < grew:
                raise SystemExit(
                    f"{member} 0x{offset:X} 가 {grew}B 넘치는데 끝 여백은 {spare}B 뿐이다")
            fresh = fresh[:len(fresh) - grew]
        elif grew < 0:
            # keep the body exactly as long as it was, so the terminator and
            # everything after it stay where the engine expects them
            fresh = fresh + bytes((PAD,)) * (-grew)
        if len(fresh) != len(body):
            raise SystemExit(f"{member} 0x{offset:X} 본문 길이를 못 맞췄다")
        data[offset:offset + len(fresh)] = fresh
        report.append((member, offset, was, now, f"본문 직접 {len(body)}B -> {len(fresh)}B"))

    for member, data in edited.items():
        if len(data) != len(members[member]):
            raise SystemExit(f"{member} 길이가 변했다")
        members[member] = bytes(data)

    # nothing may move: every body must keep its length, its first byte class
    # and its control markers exactly as v197 had them
    for member, offset, *_ in JOBS:
        was_body, now_body = run(before[member], offset), run(members[member], offset)
        if len(was_body) != len(now_body):
            raise SystemExit(f"{member} 0x{offset:X} 본문 길이가 변했다")
        if (was_body[0] == E2) != (now_body[0] == E2):
            raise SystemExit(f"{member} 0x{offset:X} 슬롯 참조 여부가 변했다")
        if markers(was_body) != markers(now_body):
            raise SystemExit(f"{member} 0x{offset:X} 제어 마커가 변했다")

    changed = sorted(n for n in members if members[n] != before[n])
    if changed != sorted({m for m, *_ in JOBS}):
        raise SystemExit(f"바뀐 멤버가 {changed} 다")
    if members["PSX.EXE"] != before["PSX.EXE"] or members["COMM.IMG"] != before["COMM.IMG"]:
        raise SystemExit("PSX.EXE 또는 COMM.IMG 가 변했다")

    with ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])

    print("v203  두목 · 세상의 미래 (구조 변경 없음)")
    print(f"  base    {BASE.name}")
    for member, offset, was, now, how in report:
        print(f"    {member:14} 0x{offset:X}  {was} -> {now}   {how}")
    print(f"\n  바뀐 멤버  {changed}")
    print("  본문 길이 · 슬롯 참조 여부 · 제어 마커  모두 v197 과 동일")
    print("  PSX.EXE 와 COMM.IMG  v197 과 동일")
    print(f"  output  {OUT.name}")
    print(f"  sha256  {hashlib.sha256(OUT.read_bytes()).hexdigest().upper()}")


def markers(body: bytes) -> list:
    return [(i, body[i], body[i + 1]) for i in range(len(body) - 1)
            if body[i] in (0xE4, 0xE5, 0xE6)]


def text_has_control(body: bytes) -> bool:
    return any(b in (0xE4, 0xE5, 0xE6) for b in body[:1])


if __name__ == "__main__":
    main()
