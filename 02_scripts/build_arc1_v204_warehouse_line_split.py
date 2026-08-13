"""Translate the one line the extractor never listed.

A tester found Japanese still on screen in the warehouse.  The line is not in
dialogue_all.csv at all -- the extractor missed it -- so there was no offset to
work from.  Searching the original disc for the byte run that spells 様子が変
located both of them:

    4/S4011.DAT 0x485A2  21B   ちょっと待った。 / 何か様子が変だ。

The second hit, 4/S4061.DAT 0x478AE, already starts with E2 82 -- it was
translated onto a slot long ago -- so it is left alone.

The line shows as broken Japanese rather than clean Japanese because the project
has since overwritten some of those glyph cells with Hangul.

Both bodies still match the original byte for byte, which is what proves nobody
has translated them yet.  The E6 01 line break in the first one keeps its exact
position: line one is written into its 10 bytes and line two into its 9, each
padded with 9C so nothing after them moves.
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

BASE = ROOT / "03_output/arc1_v203_boss_and_world.zip"
BASE_SHA256 = "40E35DE6B1C6C80C2F4D39616C3C913D9F42C55EC4DCAFA03E91166ED7A3F1CC"
OUT = ROOT / "03_output/arc1_v204_warehouse_line_split.zip"
ORIGINAL = ROOT / "00_original/arc.zip"
MANIFEST = ROOT / "01_work/analysis/arc1_v190_dynamic_owner_repair/source_manifest.csv"

PAD = 0x9C
BREAK = bytes((0xE6, 0x01))

# member, offset, the Japanese it must still hold, the Korean per line
# the line already reads Korean, so the check is against what v202 wrote
JOBS = (
    ("4/S4011.DAT", 0x485A2,
     "de d4 e9 35 0f 9c 9c 9c 9c 9c e6 01 e1 e9 8f 9c de 3c cd 74 0f",
     ("잠깐, 뭔가", "이상해.")),
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
    table.update({",": bytes((0x0D,)), " ": bytes((PAD,)),
                  "!": bytes((0x02,)), ".": bytes((0x0F,))})
    return table


def spell(text: str, table: dict) -> bytes:
    missing = [c for c in text if c not in table]
    if missing:
        raise SystemExit(f"{text} 에 없는 글자 {missing}")
    return b"".join(table[c] for c in text)


def main() -> None:
    if hashlib.sha256(BASE.read_bytes()).hexdigest().upper() != BASE_SHA256:
        raise SystemExit("base 아카이브 해시가 다르다")
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        before = {i.filename: archive.read(i.filename) for i in infos}
    with ZipFile(ORIGINAL) as archive:
        stock = {n: archive.read(n) for n in archive.namelist()}

    table = mapping()
    members = dict(before)
    edited: dict = {}
    report = []

    for member, offset, japanese, korean in JOBS:
        want = bytes.fromhex(japanese)
        data = edited.setdefault(member, bytearray(members[member]))
        here = bytes(data[offset:offset + len(want)])
        if here != want:
            raise SystemExit(f"{member} 0x{offset:X} 가 원본 일본어가 아니다. 이미 손댔다")
        # the body no longer matches the disc -- v202 translated it
        if data[offset + len(want)]:
            raise SystemExit(f"{member} 0x{offset:X} 뒤에 종료자가 없다")

        slots = want.split(BREAK)
        if len(slots) != len(korean):
            raise SystemExit(f"{member} 줄 수가 {len(slots)} 인데 번역은 {len(korean)} 줄이다")

        built = []
        for room, line in zip(slots, korean):
            text = spell(line, table)
            if len(text) > len(room):
                raise SystemExit(f"{member} '{line}' 이 {len(text)}B 로 자리 {len(room)}B 를 넘는다")
            built.append(text + bytes((PAD,)) * (len(room) - len(text)))
        fresh = BREAK.join(built)
        if len(fresh) != len(want):
            raise SystemExit(f"{member} 0x{offset:X} 길이가 {len(fresh)} != {len(want)}")

        data[offset:offset + len(fresh)] = fresh
        report.append((member, offset, len(want), " / ".join(korean)))

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

    print("v204  창고 대사 줄 배치")
    print(f"  base    {BASE.name}")
    for member, offset, size, text in report:
        print(f"    {member:14} 0x{offset:X}  {size}B   {text}")
    print(f"\n  바뀐 멤버  {changed}")
    print("  E6 줄바꿈 위치 · 본문 길이  그대로")
    print("  PSX.EXE 와 COMM.IMG  변경 없음")
    print(f"  output  {OUT.name}")
    print(f"  sha256  {hashlib.sha256(OUT.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
