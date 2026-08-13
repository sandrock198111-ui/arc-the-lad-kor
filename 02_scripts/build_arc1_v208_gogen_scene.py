"""Translate the Gogen meeting scene, which was still entirely Japanese.

Ten consecutive lines in D/SD031.DAT had never been touched -- the player meets
the old man and every word of it is the original script.  They are not in
dialogue_all.csv, so they were found by searching the disc for the byte runs that
spell the Japanese.

Each line is written into the exact bytes the original used.  Korean runs longer
than Japanese here, so eight of the ten were shortened to fit; the wording below
is what the user approved after seeing the byte counts.  The one line carrying an
E6 01 break keeps it, with each half sized to its own half of the run.

Whatever is left over is padded with 9C so the terminator stays put and nothing
after these lines moves.
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

BASE = ROOT / "03_output/arc1_v207_move_stub_strings.zip"
OUT = ROOT / "03_output/arc1_v208_gogen_scene.zip"
ORIGINAL = ROOT / "00_original/arc.zip"
MANIFEST = ROOT / "01_work/analysis/arc1_v190_dynamic_owner_repair/source_manifest.csv"

MEMBER = "D/SD031.DAT"
PAD = 0x9C
BREAK = bytes((0xE6, 0x01))

JOBS = (
    (0x459BC, ("영감님, 누구요?",)),
    (0x45AFE, ("그럼 당신이…?",)),
    (0x45B96, ("허허허 허허허 허허허",)),
    (0x45C4B, ("다시 깨어난 건 정령에게 이변이 생겼다는 뜻이지.",)),
    (0x45E45, ("다섯 개 모아", "봉인을 풀어라.")),
    (0x45F8E, ("그건 어디서 난 것인고?",)),
    (0x45FDA, ("아라라토스다!",)),
    (0x46190, ("이놈!!",)),
    (0x46226, ("그럼 굉장한 마법을 쓰는 거네.",)),
    (0x462BC, ("왠지 못 미더운데…",)),
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
    table.update({",": bytes((0x0D,)), " ": bytes((PAD,)), "!": bytes((0x02,)),
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
    report = []

    for offset, lines in JOBS:
        end = offset
        while data[end]:
            end += 1
        body = bytes(data[offset:end])
        if body != stock[offset:end]:
            raise SystemExit(f"0x{offset:X} 가 원본 일본어가 아니다. 이미 손댔다")

        rooms = body.split(BREAK)
        if len(rooms) != len(lines):
            raise SystemExit(f"0x{offset:X} 줄 수 {len(rooms)} != 번역 {len(lines)}")

        built = []
        for room, line in zip(rooms, lines):
            text = spell(line, table)
            if len(text) > len(room):
                raise SystemExit(f"0x{offset:X} '{line}' 이 {len(text)}B 로 자리 {len(room)}B 초과")
            built.append(text + bytes((PAD,)) * (len(room) - len(text)))
        fresh = BREAK.join(built)
        if len(fresh) != len(body):
            raise SystemExit(f"0x{offset:X} 길이 {len(fresh)} != {len(body)}")

        data[offset:offset + len(fresh)] = fresh
        report.append((offset, len(body), " / ".join(lines)))

    if len(data) != len(before[MEMBER]):
        raise SystemExit("길이가 변했다")
    members = dict(before)
    members[MEMBER] = bytes(data)

    changed = sorted(n for n in members if members[n] != before[n])
    if changed != [MEMBER]:
        raise SystemExit(f"바뀐 멤버가 {changed} 다")

    with ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])

    print("v208  고겐 만나는 장면 열 줄 번역")
    print(f"  base    {BASE.name}")
    for offset, size, text in report:
        print(f"    0x{offset:X}  {size:3}B   {text}")
    print(f"\n  바뀐 멤버  {changed}")
    print("  E6 줄바꿈 위치 · 본문 길이  그대로")
    print(f"  output  {OUT.name}")
    print(f"  sha256  {hashlib.sha256(OUT.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
