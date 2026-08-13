"""Settle the place name on 팔렌시아.

A tester reported both spellings in play.  Counting the byte run for each across
every archive member gives 29 of 팔렌 against a single 파렌, in 1/S1011.DAT --
the one line that drifted.

파 and 팔 are both two bytes (DF A0 and DF 8B), so the run is the same length
either way: two bytes change and nothing moves.  The original disc contains this
run zero times, which is what proves every hit is our own text rather than game
data that happens to read that way.
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

BASE = ROOT / "03_output/arc1_v200_jail_scene_wording.zip"
BASE_SHA256 = "3D4028923BE3D448215F3ADC7B7CDF03498CB84CF8D8D276024F97FCD232E77C"
OUT = ROOT / "03_output/arc1_v201_palencia_spelling.zip"
ORIGINAL = ROOT / "00_original/arc.zip"
MANIFEST = ROOT / "01_work/analysis/arc1_v190_dynamic_owner_repair/source_manifest.csv"


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
    return table


def main() -> None:
    if hashlib.sha256(BASE.read_bytes()).hexdigest().upper() != BASE_SHA256:
        raise SystemExit("base 아카이브 해시가 다르다")
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        before = {i.filename: archive.read(i.filename) for i in infos}
    with ZipFile(ORIGINAL) as archive:
        stock = {n: archive.read(n) for n in archive.namelist()}

    table = mapping()
    wrong = table["파"] + table["렌"]
    right = table["팔"] + table["렌"]
    if len(wrong) != len(right):
        raise SystemExit("두 표기의 바이트 길이가 다르다")

    # the run must not occur on the original disc, or a hit could be game data
    # that merely reads as text
    intruder = sum(d.count(wrong) for n, d in stock.items() if n != "COMM.IMG")
    if intruder:
        raise SystemExit(f"원본에 같은 바이트열이 {intruder}번 있다. 오탐 위험")

    members = dict(before)
    hits = []
    for name, data in before.items():
        if name == "COMM.IMG" or wrong not in data:
            continue
        count = data.count(wrong)
        members[name] = data.replace(wrong, right)
        if len(members[name]) != len(data):
            raise SystemExit(f"{name} 길이가 변했)")
        hits.append((name, count))

    if not hits:
        raise SystemExit("바꿀 것이 없다")
    changed_bytes = sum(
        1 for n in members for a, b in zip(members[n], before[n]) if a != b)
    差 = sum(1 for a, b in zip(wrong, right) if a != b)
    if changed_bytes != sum(c for _, c in hits) * 差:
        raise SystemExit(f"{changed_bytes}바이트가 변했다. {sum(c for _, c in hits)*差} 여야 한다")
    if members["PSX.EXE"] != before["PSX.EXE"] or members["COMM.IMG"] != before["COMM.IMG"]:
        raise SystemExit("PSX.EXE 또는 COMM.IMG 가 변했다")
    left = sum(d.count(wrong) for n, d in members.items() if n != "COMM.IMG")
    if left:
        raise SystemExit(f"파렌 이 {left}곳 남았다")

    with ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])

    total = sum(d.count(right) for n, d in members.items() if n != "COMM.IMG")
    print("v201  지명 표기를 팔렌시아 로 통일")
    print(f"  base    {BASE.name}")
    for name, count in hits:
        print(f"    {name:14} 파렌 -> 팔렌  {count}곳")
    print(f"\n  바뀐 바이트  {changed_bytes}개")
    print(f"  통일 후 팔렌 {total}곳,  파렌 0곳")
    print("  원본 디스크에 같은 바이트열 0회 (전부 우리 텍스트임을 확인)")
    print("  PSX.EXE 와 COMM.IMG  변경 없음")
    print(f"  output  {OUT.name}")
    print(f"  sha256  {hashlib.sha256(OUT.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
