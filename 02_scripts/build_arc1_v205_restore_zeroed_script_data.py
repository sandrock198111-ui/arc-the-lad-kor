"""Put back script bytes an old reinsertion pass zeroed out.

A player reported the game stops advancing when Gogen says his line.  The line
itself is fine -- 51 bytes, same length as the original.  What is gone is what
follows it:

    D/SD031.DAT 0x45A31   end of the line
    D/SD031.DAT 0x45A34   원본 00 00 00 21 00 05 00 00 00 1b 00 01
                          현재 00 00 00 00 00 00 00 00 00 00 00 00

The engine reads on past the line for what comes next and finds nothing, so it
never leaves that line.

The same thing exists in 16 files, 1,549 bytes in total, and it is identical in
v151, v190 and v197 -- an old pass wrote translated text into a body and cleared
whatever tail it thought was slack.

Every one of those bytes is 0 today, which is what makes the repair safe: a zero
means nothing of ours lives there, so restoring the original value cannot
overwrite a single byte of translation.  The build refuses to write anywhere the
current archive is non-zero.
"""
from __future__ import annotations

import collections
import hashlib
import sys
import zipfile
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = ROOT / "03_output/arc1_v204_warehouse_line_split.zip"
OUT = ROOT / "03_output/arc1_v205_restore_zeroed_script_data.zip"
ORIGINAL = ROOT / "00_original/arc.zip"


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system",
                 "create_version", "extract_version", "flag_bits", "volume",
                 "internal_attr", "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def main() -> None:
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        before = {i.filename: archive.read(i.filename) for i in infos}
    with ZipFile(ORIGINAL) as archive:
        stock = {n: archive.read(n) for n in archive.namelist()}

    members = dict(before)
    restored = collections.Counter()
    spans = collections.Counter()
    for name, current in before.items():
        if name in ("COMM.IMG", "PSX.EXE") or name not in stock:
            continue
        original = stock[name]
        if len(original) != len(current):
            continue
        holes = [i for i in range(len(original)) if original[i] and not current[i]]
        if not holes:
            continue
        data = bytearray(current)
        for at in holes:
            if data[at]:
                raise SystemExit(f"{name} 0x{at:X} 가 0이 아니다. 우리 글자를 덮을 뻔했다")
            data[at] = original[at]
        if len(data) != len(current):
            raise SystemExit(f"{name} 길이가 변했다")
        members[name] = bytes(data)
        restored[name] = len(holes)
        spans[name] = sum(1 for k, at in enumerate(holes) if k == 0 or at != holes[k - 1] + 1)

    if not restored:
        raise SystemExit("되돌릴 것이 없다")

    # every byte we wrote must now equal the original, and every byte that was
    # already ours must be untouched
    for name in restored:
        original, current, made = stock[name], before[name], members[name]
        for i in range(len(made)):
            if current[i]:
                if made[i] != current[i]:
                    raise SystemExit(f"{name} 0x{i:X} 우리 바이트가 변했다")
            elif original[i]:
                if made[i] != original[i]:
                    raise SystemExit(f"{name} 0x{i:X} 복구가 안 됐다")
            elif made[i]:
                raise SystemExit(f"{name} 0x{i:X} 없던 값이 생겼다")
    if members["PSX.EXE"] != before["PSX.EXE"] or members["COMM.IMG"] != before["COMM.IMG"]:
        raise SystemExit("PSX.EXE 또는 COMM.IMG 가 변했다")

    with ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])

    print("v205  옛 재삽입이 0으로 지운 스크립트 바이트 복구")
    print(f"  base    {BASE.name}")
    print(f"  파일 {len(restored)}개,  {sum(restored.values())}바이트,  {sum(spans.values())}구간\n")
    for name, count in restored.most_common():
        print(f"    {name:16} {count:5}B  {spans[name]:4}구간")
    print("\n  전부 현재 0인 자리에만 썼다. 번역 바이트는 하나도 안 건드렸다")
    print("  PSX.EXE 와 COMM.IMG  변경 없음")
    print(f"  output  {OUT.name}")
    print(f"  sha256  {hashlib.sha256(OUT.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
