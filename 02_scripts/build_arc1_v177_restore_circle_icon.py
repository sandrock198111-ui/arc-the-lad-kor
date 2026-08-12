"""Put the circle icon back into the two strings where v171 turned it into a syllable.

The button icons are control codes: 0xE7 followed by an argument.  The parser at
0x8016BBE4 stores that argument minus one:

    8016BC08  lbu   v0, 1(v1)      the byte after E7
    8016BC10  addiu v0, v0, 255    minus 1
    8016BC18  sb    v0, 29(s0)

and the stub at 0x8019D000 accepts ids 1, 2, 4 and 7 as icons, reading U from the
table at 0x8019AA10.  So the four button prompts are written E7 02 (id1, U=192, the
circle), E7 03 (id2, U=180, the square), E7 05 (id4, U=204, the cross) and E7 08
(id7, U=216, START).

Every part of that path is byte-identical to v151: the jump table at 0x8011B644,
the classifier at 0x801A779C, the hook at 0x8016B6C8, the stub, and the U table.
What changed is the text.  Comparing all 5,320 string pointers that both builds
share, exactly two strings differ in their icon content, and both lost the same
thing -- a leading E7 02 rewritten as EA 66, the two-byte cache escape for a
Hangul syllable:

    0x08234C   v151  e7 02 e0 c6 e0 40 ...      v176  ea 66 de 92 de 85 ...
    0x08235C   v151  e7 02 df 86 e0 eb ...      v176  ea 66 df 86 e9 cd ...

The frame buffer of a v176 savestate confirms it: where v151 draws "○ 공격", the
current build draws "잎공격".  v171 repacked the executable's Hangul into the new
cache banks and treated E7 02 as if it were a glyph token.

Both replacements are two bytes wide, so this writes two bytes twice.  No string
moves, no pointer changes, no repacking.
"""
from __future__ import annotations

import hashlib
import struct
import sys
import zipfile
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = ROOT / "03_output/arc1_v176_control_code_dispatch.zip"
CONTROL = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
OUT = ROOT / "03_output/arc1_v177_restore_circle_icon.zip"

R2F = 0x8011A800
SLOTS = (0x08234C, 0x08235C)     # pointer words for the two damaged strings
WRONG = bytes((0xEA, 0x66))      # the cache escape for 잎
RIGHT = bytes((0xE7, 0x02))      # icon id1 -> U=192, the circle
POOL_LO, POOL_HI = 0x78000, 0x83000
RAM_LO, RAM_HI = 0x80000000, 0x80200000

# every part of the icon path that must still match v151
IDENTICAL = ((0x8011B644, 28, "제어코드 분기표"),
             (0x8019AA10, 18, "아이콘 U 표"),
             (0x8019D000, 72, "V 결정 스텁"),
             (0x8016B690, 64, "아이콘 U 기록부"))


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system",
                 "create_version", "extract_version", "flag_bits", "volume",
                 "internal_attr", "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def string_at(exe: bytes, ram: int) -> bytes:
    at = ram - R2F
    end = at
    while end < len(exe) and exe[end]:
        end += 1
    return exe[at:end]


def main() -> None:
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}
    with ZipFile(CONTROL) as archive:
        control = archive.read("PSX.EXE")
    with ZipFile(ROOT / "00_original/arc.zip") as archive:
        stock = archive.read("PSX.EXE")

    exe = bytearray(members["PSX.EXE"])

    # The code path is not what broke.  Refuse to run if it has drifted from v151,
    # because then the missing icon would have a second cause and this fix would
    # hide it rather than solve it.
    for ram, length, name in IDENTICAL:
        at = ram - R2F
        if bytes(exe[at:at + length]) != control[at:at + length]:
            raise SystemExit(f"{name} 0x{ram:08X} 가 v151 과 다르다. 원인이 하나가 아니다")

    touched = []
    for slot in SLOTS:
        here = struct.unpack_from("<I", exe, slot)[0]
        there = struct.unpack_from("<I", control, slot)[0]
        if not (RAM_LO <= here < RAM_HI and RAM_LO <= there < RAM_HI):
            raise SystemExit(f"슬롯 0x{slot:06X} 가 문자열을 가리키지 않는다")
        now, was = string_at(exe, here), string_at(control, there)
        if not was.startswith(RIGHT):
            raise SystemExit(f"v151 의 0x{there:08X} 가 E7 02 로 시작하지 않는다")
        if not now.startswith(WRONG):
            raise SystemExit(f"0x{here:08X} 가 EA 66 으로 시작하지 않는다. 이미 다르다")
        if len(now) != len(was):
            raise SystemExit(f"0x{here:08X} 길이 {len(now)} != v151 {len(was)}")
        at = here - R2F
        exe[at:at + 2] = RIGHT
        touched.append((slot, here, was, now, bytes(exe[at:at + len(now)])))

    changed = [i for i in range(len(exe)) if exe[i] != members["PSX.EXE"][i]]
    if len(changed) != 4:
        raise SystemExit(f"{len(changed)}바이트가 변했다. 4여야 한다")
    if len(exe) != len(members["PSX.EXE"]):
        raise SystemExit("PSX.EXE 크기가 변했다")
    members["PSX.EXE"] = bytes(exe)

    broken = [i for i in range(POOL_LO, POOL_HI, 4)
              if RAM_LO <= struct.unpack_from("<I", stock, i)[0] < RAM_HI
              and not (RAM_LO <= struct.unpack_from("<I", exe, i)[0] < RAM_HI)]
    if broken:
        raise SystemExit(f"문자열 풀 포인터 {len(broken)}개가 RAM 밖")

    with ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])

    print("v177  ○ 아이콘 복구")
    print(f"  base    {BASE.name}")
    print(f"  대조     {CONTROL.name}")
    for slot, ram, was, now, after in touched:
        print(f"\n  포인터 파일0x{slot:06X}  ->  0x{ram:08X}  ({len(now)}바이트)")
        print(f"    v151   {was.hex(' ')}")
        print(f"    이전   {now.hex(' ')}")
        print(f"    이후   {after.hex(' ')}")
    print(f"\n  아이콘 경로 4곳 v151 과 동일  확인됨")
    print(f"  바뀐 바이트  {len(changed)}개, 전부 PSX.EXE")
    print(f"  포인터 무결성  이상 0개")
    print(f"  output  {OUT.name}")
    print(f"  sha256  {hashlib.sha256(OUT.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
