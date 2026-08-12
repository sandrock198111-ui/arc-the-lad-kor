"""Drop the subject particle from the six level-up stat names.

The level-up line is assembled from a seven-entry pointer table at file 0x082518:

    0x082518  "레벨 상승!!"      header
    0x08251C  "최대 체력이"      stat names, one per raised statistic
    0x082520  "최대 마력이"
    0x082524  "공격력이"
    0x082528  "방어력이"
    0x08252C  "마력이"
    0x082530  "민첩성이"
    0x082534  " "                separator
    0x082538  " 상승"            suffix

so the game prints "공격력이 1 상승".  The particle reads as a sentence opening
that never arrives; a Korean stat readout is written "공격력 1 상승".

Each name ends with the two bytes DE 3C, the glyph 이.  Writing 00 00 over them
terminates the string one glyph earlier.  Nothing moves: the original NUL still
follows, every pointer keeps its value, and each of the six strings has exactly
one referencing pointer, so no other line is affected.
"""
from __future__ import annotations

import hashlib
import struct
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

BASE = ROOT / "03_output/arc1_v194_remove_last_blank_cell_hangul_63FE7FD6.zip"
BASE_SHA256 = "63FE7FD64A1FCCC005139AE6AC71A62D3DE2109D930B40EF43D747269EE9D744"
OUT = ROOT / "03_output/arc1_v195_levelup_stat_particle.zip"

R2F = 0x8011A800
SLOTS = (0x08251C, 0x082520, 0x082524, 0x082528, 0x08252C, 0x082530)
PARTICLE = bytes((0xDE, 0x3C))          # 이
POOL_LO, POOL_HI = 0x78000, 0x83000
RAM_LO, RAM_HI = 0x80000000, 0x80200000


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system",
                 "create_version", "extract_version", "flag_bits", "volume",
                 "internal_attr", "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def main() -> None:
    if hashlib.sha256(BASE.read_bytes()).hexdigest().upper() != BASE_SHA256:
        raise SystemExit("base 아카이브 해시가 다르다")
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}
    with ZipFile(ROOT / "00_original/arc.zip") as archive:
        stock = archive.read("PSX.EXE")

    import verify_arc1_v191_yagun_choice_local_fixes as v191
    import build_arc1_v186_runtime_text_choice_fixes as v186
    exe = bytearray(members["PSX.EXE"])
    decode = v191.runtime_decoder(bytes(exe))

    def read(ram: int) -> tuple[int, bytes]:
        at = ram - R2F
        end = at
        while exe[end]:
            end += 1
        return at, bytes(exe[at:end])

    def spell(blob: bytes) -> str:
        out = []
        for token in v186.tokens(blob):
            try:
                out.append(decode(token))
            except BaseException:
                out.append("·")
        return "".join(out)

    changes = []
    for slot in SLOTS:
        ram = struct.unpack_from("<I", exe, slot)[0]
        if not (RAM_LO <= ram < RAM_HI):
            raise SystemExit(f"슬롯 0x{slot:06X} 가 문자열을 가리키지 않는다")
        at, blob = read(ram)
        if not blob.endswith(PARTICLE):
            raise SystemExit(f"0x{ram:08X} 가 '이' 로 끝나지 않는다: {blob.hex(' ')}")
        refs = [i for i in range(POOL_LO, POOL_HI, 4)
                if struct.unpack_from("<I", exe, i)[0] == ram]
        if refs != [slot]:
            raise SystemExit(f"0x{ram:08X} 를 가리키는 포인터가 {len(refs)}곳이다")
        if exe[at + len(blob)]:
            raise SystemExit(f"0x{ram:08X} 뒤에 종료자가 없다")
        before = spell(blob)
        exe[at + len(blob) - 2:at + len(blob)] = b"\0\0"
        after = spell(read(ram)[1])
        if after + "이" != before:
            raise SystemExit(f"해독 결과가 기대와 다르다: '{before}' -> '{after}'")
        changes.append((slot, ram, before, after))

    if len(exe) != len(members["PSX.EXE"]):
        raise SystemExit("PSX.EXE 크기가 변했다")
    differing = sum(1 for a, b in zip(exe, members["PSX.EXE"]) if a != b)
    if differing != len(SLOTS) * 2:
        raise SystemExit(f"{differing}바이트가 변했다. {len(SLOTS) * 2} 여야 한다")
    members["PSX.EXE"] = bytes(exe)

    broken = [i for i in range(POOL_LO, POOL_HI, 4)
              if RAM_LO <= struct.unpack_from("<I", stock, i)[0] < RAM_HI
              and not (RAM_LO <= struct.unpack_from("<I", exe, i)[0] < RAM_HI)]
    if broken:
        raise SystemExit(f"문자열 풀 포인터 {len(broken)}개가 RAM 밖")

    with ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])

    print("v195  레벨업 능력치 문구에서 주격 조사 제거")
    print(f"  base    {BASE.name}")
    for slot, ram, before, after in changes:
        print(f"    파일0x{slot:06X} -> 0x{ram:08X}   '{before} 1 상승'  ->  '{after} 1 상승'")
    print(f"\n  바뀐 바이트  {differing}개, 전부 PSX.EXE")
    print(f"  COMM.IMG 와 DAT  v194 와 동일")
    print(f"  포인터 무결성  이상 0개")
    print(f"  output  {OUT.name}")
    print(f"  sha256  {hashlib.sha256(OUT.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
