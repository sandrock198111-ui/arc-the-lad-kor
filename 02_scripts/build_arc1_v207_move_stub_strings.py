"""Give back the skill strings v173 and v176 wrote code over.

v171 packed 29 short strings into 0x8019D000..0x8019D078.  v173 then restored the
72-byte E7 icon stub to 0x8019D000 -- which stopped the freeze and brought the
button icons back -- and v176 put the control-code dispatcher at 0x8019D074.
Both landed on top of those strings.

Seventeen of the 29 are damaged, and they are exactly the skill vocabulary:

    불러내기  초음파  던지기  점프  합체  강타  반격  자폭  부활  일반 …

which is why a level-up reads "슬로우 에너미의" and then stops.

The strings cannot simply be rewritten in place: the code has to stay where it
is.  So the whole 120-byte run is copied to free space and every pointer into it
is shifted by the same amount.  Copying the run whole -- rather than string by
string -- keeps the relative offsets, which matters because several of these are
addressed by pointing partway into a neighbour.
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

BASE = ROOT / "03_output/arc1_v206_restore_zeroed_script_data.zip"
DONOR = ROOT / "03_output/arc1_v172_lookup_width_fix_109252A0.zip"
OUT = ROOT / "03_output/arc1_v207_move_stub_strings.zip"

R2F = 0x8011A800
OLD, LENGTH = 0x8019D000, 0x78          # the run v171 packed, 120 bytes
NEW = 0x80193B44                        # 128 free bytes in the string pool
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
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}
    with ZipFile(DONOR) as archive:
        donor = archive.read("PSX.EXE")
    with ZipFile(ROOT / "00_original/arc.zip") as archive:
        stock = archive.read("PSX.EXE")

    exe = bytearray(members["PSX.EXE"])

    def spell(image, ram, limit=60):
        s = ram - R2F
        e = s
        while e < len(image) and image[e] and e - s < limit:
            e += 1
        return bytes(image[s:e])

    # only the strings the code actually landed on, and only those a pointer
    # still reaches -- the rest of the run is untouched and needs no move
    damaged = {}
    for p in range(POOL_LO, POOL_HI, 4):
        target = struct.unpack_from("<I", exe, p)[0]
        if not (OLD <= target < OLD + LENGTH):
            continue
        if spell(exe, target) != spell(donor, target):
            damaged.setdefault(target, []).append(p)
    if not damaged:
        raise SystemExit("손상된 문자열이 없다")

    need = sum(len(spell(donor, a)) + 1 for a in damaged)
    holes = []
    start = None
    for i in range(POOL_LO, POOL_HI):
        if not exe[i]:
            if start is None:
                start = i
        else:
            if start is not None and i - start >= 8:
                holes.append((start, i - start))
            start = None
    # 0x8019D000..0x8019D0D0 is the E7 stub and the control-code dispatcher.
    # Its trailing NOPs read as free space but the last one is the delay slot of
    # `j 0x8016B5E0` -- writing a string there breaks the dispatcher.
    CODE_LO, CODE_HI = 0x8019D000 - R2F, 0x8019D0D0 - R2F
    holes = [(s, n) for s, n in holes
             if not (s < CODE_HI and s + n > CODE_LO)
             and not any(RAM_LO <= struct.unpack_from("<I", exe, q)[0] < RAM_HI
                         and s <= struct.unpack_from("<I", exe, q)[0] - R2F < s + n
                         for q in range(POOL_LO, POOL_HI, 4))]
    holes.sort(key=lambda x: -x[1])
    if not holes or holes[0][1] < need:
        raise SystemExit(f"{need}B 가 필요한데 가장 큰 빈 구간은 {holes[0][1] if holes else 0}B")

    where = holes[0][0]
    cursor = where
    moved = []
    for target in sorted(damaged):
        text = spell(donor, target)
        exe[cursor:cursor + len(text)] = text
        exe[cursor + len(text)] = 0
        fresh = cursor + R2F
        for p in damaged[target]:
            struct.pack_into("<I", exe, p, fresh)
            moved.append((p, target, fresh))
        cursor += len(text) + 1

    for p, was, now in moved:
        if spell(exe, now) != spell(donor, was):
            raise SystemExit(f"0x{p:06X} 의 문자열이 v172 와 다르다")

    if any(exe[OLD - R2F + i] != members["PSX.EXE"][OLD - R2F + i] for i in range(LENGTH)):
        raise SystemExit("옛 자리의 코드가 변했다")
    if len(exe) != len(members["PSX.EXE"]):
        raise SystemExit("PSX.EXE 크기가 변했다")
    members["PSX.EXE"] = bytes(exe)

    broken = [i for i in range(POOL_LO, POOL_HI, 4)
              if RAM_LO <= struct.unpack_from("<I", stock, i)[0] < RAM_HI
              and not (RAM_LO <= struct.unpack_from("<I", exe, i)[0] < RAM_HI)]
    if broken:
        raise SystemExit(f"문자열 풀 포인터 {len(broken)}개가 RAM 밖")

    changed = [n for n in members if members[n] != {i.filename: None for i in infos}.get(n, None)]
    with ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])

    print("v207  스텁이 덮은 기술 문자열을 빈 자리로 옮김")
    print(f"  base    {BASE.name}")
    print(f"  donor   {DONOR.name}")
    print(f"  손상된 문자열 {len(damaged)}개, {need}B  ->  0x{where + R2F:08X}")
    print(f"  옮긴 포인터  {len(moved)}개")
    for p, was, now in moved[:20]:
        print(f"    파일0x{p:06X}  0x{was:08X} -> 0x{now:08X}")
    print(f"\n  17개 문자열이 v172 와 같은지  전부 확인됨")
    print(f"  E7 스텁과 제어코드 분배기  제자리 유지")
    print(f"  문자열 풀 포인터 무결성  이상 0개")
    print(f"  output  {OUT.name}")
    print(f"  sha256  {hashlib.sha256(OUT.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
