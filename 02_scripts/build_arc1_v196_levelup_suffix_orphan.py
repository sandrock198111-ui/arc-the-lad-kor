"""Point the level-up suffix at the glyphs v193 left it without.

v182 stored `LV`, `상` and `승` as static pixels in COMM.IMG row 11, column 3.
v193 found that the skill-range cursor reads x=0..64, y=128..160 as a texture --
that cell is inside it -- and restored the four planes to the original, moving the
level-up header to codes that already existed:

    header  0x8019FCC8   df e8 e1 ea 9c cd 8e df e3 df e3   레벨 상승!!

The suffix that every stat line ends with was not moved:

    suffix  0x8019FCF0   9c df d0 df d1                     " 상승"

DF D0 and DF D1 are glyph 937 and 938, which are row 11 column 3 planes 1 and 2 --
the pixels v193 blanked.  They are in no conflict range, so nothing redirects them
to the cache and the renderer draws two empty cells.  `상승` has been invisible on
every level-up line since v193; it is not a v195 regression.

The header's own codes are the fix.  CD is glyph 204, inside range 204..205 and
therefore served from the dynamic source; 8E is glyph 141, still inked in
COMM.IMG.  Writing `9c cd 8e` and terminating leaves the string two bytes shorter
in place, so no pointer moves.

Only one executable string references the orphaned pair, so this is the whole
repair on the executable side.
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

BASE = ROOT / "03_output/arc1_v195_levelup_stat_particle.zip"
BASE_SHA256 = "48E1F37E36A39E61CD8D0AAC18F464AE6A950ABD1229DB26521E656CB41D3D90"
OUT = ROOT / "03_output/arc1_v196_levelup_suffix_orphan.zip"

R2F = 0x8011A800
SUFFIX_RAM = 0x8019FCF0
HEADER_RAM = 0x8019FCC8
WAS = bytes((0x9C, 0xDF, 0xD0, 0xDF, 0xD1))       # " " + glyph 937 + glyph 938
NOW = bytes((0x9C, 0xCD, 0x8E, 0x00, 0x00))       # " " + glyph 204 + glyph 141
HEADER = bytes.fromhex("df e8 e1 ea 9c cd 8e df e3 df e3")
RANGES_RAM, ROW_BYTES, IPR = 0x801A74C0, 896, 84
POOL_LO, POOL_HI = 0x78000, 0x83000
RAM_LO, RAM_HI = 0x80000000, 0x80200000


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system",
                 "create_version", "extract_version", "flag_bits", "volume",
                 "internal_attr", "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def inked(font: bytes, index: int) -> bool:
    row, col, plane = index // IPR, (index % IPR) // 4, index % 4
    bit = 1 << plane
    for dy in range(12):
        at = (row * 12 + dy) * ROW_BYTES + col * 6
        for byte in font[at:at + 6]:
            if (byte & 0x0F & bit) or ((byte >> 4) & bit):
                return True
    return False


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
    font = members["COMM.IMG"]
    decode = v191.runtime_decoder(bytes(exe))

    def spell(blob: bytes) -> str:
        out = []
        for token in v186.tokens(blob):
            try:
                out.append(decode(token))
            except BaseException:
                out.append("·")
        return "".join(out)

    at = SUFFIX_RAM - R2F
    if bytes(exe[at:at + len(WAS)]) != WAS:
        raise SystemExit(f"0x{SUFFIX_RAM:08X} 가 기대한 꼬리가 아니다: {bytes(exe[at:at+5]).hex(' ')}")
    if exe[at + len(WAS)]:
        raise SystemExit("꼬리 뒤에 종료자가 없다")
    head = HEADER_RAM - R2F
    if bytes(exe[head:head + len(HEADER)]) != HEADER:
        raise SystemExit("머리말이 v193 형태가 아니다")

    # the glyphs we are moving away from must really be empty, and the ones we
    # move to must really be reachable -- otherwise this trades one blank for another
    covered = set()
    raw = bytes(exe[RANGES_RAM - R2F:RANGES_RAM - R2F + 96])
    for k in range(48):
        word = struct.unpack_from("<H", raw, k * 2)[0]
        start, length = word & 0x7FF, (word >> 11) + 1
        covered.update(range(start, start + length))
    for index in (937, 938):
        if inked(font, index) or index in covered:
            raise SystemExit(f"번호 {index} 는 고아가 아니다. 전제가 틀렸다")
    for index in (204, 141):
        if not (inked(font, index) or index in covered):
            raise SystemExit(f"번호 {index} 도 비어 있다. 대체가 안 된다")

    before = spell(WAS)
    exe[at:at + len(NOW)] = NOW
    after = spell(bytes(exe[at:at + 3]))
    if after != " 상승":
        raise SystemExit(f"새 꼬리가 ' 상승' 으로 해독되지 않는다: '{after}'")

    differing = sum(1 for a, b in zip(exe, members["PSX.EXE"]) if a != b)
    if differing != 4 or len(exe) != len(members["PSX.EXE"]):
        raise SystemExit(f"{differing}바이트가 변했다. 4여야 한다")
    members["PSX.EXE"] = bytes(exe)

    broken = [i for i in range(POOL_LO, POOL_HI, 4)
              if RAM_LO <= struct.unpack_from("<I", stock, i)[0] < RAM_HI
              and not (RAM_LO <= struct.unpack_from("<I", exe, i)[0] < RAM_HI)]
    if broken:
        raise SystemExit(f"문자열 풀 포인터 {len(broken)}개가 RAM 밖")

    with ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])

    print("v196  레벨업 꼬리 ' 상승' 을 살아 있는 글자로 되돌림")
    print(f"  base    {BASE.name}")
    print(f"  0x{SUFFIX_RAM:08X}   {WAS.hex(' ')}  ->  {NOW.hex(' ')}")
    print(f"    해독   '{before}'  ->  '{after}'")
    print(f"    번호937·938 = 행11 열3 면1·2, v193 이 원본으로 되돌린 칸. 범위표 밖")
    print(f"    번호204 은 범위 안, 번호141 은 COMM.IMG 에 살아 있다")
    print(f"\n  바뀐 바이트  {differing}개, 전부 PSX.EXE")
    print(f"  COMM.IMG 와 DAT  v195 와 동일")
    print(f"  포인터 무결성  이상 0개")
    print(f"  output  {OUT.name}")
    print(f"  sha256  {hashlib.sha256(OUT.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
