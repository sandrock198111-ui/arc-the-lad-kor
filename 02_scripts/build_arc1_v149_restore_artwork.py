"""v149: give back the parts of COMM.IMG that are not font and were never ours.

A slime sprite draws corrupted, and only in one colour -- the same damaged pixels seen
through different palettes. It is still wrong in v148, so v146 was not the cause; the
damage is older.

Finding it needed a test that actually means something. Two earlier attempts did not:
counting colour values says "artwork" for any area holding four glyph planes, and asking
whether the original cell decodes to Hangul says "not a glyph" for the whole Japanese
font. The test that works is to ask what this build reads: collect every font index the
shipped text actually draws -- from bodies, slots, the lookup table and the UI pool --
and then look at the areas whose pixels differ from the original disc. An area none of
whose four planes is ever read is an area we wrote into for no reason.

There are 23, holding 1,030 bytes. Thirteen of them are row 24, columns 131 to 146.
Glyph columns only run 0..20: `column = (index % 84) // 4`, so x stops at 252 while the
image is 1792 wide. Columns 131 to 146 are not font at all.

This restores those 23 areas from the original disc byte for byte. Nothing the game draws
as text can change, because nothing the game draws as text reads them.
"""
from __future__ import annotations

import csv
import hashlib
import struct
import sys
import zipfile
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from plan_bulk_insertion import (  # noqa: E402
    CELL, IPR, LOOKUP_N, LOOKUP_SRC, PLANES, RAM_TO_FILE, SLOT_BASE, SLOT_COUNT,
    SLOT_SIZE, tokens,
)

BASE_ZIP = ROOT / "03_output/arc1_v148_e2_via_lookup_310A3DFB.zip"
BASE_SHA = "310A3DFB1BA7A2985EC582737EBFB742DD64596D550B8549E82685268A6DF69C"
PRISTINE = ROOT / "00_original/arc.zip"
ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"
OUT_DIR, OUT_STEM = ROOT / "03_output", "arc1_v149_restore_artwork"
ANALYSIS = ROOT / "01_work/analysis/arc1_v149_restore_artwork"
ROW_BYTES = 0x380


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system", "create_version",
                 "extract_version", "flag_bits", "volume", "internal_attr",
                 "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def main() -> None:
    if digest(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not v148")
    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}
    with ZipFile(PRISTINE) as pristine:
        original = pristine.read("COMM.IMG")
    exe = members["PSX.EXE"]
    font = bytearray(members["COMM.IMG"])
    if len(font) != len(original):
        raise SystemExit("COMM.IMG changed size at some point")
    lut = struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP_SRC - RAM_TO_FILE)

    # every font index the shipped text draws
    read: set[int] = set()

    def note(token: bytes) -> None:
        if len(token) == 1:
            read.add(token[0] - 1)
        elif 0xDD <= token[0] <= 0xE8:
            read.add((token[0] - 0xDD) * 255 + token[1] + 0xDB)
        elif token[0] in (0xE9, 0xEA):
            slot = (token[0] - 0xE9) * 254 + token[1] - 1
            if 0 <= slot < LOOKUP_N:
                read.add(lut[slot])

    with ORIGINAL_CSV.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
        items = [(r["source file"], int(r[key], 0),
                  len(bytes.fromhex(r["raw bytes as hex"].replace(" ", "")))) for r in reader]
    done: set[str] = set()
    for name, offset, length in items:
        if name not in members:
            continue
        data = members[name]
        if name not in done:
            done.add(name)
            for token in tokens(data[SLOT_BASE:SLOT_BASE + SLOT_COUNT * SLOT_SIZE]):
                note(token)
        for token in tokens(data[offset:offset + length]):
            note(token)
    for token in tokens(exe[0x78000:0x83000]):
        note(token)

    # areas we changed that nothing reads
    changed: dict[tuple[int, int], int] = {}
    for i in range(len(font)):
        if font[i] != original[i]:
            y, x = divmod(i, ROW_BYTES)
            changed[(y // CELL, (x * 2) // CELL)] = changed.get(
                (y // CELL, (x * 2) // CELL), 0) + 1
    give_back = []
    for (row, col), count in sorted(changed.items()):
        planes = [row * IPR + col * PLANES + p for p in range(PLANES)]
        if col < IPR // PLANES and any(p in read for p in planes):
            continue
        give_back.append((row, col, count))
    if not give_back:
        raise SystemExit("nothing to give back")

    restored = 0
    for row, col, _ in give_back:
        for dy in range(CELL):
            y = row * CELL + dy
            lo = y * ROW_BYTES + (col * CELL) // 2
            hi = lo + CELL // 2
            for i in range(lo, hi):
                if font[i] != original[i]:
                    restored += 1
                font[i] = original[i]

    # not one index the text reads may change its picture
    from plan_bulk_insertion import bitmap, drawable  # noqa: E402
    for index in sorted(read):
        if index < 0 or not drawable(exe, index):
            continue
        if bitmap(exe, members["COMM.IMG"], index) != bitmap(exe, bytes(font), index):
            raise SystemExit(f"cell {index} is read by the text and changed")
    members["COMM.IMG"] = bytes(font)

    with ZipFile(BASE_ZIP) as base:
        differing = sorted(n for n in members if members[n] != base.read(n))
        if differing != ["COMM.IMG"]:
            raise SystemExit(f"members differing from v148: {differing}")
        if len(members["COMM.IMG"]) != len(base.read("COMM.IMG")):
            raise SystemExit("COMM.IMG changed size")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tmp = OUT_DIR / f"{OUT_STEM}_building.zip"
    with ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    with ZipFile(tmp) as check:
        if {i.filename: check.read(i.filename) for i in check.infolist()} != members:
            raise SystemExit("the archive did not read back as written")
    stamp = digest(tmp.read_bytes())
    final = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    tmp.replace(final)
    (OUT_DIR / "LATEST.txt").write_text(
        f"ship this one\n  file    {final.name}\n  sha256  {stamp}\n", encoding="utf-8")

    lines = [
        "v149 폰트가 아닌 자리를 원본으로 되돌림",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {final.name}",
        f"        sha256 {stamp}",
        "",
        f"되돌린 자리 {len(give_back)}곳, {restored}바이트",
        *(f"  행{r:2d} 열{c:3d}  {n}바이트" for r, c, n in give_back),
        "",
        "어떻게 찾았나",
        "  앞선 두 판정은 아무것도 증명하지 못했다. 색 값이 0~15를 다 쓴다는 것은 글자 넷이",
        "  비트플레인으로 겹친 자리도 마찬가지고, 원본 칸이 한글로 안 읽힌다는 것은 원본",
        "  폰트가 일본어라 전부 그렇다.",
        "  뜻이 있는 질문은 '이 빌드가 이 자리를 읽는가'다. 본문, 슬롯, 조회표, UI 풀에서",
        "  실제로 그려지는 font index를 전부 모으고, 원본과 픽셀이 다른 자리 가운데 네",
        "  플레인 어느 것도 그 목록에 없는 곳을 찾았다.",
        f"  글자 칸의 열은 0~{IPR // PLANES - 1}까지다 -- column = (index % {IPR}) // {PLANES} 이므로",
        "  x는 252에서 끝나는데 이미지는 1792 넓이다. 열 131~146은 폰트가 아니다.",
        "",
        "verified",
        "  base digest matches v148",
        "  텍스트가 읽는 모든 index의 그림이 v148과 똑같다 -- 글자는 하나도 안 변한다",
        "  되돌린 바이트는 전부 원본 디스크와 같아졌다",
        "  v148과 다른 멤버는 COMM.IMG 하나, 크기 그대로",
        "",
        "NOT verified here: a cold boot. 그 색 슬라임이 나오는 전투를 볼 것.",
        "",
        "rollback: v148",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
