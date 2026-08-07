"""v148: redo v146's repair without touching a single pixel.

v146 moved 35 syllables out of the 0xE2 range by copying their pixels into cells it
judged free. That judgement was wrong and it broke the game's artwork -- the battle
field's tile cursor and the ground tiles came back corrupted, because "no Hangul shape
and no text code uses it" is also true of a picture. Measured afterwards: 28 of the
areas written to hold original pixels using all sixteen colour values. They were
artwork, and v146 punched one bit-plane of a letter through each of them.

None of it was necessary. All 35 syllables already have a code in the 0xE9/0xEA lookup
space -- 능 is EA 27 -- and dialogue bodies already use that space: 혜 in 은혜의 정령 is
EA CC and draws correctly on screen. So the repair is a straight two-byte-for-two-byte
substitution in the text, with COMM.IMG untouched.

Built on v145, not on v146, so the corrupted font never enters the chain. v147's choice
change is left out as well: it fixed the row width but put the menu cursor a row below
its option, which is worse than what it replaced.
"""
from __future__ import annotations

import csv
import hashlib
import pickle
import struct
import sys
import zipfile
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from plan_bulk_insertion import (  # noqa: E402
    CACHE, CHOICE, LOOKUP_N, LOOKUP_SRC, RAM_TO_FILE, SLOT_BASE, SLOT_COUNT, SLOT_SIZE,
    bitmap, build_encoder, drawable, encode, has_marker, tokens,
)

BASE_ZIP = ROOT / "03_output/arc1_v145_pool_addresses_7A6018A8.zip"
BASE_SHA = "7A6018A86B199A153FF0591F4CB98D36EBB3CDCC62CBD7A229DEA3E90982B8FE"
ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"
OUT_DIR, OUT_STEM = ROOT / "03_output", "arc1_v148_e2_via_lookup"
ANALYSIS = ROOT / "01_work/analysis/arc1_v148_e2_via_lookup"

SPACE, LINEBREAK = 0x9C, b"\xE6\x01"
HONORIFICS = [
    ("32/S3062.DAT", 0x47E48, "향하거라.", "향하세요."),
    ("32/S3061.DAT", 0x48344, "돌아가거라.", "돌아가세요."),
    ("32/S3063.DAT", 0x47D88, "있었단다.", "있었습니다."),
]


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
        raise SystemExit("base archive is not v145")
    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}
    exe, font = members["PSX.EXE"], members["COMM.IMG"]
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    lut = struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP_SRC - RAM_TO_FILE)

    def named(index: int) -> str | None:
        return shapes.get(bitmap(exe, font, index)) if drawable(exe, index) else None

    # the syllables reachable only behind 0xE2, and the lookup code for each
    elsewhere = {c for c in (named(code - 1) for code in range(0x01, 0xDD)) if c}
    for lead in (*range(0xDD, 0xE2), *range(0xE3, 0xE9)):
        for trail in range(0x01, 0xFF):
            if char := named((lead - 0xDD) * 255 + trail + 0xDB):
                elsewhere.add(char)
    by_lookup: dict[str, bytes] = {}
    for slot, index in enumerate(lut):
        if char := named(index):
            by_lookup.setdefault(char, bytes((0xE9 + slot // 254, slot % 254 + 1)))

    swap: dict[bytes, bytes] = {}
    moved = []
    for trail in range(0x01, 0xFF):
        index = (0xE2 - 0xDD) * 255 + trail + 0xDB
        char = named(index)
        if not char or char in elsewhere:
            continue
        code = by_lookup.get(char)
        if code is None:
            raise SystemExit(f"{char} has no lookup code either")
        if named(lut[(code[0] - 0xE9) * 254 + code[1] - 1]) != char:
            raise SystemExit(f"{code.hex()} does not draw {char}")
        swap[bytes((0xE2, trail))] = code
        moved.append((char, bytes((0xE2, trail)), code))
    if not moved:
        raise SystemExit("nothing is stranded behind 0xE2")

    bodies: dict[str, list[tuple[int, bytes]]] = {}
    with ORIGINAL_CSV.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
        for row in reader:
            bodies.setdefault(row["source file"], []).append(
                (int(row[key], 0),
                 bytes.fromhex(row["raw bytes as hex"].replace(" ", ""))))

    def span_starts(raw: bytes) -> set[int]:
        out, position = {0}, 0
        for token in tokens(raw):
            if token[0] == CHOICE or token == LINEBREAK:
                out.add(position + len(token))
            position += len(token)
        return out

    def rewrite(payload: bytes, skip: set[int]) -> tuple[bytes, int]:
        out, position, hits = bytearray(), 0, 0
        for token in tokens(payload):
            if len(token) == 2 and token in swap and position not in skip:
                out += swap[token]
                hits += 1
            else:
                out += token
            position += len(token)
        return bytes(out), hits

    inline = slots = 0
    touched: set[str] = set()
    for name, items in bodies.items():
        if name not in members:
            continue
        data = bytearray(members[name])
        for offset, raw in items:
            here = bytes(data[offset:offset + len(raw)])
            if len(here) != len(raw):
                continue
            skip = span_starts(here) if has_marker(raw, CHOICE) else {0}
            new, hits = rewrite(here, skip)
            if hits:
                if len(new) != len(here):
                    raise SystemExit("a body changed length")
                data[offset:offset + len(here)] = new
                inline += hits
                touched.add(name)
        if len(data) >= SLOT_BASE + SLOT_COUNT * SLOT_SIZE:
            for slot in range(SLOT_COUNT):
                at = SLOT_BASE + slot * SLOT_SIZE
                seg = bytes(data[at:at + SLOT_SIZE])
                if 0 not in seg[:SLOT_SIZE - 1]:
                    continue
                text = seg[:seg.index(0)]
                new, hits = rewrite(text, set())
                if hits:
                    if len(new) != len(text):
                        raise SystemExit("a slot changed length")
                    data[at:at + len(new)] = new
                    slots += hits
                    touched.add(name)
        members[name] = bytes(data)

    table = build_encoder(exe, font)
    fixed = []
    for name, offset, was, now in HONORIFICS:
        old_bytes, m1 = encode(was, table, keep_breaks=False)
        new_bytes, m2 = encode(now, table, keep_breaks=False)
        if m1 or m2:
            raise SystemExit(f"cannot encode {was} / {now}")
        if len(new_bytes) > len(old_bytes):
            raise SystemExit(f"{now} is longer than {was}")
        data = bytearray(members[name])
        raw = dict(bodies[name])[offset]
        at = data.find(old_bytes, offset, offset + len(raw))
        where = "본문"
        if at < 0:
            for slot in range(SLOT_COUNT):
                base = SLOT_BASE + slot * SLOT_SIZE
                found = data.find(old_bytes, base, base + SLOT_SIZE)
                if found >= 0:
                    at, where = found, f"슬롯 {slot}"
                    break
        if at < 0:
            raise SystemExit(f"{was} not found in {name}")
        data[at:at + len(old_bytes)] = new_bytes + bytes(
            [SPACE] * (len(old_bytes) - len(new_bytes)))
        members[name] = bytes(data)
        fixed.append((name, offset, where, was, now))
        touched.add(name)

    with ZipFile(BASE_ZIP) as base:
        if members["COMM.IMG"] != base.read("COMM.IMG"):
            raise SystemExit("COMM.IMG changed and must not")
        if members["PSX.EXE"] != base.read("PSX.EXE"):
            raise SystemExit("PSX.EXE changed and must not")
        differing = sorted(n for n in members if members[n] != base.read(n))
        for name in differing:
            if len(members[name]) != len(base.read(name)):
                raise SystemExit(f"{name} changed size")
    if set(differing) != touched:
        raise SystemExit(f"unexpected members changed: {sorted(set(differing) ^ touched)}")
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
        "v148 E2 음절을 조회표 코드로 (폰트 손대지 않음)",
        "",
        f"base    {BASE_ZIP.name}   <- v146이 아니라 v145",
        f"output  {final.name}",
        f"        sha256 {stamp}",
        "",
        f"바꾼 코드 {len(moved)}음절, 본문 {inline}곳, 슬롯 {slots}곳, 파일 {len(touched)}개",
        "",
        *(f"  {char}  {old.hex(' ')} -> {new.hex(' ')}" for char, old, new in moved),
        "",
        "은혜의 정령 존댓말",
        *(f"  {n} 0x{o:X} {w}  {a} -> {b}" for n, o, w, a, b in fixed),
        "",
        "v146이 왜 폐기됐나",
        "  v146은 35음절의 픽셀을 '비어 있다'고 판단한 칸으로 복사했다. 그 판단이 틀렸다.",
        "  '한글 모양이 아니고 어떤 텍스트 코드도 안 쓴다'는 조건은 그림 타일도 만족한다.",
        "  나중에 재보니 v146이 쓴 자리 28곳의 원본 픽셀이 0~15 색을 다 쓴다 -- 글자가 아니라",
        "  아트워크였다. 전투 지형 커서와 바닥 타일이 그래서 깨졌다.",
        "  애초에 옮길 필요가 없었다. 35음절 전부 0xE9/0xEA 조회표에 코드가 있고, 대사 본문도",
        "  그 공간을 쓴다 -- 은혜의 정령의 혜가 EA CC이고 화면에 잘 나온다.",
        "",
        "verified",
        "  base digest matches v145",
        "  COMM.IMG와 PSX.EXE는 v145와 바이트 단위로 같다 -- 픽셀을 하나도 안 건드렸다",
        "  바꾼 코드가 각각 의도한 글자를 그리는지 조회표로 확인",
        "  바뀐 줄과 슬롯의 길이가 전부 그대로, 모든 멤버 크기 불변",
        "  바뀐 멤버는 실제로 손댄 .DAT 파일들뿐",
        "",
        "여기 없는 것: v147의 선택지 수정. 폭은 맞췄지만 메뉴 커서가 자기 칸보다 한 줄",
        "  아래에 서서 이전보다 나빴다. 커서 줄 규칙을 알아낸 뒤에 다시 한다.",
        "",
        "rollback: v145",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
