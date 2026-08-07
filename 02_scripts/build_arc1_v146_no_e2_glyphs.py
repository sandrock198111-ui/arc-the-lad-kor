"""v146: get the 35 syllables that only exist behind an 0xE2 lead out of there.

Reported: 만능약 draws as `만 약`. The bytes at 32/S3062.DAT 0x47E9A are
`68 E2 B6 DF B1 ...` -- 만 is 0x68 and 약 is 0xDF 0xB1 and both draw; 능 is 0xE2 0xB6
and draws nothing. It is not at the start of the body, it is in the middle of it, and it
still disappears. So 0xE2 is read as a command wherever it appears, and the note in
codex_notes.txt saying it doubles as a glyph lead -- `E2 EB` for 링, `E2 DE` for 띠 --
is wrong. Those two never drew either.

Taking every code form together, 35 syllables have no spelling except an 0xE2 lead:

    개 능 닷 덴 독 듦 띄 띠 락 랑 랙 랩 렉 렘 렛 렬 뢰 룬 률 링 맨 묵 박 베 벨 벽 붕 뷰
    블 빙 뿔 샘 샤 샬 석

They appear in 59 inline bodies and 112 slots across 63 files, and every one of those is
a hole in a sentence a player reads.

The repair is v138's, in the other direction. 111 cells are reachable, hold no Hangul,
are not behind 0xE2 and are used by nothing: 35 of them take a copy of the pixels, and
every 0xE2 pair that meant one of these syllables becomes the new two-byte code. Both
forms are two bytes, so nothing moves -- no line changes length, no slot is reallocated,
no marker shifts.

Which 0xE2 pairs are glyphs and which are commands cannot be told apart by their bytes:
the trail of `E2 B6` is 0xB6 and a redirect's trail is a disk id in 0x81..0xD0, so they
overlap. It is decided by position, the way the 2026-07-17 record already establishes: an
0xE2 at the start of a body, or at the start of a choice span, is a redirect. Anywhere
else it is text. Slot contents are pure text and hold no redirects at all.

Three lines of the 은혜의 정령 are fixed at the same time. She speaks 존댓말 everywhere
except four lines, and the sibling line one file over says 향하세요 where this one says
향하거라 for the same Japanese なさい. Nothing forced it: 향하세요 is a byte SHORTER than
향하거라. It was simply inconsistent.
"""
from __future__ import annotations

import csv
import hashlib
import pickle
import sys
import zipfile
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from plan_bulk_insertion import (  # noqa: E402
    CACHE, CELL, CHOICE, IPR, PLANES, SLOT_BASE, SLOT_COUNT, SLOT_SIZE, STRIPS,
    bitmap, build_encoder, drawable, encode, has_marker, remap_slot, tokens,
)

BASE_ZIP = ROOT / "03_output/arc1_v145_pool_addresses_7A6018A8.zip"
BASE_SHA = "7A6018A86B199A153FF0591F4CB98D36EBB3CDCC62CBD7A229DEA3E90982B8FE"
ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"
OUT_DIR, OUT_STEM = ROOT / "03_output", "arc1_v146_no_e2_glyphs"
ANALYSIS = ROOT / "01_work/analysis/arc1_v146_no_e2_glyphs"

ROW_BYTES, SPACE, LINEBREAK = 0x380, 0x9C, b"\xE6\x01"

# 은혜의 정령 speaks 존댓말 except here. Each replacement is the same length or shorter,
# so it goes in where it stands.
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


def wide(lead: int, trail: int) -> int:
    return (lead - 0xDD) * 255 + trail + 0xDB


def main() -> None:
    if digest(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not v145")
    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}
    exe = members["PSX.EXE"]
    font = bytearray(members["COMM.IMG"])
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())

    def plain(index: int) -> bool:
        """A cell whose pixels can simply be copied: no remap, no strip, base page."""
        row = index // IPR
        return (remap_slot(exe, index) is None and row not in STRIPS
                and (row + 1) * CELL <= 256)

    def named(index: int) -> str | None:
        return shapes.get(bitmap(exe, bytes(font), index)) if drawable(exe, index) else None

    # every two-byte code the shipped build actually uses
    bodies: dict[str, list[tuple[int, bytes]]] = {}
    with ORIGINAL_CSV.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
        for row in reader:
            bodies.setdefault(row["source file"], []).append(
                (int(row[key], 0),
                 bytes.fromhex(row["raw bytes as hex"].replace(" ", ""))))

    used: set[bytes] = set()
    for name, items in bodies.items():
        if name not in members:
            continue
        data = members[name]
        for token in tokens(data[SLOT_BASE:SLOT_BASE + SLOT_COUNT * SLOT_SIZE]):
            if len(token) == 2:
                used.add(token)
        for offset, raw in items:
            for token in tokens(data[offset:offset + len(raw)]):
                if len(token) == 2:
                    used.add(token)
    for token in tokens(exe[0x78000:0x83000]):
        if len(token) == 2:
            used.add(token)

    # the syllables with nowhere else to live, and the cells that will take them
    elsewhere = {c for c in (named(code - 1) for code in range(0x01, 0xDD)) if c}
    for lead in (*range(0xDD, 0xE2), *range(0xE3, 0xE9)):
        for trail in range(0x01, 0xFF):
            if char := named(wide(lead, trail)):
                elsewhere.add(char)
    stranded = {}
    for trail in range(0x01, 0xFF):
        index = wide(0xE2, trail)
        char = named(index)
        if char and char not in elsewhere:
            stranded.setdefault(char, (bytes((0xE2, trail)), index))
    if not stranded:
        raise SystemExit("no syllable is stranded behind 0xE2; already done?")

    spare = []
    for lead in (*range(0xDD, 0xE2), *range(0xE3, 0xE9)):
        for trail in range(0x01, 0xFF):
            index = wide(lead, trail)
            if (drawable(exe, index) and plain(index) and not named(index)
                    and bytes((lead, trail)) not in used):
                spare.append((bytes((lead, trail)), index))
    if len(spare) < len(stranded):
        raise SystemExit(f"{len(stranded)} needed, {len(spare)} free")

    # Four glyphs share one 12x12 area, one per bit-plane: bitmap() reads
    # `column, plane = divmod(index % IPR, PLANES)` and tests bit `1 << plane`. So a
    # glyph is copied one BIT at a time. Copying the nibble would carry the three
    # neighbours along with it and wreck them, which is what the first attempt did.
    def nibble(data, x: int, y: int) -> int:
        b = data[y * ROW_BYTES + x // 2]
        return b & 0xF if x % 2 == 0 else b >> 4

    def put_bit(data: bytearray, x: int, y: int, plane: int, on: bool) -> None:
        at = y * ROW_BYTES + x // 2
        b = data[at]
        value = (b & 0xF) if x % 2 == 0 else (b >> 4)
        value = value | (1 << plane) if on else value & ~(1 << plane) & 0xF
        data[at] = (b & 0xF0) | value if x % 2 == 0 else (b & 0x0F) | (value << 4)

    swap: dict[bytes, bytes] = {}
    moves = []
    source = members["COMM.IMG"]
    for (char, (old, src)), (new, dst) in zip(sorted(stranded.items()), spare):
        sr, srest = divmod(src, IPR)
        sc, splane = divmod(srest, PLANES)
        dr, drest = divmod(dst, IPR)
        dc, dplane = divmod(drest, PLANES)
        for dy in range(CELL):
            for dx in range(CELL):
                on = bool(nibble(source, sc * CELL + dx, sr * CELL + dy) & (1 << splane))
                put_bit(font, dc * CELL + dx, dr * CELL + dy, dplane, on)
        swap[old] = new
        moves.append((char, old, new, src, dst))

    for char, old, new, src, dst in moves:
        if shapes.get(bitmap(exe, bytes(font), dst)) != char:
            raise SystemExit(f"{char} did not land in its new cell")
        if shapes.get(bitmap(exe, bytes(font), src)) != char:
            raise SystemExit(f"{char} left its old cell")

    # the three glyphs sharing each destination area must be untouched
    written = {d for _, _, _, _, d in moves}
    for index in range(IPR * (512 // CELL)):
        if index in written:
            continue
        before = bitmap(exe, source, index)
        after = bitmap(exe, bytes(font), index)
        if before != after:
            raise SystemExit(f"cell {index} changed and should not have")
    members["COMM.IMG"] = bytes(font)

    # rewrite every 0xE2 that means one of these syllables
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
    touched: dict[str, int] = {}
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
                touched[name] = touched.get(name, 0) + hits
        if len(data) >= SLOT_BASE + SLOT_COUNT * SLOT_SIZE:
            for slot in range(SLOT_COUNT):
                at = SLOT_BASE + slot * SLOT_SIZE
                seg = bytes(data[at:at + SLOT_SIZE])
                if 0 not in seg[:SLOT_SIZE - 1]:
                    continue
                text = seg[:seg.index(0)]
                new, hits = rewrite(text, set())      # a slot holds text, never a redirect
                if hits:
                    if len(new) != len(text):
                        raise SystemExit("a slot changed length")
                    data[at:at + len(new)] = new
                    slots += hits
                    touched[name] = touched.get(name, 0) + hits
        members[name] = bytes(data)

    # the honorifics, in place
    table = build_encoder(exe, members["COMM.IMG"])
    fixed = []
    for name, offset, was, now in HONORIFICS:
        if name not in members:
            raise SystemExit(f"{name} is not in the archive")
        old_bytes, missing = encode(was, table, keep_breaks=False)
        new_bytes, missing2 = encode(now, table, keep_breaks=False)
        if missing or missing2:
            raise SystemExit(f"cannot encode {was} / {now}")
        if len(new_bytes) > len(old_bytes):
            raise SystemExit(f"{now} is longer than {was}")
        data = bytearray(members[name])
        raw = dict(bodies[name])[offset]
        window = (offset, offset + len(raw))
        at = data.find(old_bytes, *window)
        where = "본문"
        if at < 0:                                   # the line lives in a slot
            for slot in range(SLOT_COUNT):
                base = SLOT_BASE + slot * SLOT_SIZE
                found = data.find(old_bytes, base, base + SLOT_SIZE)
                if found >= 0:
                    at, where = found, f"슬롯 {slot}"
                    break
        if at < 0:
            raise SystemExit(f"{was} not found in {name}")
        data[at:at + len(old_bytes)] = new_bytes + bytes([SPACE] * (len(old_bytes) - len(new_bytes)))
        members[name] = bytes(data)
        fixed.append((name, offset, where, was, now, len(old_bytes), len(new_bytes)))

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tmp = OUT_DIR / f"{OUT_STEM}_building.zip"
    with ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    with ZipFile(tmp) as check:
        if {i.filename: check.read(i.filename) for i in check.infolist()} != members:
            raise SystemExit("the archive did not read back as written")
    with ZipFile(BASE_ZIP) as base:
        for name in members:
            if len(members[name]) != len(base.read(name)):
                raise SystemExit(f"{name} changed size")

    stamp = digest(tmp.read_bytes())
    final = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    tmp.replace(final)
    (OUT_DIR / "LATEST.txt").write_text(
        f"ship this one\n  file    {final.name}\n  sha256  {stamp}\n", encoding="utf-8")

    lines = [
        "v146 E2 뒤에 갇힌 35음절을 꺼냄",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {final.name}",
        f"        sha256 {stamp}",
        "",
        f"옮긴 음절 {len(moves)}개, 바꾼 코드 본문 {inline}곳 슬롯 {slots}곳, 파일 {len(touched)}개",
        "",
        *(f"  {char}  {old.hex(' ')} -> {new.hex(' ')}   칸 {src} -> {dst}"
          for char, old, new, src, dst in moves),
        "",
        "은혜의 정령 존댓말",
        *(f"  {name} 0x{off:X} {where}  {was} -> {now}  ({a}B -> {b}B)"
          for name, off, where, was, now, a, b in fixed),
        "",
        "왜 이렇게 고치나",
        "  제보: 만능약이 '만 약'으로 나온다. 32/S3062.DAT 0x47E9A = 68 E2 B6 DF B1.",
        "  만(68)과 약(DF B1)은 그려지고 능(E2 B6)만 사라진다. 본문 첫 바이트가 아니라",
        "  한가운데인데도 그렇다. E2는 어디에 있든 명령으로 먹히고, codex_notes의",
        "  'E2도 글자 선두다(E2 EB=링, E2 DE=띠)'는 틀렸다. 링도 띠도 안 나왔다.",
        "  어느 E2가 글자이고 어느 것이 명령인지는 바이트로 못 가른다 -- E2 B6의 뒤가",
        "  0xB6이고 리다이렉트의 뒤는 디스크 번호 0x81~0xD0이라 겹친다. 자리로 가른다:",
        "  본문 첫 바이트와 선택지 칸 첫 바이트면 명령, 그 밖이면 글자. 슬롯은 순수 텍스트라",
        "  리다이렉트가 없다.",
        "  두 형태 모두 2바이트라 어떤 줄도 길이가 변하지 않는다. 재배치도 슬롯 재할당도",
        "  마커 이동도 없다.",
        "",
        "verified",
        "  base digest matches v145",
        "  옮긴 35칸이 각각 의도한 글자로 읽히고, 원래 칸도 그대로다",
        "  폰트에서 그 35칸 밖으로 바뀐 픽셀 없음",
        "  바꾼 줄과 슬롯의 길이가 전부 그대로, 모든 멤버 크기 불변",
        "  향하세요는 향하거라보다 1바이트 짧다 -- 슬롯도 글리프도 원인이 아니었다",
        "",
        "NOT verified here: a cold boot. 만능약을 얻어 보고, 정령 마지막 대사를 볼 것.",
        "",
        "rollback: v145",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
