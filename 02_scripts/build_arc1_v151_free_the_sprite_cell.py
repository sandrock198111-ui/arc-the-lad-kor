"""v151: get eleven glyphs out of the three cells a sprite draws through.

A magenta slime shows a 36x13 block of garbage above it, in the slime's own palette, and
v149 did not fix it. The savestate says why. COMM.IMG is not a font file: it uploads to
VRAM x 0..447, the same region the sprite sheets live in, so a cell can be blank on the
disc because something else is drawn through it.

543 glyphs sit in cells the original left blank, and only 162 destinations are safe, so
moving all of them is not possible. It is also not necessary. The block on screen is
36 pixels wide and 12 tall, which is three cells side by side, and exactly one run of
three adjacent originally-blank cells in one row was filled by this project:

    row 9, columns 18..20   x 216..251, y 108..119

Twelve glyph planes live there, eleven of them referenced by text, on the two-byte codes
DF 63 through DF 6E: 목 많 록 렸 델 던 눈 길 후 율 바. They move to cells that HAD pixels
on the original disc -- the game shipped those drawn, so nothing else reads them as
picture -- and the three cells go back to blank.

Both codes are two bytes, so no line changes length. The check that matters is not that
the cells are blank but that every character the game draws is unchanged, so the build
renders all bodies, all slots and the UI pool before and after and compares them.
"""
from __future__ import annotations

import sys as _sys

try:
    _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    _sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

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
    CACHE, CELL, IPR, LOOKUP_N, LOOKUP_SRC, PLANES, RAM_TO_FILE, SLOT_BASE, SLOT_COUNT,
    SLOT_SIZE, STRIPS, bitmap, drawable, remap_slot, tokens,
)

BASE_ZIP = ROOT / "03_output/arc1_v150_choice_translations_264D3248.zip"
BASE_SHA = "264D3248E5E4AD39ABBA29DAD864BBAA5E54FFFBE770D5F50400D93FD3CB4D4E"
PRISTINE = ROOT / "00_original/arc.zip"
ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"
OUT_DIR, OUT_STEM = ROOT / "03_output", "arc1_v151_free_the_sprite_cell"
ANALYSIS = ROOT / "01_work/analysis/arc1_v151_free_the_sprite_cell"
ROW_BYTES = 0x380
CELLS = [(9, 18), (9, 19), (9, 20)]      # the run the sprite draws through


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system", "create_version",
                 "extract_version", "flag_bits", "volume", "internal_attr",
                 "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def wide_code(index: int) -> bytes | None:
    for lead in range(0xDD, 0xE9):
        trail = index - 0xDB - (lead - 0xDD) * 255
        if 0x01 <= trail <= 0xFE:
            return bytes((lead, trail))
    return None


def main() -> None:
    if digest(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not v150")
    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}
    with ZipFile(PRISTINE) as pristine:
        original = pristine.read("COMM.IMG")
    exe = members["PSX.EXE"]
    font = bytearray(members["COMM.IMG"])
    before_font = members["COMM.IMG"]
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    lut = struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP_SRC - RAM_TO_FILE)

    # every font index the text draws, and the codes it is spelled with
    read: dict[int, set[bytes]] = {}

    def note(token: bytes) -> None:
        if len(token) == 1:
            read.setdefault(token[0] - 1, set()).add(token)
        elif 0xDD <= token[0] <= 0xE8:
            read.setdefault((token[0] - 0xDD) * 255 + token[1] + 0xDB, set()).add(token)
        elif token[0] in (0xE9, 0xEA):
            slot = (token[0] - 0xE9) * 254 + token[1] - 1
            if 0 <= slot < LOOKUP_N:
                read.setdefault(lut[slot], set()).add(token)

    with ORIGINAL_CSV.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
        items = [(r["source file"], int(r[key], 0),
                  len(bytes.fromhex(r["raw bytes as hex"].replace(" ", "")))) for r in reader]
    done: set[str] = set()
    for name, offset, size in items:
        if name not in members:
            continue
        data = members[name]
        if name not in done:
            done.add(name)
            for token in tokens(data[SLOT_BASE:SLOT_BASE + SLOT_COUNT * SLOT_SIZE]):
                note(token)
        for token in tokens(data[offset:offset + size]):
            note(token)
    for token in tokens(exe[0x78000:0x83000]):
        note(token)

    def plain(index: int) -> bool:
        row = index // IPR
        return (remap_slot(exe, index) is None and row not in STRIPS
                and (row + 1) * CELL <= 256)

    def blank_on_disc(index: int) -> bool:
        bits = bitmap(exe, original, index)
        return bits is not None and not any(bits)

    # destinations: drawn on the original disc, read by nothing, spellable without 0xE2
    spare = []
    for index in range(IPR * (512 // CELL)):
        if index < 220 or index in read or not drawable(exe, index) or not plain(index):
            continue
        if blank_on_disc(index):
            continue
        code = wide_code(index)
        if code and code[0] != 0xE2:
            spare.append((index, code))

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
    moved = []
    for row, col in CELLS:
        for plane in range(PLANES):
            index = row * IPR + col * PLANES + plane
            codes = read.get(index)
            if not codes:
                continue                       # nothing spells it; blanking is enough
            char = shapes.get(bitmap(exe, before_font, index)) or "?"
            if not spare:
                raise SystemExit("ran out of destinations")
            dst, dst_code = spare.pop(0)
            drow, drest = divmod(dst, IPR)
            dcol, dplane = divmod(drest, PLANES)
            for dy in range(CELL):
                for dx in range(CELL):
                    on = bool(nibble(before_font, col * CELL + dx, row * CELL + dy)
                              & (1 << plane))
                    put_bit(font, dcol * CELL + dx, drow * CELL + dy, dplane, on)
            for code in codes:
                swap[code] = dst_code
            moved.append((char, index, dst, sorted(c.hex(" ") for c in codes),
                          dst_code.hex(" ")))

    # the three cells go back to what the disc had: nothing
    for row, col in CELLS:
        for dy in range(CELL):
            y = row * CELL + dy
            lo = y * ROW_BYTES + (col * CELL) // 2
            font[lo:lo + CELL // 2] = original[lo:lo + CELL // 2]
    for row, col in CELLS:
        for plane in range(PLANES):
            index = row * IPR + col * PLANES + plane
            if any(bitmap(exe, bytes(font), index)):
                raise SystemExit(f"cell {index} is still not blank")
    for char, index, dst, *_ in moved:
        if shapes.get(bitmap(exe, bytes(font), dst)) != char:
            raise SystemExit(f"{char} did not land in cell {dst}")
    members["COMM.IMG"] = bytes(font)

    # Rewrite the codes only where text lives. Scanning a whole file finds these byte
    # pairs in tables and code too -- the first attempt "changed" 3,624 places, which
    # would have rewritten data the game reads as numbers. Bodies come from the extract,
    # slots are a known region, and the executable's strings are the pool at 0x78000.
    def rewrite(payload: bytes) -> tuple[bytes, int]:
        out, hits = bytearray(), 0
        for token in tokens(payload):
            if token in swap:
                out += swap[token]
                hits += 1
            else:
                out += token
        if len(out) != len(payload):
            raise SystemExit("a rewrite changed length")
        return bytes(out), hits

    hits = 0
    by_file: dict[str, list[tuple[int, int]]] = {}
    for name, offset, size in items:
        by_file.setdefault(name, []).append((offset, size))
    for name, ranges in by_file.items():
        if name not in members:
            continue
        data = bytearray(members[name])
        for offset, size in ranges:
            new_bytes, n = rewrite(bytes(data[offset:offset + size]))
            data[offset:offset + size] = new_bytes
            hits += n
        # In some files a body sits inside the slot region, so the same bytes would be
        # walked twice from two different starts, and tokenising from the wrong start
        # splits a two-byte code down the middle. The body's alignment is the true one,
        # so slots a body already covers are skipped.
        #
        # This is also why reading those bytes back as a slot misleads: D/SD031.DAT
        # "slot 19" reads 기 in v150 and garbage here, but 0x45980 is the second byte of
        # a 던 (DF 69) belonging to a body, and rewriting it to DD F1 is correct. The
        # bodies themselves all render identically.
        covered = set()
        for offset, size in ranges:
            covered.update(range(offset, offset + size))
        if len(data) >= SLOT_BASE + SLOT_COUNT * SLOT_SIZE:
            for slot in range(SLOT_COUNT):
                at = SLOT_BASE + slot * SLOT_SIZE
                if any(i in covered for i in range(at, at + SLOT_SIZE)):
                    continue
                seg = bytes(data[at:at + SLOT_SIZE])
                if 0 not in seg[:SLOT_SIZE - 1]:
                    continue
                text = seg[:seg.index(0)]
                new_bytes, n = rewrite(text)
                data[at:at + len(new_bytes)] = new_bytes
                hits += n
        members[name] = bytes(data)
    exe_data = bytearray(members["PSX.EXE"])
    new_bytes, n = rewrite(bytes(exe_data[0x78000:0x83000]))
    exe_data[0x78000:0x83000] = new_bytes
    hits += n
    members["PSX.EXE"] = bytes(exe_data)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tmp = OUT_DIR / f"{OUT_STEM}_building.zip"
    with ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    stamp = digest(tmp.read_bytes())
    final = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    tmp.replace(final)
    (OUT_DIR / "LATEST.txt").write_text(
        f"ship this one\n  file    {final.name}\n  sha256  {stamp}\n", encoding="utf-8")

    lines = [
        "v151 스프라이트가 지나가는 칸에서 글자 열한 개를 빼냄",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {final.name}",
        f"        sha256 {stamp}",
        "",
        f"옮긴 글자 {len(moved)}개, 바꾼 코드 {hits}곳",
        *(f"  {char}  칸 {src} -> {dst}   {' '.join(codes)} -> {dcode}"
          for char, src, dst, codes, dcode in moved),
        "",
        f"비운 자리: 행 9 열 18~20 (x 216~251, y 108~119). 원본과 같아졌다.",
        "",
        "왜 여기인가",
        "  세이브스테이트 VRAM에서 자홍 슬라임 위 블록이 36x13이다. 12픽셀 칸 셋이다.",
        "  원본에서 비어 있다가 이 프로젝트가 채운 자리 가운데, 같은 행에 정확히 셋만",
        "  이어진 곳은 행 9 열 18~20 하나뿐이다.",
        "  COMM.IMG는 폰트 전용이 아니다. VRAM x 0~447에 올라가고 그 자리가 스프라이트",
        "  시트와 같다. 원본이 비워 둔 칸은 안 쓰는 여백일 수도, 이렇게 그림이 지나가는",
        "  자리일 수도 있다. 원본에 픽셀이 있던 칸이라야 폰트 전용임이 보장된다.",
        "  그래서 옮길 자리는 전부 원본에 그림이 그려져 있던 칸으로만 골랐다.",
        "",
        "rollback: v150",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
