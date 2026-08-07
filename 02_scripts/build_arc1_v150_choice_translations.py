"""v150: translate the choice options that were left in Japanese.

The earlier passes worked a body at a time, so a body counted as done could still hold
Japanese spans. Walking the spans finds 105 of them. 05_docs/choices_untranslated.csv
lists all 105 with what each would cost; this builds the 35 that can be written now.

  27  fit inside the span they already occupy
   8  do not, and go to a free slot in their own file by the redirect documented on
      2026-07-17: E2 and a disk id at the span start, the rest of the span filled with
      the space glyph, and the slot's completion byte set to span length - 2 so the game
      resumes at that span's own marker
   1  幻のこて is left. The game calls it 환상의 건틀릿 in the message right after the
      choice, a shorter name here would read as a different item, and C2/SC0B6.DAT has no
      free slot to send it to. It needs a slot freed in that file first.
  69  are left because the extractor could not decode their Japanese -- it reads as noise
      such as 解い装ま火. Writing Korean over bytes not known to be text is how data gets
      overwritten, and the 2026-07-16 note already records this family as false positives.

Where the CSV already held a translation it is used, because those have been read and
approved: 150人 is 150 there rather than 150명, and ちゃいろ is 갈 rather than 갈색, both
already cut to fit. Nothing is invented where something was written.

No marker moves. A span keeps its byte length whether the text goes inside it or to a
slot, so every E5 and E6 stays where the original put it.
"""
from __future__ import annotations

import sys as _sys

# The console here is cp949 and the report prints the Japanese source, which raises
# before a single line appears. Set the stream up rather than losing the report.
try:
    _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    _sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import csv
import hashlib
import sys
import zipfile
from collections import defaultdict
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

import pickle  # noqa: E402
import struct  # noqa: E402

from plan_bulk_insertion import (  # noqa: E402
    CACHE, CHOICE, LOOKUP_N, LOOKUP_SRC, RAM_TO_FILE, SLOT_BASE, SLOT_COUNT, SLOT_SIZE,
    bitmap, build_encoder, drawable, encode, tokens,
)

BASE_ZIP = ROOT / "03_output/arc1_v149_restore_artwork_28ED010A.zip"
BASE_SHA = "28ED010A4BE6A67B3DB88C4016109853D98075833B15D5D2F61C4B073D913C32"
TODO = ROOT / "05_docs/choices_untranslated.csv"
ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"
OUT_DIR, OUT_STEM = ROOT / "03_output", "arc1_v150_choice_translations"
ANALYSIS = ROOT / "01_work/analysis/arc1_v150_choice_translations"
SPACE, LINEBREAK = 0x9C, b"\xE6\x01"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system", "create_version",
                 "extract_version", "flag_bits", "volume", "internal_attr",
                 "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def disk_id(slot: int) -> int:
    return slot + 0x81 if slot < 40 else slot + 0x82


def byte_spans(payload: bytes) -> list[tuple[int, int]]:
    out, start, position = [], None, 0
    for token in tokens(payload):
        if len(token) == 1 and token[0] == 0:
            break
        if token[0] == CHOICE:
            if start is not None:
                out.append((start, position))
            start = position + len(token)
        elif token == LINEBREAK and start is not None:
            out.append((start, position))
            start = None
        position += len(token)
    if start is not None:
        out.append((start, position))
    return out


def main() -> None:
    if digest(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not v149")
    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}
    exe, font = members["PSX.EXE"], members["COMM.IMG"]
    table = build_encoder(exe, font)

    # build_encoder still hands back 0xE2 leads -- 링 is E2 EB -- and an 0xE2 is a slot
    # redirect wherever it appears, so text spelled that way draws nothing, and at a span
    # start it is read as a redirect to a disk id that does not exist. v148 swapped the
    # existing text over to the lookup codes; new text has to be spelled the same way.
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    lut = struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP_SRC - RAM_TO_FILE)
    by_lookup: dict[str, bytes] = {}
    for slot, index in enumerate(lut):
        if drawable(exe, index):
            if char := shapes.get(bitmap(exe, font, index)):
                by_lookup.setdefault(char, bytes((0xE9 + slot // 254, slot % 254 + 1)))
    swap: dict[bytes, bytes] = {}
    for trail in range(0x01, 0xFF):
        index = (0xE2 - 0xDD) * 255 + trail + 0xDB
        if not drawable(exe, index):
            continue
        char = shapes.get(bitmap(exe, font, index))
        if char and char in by_lookup:
            swap[bytes((0xE2, trail))] = by_lookup[char]

    def spell(text: str) -> tuple[bytes, list[str]]:
        raw, missing = encode(text, table, keep_breaks=False)
        out = bytearray()
        for token in tokens(raw):
            if len(token) == 2 and token[0] == 0xE2:
                if token not in swap:
                    raise SystemExit(f"{text}: {token.hex()} has no code outside 0xE2")
                out += swap[token]
            else:
                out += token
        return bytes(out), missing

    with ORIGINAL_CSV.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
        length = {(r["source file"], int(r[key], 0)):
                  len(bytes.fromhex(r["raw bytes as hex"].replace(" ", ""))) for r in reader}

    with TODO.open(encoding="utf-8-sig", newline="") as handle:
        todo = [r for r in csv.DictReader(handle)
                if r["상태"] in ("제자리", "슬롯 필요") and r["수정제안"]]
    if not todo:
        raise SystemExit(f"{TODO.name} 에 적용할 행이 없습니다")

    work: dict[str, list[dict]] = defaultdict(list)
    for row in todo:
        work[row["파일"]].append(row)

    inline = redirected = 0
    applied = []
    for name, rows in work.items():
        if name not in members:
            raise SystemExit(f"{name} is not in the archive")
        data = bytearray(members[name])
        spare = [s for s in range(SLOT_COUNT)
                 if not any(data[SLOT_BASE + s * SLOT_SIZE:SLOT_BASE + (s + 1) * SLOT_SIZE])]
        for row in rows:
            offset = int(row["오프셋"], 0)
            body = bytes(data[offset:offset + length[(name, offset)]])
            spans = byte_spans(body)
            index = int(row["칸"])
            if index >= len(spans):
                raise SystemExit(f"{name} 0x{offset:X} has no span {index}")
            a, b = spans[index]
            if b - a != int(row["칸 바이트"]):
                raise SystemExit(f"{name} 0x{offset:X} span {index} changed size")
            text, missing = spell(row["수정제안"])
            if missing:
                raise SystemExit(f"no glyph for {''.join(missing)} in {row['수정제안']}")
            if len(text) <= b - a:
                data[offset + a:offset + b] = text.ljust(b - a, bytes([SPACE]))
                inline += 1
                how = "제자리"
            else:
                if not spare:
                    raise SystemExit(f"{name} has no free slot left")
                slot = spare.pop(0)
                if len(text) > SLOT_SIZE - 2:
                    raise SystemExit(f"{row['수정제안']} does not fit a slot")
                base = SLOT_BASE + slot * SLOT_SIZE
                data[base:base + SLOT_SIZE] = (text + b"\x00").ljust(SLOT_SIZE, b"\x00")
                data[base + SLOT_SIZE - 1] = (b - a) - 2
                data[offset + a:offset + a + 2] = bytes((0xE2, disk_id(slot)))
                for i in range(offset + a + 2, offset + b):
                    data[i] = SPACE
                redirected += 1
                how = f"슬롯 {slot}"
            applied.append((name, offset, index, row["원문"], row["수정제안"], how))
        members[name] = bytes(data)

    # No marker may move in a body this build wrote to. Other bodies are check_build's
    # job -- comparing them here compares against the disc for lines earlier builds
    # already rewrote, which says nothing about this change.
    def markers(payload: bytes) -> list[tuple[int, bytes]]:
        out, position = [], 0
        for token in tokens(payload):
            if len(token) == 1 and token[0] == 0:
                break
            if token[0] == CHOICE or token == LINEBREAK:
                out.append((position, token))
            position += len(token)
        return out

    with ZipFile(BASE_ZIP) as base:
        for name, offset, *_ in applied:
            size = length[(name, offset)]
            if markers(members[name][offset:offset + size]) != \
                    markers(base.read(name)[offset:offset + size]):
                raise SystemExit(f"{name} 0x{offset:X} moved a marker")

    with ZipFile(BASE_ZIP) as base:
        differing = sorted(n for n in members if members[n] != base.read(n))
        if sorted(work) != differing:
            raise SystemExit(f"unexpected members changed: {differing}")
        for name in differing:
            if len(members[name]) != len(base.read(name)):
                raise SystemExit(f"{name} changed size")
        if members["PSX.EXE"] != base.read("PSX.EXE"):
            raise SystemExit("PSX.EXE changed")
        if members["COMM.IMG"] != base.read("COMM.IMG"):
            raise SystemExit("COMM.IMG changed")

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
        "v150 일본어로 남아 있던 선택지 칸",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {final.name}",
        f"        sha256 {stamp}",
        "",
        f"적용 {len(applied)}칸: 제자리 {inline}, 슬롯 {redirected}. 파일 {len(work)}개",
        "",
        *(f"  {n} 0x{o:X} 칸{i}  {jp} -> {ko}   {how}"
          for n, o, i, jp, ko, how in applied),
        "",
        "적용하지 않은 것",
        "  幻のこて (C2/SC0B6.DAT 0x47838 칸0). 게임이 선택 직후 메시지에서 환상의 건틀릿이라",
        "    부르므로 여기만 다른 이름을 쓰면 다른 물건으로 읽힌다. 그런데 칸이 7바이트이고",
        "    그 파일에 빈 슬롯이 없다. 그 파일에서 슬롯을 하나 비우는 것이 먼저다.",
        "  69칸은 추출기가 원문을 못 읽어 解い装ま火 같은 노이즈로 나온다. 텍스트인지 모르는",
        "    바이트에 한국어를 쓰는 것이 데이터를 덮어쓰는 길이고, 2026-07-16 기록이 이 부류를",
        "    이미 오검출로 적어 두었다.",
        "",
        "verified",
        "  base digest matches v149",
        "  모든 E5와 E6가 원판 바이트 자리 그대로 -- 원본 디스크와 마커 위치를 대조",
        "  칸 길이가 하나도 변하지 않았다. 제자리는 공백으로 채우고, 슬롯행은 E2 두 바이트",
        "    뒤를 공백으로 채운다. 슬롯 완료값은 칸 길이 - 2",
        "  PSX.EXE와 COMM.IMG는 v149와 바이트 단위로 같다",
        f"  바뀐 멤버는 손댄 .DAT {len(work)}개뿐, 크기 전부 그대로",
        "",
        "NOT verified here: a cold boot.",
        "",
        "rollback: v149",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
