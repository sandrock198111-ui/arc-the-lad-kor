"""v147: the two choice rows that stopped fitting when the choices were re-applied.

The player is right that these used to work. v134 drew them like this:

    편지를 읽을까?                     90px
    강해지는 법 / 작전 세우기 / 피해 감소 1 / 다음    four rows, none over 84px

v135 reverted the choice bodies to Japanese, and v137 put them back by the documented
rule -- every E5 and E6 at the byte offset the original used. That rule is right and it
is what stopped the menu cursor landing on the wrong row, but it also restored the
original's row structure, in which option 3 and option 4 share a row. The CSV's longer
wording then went into rows that no longer had space for it:

    1/S1023.DAT 0x47952 줄1  234px  아버지가 남긴 편지가 있는데 읽어 볼래?
    1/S1023.DAT 0x47AB0 줄2  258px  적에게 피해를 입지 않으려면 + 다음 페이지

A row holds 228px, so the first wraps its `?` onto the cursor row and the second wraps
`다음 페이지` to the left margin. Comparing every choice row in the game against v134,
these two are the only regressions: 2 of 357 bodies.

The remaining 69 rows over 228px are the untranslated Japanese ones, which were 408px in
v134 too. They are the known "출처가 대사가 아닌 선택지" and are not touched here.

How each is fixed:

  0x47952  the question is already in a slot, so it is simply shortened.
  0x47AB0  option 3 is written inline, and shortening it in place would move the E5 that
           follows -- exactly what v137 exists to prevent. So it takes the documented
           redirect instead: E2 plus a disk id at the span start, the text in a free slot,
           and the slot's completion byte set to span length - 2 so the game resumes at
           this span's own marker. The span's remaining bytes are then never drawn, which
           is the point: the row's width becomes the slot's width.
           The wording follows the next page, which already says 피해 줄이기 2.
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
    CACHE, CHOICE, SLOT_BASE, SLOT_COUNT, SLOT_SIZE, bitmap, build_encoder, drawable,
    encode, tokens,
)
from review_editor import ROW_PIXELS, advance  # noqa: E402

BASE_ZIP = ROOT / "03_output/arc1_v146_no_e2_glyphs_1F4072BC.zip"
BASE_SHA = "1F4072BC4017A531B1B2D082A75991C3C9BAD2570C9533F153706C72E820EF3A"
ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"
OUT_DIR, OUT_STEM = ROOT / "03_output", "arc1_v147_choice_rows"
ANALYSIS = ROOT / "01_work/analysis/arc1_v147_choice_rows"

FILE = "1/S1023.DAT"
SPACE, LINEBREAK = 0x9C, b"\xE6\x01"
QUESTION = (0x47952, "아버지가 남긴 편지가 있는데 읽어 볼래?", "아버지 편지가 있는데 읽어 볼래?")
OPTION = (0x47AB0, "적에게 피해를 입지 않으려면", "피해 줄이기 1")


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


def main() -> None:
    if digest(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not v146")
    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}
    exe, font = members["PSX.EXE"], members["COMM.IMG"]
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    table = build_encoder(exe, font)
    data = bytearray(members[FILE])

    with ORIGINAL_CSV.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
        lengths = {int(r[key], 0): len(bytes.fromhex(r["raw bytes as hex"].replace(" ", "")))
                   for r in reader if r["source file"] == FILE}

    def spell(payload: bytes) -> str:
        out = []
        for token in tokens(payload):
            index = (token[0] - 1 if len(token) == 1 else
                     (token[0] - 0xDD) * 255 + token[1] + 0xDB
                     if 0xDD <= token[0] <= 0xE8 else None)
            if index is None or not drawable(exe, index):
                out.append("·")
                continue
            bits = bitmap(exe, font, index)
            out.append(shapes.get(bits) or (" " if not any(bits) else "?"))
        return "".join(out)

    def row_widths(offset: int) -> list[tuple[int, str]]:
        """Widths as drawn: a span starting with E2 draws its slot, the rest is skipped."""
        out, row, at_start, skipping = [], [], True, False
        for token in tokens(bytes(data[offset:offset + lengths[offset]])):
            if len(token) == 1 and token[0] == 0:
                break
            if token == LINEBREAK:
                out.append(row)
                row, at_start, skipping = [], True, False
                continue
            if token[0] == CHOICE:
                row.append(token)
                at_start, skipping = True, False
                continue
            if at_start and len(token) == 2 and token[0] == 0xE2:
                slot = token[1] - 0x81 if token[1] < 0xA9 else token[1] - 0x82
                seg = bytes(data[SLOT_BASE + slot * SLOT_SIZE:
                                 SLOT_BASE + (slot + 1) * SLOT_SIZE])
                if 0 in seg:
                    row.extend(tokens(seg[:seg.index(0)]))
                at_start, skipping = False, True
                continue
            at_start = False
            if not skipping:
                row.append(token)
        out.append(row)
        result = []
        for r in out:
            while r and len(r[-1]) == 1 and r[-1][0] == SPACE:
                r = r[:-1]
            result.append((sum(advance(t) for t in r), spell(b"".join(r))))
        return result

    before = {off: row_widths(off) for off, *_ in (QUESTION, OPTION)}
    notes = []

    # 1. the question already lives in a slot: shorten the text where it is
    off, was, now = QUESTION
    old_bytes, m1 = encode(was, table, keep_breaks=False)
    new_bytes, m2 = encode(now, table, keep_breaks=False)
    if m1 or m2:
        raise SystemExit(f"cannot encode {was} / {now}")
    found = None
    for slot in range(SLOT_COUNT):
        base = SLOT_BASE + slot * SLOT_SIZE
        if bytes(data[base:base + len(old_bytes)]) == old_bytes:
            found = (slot, base)
            break
    if found is None:
        raise SystemExit(f"{was} is not at the start of any slot in {FILE}")
    slot, base = found
    tail = bytes(data[base + len(old_bytes):base + SLOT_SIZE - 1])
    if tail[:1] != b"\x00":
        raise SystemExit("the question is not the whole slot")
    data[base:base + SLOT_SIZE - 1] = (new_bytes + b"\x00").ljust(SLOT_SIZE - 1, b"\x00")
    notes.append(f"  0x{off:X}  슬롯 {slot}의 글을 줄임  {was} -> {now}")

    # 2. option 3 is inline; send it to a slot so the row shrinks without moving the E5
    off, was, now = OPTION
    span_bytes, _ = encode(was, table, keep_breaks=False)
    body = bytes(data[off:off + lengths[off]])
    at = body.find(span_bytes)
    if at < 0:
        raise SystemExit(f"{was} is not inline at 0x{off:X}")
    start = at
    end = at + len(span_bytes)
    while end < len(body) and body[end] == SPACE:      # the span runs to the next marker
        end += 1
    if body[end] != CHOICE:
        raise SystemExit("the span does not end at a choice marker")
    if start < 2 or body[start - 2] != CHOICE:
        raise SystemExit("the span does not begin right after a choice marker")
    free = [s for s in range(SLOT_COUNT)
            if not any(data[SLOT_BASE + s * SLOT_SIZE:SLOT_BASE + (s + 1) * SLOT_SIZE])]
    if not free:
        raise SystemExit(f"no free slot in {FILE}")
    slot = free[0]
    text, missing = encode(now, table, keep_breaks=False)
    if missing:
        raise SystemExit(f"no glyph for {''.join(missing)}")
    if len(text) > SLOT_SIZE - 2:
        raise SystemExit("the replacement does not fit a slot")
    base = SLOT_BASE + slot * SLOT_SIZE
    data[base:base + SLOT_SIZE] = (text + b"\x00").ljust(SLOT_SIZE, b"\x00")
    data[base + SLOT_SIZE - 1] = (end - start) - 2      # resume at this span's own marker
    data[off + start:off + start + 2] = bytes((0xE2, disk_id(slot)))
    for i in range(off + start + 2, off + end):
        data[i] = SPACE
    notes.append(f"  0x{off:X}  칸을 슬롯 {slot}으로 보냄  {was} -> {now}"
                 f"  (칸 {end - start}B, 완료값 {(end - start) - 2})")

    members[FILE] = bytes(data)
    after = {o: row_widths(o) for o, *_ in (QUESTION, OPTION)}
    for o in after:
        for j, (w, text) in enumerate(after[o]):
            if w > ROW_PIXELS:
                raise SystemExit(f"0x{o:X} 줄{j} is still {w}px")

    if len(members[FILE]) != len(ZipFile(BASE_ZIP).read(FILE)):
        raise SystemExit(f"{FILE} changed size")
    with ZipFile(BASE_ZIP) as base_zip:
        differing = sorted(n for n in members if members[n] != base_zip.read(n))
    if differing != [FILE]:
        raise SystemExit(f"members differing from v146: {differing}")

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
        "v147 재적용 때 넘치게 된 선택지 두 줄",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {final.name}",
        f"        sha256 {stamp}",
        "",
        *notes,
        "",
        f"줄 폭 (한 줄 {ROW_PIXELS}px)",
        *(f"  0x{o:X} 줄{j}  {before[o][j][0]:3d}px -> {after[o][j][0]:3d}px  "
          f"{after[o][j][1]!r}"
          for o in before for j in range(len(before[o]))),
        "",
        "이건 회귀가 맞다",
        "  v134에서는 편지를 읽을까?(90px)였고 강해지는 법 / 작전 세우기 / 피해 감소 1 /",
        "  다음이 네 줄로 각각 들어갔다. v135가 선택지를 일본어로 되돌렸고 v137이 기록된",
        "  규칙대로 -- E5와 E6를 원판 바이트 자리에 -- 되돌려 넣으면서 원판의 줄 구조가",
        "  같이 돌아왔다. 원판은 3번 칸과 4번 칸이 한 줄을 나눠 쓴다. 거기에 CSV의 긴",
        "  문구가 들어가 넘쳤다.",
        "  v134과 게임 전체를 대조한 결과 이런 회귀는 선택지 357개 중 이 두 줄뿐이다.",
        "  228px를 넘는 나머지 69줄은 v134에서도 408px이던 미번역 일본어 줄이다.",
        "",
        "verified",
        "  base digest matches v146",
        "  고친 두 본문의 모든 줄이 228px 이하",
        f"  {FILE} 크기 그대로, v146과 다른 멤버는 이 파일 하나뿐",
        "  칸 안의 E5/E6는 하나도 움직이지 않았다 -- 칸 내용만 슬롯으로 보냈다",
        "",
        "NOT verified here: a cold boot. 어머니에게 말을 걸고 전투 요령을 열어 볼 것.",
        "",
        "rollback: v146",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
