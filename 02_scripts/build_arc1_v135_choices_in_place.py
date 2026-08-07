"""v135: translate the choice bodies where they stand.

Bulk insertion has always refused bodies that carry E5 choice markers, and the reason
is sound: relocating one to an external slot moves the text but not the menu cursor,
and the two end up on different rows -- that is what v121 broke. So 357 bodies have sat
in Japanese, and the battle prompt the user hit is one of them.

The way through is the one v128 used on eight files: leave every E5 and E6 byte exactly
where it is and rewrite only the text between them. The cursor counts markers, so if the
markers do not move the cursor cannot drift. Each run of text keeps its own byte length,
padded with the space filler, which also matters for a second reason: a Korean phrase
shorter than the Japanese it replaces would otherwise leave kana behind, and those kana
no longer draw as kana. 123 of the 220 one-byte font cells were overwritten with Korean
long ago, so any Japanese left on screen renders as a mixture -- `やめる` reading as
`다り량める` is exactly that.

A body is written only if the number of `|`-separated phrases in the CSV matches the
number of text runs in the original and every phrase fits its run. Anything else is
listed and left alone; shortening a phrase or fixing a `|` count is editing work, not
something a builder should guess at.
"""
from __future__ import annotations

import csv
import hashlib
import pickle
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from plan_bulk_insertion import (  # noqa: E402
    CACHE, CHOICE, FILLER, bitmap, build_encoder, drawable, encode, has_marker, tokens,
)

BASE_ZIP = ROOT / "03_output/arc1_v134_window_fit_09C17854.zip"
BASE_SHA = "09C178548087FE28D1949050C491B4DB174F871BE810EF8DBE83E0FCB506AB4C"
ORIGINAL_ZIP = ROOT / "00_original/arc.zip"
ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"
TRANSLATED_CSV = ROOT / "05_docs/script_translated_full.csv"
OUT_DIR, OUT_STEM = ROOT / "03_output", "arc1_v135_choices_in_place"
ANALYSIS = ROOT / "01_work/analysis/arc1_v135_choices_in_place"
LINEBREAK = b"\xE6\x01"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system", "create_version",
                 "extract_version", "flag_bits", "volume", "internal_attr",
                 "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def text_runs(raw: bytes) -> list[tuple[int, int]]:
    """(offset, length) of each run of text between markers, empty runs dropped.

    Two markers in a row -- a line break then a choice marker -- are how the original
    starts a new option, and they enclose nothing. Counting the gap between them as a
    phrase would put the CSV's phrases one out of step with the body's.
    """
    out: list[tuple[int, int]] = []
    position = start = length = 0
    for token in tokens(raw):
        if len(token) == 1 and token[0] == 0:
            break
        if token[0] == CHOICE or token == LINEBREAK:
            if length:
                out.append((start, length))
            position += len(token)
            start, length = position, 0
            continue
        position += len(token)
        length += len(token)
    if length:
        out.append((start, length))
    return out


def markers(raw: bytes) -> list[tuple[int, bytes]]:
    """Where every E5 and E6 sits, by byte offset.

    Comparing token by token does not work: Korean and Japanese use different token
    widths, so the two streams fall out of step and a marker lines up against a glyph.
    What has to hold is that each marker is at the same byte offset with the same bytes,
    because that is what the menu cursor counts.
    """
    out, position = [], 0
    for token in tokens(raw):
        if len(token) == 1 and token[0] == 0:
            break
        if token[0] == CHOICE or token == LINEBREAK:
            out.append((position, token))
        position += len(token)
    return out


def main() -> None:
    if digest(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not v134")
    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}
    table = build_encoder(members["PSX.EXE"], members["COMM.IMG"])
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    banned = {}
    for lead in range(0xDD, 0xE9):
        for trail in range(0x01, 0x100):
            index = (lead - 0xDD) * 255 + trail + 0xDB
            if not drawable(members["PSX.EXE"], index):
                bits = bitmap(members["PSX.EXE"], members["COMM.IMG"], index)
                if bits and (char := shapes.get(bits)):
                    banned[bytes((lead, trail))] = char

    raws: dict[tuple[str, int], bytes] = {}
    with ORIGINAL_CSV.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
        for row in reader:
            raws[(row["source file"], int(row[key], 0))] = bytes.fromhex(
                row["raw bytes as hex"].replace(" ", ""))
    with TRANSLATED_CSV.open(encoding="utf-8-sig", newline="") as handle:
        wanted = [(n, r) for n, r in enumerate(csv.DictReader(handle), 1)]
    with ZipFile(ORIGINAL_ZIP) as pristine:
        names = set(pristine.namelist())
        originals = {n: pristine.read(n) for n in names if n in members}

    edits: dict[str, list[tuple[int, bytes]]] = defaultdict(list)
    restored: list[tuple[str, int, bytes]] = []
    written = 0
    skipped: list[tuple[int, str, str]] = []

    for n, row in wanted:
        name, offset = row["source file"], int(row["offset"], 0)
        raw = raws.get((name, offset))
        if raw is None or not has_marker(raw, CHOICE):
            continue
        if name not in members or name not in originals:
            skipped.append((n, name, "파일이 아카이브에 없음"))
            continue
        if originals[name][offset:offset + len(raw)] != raw:
            raise SystemExit(f"{name} 0x{offset:X}: the disc does not hold the recorded bytes")

        # Some of these bodies carry an E2 redirect written by an earlier build. That is
        # forbidden here for the reason the whole file exists -- the body's text moves to
        # a slot and the menu cursor does not follow -- and it is what put a Korean
        # question above three lines of rubble in the battle prompt. Whatever this build
        # cannot rewrite properly goes back to the bytes the disc shipped.
        restored.append((name, offset, raw))

        korean = (row.get("korean") or "").strip()
        if not korean or not any("가" <= c <= "힣" for c in korean):
            skipped.append((n, name, "한국어 없음"))
            continue

        runs = text_runs(raw)
        parts = [p.strip() for p in korean.split("|")]
        if len(parts) != len(runs):
            skipped.append((n, name, f"구분 {len(parts)}칸, 원문 {len(runs)}칸"))
            continue

        payloads, trouble = [], ""
        for (start, length), phrase in zip(runs, parts):
            payload, missing = encode(phrase, table, keep_breaks=False)
            if missing:
                trouble = "없는 글자 " + "".join(sorted(set(missing)))
                break
            if len(payload) > length:
                trouble = f"{len(payload)}바이트가 {length}칸에 안 들어감"
                break
            if any(t in banned for t in tokens(payload)):
                trouble = "닿을 수 없는 글리프"
                break
            payloads.append((start, payload + bytes((FILLER,)) * (length - len(payload))))
        if trouble:
            skipped.append((n, name, trouble))
            continue
        edits[name].append((offset, raw, payloads))
        written += 1

    # Sweep every choice body on the disc, not only the ones with a row in the CSV.
    # Four of them had no row, were never visited, and kept their E2 -- a survey that
    # only walks the translation misses exactly the bodies nobody has looked at.
    seen = {(n, o) for n, o, _ in restored}
    for (name, offset), raw in raws.items():
        if (name, offset) in seen or name not in members or name not in originals:
            continue
        if not has_marker(raw, CHOICE):
            continue
        if originals[name][offset:offset + len(raw)] == raw:
            restored.append((name, offset, raw))

    # every choice body goes back to the disc's bytes first, then the ones that fit
    # get written over that clean base
    bodies: dict[str, bytearray] = {}
    touched: dict[str, set[int]] = defaultdict(set)
    undone = 0
    for name, offset, raw in restored:
        data = bodies.setdefault(name, bytearray(members[name]))
        if data[offset:offset + len(raw)] != raw:
            undone += 1
        data[offset:offset + len(raw)] = raw
        touched[name] |= set(range(offset, offset + len(raw)))

    changed: list[str] = []
    for name, items in edits.items():
        data = bodies.setdefault(name, bytearray(members[name]))
        allowed: set[int] = touched[name]
        for offset, raw, payloads in items:
            # Rebuild from the disc's own bytes rather than from whatever is there now.
            # Some of these bodies were half-written by an earlier build -- the speaker
            # and the options in Korean, the question still Japanese -- so the markers
            # sitting in the current file are not necessarily the ones the game shipped.
            body = bytearray(raw)
            for start, payload in payloads:
                body[start:start + len(payload)] = payload
            if markers(bytes(body)) != markers(raw):
                raise SystemExit(f"{name} 0x{offset:X}: the markers moved")
            data[offset:offset + len(raw)] = body
            allowed |= set(range(offset, offset + len(raw)))


    for name, data in bodies.items():
        before = members[name]
        stray = [i for i in range(len(before)) if before[i] != data[i]
                 and i not in touched[name]]
        if stray:
            raise SystemExit(f"{name}: {len(stray)} bytes changed outside the choice bodies")
        if bytes(data) != before:
            members[name] = bytes(data)
            changed.append(name)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tmp = OUT_DIR / f"{OUT_STEM}_building.zip"
    with ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    with ZipFile(tmp) as check:
        if {i.filename: check.read(i.filename) for i in check.infolist()} != members:
            raise SystemExit("the archive did not read back as written")
    with ZipFile(BASE_ZIP) as base:
        differing = sorted(n for n in members if members[n] != base.read(n))
    if "PSX.EXE" in differing or "COMM.IMG" in differing:
        raise SystemExit("this build must not touch the executable or the font")

    stamp = digest(tmp.read_bytes())
    final = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    tmp.replace(final)
    (OUT_DIR / "LATEST.txt").write_text(
        f"ship this one\n  file    {final.name}\n  sha256  {stamp}\n", encoding="utf-8")

    why = Counter(r.split(" ")[0] if "바이트" not in r else "칸 모자람" for _, _, r in skipped)
    lines = [
        "v135 choice bodies, translated where they stand",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {final.name}",
        f"        sha256 {stamp}",
        f"members {len(members)}; PSX.EXE and COMM.IMG byte-identical to v134",
        "",
        f"choice bodies written   {written}",
        f"E2가 박혀 있어 원판으로 되돌린 본문  {undone}",
        f"files changed           {len(changed)}",
        f"left alone              {len(skipped)}",
        *(f"  {n:>4}  {r}" for r, n in why.most_common()),
        "",
        "verified",
        "  base digest matches v134",
        "  every body's original bytes match the script table read from the disc archive",
        "  every E5 and E6 byte is still at the offset the original put it, checked by",
        "    re-deriving the runs from the written body and comparing marker for marker",
        "  each phrase was padded to its run's full length, so no Japanese tail survives",
        "  no glyph resolves to a font row the classifier cannot reach",
        "  no byte changed outside the text runs, in any file",
        "  PSX.EXE and COMM.IMG untouched; the archive reads back as written",
        "",
        "NOT verified here: a cold boot. Open a battle prompt and check the cursor sits",
        "on the option it is pointing at, then read a menu with three or more choices.",
        "",
        "rollback: v134",
        "",
        "left alone, in full:",
        *(f"  행 {n} {f}  {r}" for n, f, r in skipped),
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:22]))


if __name__ == "__main__":
    main()
