"""v123: find out whether a plain dialogue body may be relocated whole.

v121 gave every relocated body a `capacity - 2` skip, which jumps its own E6 line
breaks, and menus broke: choices a row above their cursor, the cursor over an option.
The rule on record explains exactly that, and it is written entirely about menus --
the renderer's row and *the menu cursor's* row diverging. A body with no choices has
no cursor to diverge from.

So the guard added after v121 may be too wide. It refuses every body containing E6,
and only 47 of the 1,557 it refuses contain a choice. If plain dialogue tolerates the
whole-body skip, those 1,510 need nothing but inserting.

Guessing either way decides the fate of 1,557 lines, so this decides it by measurement
instead. One file, 1/S1021.DAT, an early house scene the player passes through in the
first minutes. Every plain body in it that has a line break and a translation is
relocated the way v121 did it. Nothing else in the game is touched, so a failure is
confined to one scene and a success is unambiguous.

Read it in game and look for what v121 showed: a line drifting down the window, or a
sentence starting on the wrong row. If the scene reads normally, the guard can be
narrowed to bodies with choices and the bulk insertion is nearly unblocked.
"""
from __future__ import annotations

import csv
import hashlib
import sys
import zipfile
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from plan_bulk_insertion import (  # noqa: E402
    CHOICE, SLOT_BASE, SLOT_COUNT, SLOT_SIZE, SLOT_TEXT_MAX,
    build_encoder, disk_id, encode,
)

BASE_ZIP = ROOT / "03_output/story_v122_slot_e6_swept_patch_only.zip"
BASE_SHA = "B090EF58D8CF3B80053DF20689F116B38178963E2A228FC07629436E1E7F5C08"
ORIGINAL_ZIP = ROOT / "00_original/arc.zip"
TRANSLATED = ROOT / "05_docs/script_translated_full.csv"
ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"
OUTPUT = ROOT / "03_output/story_v123_e6_skip_probe_patch_only.zip"
ANALYSIS = ROOT / "01_work/analysis/story_v123_e6_skip_probe"

TARGET = "1/S1021.DAT"
BREAK = b"\xE6\x01"


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
        raise SystemExit("base archive is not the v122 build")
    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}
    if TARGET not in members:
        raise SystemExit(f"{TARGET} is not in the base archive")
    table = build_encoder(members["PSX.EXE"], members["COMM.IMG"])

    raws: dict[tuple[str, str], bytes] = {}
    with ORIGINAL_CSV.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
        for row in reader:
            raws[(row["source file"], row[key])] = bytes.fromhex(
                row["raw bytes as hex"].replace(" ", ""))
    with TRANSLATED.open(encoding="utf-8-sig", newline="") as handle:
        rows = [r for r in csv.DictReader(handle)
                if r["source file"] == TARGET
                and any("가" <= c <= "힣" for c in (r.get("korean") or ""))]

    with ZipFile(ORIGINAL_ZIP) as pristine:
        original = pristine.read(TARGET)
    data = bytearray(members[TARGET])
    if len(data) != len(original):
        raise SystemExit("the patched file and the disc copy differ in length")

    free = [s for s in range(SLOT_COUNT)
            if not any(data[SLOT_BASE + s * SLOT_SIZE:SLOT_BASE + (s + 1) * SLOT_SIZE])]
    allowed: set[int] = set()
    written: list[dict[str, object]] = []

    for row in sorted(rows, key=lambda r: int(r["offset"], 0)):
        raw = raws.get((TARGET, row["offset"]))
        if raw is None:
            continue
        if CHOICE in raw or BREAK not in raw:
            continue                       # choices are out; a body with no break proves nothing
        offset, capacity = int(row["offset"], 0), len(raw)
        if original[offset:offset + capacity] != raw:
            raise SystemExit(f"0x{offset:X}: the disc does not hold the recorded bytes")
        if original[offset + capacity:offset + capacity + 2] != bytes(2):
            continue
        text = (row["korean"] or "").strip()
        payload, missing = encode(text, table, keep_breaks=False)
        if missing or not payload or len(payload) > SLOT_TEXT_MAX or not free:
            continue
        slot = free.pop(0)
        start = SLOT_BASE + slot * SLOT_SIZE
        data[start:start + SLOT_SIZE] = bytes(SLOT_SIZE)
        data[start:start + len(payload)] = payload
        data[start + SLOT_SIZE - 1] = capacity - 2
        data[offset:offset + 2] = bytes((0xE2, disk_id(slot)))
        allowed |= set(range(start, start + SLOT_SIZE)) | {offset, offset + 1}
        written.append({"offset": row["offset"], "slot": slot,
                        "disk_id": f"{disk_id(slot):02X}", "skip": capacity - 2,
                        "rows": raw.count(BREAK) + 1, "bytes": len(payload),
                        "korean": text})

    if not written:
        raise SystemExit("nothing was eligible; the probe would prove nothing")
    before = members[TARGET]
    stray = [i for i in range(len(before)) if before[i] != data[i] and i not in allowed]
    if stray:
        raise SystemExit(f"{len(stray)} bytes changed outside the bodies and slots")
    members[TARGET] = bytes(data)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    with ZipFile(OUTPUT) as check:
        rebuilt = {i.filename: check.read(i.filename) for i in check.infolist()}
    changed = sorted(n for n in rebuilt if rebuilt[n] != ZipFile(BASE_ZIP).read(n))
    if changed != [TARGET]:
        raise SystemExit(f"members changed: {changed}, expected only {TARGET}")

    lines = [
        "v123 probe: may a plain dialogue body be relocated whole?",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {OUTPUT.name}",
        f"        sha256 {digest(OUTPUT.read_bytes())}",
        f"changed {TARGET} only. PSX.EXE, COMM.IMG and every other file are v122's.",
        "",
        f"bodies relocated   {len(written)}",
        f"slots used         {len(written)} of the {len(written) + len(free)} that were free",
        f"source rows spanned {sum(int(w['rows']) for w in written)}",
        "",
        "Each body carries a line break the skip jumps over -- the exact thing v121 did",
        "1,292 times. None of them contains a choice, which is the half of the rule that",
        "is actually about menus.",
        "",
        "what to read in game",
        f"  the early house scene in {TARGET}, from the first line onward",
        "  a line drifting down its window, or a sentence starting on the wrong row,",
        "  is the failure. Ordinary reading with the renderer choosing its own wraps",
        "  is the pass.",
        "",
        "what the answer decides",
        "  pass  the guard narrows to bodies with choices; 1,510 of the 1,557 it now",
        "        refuses become insertable with no editing at all",
        "  fail  the documented repair is required: one E2 per source text row, each",
        "        skip ending just before that row's E6",
        "",
        "verified",
        "  base archive digest matches v122",
        "  every body's original bytes match the script table read from the disc archive",
        "  every body ends at a 00 00 boundary and every slot was empty before writing",
        "  no byte changed outside the bodies and slots, and no other member changed",
        "",
        "rollback: v122",
        "",
        "bodies written:",
    ]
    for w in written:
        lines.append(f"  {w['offset']}  slot {w['slot']:>2}  E2 {w['disk_id']}  "
                     f"skip {w['skip']:>3}  {w['rows']} rows  {w['bytes']:>3}B  "
                     f"{str(w['korean'])[:40]}")
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:34]))


if __name__ == "__main__":
    main()
