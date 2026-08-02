"""v121: apply the bulk insertion plan -- 2,166 translated lines in one build.

The plan is `plan_bulk_insertion.py`'s manifest and this only carries it out. Two
write shapes, and the second one is easy to get wrong:

  inline  fill the body's capacity with the space filler, then write the payload
          over the front of it

  e2      write `E2 <disk id>` over the body's FIRST TWO BYTES ONLY, put the text in
          the external slot, and store `capacity - 2` at the slot's byte 0x7F. The
          rest of the old body is deliberately left alone: the metadata makes the
          renderer skip it. Overwriting it is not needed, and failing to store the
          skip is what once left `속 지킬 거야?` on screen, the tail of an old line
          resuming from its second glyph.

Every offset is proved before it is used. The manifest's body must match, byte for
byte, the raw bytes the original script table recorded for that file and offset, read
out of the untouched disc archive. A file the build has never touched starts from that
same archive; a file earlier work already patched starts from the patch archive, so
its existing translations and the slots they consumed are preserved.
"""
from __future__ import annotations

import csv
import hashlib
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from plan_bulk_insertion import (  # noqa: E402
    CHOICE, FILLER, LINEBREAK, SLOT_BASE, SLOT_SIZE, SLOT_TEXT_MAX,
    build_encoder, disk_id, encode,
)

BASE_ZIP = ROOT / "03_output/ui_hud_e7_v119_strip_c_patch_only.zip"
BASE_SHA = "7EFBE624E56433C28295FB51FB56611ABDB06A54678D0D4EFB9FEC9E740F5722"
ORIGINAL_ZIP = ROOT / "00_original/arc.zip"
MANIFEST = ROOT / "05_docs/bulk_insertion_manifest.csv"
ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"
OUTPUT = ROOT / "03_output/story_bulk_v121_patch_only.zip"
ANALYSIS = ROOT / "01_work/analysis/story_bulk_v121"

PSX, COMM = "PSX.EXE", "COMM.IMG"


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
        raise SystemExit("base archive is not the accepted v119 build")
    with ZipFile(BASE_ZIP) as archive:
        base_infos = archive.infolist()
        base = {i.filename: archive.read(i.filename) for i in base_infos}
    table = build_encoder(base[PSX], base[COMM])

    raws: dict[tuple[str, str], bytes] = {}
    with ORIGINAL_CSV.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
        for row in reader:
            raws[(row["source file"], row[key])] = bytes.fromhex(
                row["raw bytes as hex"].replace(" ", ""))
    with MANIFEST.open(encoding="utf-8-sig", newline="") as handle:
        plan = list(csv.DictReader(handle))
    if not plan:
        raise SystemExit("the manifest is empty; run plan_bulk_insertion.py first")

    by_file: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in plan:
        by_file[row["file"]].append(row)

    with ZipFile(ORIGINAL_ZIP) as pristine:
        pristine_names = set(pristine.namelist())
        missing = [n for n in by_file if n not in pristine_names]
        if missing:
            raise SystemExit(f"not on the original disc: {missing[:3]}")
        originals = {n: pristine.read(n) for n in by_file}

    out: dict[str, bytes] = dict(base)
    added: list[str] = []
    touched: dict[str, set[int]] = {}
    modes: Counter = Counter()
    slot_use: Counter = Counter()

    for name, items in by_file.items():
        original = originals[name]
        if name in base:
            data = bytearray(base[name])
        else:
            data = bytearray(original)
            added.append(name)
        if len(data) != len(original):
            raise SystemExit(f"{name}: length differs from the original disc copy")

        allowed: set[int] = set()
        for item in items:
            offset, capacity = int(item["offset"], 0), int(item["capacity"])
            raw = raws.get((name, item["offset"]))
            if raw is None or len(raw) != capacity:
                raise SystemExit(f"{name} {item['offset']}: no original row of that length")
            if original[offset:offset + capacity] != raw:
                raise SystemExit(f"{name} {item['offset']}: the disc does not hold the "
                                 f"bytes the script table recorded")

            if item["mode"] == "inline":
                payload, miss = encode(item["korean"], table, keep_breaks=True)
                if miss:
                    raise SystemExit(f"{name} {item['offset']}: no code for {miss}")
                if len(payload) > capacity:
                    raise SystemExit(f"{name} {item['offset']}: {len(payload)} > {capacity}")
                data[offset:offset + capacity] = bytes((FILLER,)) * capacity
                data[offset:offset + len(payload)] = payload
                allowed |= set(range(offset, offset + capacity))
                modes["inline"] += 1
                continue

            if item["mode"] != "e2":
                raise SystemExit(f"{name} {item['offset']}: unknown mode {item['mode']}")
            if CHOICE in raw:
                raise SystemExit(f"{name} {item['offset']}: E5 body must not take e2")
            if original[offset + capacity:offset + capacity + 2] != bytes(2):
                raise SystemExit(f"{name} {item['offset']}: body has no 00 00 boundary")
            payload, miss = encode(item["korean"], table, keep_breaks=False)
            if miss:
                raise SystemExit(f"{name} {item['offset']}: no code for {miss}")
            if len(payload) > SLOT_TEXT_MAX:
                raise SystemExit(f"{name} {item['offset']}: {len(payload)} > {SLOT_TEXT_MAX}")
            slot = int(item["slot"])
            start = SLOT_BASE + slot * SLOT_SIZE
            if any(data[start:start + SLOT_SIZE]):
                raise SystemExit(f"{name}: slot {slot} is not empty")
            if int(item["disk_id"], 16) != disk_id(slot):
                raise SystemExit(f"{name}: slot {slot} disk id disagrees with the manifest")
            data[start:start + SLOT_SIZE] = bytes(SLOT_SIZE)
            data[start:start + len(payload)] = payload
            data[start + SLOT_SIZE - 1] = capacity - 2
            data[offset:offset + 2] = bytes((0xE2, disk_id(slot)))
            allowed |= set(range(start, start + SLOT_SIZE))
            allowed |= {offset, offset + 1}
            modes["e2"] += 1
            slot_use[name] += 1

        before = base.get(name, original)
        stray = [i for i in range(len(before)) if before[i] != data[i] and i not in allowed]
        if stray:
            raise SystemExit(f"{name}: {len(stray)} bytes changed outside the declared "
                             f"bodies and slots, first at 0x{stray[0]:X}")
        touched[name] = allowed
        out[name] = bytes(data)

    if out[PSX] != base[PSX] or out[COMM] != base[COMM]:
        raise SystemExit("the executable or the font changed; this build must not touch them")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in base_infos:
            archive.writestr(clone(info), out[info.filename])
        for name in sorted(added):
            archive.writestr(name, out[name])

    with ZipFile(OUTPUT) as check:
        rebuilt = {i.filename: check.read(i.filename) for i in check.infolist()}
    if rebuilt != out:
        raise SystemExit("the archive did not read back as written")
    changed_from_base = sorted(n for n in base if rebuilt[n] != base[n])

    lines = [
        "v121 bulk story insertion",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {OUTPUT.name}",
        f"        sha256 {digest(OUTPUT.read_bytes())}",
        f"members {len(rebuilt)}  ({len(base_infos)} from v119 + {len(added)} new)",
        "",
        f"lines written              {modes['inline'] + modes['e2']}",
        f"  in place                 {modes['inline']}",
        f"  through an E2 slot       {modes['e2']}",
        f"files changed from v119    {len(changed_from_base)}",
        f"files added                {len(added)}",
        "",
        "external slots consumed, worst files:",
        *(f"  {n:>3}  {f}" for f, n in slot_use.most_common(10)),
        "",
        "verified",
        "  base archive digest matches the accepted v119 build",
        "  every body's original bytes match the script table, read from 00_original/arc.zip",
        "  every e2 body ends at a 00 00 boundary and its slot was empty before writing",
        "  every slot's disk id agrees with the manifest and with the 81-A8 / AA-D0 map",
        "  no byte changed outside the declared bodies and slots, in any file",
        "  PSX.EXE and COMM.IMG are byte-identical to v119",
        "  the archive reads back exactly as written",
        "",
        "NOT verified here, needs a cold boot:",
        "  that the inserted text renders and that scenes advance",
        "  that no E2 skip leaves a tail of the old line on screen",
        "",
        "left out of this build, by the planner's count:",
        "  380 lines whose file ran out of slots; each needs a small trim, median 10 bytes",
        "  47 bodies that mix prose with E5 choices",
        "  57 lines containing characters with no code",
        "",
        "rebuild with arc1_v104.xml, then run verify_iso_layout.py",
        "rollback: v119, which this build does not modify",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
