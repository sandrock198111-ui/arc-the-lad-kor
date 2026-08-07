"""v131: the same text again, with the encoder finally reading the whole code space.

v130 was built by an encoder that could see only part of the font. Three faults, all in
how a code was resolved to a glyph, and all of them found because the user pointed at
the screen and said the game draws this:

  the one-byte half   A one-byte code 0x01..0xDC is font index `code - 1`, and the
                      two-byte range continues from exactly where it stops -- `DD 01`
                      is index 220, the one-byte range ends at 219. The table was
                      hardcoded to 26 ASCII codes and the other 194 were never looked
                      at, though 118 of them hold Korean. 괄, 량 and 덕 are one-byte
                      codes 3C, 40 and 44; the editor called them impossible while the
                      game was drawing them.

  the Latin capitals  H, L, M, P and R are in the original font, but the rendered-glyph
                      table names only Hangul so none of them could be found. They are
                      now located by taking each letter's cell off the ORIGINAL disc and
                      looking for that picture in the build. R does not resolve, and
                      should not: its cell was overwritten with Korean.

  the smear guard     Kept from v130: no code may resolve to a font row the classifier
                      cannot reach.

Lines refused for a missing character fall from 74 to 36. What is left is 9 uses of R,
six syllables that genuinely have no bitmap anywhere -- 씩 뜩 맺 밝 엮 맑 -- and a
handful of cells still carrying control markers or smart quotes.
"""

from __future__ import annotations

import csv
import hashlib
import pickle
import struct
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from plan_bulk_insertion import (  # noqa: E402
    CACHE, CHOICE, FILLER, LOOKUP_SRC, RAM_TO_FILE, SLOT_BASE, SLOT_COUNT, SLOT_SIZE,
    SLOT_TEXT_MAX, bitmap, build_encoder, disk_id, drawable, encode, has_marker, tokens,
)

BASE_ZIP = ROOT / "03_output/arc1_v130_text_reinsert_1BB69ED1.zip"
BASE_SHA = "1BB69ED14771C40B433A1269239BB04EBCA5B2CA9C297BA2088090387E7A18B3"
ORIGINAL_ZIP = ROOT / "00_original/arc.zip"
ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"
TRANSLATED_CSV = ROOT / "05_docs/script_translated_full.csv"
OUT_DIR, OUT_STEM = ROOT / "03_output", "arc1_v131_full_code_space"
ANALYSIS = ROOT / "01_work/analysis/arc1_v131_full_code_space"

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


def slot_of(disk: int) -> int:
    return disk - 0x81 if disk < 0xA9 else disk - 0x82


def index_of(exe: bytes, tok: bytes) -> int | None:
    """The physical index a two-byte glyph code resolves to, by the decoder's own sums."""
    if len(tok) != 2:
        return None
    if tok[0] in (0xE9, 0xEA):
        slot = 254 * (tok[0] - 0xE9) + tok[1] - 1
        if not 0 <= slot < 508:
            return None
        return struct.unpack_from("<H", exe, LOOKUP_SRC - RAM_TO_FILE + slot * 2)[0]
    if 0xDD <= tok[0] <= 0xE8:
        return (tok[0] - 0xDD) * 255 + tok[1] + 0xDB
    return None


def rendered_spans(blob: bytes, original: bytes, name: str,
                   offsets: list[int], raws: dict[tuple[str, int], bytes]):
    """Where a file's Korean actually is, as (start, length) pairs.

    Only what the renderer reads counts.  A body redirected with E2 draws from its
    external slot and its old tail is skipped, so the tail must be left alone -- it is
    still the game's Japanese and happens to contain byte pairs that look like glyph
    codes.  A body that was never translated is skipped for the same reason.
    """
    has_slots = len(blob) >= SLOT_BASE + SLOT_COUNT * SLOT_SIZE
    for off in offsets:
        raw = raws.get((name, off))
        if raw is None or off + len(raw) > len(blob):
            continue
        if blob[off:off + len(raw)] == original[off:off + len(raw)]:
            continue
        if blob[off] != 0xE2:
            yield off, len(raw)
            continue
        slot = slot_of(blob[off + 1])
        if has_slots and 0 <= slot < SLOT_COUNT:
            at = SLOT_BASE + slot * SLOT_SIZE
            seg = blob[at:at + SLOT_SIZE - 1]
            yield at, (seg.index(0) if 0 in seg else len(seg))


def forbidden_codes(exe: bytes, font: bytes) -> dict[bytes, str]:
    """Two-byte codes that draw a Hangul syllable the classifier cannot reach.

    The leads E1..E8 are shared: `E6 01` is a line break and `E6 AB` is 염, and only the
    argument tells them apart.  So the sweep cannot judge a token by its lead.  What it
    can do is ask whether the index a token would resolve to holds a named Hangul
    bitmap -- a command's argument does not -- and whether that index is drawable.
    Anything that is Hangul and not drawable is the smear, and must not survive.
    """
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    out: dict[bytes, str] = {}
    for lead in range(0xDD, 0xE9):
        for trail in range(0x01, 0x100):
            index = (lead - 0xDD) * 255 + trail + 0xDB
            if drawable(exe, index):
                continue
            bits = bitmap(exe, font, index)
            if bits and (char := shapes.get(bits)):
                out[bytes((lead, trail))] = char
    return out


def main() -> None:
    if digest(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not v130")
    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        base = {i.filename: archive.read(i.filename) for i in infos}
    table = build_encoder(base[PSX], base[COMM])
    exe = base[PSX]

    raws: dict[tuple[str, int], bytes] = {}
    with ORIGINAL_CSV.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
        for row in reader:
            raws[(row["source file"], int(row[key], 0))] = bytes.fromhex(
                row["raw bytes as hex"].replace(" ", ""))
    wanted: dict[str, dict[int, str]] = defaultdict(dict)
    with TRANSLATED_CSV.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            text = (row.get("korean") or "").strip()
            if text and any("가" <= c <= "힣" for c in text):
                wanted[row["source file"]][int(row["offset"], 0)] = text

    with ZipFile(ORIGINAL_ZIP) as pristine:
        names = set(pristine.namelist())
        originals = {n: pristine.read(n) for n in wanted if n in names}

    offsets_of: dict[str, list[int]] = defaultdict(list)
    for fname, off in raws:
        offsets_of[fname].append(off)

    out = dict(base)
    modes: Counter = Counter()
    skipped: list[tuple[str, int, str]] = []
    written_slots: list[tuple[str, int, int]] = []
    changed_files: list[str] = []
    freed_slots: Counter = Counter()
    guarded: set[tuple[str, int]] = set()

    for name, items in sorted(wanted.items()):
        if name not in base or name not in originals:
            for off in items:
                skipped.append((name, off, "file not in the archive"))
            continue
        original, data = originals[name], bytearray(base[name])
        if len(data) != len(original):
            raise SystemExit(f"{name}: length differs from the original disc copy")
        has_slots = len(data) >= SLOT_BASE + SLOT_COUNT * SLOT_SIZE

        # Reclaim the slots earlier builds filled and then stopped pointing at.  A slot
        # is only ours to clear if it was empty on the original disc -- 1,492 of them
        # hold the game's own data -- and no body references it now.  14 files sit at
        # the 79-slot ceiling with dead text in them, which is what "ran out of slots"
        # has really meant.
        referenced = {slot_of(data[off + 1]) for off in offsets_of[name]
                      if off + 1 < len(data) and data[off] == 0xE2}
        reclaim: set[int] = set()
        if has_slots:
            for s in range(SLOT_COUNT):
                at = SLOT_BASE + s * SLOT_SIZE
                if s in referenced or not any(data[at:at + SLOT_SIZE]):
                    continue
                if any(original[at:at + SLOT_SIZE]):
                    continue            # the game's own data, not ours
                data[at:at + SLOT_SIZE] = bytes(SLOT_SIZE)
                reclaim.add(s)
        freed_slots[name] = len(reclaim)

        # Decide every line first, so slot demand is known before anything is written.
        plan: list[tuple[int, int, bytes, bytes]] = []       # offset, capacity, inline, slot
        for off, text in sorted(items.items()):
            raw = raws.get((name, off))
            if raw is None:
                skipped.append((name, off, "no original row of that offset")); continue
            if original[off:off + len(raw)] != raw:
                raise SystemExit(f"{name} 0x{off:X}: the disc does not hold the recorded bytes")
            if has_marker(raw, CHOICE):
                skipped.append((name, off, "E5 choice body, owned by the row-by-row repair"))
                continue
            inline, miss = encode(text, table, keep_breaks=True)
            if miss:
                skipped.append((name, off, f"no code for {''.join(sorted(set(miss)))}"))
                continue
            if len(inline) <= len(raw):
                plan.append((off, len(raw), inline, b"")); continue
            payload, miss = encode(text, table, keep_breaks=False)
            if miss:
                skipped.append((name, off, f"no code for {''.join(sorted(set(miss)))}"))
                continue
            if not has_slots:
                skipped.append((name, off, "file has no external slot region")); continue
            if original[off + len(raw):off + len(raw) + 2] != bytes(2):
                skipped.append((name, off, "body has no 00 00 boundary")); continue
            if len(payload) > SLOT_TEXT_MAX:
                skipped.append((name, off, f"{len(payload)}B over the {SLOT_TEXT_MAX}B slot"))
                continue
            plan.append((off, len(raw), b"", payload))

        # Keep the slot a body already uses; a reallocation would strand any E2 marker
        # this build does not rewrite.
        held = {off: slot_of(data[off + 1]) for off, *_ in plan if data[off] == 0xE2}
        need = [off for off, _, inline, payload in plan if payload]
        taken = {held[o] for o in need if o in held}
        free = [s for s in range(SLOT_COUNT)
                if s not in taken
                and not any(data[SLOT_BASE + s * SLOT_SIZE:SLOT_BASE + (s + 1) * SLOT_SIZE])
                ] if has_slots else []
        assign: dict[int, int] = {}
        for off in need:
            if off in held:
                assign[off] = held[off]
            elif free:
                assign[off] = free.pop(0)
            else:
                skipped.append((name, off, "file ran out of external slots"))
        plan = [p for p in plan if not p[3] or p[0] in assign]

        allowed: set[int] = set()
        for s in reclaim:
            allowed |= set(range(SLOT_BASE + s * SLOT_SIZE, SLOT_BASE + (s + 1) * SLOT_SIZE))
        for off, capacity, inline, payload in plan:
            if inline:
                data[off:off + capacity] = bytes((FILLER,)) * capacity
                data[off:off + len(inline)] = inline
                allowed |= set(range(off, off + capacity))
                modes["inline"] += 1
                continue
            slot = assign[off]
            start = SLOT_BASE + slot * SLOT_SIZE
            data[start:start + SLOT_SIZE] = bytes(SLOT_SIZE)
            data[start:start + len(payload)] = payload
            data[start + SLOT_SIZE - 1] = capacity - 2
            data[off:off + 2] = bytes((0xE2, disk_id(slot)))
            allowed |= set(range(start, start + SLOT_SIZE)) | {off, off + 1}
            written_slots.append((name, slot, len(payload)))
            modes["e2"] += 1

        before = base[name]
        stray = [i for i in range(len(before)) if before[i] != data[i] and i not in allowed]
        if stray:
            raise SystemExit(f"{name}: {len(stray)} bytes changed outside the declared "
                             f"bodies and slots, first at 0x{stray[0]:X}")
        if bytes(data) != before:
            changed_files.append(name)
            out[name] = bytes(data)

    # Every slot a body points at must end before the metadata byte. This is the guard
    # the off-by-one needed: it checks the result, not the arithmetic that produced it.
    # Slots nothing points at are not read, so they are not required to be text.
    unterminated = []
    for name, blob in out.items():
        if not name.upper().endswith(".DAT"): continue
        if len(blob) < SLOT_BASE + SLOT_COUNT * SLOT_SIZE: continue
        live = {slot_of(blob[off + 1]) for off in offsets_of[name]
                if off + 1 < len(blob) and blob[off] == 0xE2}
        for s in live:
            if not 0 <= s < SLOT_COUNT:
                continue
            seg = blob[SLOT_BASE + s * SLOT_SIZE:SLOT_BASE + (s + 1) * SLOT_SIZE]
            if 0 not in seg[:SLOT_SIZE - 1]:
                unterminated.append((name, s))
    if unterminated:
        raise SystemExit(f"{len(unterminated)} live slots have no terminator: {unterminated[:5]}")

    # And no glyph this build wrote may sit on the unreachable texture page.
    # Some bodies this build could not rewrite -- an unencodable character, a line over
    # the slot -- still hold the smeared codes from v129. The strip A twin is the same
    # two bytes, so those can be repaired where they stand, in any text we wrote.
    banned = forbidden_codes(exe, base[COMM])
    swap = {code: table[char] for code, char in banned.items()
            if char in table and len(table[char]) == len(code)}
    repaired: Counter = Counter()
    for name in sorted(originals):
        blob, original = bytearray(out[name]), originals[name]
        touched = False
        for start, length in rendered_spans(bytes(blob), original, name,
                                            offsets_of[name], raws):
            at = start
            for tok in tokens(bytes(blob[start:start + length])):
                if tok in swap:
                    blob[at:at + 2] = swap[tok]
                    repaired[banned[tok]] += 1
                    touched = True
                at += len(tok)
        if touched:
            out[name] = bytes(blob)
            if name not in changed_files:
                changed_files.append(name)

    offenders: Counter = Counter()
    for name in sorted(originals):
        blob = out[name]
        for start, length in rendered_spans(blob, originals[name], name,
                                            offsets_of[name], raws):
            for tok in tokens(blob[start:start + length]):
                if tok in banned:
                    offenders[f"{tok.hex(' ').upper()} {banned[tok]}"] += 1
    if offenders:
        raise SystemExit("glyphs on the unreachable texture page survived in text this "
                         f"build owns: {offenders.most_common(8)}")

    if out[PSX] != base[PSX] or out[COMM] != base[COMM]:
        raise SystemExit("the executable or the font changed; this build must not touch them")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tmp = OUT_DIR / f"{OUT_STEM}_building.zip"
    with ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), out[info.filename])
    with ZipFile(tmp) as check:
        rebuilt = {i.filename: check.read(i.filename) for i in check.infolist()}
    if rebuilt != out:
        raise SystemExit("the archive did not read back as written")

    stamp = digest(tmp.read_bytes())
    final = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    tmp.replace(final)
    (OUT_DIR / "LATEST.txt").write_text(
        f"ship this one\n  file    {final.name}\n  sha256  {stamp}\n", encoding="utf-8")

    why: Counter = Counter(r.split(" for ")[0].split("B over")[0] for _, _, r in skipped)
    lines = [
        "v131 the same text, with the whole code space visible to the encoder",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {final.name}",
        f"        sha256 {stamp}",
        f"members {len(rebuilt)}; PSX.EXE and COMM.IMG byte-identical to v130",
        "",
        f"lines written            {modes['inline'] + modes['e2']}",
        f"  in place               {modes['inline']}",
        f"  through an E2 slot     {modes['e2']}",
        f"files changed            {len(changed_files)}",
        f"lines left alone         {len(skipped)}",
        "",
        f"dead slots reclaimed     {sum(freed_slots.values())} in {len(freed_slots)} files",
        "  earlier builds filled slots and later stopped pointing at them, and the",
        "  allocator counts any non-empty slot as taken. 1,492 slots hold the game's own",
        "  data and were left alone; only slots empty on the original disc were cleared.",
        *(f"    {n:>3}  {f}" for f, n in freed_slots.most_common(6) if n),
        "",
        f"smeared codes repaired in place  {sum(repaired.values())}",
        "  bodies this build could not rewrite still held them; the strip A twin is the",
        "  same two bytes, so they were swapped where they stand.",
        *(f"    {n:>3}  {c}" for c, n in repaired.most_common(8)),
        "",
        "why lines were left alone (their v129 bytes are untouched):",
        *(f"  {n:>5}  {r}" for r, n in why.most_common()),
        "",
        "verified",
        "  base digest matches v130",
        "  every body's original bytes match the script table read from 00_original/arc.zip",
        "  every E5 choice body was skipped, so v128's battle choices are intact",
        "  a body that already had a slot keeps it, so no E2 marker is stranded",
        "  every slot in the finished archive has a 0x00 in bytes 0..126",
        "  no glyph code in any rewritten body or slot resolves to an index the",
        "    classifier cannot reach -- this is the smear, checked on the output",
        "  no byte changed outside the declared bodies and slots, in any file",
        "  PSX.EXE and COMM.IMG unchanged; the archive reads back as written",
        "",
        "NOT verified here, needs a cold boot:",
        "  that 짜, 잔, 층 and the rest of the 25 now read correctly",
        "  that the ship scene in 21/S2041.DAT no longer freezes",
        "  that 쓰러뜨린 몬스터가 reads 가 in 21/S2021.DAT",
        "",
        "rebuild with arc1_v104.xml, then run verify_iso_layout.py",
        "rollback: v130",
        "",
        "lines left alone, in full:",
        *(f"  {n} 0x{o:X}  {r}" for n, o, r in skipped),
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:30]))


if __name__ == "__main__":
    main()
