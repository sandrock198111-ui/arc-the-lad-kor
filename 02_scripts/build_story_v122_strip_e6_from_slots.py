"""v122: take the E6 line breaks back out of the external slots.

`E6 01` is a line break the inline parser executes. An E2 secondary string is not
parsed that way, so an E6 sitting inside a slot is not a break -- the renderer draws
it, and it appears as one squashed glyph in the middle of a sentence. That was
established on 2026-07-15 and written down: use spaces and let the renderer wrap.

The rule stopped new ones being written. It never removed the ones already in the
archive, and 62 of them are still there, one visible defect each. This sweeps them.

The edit is confined to slot text. Each `E6 01` becomes a single space and the rest
of the string shifts down one byte, so the text ends earlier and the freed tail is
zeroed. Byte 0x7F is not touched: it carries `capacity - 2`, how much of the old
inline body the renderer must skip, which has nothing to do with how long the slot's
text is. Nothing outside the slots changes, and neither do the E2 commands that
select them.
"""
from __future__ import annotations

import hashlib
import zipfile
from collections import Counter
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
BASE_ZIP = ROOT / "03_output/ui_hud_e7_v119_strip_c_patch_only.zip"
BASE_SHA = "7EFBE624E56433C28295FB51FB56611ABDB06A54678D0D4EFB9FEC9E740F5722"
OUTPUT = ROOT / "03_output/story_v122_slot_e6_swept_patch_only.zip"
ANALYSIS = ROOT / "01_work/analysis/story_v122_slot_e6_swept"

SLOT_BASE, SLOT_SIZE, SLOT_COUNT = 0x45000, 0x80, 79
META = SLOT_SIZE - 1                  # byte 0x7F, the completion skip
BREAK = b"\xE6\x01"
SPACE = 0x9C


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system", "create_version",
                 "extract_version", "flag_bits", "volume", "internal_attr",
                 "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def tokens(text: bytes):
    """Walk the stream the way the runtime does, so a byte is judged in its place.

    0x01..0xDC is a one-byte glyph, 0xDD..0xE0 a two-byte glyph, 0xE1 and above a
    two-byte command with its argument. An 0xE6 that happens to be the second byte of
    a glyph is glyph data, not a line break, and mistaking the two is a documented way
    to corrupt text.
    """
    i = 0
    while i < len(text):
        lead = text[i]
        width = 1 if lead < 0xDD else 2
        yield i, text[i:i + width]
        i += width


def has_break(text: bytes) -> bool:
    return any(tok == BREAK for _, tok in tokens(text))


def sweep(slot: bytearray) -> tuple[bytearray, int]:
    """Replace every E6 01 token in the slot's text with one space. Metadata untouched."""
    end = slot.find(0)
    if end < 0:
        end = META
    text = bytes(slot[:end])
    removed = 0
    out = bytearray()
    for _, tok in tokens(text):
        if tok == BREAK:
            out.append(SPACE)
            removed += 1
        else:
            out += tok
    if not removed:
        return slot, 0
    fixed = bytearray(slot)
    fixed[:META] = bytes(META)
    fixed[:len(out)] = out
    return fixed, removed


def main() -> None:
    if digest(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not the accepted v119 build")
    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}

    out: dict[str, bytes] = {}
    per_file: Counter = Counter()
    breaks_removed = 0
    for name, data in members.items():
        if not name.endswith(".DAT") or len(data) < SLOT_BASE + SLOT_COUNT * SLOT_SIZE:
            out[name] = data
            continue
        buf = bytearray(data)
        for s in range(SLOT_COUNT):
            start = SLOT_BASE + s * SLOT_SIZE
            slot = bytearray(buf[start:start + SLOT_SIZE])
            if not any(slot):
                continue
            fixed, removed = sweep(slot)
            if not removed:
                continue
            if fixed[META] != slot[META]:
                raise SystemExit(f"{name} slot {s}: the metadata byte moved")
            buf[start:start + SLOT_SIZE] = fixed
            per_file[name] += 1
            breaks_removed += removed
        out[name] = bytes(buf)

    # nothing may change outside the slot banks
    for name, data in out.items():
        before = members[name]
        if data == before:
            continue
        allowed = set(range(SLOT_BASE, SLOT_BASE + SLOT_COUNT * SLOT_SIZE))
        stray = [i for i in range(len(before)) if before[i] != data[i] and i not in allowed]
        if stray:
            raise SystemExit(f"{name}: {len(stray)} bytes changed outside the slot bank")
    if out["PSX.EXE"] != members["PSX.EXE"] or out["COMM.IMG"] != members["COMM.IMG"]:
        raise SystemExit("this build must not touch the executable or the font")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), out[info.filename])

    with ZipFile(OUTPUT) as check:
        rebuilt = {i.filename: check.read(i.filename) for i in check.infolist()}
    if rebuilt != out:
        raise SystemExit("the archive did not read back as written")
    left = 0
    for name, data in rebuilt.items():
        if not name.endswith(".DAT") or len(data) < SLOT_BASE + SLOT_COUNT * SLOT_SIZE:
            continue
        for s in range(SLOT_COUNT):
            slot = data[SLOT_BASE + s * SLOT_SIZE:SLOT_BASE + (s + 1) * SLOT_SIZE]
            if not any(slot):
                continue
            end = slot.find(0)
            if has_break(slot[:end if end >= 0 else META]):
                left += 1
    if left:
        raise SystemExit(f"{left} slots still contain E6")

    lines = [
        "v122 sweep E6 out of the external slots",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {OUTPUT.name}",
        f"        sha256 {digest(OUTPUT.read_bytes())}",
        "",
        f"slots repaired      {sum(per_file.values())}",
        f"line breaks removed {breaks_removed}",
        f"files changed       {len(per_file)}",
        "",
        "worst files:",
        *(f"  {n:>3}  {f}" for f, n in per_file.most_common(12)),
        "",
        "why",
        "  E6 01 is a break the inline parser executes. A secondary string is not parsed",
        "  that way, so an E6 inside a slot is drawn instead of obeyed and shows up as one",
        "  squashed glyph mid-sentence. Recorded 2026-07-15; the rule stopped new ones but",
        "  never removed these.",
        "",
        "verified",
        "  base archive digest matches the accepted v119 build",
        "  each slot's byte 0x7F, the completion skip, is unchanged",
        "  no byte changed outside the slot banks, in any file",
        "  PSX.EXE and COMM.IMG are byte-identical to v119",
        "  no slot in the output contains E6 before its terminator",
        "  the archive reads back exactly as written",
        "",
        "NOT verified here, needs a cold boot:",
        "  that the repaired lines read correctly and wrap where the renderer chooses",
        "",
        "rollback: v119, which this build does not modify",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
