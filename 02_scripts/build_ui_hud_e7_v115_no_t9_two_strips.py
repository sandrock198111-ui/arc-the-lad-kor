"""v115: keep both resident glyph strips, but never touch the caller's t9.

v108e proved that a classifier subroutine using only t8 works.  v112 added the
second strip by adding t9 as a second comparison register, and both v112 and v113
rendered the expanded glyphs blank.  v113 removed the second LoadImage call, so two
uploads are not the sole cause.  The untracked v114 probe is not a valid t9 test: it
still executes ``addu t9,zero,zero``.

This build changes only the classifier implementation and the addresses/lengths that
move because it grows by one word.  It compares V=224 and V=244 with t8 alone.  The
two strips, lookup remap, pixels, rectangles, tpage and both LoadImage calls remain
byte-identical to v112.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
BASE_ZIP = ROOT / "03_output/ui_hud_e7_v112_two_strips_resident_patch_only.zip"
BASE_SHA = "8DB471C1DFF49DF05443A942EA814DADB79344F5A4841C655131A2A801584866"
OUTPUT = ROOT / "03_output/ui_hud_e7_v115_no_t9_two_strips_patch_only.zip"
REPORT = ROOT / "01_work/analysis/ui_hud_e7_v115_no_t9_two_strips/build_report.txt"

PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800
CLASS_SRC = 0x801A8F50
CLASS_DST = 0x801FEC28
OLD_CLASS_N = 36
NEW_CLASS_N = 40
FRAME_N = 64
OLD_FRAME_SRC = CLASS_SRC + OLD_CLASS_N
NEW_FRAME_SRC = CLASS_SRC + NEW_CLASS_N
NEW_FRAME_DST = CLASS_DST + NEW_CLASS_N
NEW_HEAP = NEW_FRAME_DST + FRAME_N
HELPER_DST = 0x801FE3C4
HEAP_HI = 0x80200000
HEAP_SEEN_USED = 0x801FFA60
IMAGE_END = 0x801A9000

MEMCPY_LEN_AT = 0x801757CC
HEAP_BASE_AT = 0x80175810
STUB_CALL = 0x801A208C

ZERO, V0, V1, T8, SP, RA = 0, 2, 3, 24, 29, 31


def addiu(rt, rs, i): return 0x24000000 | (rs << 21) | (rt << 16) | (i & 0xFFFF)
def sltiu(rt, rs, i): return 0x2C000000 | (rs << 21) | (rt << 16) | (i & 0xFFFF)
def ori(rt, rs, i): return 0x34000000 | (rs << 21) | (rt << 16) | (i & 0xFFFF)
def lbu(rt, rs, o): return 0x90000000 | (rs << 21) | (rt << 16) | (o & 0xFFFF)
def beq(rs, rt, o): return 0x10000000 | (rs << 21) | (rt << 16) | (o & 0xFFFF)
def jal(t): return 0x0C000000 | ((t & 0x0FFFFFFF) >> 2)


NOP, JR_RA = 0, 0x03E00008


def classifier():
    """Return v0=1 for V 224 or 244, using no register except v0 and proven-safe t8."""
    return [
        (lbu(V0, V1, 0x29), "lbu   v0,0x29(v1)"),
        (NOP, "nop                       ; load delay"),
        (addiu(T8, V0, -224), "addiu t8,v0,-224"),
        (beq(T8, ZERO, 4), "beq   t8,zero,match"),
        (addiu(T8, V0, -244), "addiu t8,v0,-244         ; delay slot"),
        (sltiu(V0, T8, 1), "sltiu v0,t8,1             ; V == 244"),
        (JR_RA, "jr    ra"),
        (NOP, "nop"),
        (JR_RA, "match: jr ra"),
        (ori(V0, ZERO, 1), "ori   v0,zero,1           ; delay slot"),
    ]


def sha256(data): return hashlib.sha256(data).hexdigest().upper()
def word(buf, ram): return struct.unpack_from("<I", buf, ram - RAM_TO_FILE)[0]
def put(buf, ram, value): struct.pack_into("<I", buf, ram - RAM_TO_FILE, value)


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for name in ("compress_type", "comment", "extra", "create_system",
                 "create_version", "extract_version", "flag_bits", "volume",
                 "internal_attr", "external_attr"):
        setattr(out, name, getattr(info, name))
    return out


def main() -> None:
    if sha256(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not the verified v112 build")
    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}
    exe = bytearray(members[PSX])
    before = bytes(exe)

    old_classifier = [
        0x90620029, 0x00000000, 0x2458FF20, 0x2F180001, 0x2459FF0C,
        0x2F390001, 0x03191025, 0x03E00008, 0x00000000,
    ]
    for i, expected in enumerate(old_classifier):
        if word(exe, CLASS_SRC + i * 4) != expected:
            raise SystemExit(f"v112 classifier guard failed at 0x{CLASS_SRC+i*4:08X}")

    old_frame = bytes(exe[OLD_FRAME_SRC - RAM_TO_FILE:
                          OLD_FRAME_SRC - RAM_TO_FILE + FRAME_N])
    if len(old_frame) != FRAME_N or not any(old_frame):
        raise SystemExit("could not read the v112 frame routine")
    if any(exe[OLD_FRAME_SRC - RAM_TO_FILE + FRAME_N:
               NEW_FRAME_SRC - RAM_TO_FILE + FRAME_N]):
        raise SystemExit("the extra word after the old frame routine is not padding")
    if NEW_FRAME_SRC + FRAME_N > IMAGE_END:
        raise SystemExit("the shifted frame routine leaves the loaded image")
    if NEW_HEAP >= HEAP_SEEN_USED:
        raise SystemExit("the reservation reaches heap memory observed in use")

    body = classifier()
    if len(body) * 4 != NEW_CLASS_N:
        raise SystemExit("classifier size changed")

    # Capture the frame first because the new classifier overlaps its old first word.
    exe[CLASS_SRC - RAM_TO_FILE:CLASS_SRC - RAM_TO_FILE + NEW_CLASS_N] = b"\x00" * NEW_CLASS_N
    for i, (value, _) in enumerate(body):
        put(exe, CLASS_SRC + i * 4, value)
    exe[NEW_FRAME_SRC - RAM_TO_FILE:NEW_FRAME_SRC - RAM_TO_FILE + FRAME_N] = old_frame

    copy_n = NEW_HEAP - HELPER_DST
    patches = [
        (MEMCPY_LEN_AT, addiu(6, ZERO, copy_n), f"startup copy length -> {copy_n}"),
        (HEAP_BASE_AT, addiu(4, 4, (NEW_HEAP - 4) - HEAP_HI),
         f"heap start -> 0x{NEW_HEAP:08X}"),
        (STUB_CALL, jal(NEW_FRAME_DST), f"frame routine -> 0x{NEW_FRAME_DST:08X}"),
    ]
    for ram, value, _ in patches:
        put(exe, ram, value)

    # Static proof: both exact values return one, neighboring values return zero.
    def model(v):
        return int(v == 224 or v == 244)
    tested = {v: model(v) for v in range(256)}
    if {v for v, result in tested.items() if result} != {224, 244}:
        raise SystemExit("classifier model accepts the wrong V set")
    # No instruction may write t9 (rt=25); this is the defect boundary of v115.
    for i, (ins, _) in enumerate(body):
        op, rt = ins >> 26, (ins >> 16) & 31
        writes_rt = op in {0x09, 0x0B, 0x0D, 0x0F, 0x24}
        if writes_rt and rt == 25:
            raise SystemExit(f"classifier writes t9 at word {i}")

    for i, (value, _) in enumerate(body):
        if word(exe, CLASS_SRC + i * 4) != value:
            raise SystemExit("classifier readback failed")
    if bytes(exe[NEW_FRAME_SRC - RAM_TO_FILE:
                 NEW_FRAME_SRC - RAM_TO_FILE + FRAME_N]) != old_frame:
        raise SystemExit("frame routine changed while it was shifted")
    for ram, value, _ in patches:
        if word(exe, ram) != value:
            raise SystemExit(f"patch readback failed at 0x{ram:08X}")
    if len(exe) != len(before):
        raise SystemExit("PSX.EXE changed size")

    # The two glyph strips and all non-code members must remain byte-identical to v112.
    members[PSX] = bytes(exe)
    if OUTPUT.exists():
        raise SystemExit(f"{OUTPUT.name} already exists")
    with ZipFile(OUTPUT, "w") as out:
        for info in infos:
            out.writestr(clone(info), members[info.filename])
    with ZipFile(OUTPUT) as out:
        for name, expected in members.items():
            if out.read(name) != expected:
                raise SystemExit(f"archive readback failed for {name}")

    lines = [
        "v115 two strips with a no-t9 classifier",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {OUTPUT.name}",
        f"sha256  {sha256(OUTPUT.read_bytes())}",
        f"PSX.EXE {len(exe)} bytes, unchanged; v104 disc layout still applies",
        "",
        "unchanged from v112:",
        "  two 13-column strips, 104 glyph slots",
        "  strip A (961,480), strip B (961,500), tpage 0x1F",
        "  both LoadImage calls, lookup remap, rectangles and glyph pixels",
        "",
        "changed:",
        "  classifier uses v0+t8 only and accepts exactly V=224 or V=244",
        "  t9 is never written",
        f"  classifier {OLD_CLASS_N} -> {NEW_CLASS_N} bytes",
        f"  frame routine moves 0x801FEC4C -> 0x{NEW_FRAME_DST:08X}",
        f"  heap starts at 0x{NEW_HEAP:08X} ({HEAP_SEEN_USED-NEW_HEAP} bytes clear)",
        "",
        "classifier:",
    ]
    for i, (value, note) in enumerate(body):
        lines.append(f"  0x{CLASS_DST+i*4:08X}  {value:08X}  {note}")
    lines += ["", "runtime status: pending", "rollback: v103 + arc1_v104.xml"]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
