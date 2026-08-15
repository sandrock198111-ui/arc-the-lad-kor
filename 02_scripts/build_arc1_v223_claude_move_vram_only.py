#!/usr/bin/env python3
"""v223 CLAUDE: move only the VRAM rectangle, leave the atlas row alone.

v222 moved the cache off the rectangle the game overwrites, and it worked -- the
tester reports the scenery bleed is gone for the first time.  What is left is
blank cells where cached glyphs should be.

v222 changed two things that have nothing to do with where the cache lives in
VRAM: the virtual atlas row (40 -> 35) and the cache index base (40*84 ->
35*84).  Those address the glyph atlas, not the framebuffer.  v211 moved them
together with the coordinates because it kept y = row * 12, but that identity is
a convention -- the upload y, U and V are each written out explicitly.

So this keeps the atlas exactly as v210 had it and moves only the five VRAM
fields:

    x 961 -> 999     U 4 -> 156
    y 480 -> 420     V 224 -> 164     upload rectangle

Measured over the union of 467 savestates:

    x961..981,y480..491    252 of 252 halfwords used by the game
    x999..1019,y420..431     0 of 252

If the blanks come from the atlas row, they go away here.  If they persist, the
cause is elsewhere and the row was never involved.
"""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32  # noqa: E402
import build_arc1_v171_ui_asset_recovery as v171  # noqa: E402
import build_arc1_v190_dynamic_owner_repair as v190  # noqa: E402

BASE = ROOT / "03_output/arc1_v210_sd031_slots_controls.zip"
BASE_SHA256 = "7FB963135C753CBF509F9E722BF826856B04D456D29743A0B1D8CB5A9B34CAF9"
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v223_CLAUDE_move_vram_only_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v223_CLAUDE_move_vram_only"

PSX = "PSX.EXE"
OLD_ROW, NEW_ROW = 40, 40      # atlas row unchanged
OLD_Y, NEW_Y = 480, 420
OLD_V, NEW_V = 224, 164
OLD_X, NEW_X = 961, 999
OLD_U, NEW_U = 4, 156

old = v171.old


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    result = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system",
                 "create_version", "extract_version", "flag_bits", "volume",
                 "internal_attr", "external_attr"):
        setattr(result, attr, getattr(info, attr))
    return result


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v210 base archive SHA256 differs")
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        before = {i.filename: archive.read(i.filename) for i in infos}
    members = dict(before)
    exe = bytearray(members[PSX])

    layout, _blobs, code_base = v190.resident_layout()
    decoder = code_base
    decoder_size = len(v190.build_decoder(decoder, layout))
    huffman = (decoder + decoder_size + 3) & ~3
    huffman_size = len(v190.build_huffman(huffman, layout))
    frame = (huffman + huffman_size + 3) & ~3
    frame_size = len(v190.build_frame(frame, huffman, layout))
    if (decoder, decoder_size, huffman, huffman_size, frame, frame_size) != (
        0x801FF348, 568, 0x801FF580, 232, 0x801FF668, 584):
        raise SystemExit("resident layout differs from the frozen v190 layout")

    source_at = old.file_at(v171.SOURCE_BASE)
    span_at, span_n = source_at, v171.COPY_N          # the whole resident image
    rect_at = source_at + layout["upload_rect"][0] - v171.RESIDENT_BASE
    low_row_at = old.file_at(v171.LOW_HELPER)

    def unique(word: int, label: str, start: int, size: int, follow: int | None = None) -> int:
        hits = [o for o in range(start, start + size, 4)
                if struct.unpack_from("<I", exe, o)[0] == word
                and (follow is None or struct.unpack_from("<I", exe, o + 4)[0] == follow)]
        if len(hits) != 1:
            raise SystemExit(f"{label}: guarded word found {len(hits)} times, need 1")
        return hits[0]

    I = old.i_type
    edits = []   # the atlas row and index base stay exactly as v210 wrote them
    # addiu t6,t6,-4 also encodes a packet-code test at 0x801FF7E0.  The U one is
    # the load of packet byte 12 followed by the 7-cell range check sltiu t5,t6,84.
    U_FOLLOW = I(0x0B, v171.T6, v171.T5, v171.CACHE_CELLS * old.CELL)
    for label, word_old, word_new, start, size, follow in (
        ("classifier V", I(0x09, v171.V0, v171.V0, -OLD_V),
                         I(0x09, v171.V0, v171.V0, -NEW_V),
         old.file_at(v171.LOW_CLASSIFIER), 36, None),
        ("frame V",  I(0x09, v171.T5, v171.T5, -OLD_V),
                     I(0x09, v171.T5, v171.T5, -NEW_V), span_at, span_n, None),
        # packet U lives in the low helper, not in the resident image
        ("packet U", I(0x09, v171.A3, v171.A3, OLD_U),
                     I(0x09, v171.A3, v171.A3, NEW_U),
         low_row_at, len(v171.build_low_helper(v171.LOW_HELPER)), None),
        # -CACHE_U appears twice in the resident image; only the frame one is ours
        ("frame U",  I(0x09, v171.T6, v171.T6, -OLD_U),
                     I(0x09, v171.T6, v171.T6, -NEW_U),
         source_at + frame - v171.RESIDENT_BASE, frame_size, U_FOLLOW),
        ("cache X",  I(0x09, v171.T0, v171.T0, OLD_X),
                     I(0x09, v171.T0, v171.T0, NEW_X), span_at, span_n, None),
    ):
        edits.append((label, unique(word_old, label, start, size, follow), word_old, word_new))

    for label, at, want, fresh in edits:
        actual = struct.unpack_from("<I", exe, at)[0]
        if actual != want:
            raise SystemExit(f"{label}: 0x{actual:08X}, expected 0x{want:08X}")
        struct.pack_into("<I", exe, at, fresh)

    rect_before = struct.unpack_from("<4H", exe, rect_at)
    if rect_before != (OLD_X, OLD_Y, 3, old.CELL):
        raise SystemExit(f"upload rectangle differs: {rect_before}")
    struct.pack_into("<2H", exe, rect_at, NEW_X, NEW_Y)
    if struct.unpack_from("<4H", exe, rect_at) != (NEW_X, NEW_Y, 3, old.CELL):
        raise SystemExit("upload rectangle readback differs")

    if NEW_U + v171.CACHE_CELLS * old.CELL > 256 or NEW_V + old.CELL > 256:
        raise SystemExit("UV leaves the texture page")
    if NEW_X // 64 != OLD_X // 64 or (NEW_X + v171.CACHE_CELLS * 3 - 1) // 64 != OLD_X // 64:
        raise SystemExit("cache leaves texture page 15")

    members[PSX] = bytes(exe)
    changed = [n for n in members if members[n] != before[n]]
    if changed != [PSX]:
        raise SystemExit(f"unexpected changed members: {changed}")
    if any(len(members[n]) != len(before[n]) for n in members):
        raise SystemExit("archive member length changed")

    diffs = [o for o, (a, b) in enumerate(zip(before[PSX], members[PSX])) if a != b]
    allowed = {rect_at + k for k in range(4)}
    for _label, at, _want, _fresh in edits:
        allowed.update(range(at, at + 4))
    if not diffs or any(o not in allowed for o in diffs):
        raise SystemExit(f"PSX.EXE changed outside guarded fields: {diffs[:20]}")

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    for label, at, size, addr in (
        ("low_helper", low_row_at, 36, v171.LOW_HELPER),
        ("decoder", source_at + decoder - v171.RESIDENT_BASE, decoder_size, decoder),
        ("frame", source_at + frame - v171.RESIDENT_BASE, frame_size, frame)):
        got = list(md.disasm(bytes(exe[at:at + size]), addr))
        if sum(i.size for i in got) != size:
            raise SystemExit(f"Capstone did not consume all of {label}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tmp = OUT_DIR / f"{OUT_STEM}_building.zip"
    if tmp.exists():
        raise SystemExit(f"refusing to overwrite: {tmp}")
    with ZipFile(tmp, "w", ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    with ZipFile(tmp) as archive:
        if archive.namelist() != [i.filename for i in infos]:
            raise SystemExit("archive member order changed")
        for name, want in members.items():
            if archive.read(name) != want:
                raise SystemExit(f"archive roundtrip differs: {name}")
    stamp = digest(tmp.read_bytes())
    out = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    if out.exists():
        raise SystemExit(f"refusing to overwrite: {out}")
    tmp.replace(out)

    wide = v171.CACHE_CELLS * 3 - 1
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    report = [
        "v223 CLAUDE TEST ONLY - VRAM rectangle moved, glyph atlas untouched",
        f"base={BASE.name}", f"output={out.name}", f"sha256={stamp}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        "occupancy_sample=467 savestates folded by union",
        f"old_rect=x{OLD_X}..{OLD_X + wide},y{OLD_Y}..{OLD_Y + old.CELL - 1} used=252/252",
        f"new_rect=x{NEW_X}..{NEW_X + wide},y{NEW_Y}..{NEW_Y + old.CELL - 1} used=0/252",
        "cache_row=40 unchanged", "cache_index_base=3360 unchanged", f"cache_y={OLD_Y}->{NEW_Y}",
        f"cache_v={OLD_V}->{NEW_V}", f"cache_x={OLD_X}->{NEW_X}", f"cache_u={OLD_U}->{NEW_U}",
        "cache_slots=28 unchanged", "tpage=page 15,1 unchanged",
        "no_AB_selector=collision removed by placement, not by per-frame choice",
        f"PSX_changed_bytes={len(diffs)}", "COMM.IMG=byte-identical PASS",
        "all_DAT_members=byte-identical PASS", "capstone_disassembly=PASS",
        "runtime=PENDING user cold boot",
        "expected=no scenery bleed (as v222) AND cached glyphs actually render",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))
    for label, at, want, fresh in edits:
        print(f"   {label:18} file 0x{at:X}  {want:08X} -> {fresh:08X}")
    print(f"   upload_rect        file 0x{rect_at:X}  x{OLD_X},y{OLD_Y} -> x{NEW_X},y{NEW_Y}")


if __name__ == "__main__":
    main()
