#!/usr/bin/env python3
"""v228 CLAUDE: move U and V together, in the one block that runs only for cache glyphs.

The stock packet builder writes the two bytes side by side and then fixes up the
cache case:

    8016B598  sb    v0, 0x28(a1)     U = col * 12
    8016B5A8  sb    v0, 0x29(a1)     V = row * 12, low byte -> 224
    8016B5B4  bne   v1, 6, skip      is this a cache glyph
    8016B5BC  lbu   v0, 0x28(a1)
    8016B5C0  nop
    8016B5C4  addiu v0, v0, 4        cache-only U bias
    8016B5C8  sb    v0, 0x28(a1)

v222 moved V by changing the cache index base, which does shift row and therefore
V -- the savestates confirmed V=164 -- but the same change breaks the `== 6`
test, so the U block above stopped running and the packets kept reading x960.
v224 and v225 chased that from the wrong end.  v227 then proved re-uploading
every frame cannot win: the game and the cache simply take turns.

0x28 and 0x29 are adjacent, so the four instructions can move both bytes at once
without growing:

    lhu   v0, 0x28(a1)      U in the low byte, V in the high
    nop
    addiu v0, v0, -15204    +156 to U, -60 to V, as one halfword
    sh    v0, 0x28(a1)

U becomes col*12 + 156 (156..228, x999..1019) and V becomes 164 (y420).  Both
land inside a byte, so there is no carry from U into V.  The index base is left
alone, so the `== 6` test keeps working and only cache glyphs are touched.

Destination measured over the union of 467 savestates:

    x961..981,y480..491    252 of 252 halfwords used by the game
    x999..1019,y420..431     0 of 252
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
OUT_STEM = "arc1_v228_CLAUDE_uv_pair_move_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v228_CLAUDE_uv_pair_move"

PSX = "PSX.EXE"
OLD_ROW, NEW_ROW = 40, 40     # atlas row and index base untouched
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
    edits = []
    # addiu t6,t6,-4 also encodes a packet-code test at 0x801FF7E0.  The U one is
    # the load of packet byte 12 followed by the 7-cell range check sltiu t5,t6,84.
    U_FOLLOW = I(0x0B, v171.T6, v171.T5, v171.CACHE_CELLS * old.CELL)
    for label, word_old, word_new, start, size, follow in (
        ("classifier V", I(0x09, v171.V0, v171.V0, -OLD_V),
                         I(0x09, v171.V0, v171.V0, -NEW_V),
         old.file_at(v171.LOW_CLASSIFIER), 36, None),
        ("frame V",  I(0x09, v171.T5, v171.T5, -OLD_V),
                     I(0x09, v171.T5, v171.T5, -NEW_V), span_at, span_n, None),
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

    # the cache-only fix-up block: widen it to a halfword so U and V move together
    A1, V0 = 5, 2
    # v0 holds the raw U (col*12) here, so the U term is the new bias itself,
    # not a difference -- the instruction being replaced was the +4 bias.
    DELTA = (NEW_U + ((NEW_V - OLD_V) << 8)) & 0xFFFF
    for site, want, fresh in (
        (0x8016B5BC, (0x24 << 26) | (A1 << 21) | (V0 << 16) | 0x28,      # lbu -> lhu
                     (0x25 << 26) | (A1 << 21) | (V0 << 16) | 0x28),
        (0x8016B5C4, I(0x09, V0, V0, OLD_U), I(0x09, V0, V0, DELTA - 0x10000)),
        (0x8016B5C8, (0x28 << 26) | (A1 << 21) | (V0 << 16) | 0x28,      # sb -> sh
                     (0x29 << 26) | (A1 << 21) | (V0 << 16) | 0x28),
    ):
        off = old.file_at(site)
        actual = struct.unpack_from("<I", exe, off)[0]
        if actual != want:
            raise SystemExit(f"0x{site:08X}: 0x{actual:08X}, expected 0x{want:08X}")
        struct.pack_into("<I", exe, off, fresh & 0xFFFFFFFF)
        edits.append((f"UV pair 0x{site:X}", off, want, fresh & 0xFFFFFFFF))
    if not (0 <= NEW_U + (v171.CACHE_CELLS - 1) * old.CELL <= 255):
        raise SystemExit("U would carry into V")

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
        "v228 CLAUDE TEST ONLY - U and V moved as one halfword in the cache-only block",
        f"base={BASE.name}", f"output={out.name}", f"sha256={stamp}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        "occupancy_sample=467 savestates folded by union",
        f"old_rect=x{OLD_X}..{OLD_X + wide},y{OLD_Y}..{OLD_Y + old.CELL - 1} used=252/252",
        f"new_rect=x{NEW_X}..{NEW_X + wide},y{NEW_Y}..{NEW_Y + old.CELL - 1} used=0/252",
        "atlas_row=40 unchanged", "cache_index_base=3360 unchanged", f"cache_y={OLD_Y}->{NEW_Y}",
        f"cache_v={OLD_V}->{NEW_V}", f"cache_x={OLD_X}->{NEW_X}", f"cache_u={OLD_U}->{NEW_U}",
        "cache_slots=28 unchanged", "tpage=page 15,1 unchanged",
        "no_AB_selector=collision removed by placement, not by per-frame choice",
        f"PSX_changed_bytes={len(diffs)}", "COMM.IMG=byte-identical PASS",
        "all_DAT_members=byte-identical PASS", "capstone_disassembly=PASS",
        "runtime=PENDING user cold boot",
        "expected=world map clean AND cache glyphs render at the new rectangle",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))
    for label, at, want, fresh in edits:
        print(f"   {label:18} file 0x{at:X}  {want:08X} -> {fresh:08X}")
    print(f"   upload_rect        file 0x{rect_at:X}  x{OLD_X},y{OLD_Y} -> x{NEW_X},y{NEW_Y}")


if __name__ == "__main__":
    main()
