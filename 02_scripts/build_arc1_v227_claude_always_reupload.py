#!/usr/bin/env python3
"""v227 CLAUDE: stop trusting the cache; re-upload every glyph every frame.

Seven attempts went into finding VRAM the game never writes, and every one of
them was disproved by a larger savestate sample.  v226 then hooked LoadImage to
mark the cache stale, and the savestates show the hook running perfectly --
active_mask really is cleared -- yet the glyphs stayed missing.

Disassembling the decoder explains why:

    801FF488  lui   t5, 0x801f
    801FF48C  ori   t5, t5, 0xf2fe     owners
    801FF494  lhu   t7, (t5)           owners[i]
    801FF49C  beq   t7, t4, 0x801ff53c is this source already cached?
    ...
    801FF53C  ori   t0, zero, 1        yes: set the active_mask bit
    801FF558  sw    t8, (t5)           and skip the upload entirely

The cache decides a glyph is present purely from the owners array.  It never
checks whether the pixels survived, so when the game loads a world map over the
rectangle the entry still claims a hit and nothing is re-sent.  active_mask is
only used further down to pick a victim slot, which is why clearing it changed
nothing.

Turning that one branch into a NOP removes the hit path.  Every glyph the frame
needs is decoded and uploaded again, so whatever the game wrote over the
rectangle is repaired on the next frame.  The cache position, U, V, the 28
slots, and every other constant stay exactly as v210 shipped them -- this is the
smallest edit that can possibly address the fault.

The cost is real: the Huffman decode now runs for each dynamic glyph on screen
every frame instead of once.  If that proves too slow, the fix is to restore the
hit path and gate it on a dirty flag, but that needs code space this build does
not have to spend.
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
OUT_STEM = "arc1_v227_CLAUDE_always_reupload_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v227_CLAUDE_always_reupload"

PSX = "PSX.EXE"
old = v171.old


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system",
                 "create_version", "extract_version", "flag_bits", "volume",
                 "internal_attr", "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


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
    owners = layout["owners"][0]
    src = old.file_at(v171.SOURCE_BASE)
    at = src + decoder - v171.RESIDENT_BASE

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    ins = list(md.disasm(bytes(exe[at:at + decoder_size]), decoder))
    if sum(i.size for i in ins) != decoder_size:
        raise SystemExit("decoder did not fully disassemble")

    # locate the owners scan: ori t5,t5,<owners low half> then lhu / beq
    anchor = None
    for k, i in enumerate(ins):
        w = struct.unpack_from("<I", exe, at + (i.address - decoder))[0]
        if (w >> 26) == 0x0D and (w & 0xFFFF) == (owners & 0xFFFF):
            anchor = k
            break
    if anchor is None:
        raise SystemExit("owners pointer not found in the decoder")

    hit = None
    for i in ins[anchor:anchor + 8]:
        w = struct.unpack_from("<I", exe, at + (i.address - decoder))[0]
        if (w >> 26) == 0x04:                      # beq
            rs, rt = (w >> 21) & 31, (w >> 16) & 31
            if rs and rt:                          # a real compare, not beq x,zero
                hit = (i.address, at + (i.address - decoder), w)
                break
    if hit is None:
        raise SystemExit("cache-hit branch not found after the owners pointer")

    addr, file_at, word = hit
    if addr != 0x801FF49C:
        raise SystemExit(f"cache-hit branch moved to 0x{addr:08X}; refusing to patch blind")
    struct.pack_into("<I", exe, file_at, 0)        # nop

    members[PSX] = bytes(exe)
    changed = [n for n in members if members[n] != before[n]]
    if changed != [PSX]:
        raise SystemExit(f"unexpected changed members: {changed}")
    if len(members[PSX]) != len(before[PSX]):
        raise SystemExit("PSX.EXE size changed")
    diffs = [o for o, (a, b) in enumerate(zip(before[PSX], members[PSX])) if a != b]
    # the branch encodes as 27 00 EC 11, so one byte is already zero and only
    # three of the four actually change
    if not diffs or any(o not in range(file_at, file_at + 4) for o in diffs):
        raise SystemExit(f"unexpected changed bytes: {diffs[:12]}")

    check = list(md.disasm(bytes(exe[at:at + decoder_size]), decoder))
    if sum(i.size for i in check) != decoder_size:
        raise SystemExit("decoder no longer disassembles cleanly")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tmp = OUT_DIR / f"{OUT_STEM}_building.zip"
    if tmp.exists():
        raise SystemExit(f"refusing to overwrite: {tmp}")
    with ZipFile(tmp, "w", ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    with ZipFile(tmp) as archive:
        for name, want in members.items():
            if archive.read(name) != want:
                raise SystemExit(f"roundtrip differs: {name}")
    stamp = digest(tmp.read_bytes())
    out = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    if out.exists():
        raise SystemExit(f"refusing to overwrite: {out}")
    tmp.replace(out)

    report = [
        "v227 CLAUDE TEST ONLY - cache hit path disabled; every glyph re-uploaded",
        f"base={BASE.name}", f"output={out.name}", f"sha256={stamp}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        f"patched=0x{addr:08X} beq t7,t4 -> nop   (file 0x{file_at:X}, was 0x{word:08X})",
        "cache_position=x961..981,y480..491 UNCHANGED",
        "cache_slots=28 UNCHANGED   U/V UNCHANGED   no LoadImage hook",
        f"PSX_changed_bytes={len(diffs)}",
        "COMM.IMG=byte-identical PASS", "all_DAT_members=byte-identical PASS",
        "decoder_disassembly=PASS",
        "runtime=PENDING user cold boot",
        "expected=glyphs survive a world map; watch for slowdown in long text",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
