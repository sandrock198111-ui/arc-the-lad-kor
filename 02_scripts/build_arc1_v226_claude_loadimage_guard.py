#!/usr/bin/env python3
"""v226 CLAUDE: stop hunting for free VRAM; re-upload the cache after the game writes.

Six separate times this project picked a VRAM or RAM address that looked unused
across a few hundred savestates and later found the game using it -- strip C at
y380, the 140 blank font cells, texture page 5,0, row 39 (yesterday), 0x801A7051
(103B free in 120 states, 103B used in 486), and the string-pool gaps.  Absence
from snapshots never proved ownership, and the sample can only ever grow.

So this stops moving the cache.  It stays at x961,y480 -- where U and V are
already correct, which is why v222..v225 could not render.  Instead the game is
allowed to overwrite it, and the cache is marked stale so the next frame refills
whatever it needs.

The hook is four instructions at the head of LoadImage, the one funnel every
VRAM upload passes through:

    80177E4C  j     0x801FF328          (was addiu sp, sp, -0x30)
    80177E50  addiu sp, sp, -0x30       delay slot, the displaced instruction

    801FF328  lui   t0, 0x8020
    801FF32C  sw    zero, -0xCC8(t0)    active_mask = 0
    801FF330  j     0x80177E54
    801FF334  sw    ra, 0x2c(sp)        delay slot, the second displaced one

No overlap test: clearing the mask unconditionally costs one refill per upload,
and LoadImage runs on scene loads, not per frame.

Sixteen bytes had to come from somewhere that no sample can invalidate, so they
come out of our own resident block, which the game does not know exists.  The
cache drops from 28 slots to 20 -- 7 cells to 5 -- and owners shrinks from 56 to
40 bytes.  The array does not move; the code simply stops using the last eight
entries, leaving 0x801FF328..0x801FF337 free, and active_mask at 0x801FF338 is
untouched.

Every glyph still renders.  What changes is how many dynamic glyphs can be on
screen at once, 28 -> 20, after which the oldest is recycled.  v160 shipped a
working 20-slot cache, so this is a return to a proven size, not a guess.
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
OUT_STEM = "arc1_v226_CLAUDE_loadimage_guard_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v226_CLAUDE_loadimage_guard"

PSX = "PSX.EXE"
OLD_N, NEW_N = 28, 20                  # cache slots
OLD_C, NEW_C = 7, 5                    # cells (slots / 4 planes)
LOADIMAGE = 0x80177E4C
HOOK = 0x801FF328

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


def jump(target: int) -> int:
    return (0x02 << 26) | ((target >> 2) & 0x03FFFFFF)


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v210 base archive SHA256 differs")
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        before = {i.filename: archive.read(i.filename) for i in infos}
    members = dict(before)
    exe = bytearray(members[PSX])

    layout, _blobs, _code = v190.resident_layout()
    owners_at, owners_n = layout["owners"]
    mask_at, _mask_n = layout["active_mask"]
    if (owners_at, owners_n, mask_at) != (0x801FF2FE, OLD_N * 2, 0x801FF338):
        raise SystemExit(f"resident layout differs: {hex(owners_at)} {owners_n} {hex(mask_at)}")
    if HOOK < owners_at + NEW_N * 2 or HOOK + 16 > mask_at:
        raise SystemExit("hook does not fit between the shortened owners and active_mask")

    src = old.file_at(v171.SOURCE_BASE)
    I = old.i_type

    # 1. the six constants that size the cache
    consts = (
        ("slot bound A", I(0x0B, old.T6, old.T7, OLD_N), I(0x0B, old.T6, old.T7, NEW_N)),
        ("slot count",   I(0x0D, old.ZERO, old.T7, OLD_N), I(0x0D, old.ZERO, old.T7, NEW_N)),
        ("slot bound B", I(0x0B, old.T6, old.T1, OLD_N), I(0x0B, old.T6, old.T1, NEW_N)),
        ("slot bound C", I(0x0B, old.T7, old.T1, OLD_N), I(0x0B, old.T7, old.T1, NEW_N)),
        ("cell bound",   I(0x0B, old.S5, old.T0, OLD_C), I(0x0B, old.S5, old.T0, NEW_C)),
        ("U range",      I(0x0B, old.T6, old.T5, OLD_C * old.CELL),
                         I(0x0B, old.T6, old.T5, NEW_C * old.CELL)),
    )
    edits = []
    for label, want, fresh in consts:
        hits = [o for o in range(src, src + v171.COPY_N, 4)
                if struct.unpack_from("<I", exe, o)[0] == want]
        if len(hits) != 1:
            raise SystemExit(f"{label}: found {len(hits)} sites, need exactly 1")
        struct.pack_into("<I", exe, hits[0], fresh)
        edits.append((label, hits[0], want, fresh))

    # 2. the hook body, written into the resident source so boot copies it up
    body = (
        (0x0F << 26) | (old.T0 << 16) | 0x8020,          # lui t0, 0x8020
        (0x2B << 26) | (old.T0 << 21) | (old.ZERO << 16) | ((mask_at - 0x80200000) & 0xFFFF),
        jump(LOADIMAGE + 8),                              # j LoadImage+8
        (0x2B << 26) | (29 << 21) | (31 << 16) | 0x002C,  # sw ra, 0x2c(sp)
    )
    hook_at = src + HOOK - v171.RESIDENT_BASE
    # 0xFF is an unused owner entry; the last two bytes are alignment padding
    # before active_mask, which is why this is not sixteen 0xFF bytes.
    area = bytes(exe[hook_at:hook_at + 16])
    if any(b not in (0x00, 0xFF) for b in area):
        raise SystemExit(f"hook area holds live data: {area.hex()}")
    if area[:owners_at + owners_n - HOOK] != b"\xFF" * (owners_at + owners_n - HOOK):
        raise SystemExit("owner entries under the hook are not free")
    for k, word in enumerate(body):
        struct.pack_into("<I", exe, hook_at + k * 4, word)
        edits.append((f"hook +{k * 4}", hook_at + k * 4, 0xFFFFFFFF, word))

    # 3. redirect LoadImage
    li_at = old.file_at(LOADIMAGE)
    first = struct.unpack_from("<I", exe, li_at)[0]
    second = struct.unpack_from("<I", exe, li_at + 4)[0]
    if first != I(0x09, 29, 29, -0x30) or second != body[3]:
        raise SystemExit(f"LoadImage head differs: {first:08X} {second:08X}")
    struct.pack_into("<I", exe, li_at, jump(HOOK))
    struct.pack_into("<I", exe, li_at + 4, first)
    edits.append(("LoadImage j", li_at, first, jump(HOOK)))
    edits.append(("LoadImage slot", li_at + 4, second, first))

    members[PSX] = bytes(exe)
    changed = [n for n in members if members[n] != before[n]]
    if changed != [PSX]:
        raise SystemExit(f"unexpected changed members: {changed}")
    if len(members[PSX]) != len(before[PSX]):
        raise SystemExit("PSX.EXE size changed")

    diffs = [o for o, (a, b) in enumerate(zip(before[PSX], members[PSX])) if a != b]
    allowed = set()
    for _l, at, _w, _f in edits:
        allowed.update(range(at, at + 4))
    if not diffs or any(o not in allowed for o in diffs):
        raise SystemExit(f"changed outside guarded fields: {diffs[:20]}")

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    shown = []
    for k in range(4):
        for i in md.disasm(bytes(exe[hook_at + k * 4:hook_at + k * 4 + 4]), HOOK + k * 4):
            shown.append(f"    {i.address:08X}  {i.mnemonic:8}{i.op_str}")
    if len(shown) != 4:
        raise SystemExit("hook did not disassemble to four instructions")

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
        "v226 CLAUDE TEST ONLY - LoadImage marks the cache stale; no VRAM move",
        f"base={BASE.name}", f"output={out.name}", f"sha256={stamp}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        "cache_position=x961..981,y480..491 UNCHANGED (U and V stay correct)",
        f"cache_slots={OLD_N}->{NEW_N}", f"cache_cells={OLD_C}->{NEW_C}",
        f"owners={OLD_N * 2}B->{NEW_N * 2}B at 0x{owners_at:08X} (array not moved)",
        f"hook=0x{HOOK:08X} 16B, inside our resident block",
        f"active_mask=0x{mask_at:08X} untouched",
        "hook_condition=none; every LoadImage clears the mask",
        f"PSX_changed_bytes={len(diffs)}",
        "COMM.IMG=byte-identical PASS", "all_DAT_members=byte-identical PASS",
        "runtime=PENDING user cold boot",
        "expected=world map clean AND glyphs return after the scene loads",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))
    print("\n  hook")
    print("\n".join(shown))
    print("\n  edits")
    for label, at, want, fresh in edits:
        print(f"    {label:16} file 0x{at:X}   {want:08X} -> {fresh:08X}")


if __name__ == "__main__":
    main()
