"""Build v237: shrink the cache to 12 slots and recover it after the game wipes it.

v235 finished the relocation -- world map place names render, no cross
contamination.  The one remaining fault is that the flight scene zero-fills part
of the rectangle and the cache never finds out: the hit test at 0x801FF49C reads
only the owners array and never checks whether the pixels survived.  So every
line after a world map keeps drawing from cells the game has already erased.

v226 proved a LoadImage hook runs and that clearing active_mask alone does not
trigger re-upload -- owners has to be invalidated.  v227/v234 proved that simply
disabling the hit test destroys the cache instead, because each glyph then
claims a fresh slot (4..10 duplicates out of 28 measured).

So the hook must wipe owners, and that needs code space.  There is none: the
resident block is 5356/5356 and owners is followed by 2 free bytes.  Space only
appears if the cache shrinks, and shrinking costs coverage:

    slots   lines fitting        lines displaced
      28    4721/4721 (100%)            0
      20    4719/4721                   2      18B free -- too small
      16    4673/4721 ( 99%)           48      26B free -- too small
      12    4465/4721 ( 94.6%)        256      34B free -- fits

Twelve slots leave 0x801FF316..0x801FF337, and the invalidator fits in 32 of
those bytes because the loop's end-address register doubles as the value it
stores: t3 ends at 0x801FF316, whose low halfword 0xF316 is far outside the
source id range, so it reads as "no owner".  The decoder never compares owners
against 0xFFFF -- checked instruction by instruction -- so any out-of-range
value works.

    801FF318  lui   t2, 0x801F
    801FF31C  ori   t2, t2, 0xF2FE      owners
    801FF320  addiu t3, t2, 24          end, and the invalid marker
    801FF324  addiu t2, t2, 2
    801FF328  bne   t2, t3, 0x801FF324
    801FF32C  sh    t3, -2(t2)          delay slot
    801FF330  j     0x80177E54
    801FF334  sw    ra, 0x2c(sp)        delay slot, the displaced instruction

Trading 5.4% of lines losing a glyph against every line after a world map being
broken is the point of this build.
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

BASE = ROOT / "03_output/arc1_v235_cache_row36_TEST_ONLY_1654F31B.zip"
BASE_SHA256 = "EBFD500237DC1C2827915CF240847FBEC09F50C0998FEF983572C9DF41D4D09E"
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v237_recovery_hook_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v237_recovery_hook"

PSX = "PSX.EXE"
OLD_N, NEW_N = 28, 12
OLD_C, NEW_C = 7, 3
LOADIMAGE = 0x80177E4C
HOOK = 0x801FF318
old = v171.old

T2, T3, SP_, RA = 10, 11, 29, 31


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
        raise SystemExit("base archive SHA256 differs")
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        before = {i.filename: archive.read(i.filename) for i in infos}
    members = dict(before)
    exe = bytearray(members[PSX])

    layout, _blobs, _code = v190.resident_layout()
    owners_at, owners_n = layout["owners"]
    mask_at = layout["active_mask"][0]
    if (owners_at, owners_n, mask_at) != (0x801FF2FE, OLD_N * 2, 0x801FF338):
        raise SystemExit(f"layout differs: {hex(owners_at)} {owners_n} {hex(mask_at)}")
    end_addr = owners_at + NEW_N * 2
    if HOOK < end_addr or HOOK + 32 > mask_at:
        raise SystemExit("hook does not fit between shortened owners and active_mask")
    if (end_addr & 0xFFFF) < 0x2000:
        raise SystemExit("end marker would look like a valid source id")

    src = old.file_at(v171.SOURCE_BASE)
    I = old.i_type
    edits = []

    # 1. the six constants that size the cache
    for label, want, fresh in (
        ("slot bound A", I(0x0B, old.T6, old.T7, OLD_N), I(0x0B, old.T6, old.T7, NEW_N)),
        ("slot count",   I(0x0D, old.ZERO, old.T7, OLD_N), I(0x0D, old.ZERO, old.T7, NEW_N)),
        ("slot bound B", I(0x0B, old.T6, old.T1, OLD_N), I(0x0B, old.T6, old.T1, NEW_N)),
        ("slot bound C", I(0x0B, old.T7, old.T1, OLD_N), I(0x0B, old.T7, old.T1, NEW_N)),
        ("cell bound",   I(0x0B, old.S5, old.T0, OLD_C), I(0x0B, old.S5, old.T0, NEW_C)),
        ("U range",      I(0x0B, old.T6, old.T5, OLD_C * old.CELL),
                         I(0x0B, old.T6, old.T5, NEW_C * old.CELL)),
    ):
        hits = [o for o in range(src, src + v171.COPY_N, 4)
                if struct.unpack_from("<I", exe, o)[0] == want]
        if len(hits) != 1:
            raise SystemExit(f"{label}: found {len(hits)} sites, need 1")
        struct.pack_into("<I", exe, hits[0], fresh)
        edits.append((label, hits[0], want, fresh))

    # 2. the invalidator, written into the freed owner entries
    body = (
        (0x0F << 26) | (T2 << 16) | (owners_at >> 16),            # lui   t2, 0x801F
        (0x0D << 26) | (T2 << 21) | (T2 << 16) | (owners_at & 0xFFFF),
        I(0x09, T2, T3, NEW_N * 2),                               # addiu t3, t2, 24
        I(0x09, T2, T2, 2),                                       # addiu t2, t2, 2
        (0x05 << 26) | (T2 << 21) | (T3 << 16) | 0xFFFE,          # bne t2,t3,-2
        (0x29 << 26) | (T2 << 21) | (T3 << 16) | 0xFFFE,          # sh t3, -2(t2)
        jump(LOADIMAGE + 8),
        (0x2B << 26) | (SP_ << 21) | (RA << 16) | 0x002C,         # sw ra, 0x2c(sp)
    )
    hook_at = src + HOOK - v171.RESIDENT_BASE
    area = bytes(exe[hook_at:hook_at + 32])
    if any(b not in (0x00, 0xFF) for b in area):
        raise SystemExit(f"hook area holds live data: {area.hex()}")
    for k, word in enumerate(body):
        struct.pack_into("<I", exe, hook_at + k * 4, word)
        edits.append((f"hook +{k * 4:02}", hook_at + k * 4,
                      struct.unpack_from("<I", bytes(area), k * 4)[0], word))

    # 3. redirect LoadImage
    li_at = old.file_at(LOADIMAGE)
    first = struct.unpack_from("<I", exe, li_at)[0]
    second = struct.unpack_from("<I", exe, li_at + 4)[0]
    if first != I(0x09, SP_, SP_, -0x30) or second != body[7]:
        raise SystemExit(f"LoadImage head differs: {first:08X} {second:08X}")
    struct.pack_into("<I", exe, li_at, jump(HOOK))
    struct.pack_into("<I", exe, li_at + 4, first)
    edits.append(("LoadImage j", li_at, first, jump(HOOK)))
    edits.append(("LoadImage slot", li_at + 4, second, first))

    members[PSX] = bytes(exe)
    if [n for n in members if members[n] != before[n]] != [PSX]:
        raise SystemExit("unexpected changed members")
    if len(members[PSX]) != len(before[PSX]):
        raise SystemExit("PSX.EXE size changed")
    diffs = [o for o, (a, b) in enumerate(zip(before[PSX], members[PSX])) if a != b]
    allowed = set()
    for _l, at, _w, _f in edits:
        allowed.update(range(at, at + 4))
    if not diffs or any(o not in allowed for o in diffs):
        raise SystemExit(f"changed outside guarded fields: {diffs[:16]}")

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    shown = [f"    {i.address:08X}  {i.mnemonic:8}{i.op_str}"
             for i in md.disasm(bytes(exe[hook_at:hook_at + 32]), HOOK)]
    if len(shown) != 8:
        raise SystemExit(f"hook disassembled to {len(shown)} instructions, need 8")

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
        "v237 CLAUDE TEST ONLY - 12-slot cache with a LoadImage recovery hook",
        f"base={BASE.name}", f"output={out.name}", f"sha256={stamp}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        f"cache_slots={OLD_N}->{NEW_N}  cells={OLD_C}->{NEW_C}",
        f"owners={OLD_N * 2}B->{NEW_N * 2}B at 0x{owners_at:08X} (array not moved)",
        f"hook=0x{HOOK:08X} 32B, inside the resident block",
        f"invalid_marker=0x{end_addr & 0xFFFF:04X} (end address low half, outside source ids)",
        "hit_test=0x801FF49C untouched (v227/v234 failed by disabling it)",
        "cache_rect=(999,432) unchanged from v235; 12 slots use x999..1007",
        "line_coverage=4465/4721 (94.6%) fit 12 slots; 256 lines lose a glyph",
        f"PSX_changed_bytes={len(diffs)}",
        "COMM.IMG=byte-identical PASS", "all_DAT_members=byte-identical PASS",
        "runtime=PENDING user cold boot",
        "expected=boots; dialogue normal after a world map for the first time",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))
    print("\n  hook")
    print("\n".join(shown))


if __name__ == "__main__":
    main()
