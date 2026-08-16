"""Build v238: switch the text renderer from a 12px glyph cell to 16px.

This is step one of the johab transition and deliberately leaves the font alone.
COMM.IMG still holds 12x12 completed-syllable glyphs, so on screen the letters
will look wrong -- what this build verifies is whether the *layout* survives a
larger cell: line spacing, cursor placement, dialogue-box overflow, choice
alignment.  If that breaks there is no point drawing johab pieces at all.

Finding the real edit sites took the whole investigation.  Scanning
0x8016B000..0x8016C400 for the constant 12 turns up 25 places, but most of them
are not the glyph size:

    x12 via sll1+addu+sll2   7 sites, only 2 are U/V; the rest are struct
                             address math (one feeds `addiu a1,a1,0x2c`)
    packet width/height     11 sites, all read their value from a struct
                             (`lhu v0,6(a2)` etc), not from a code constant
    0x8016B198 loop          s0 runs 44,56 with limit 68 -- it walks struct
                             entries 12 bytes apart, nothing to do with glyphs
    literal 12               5 sites, and these are the real ones

Touching the address-math sites would corrupt unrelated structures, which is
why they are listed here explicitly as must-not-touch.

Seven edits:

    0x8016B58C  U = col * 12  ->  col << 4      (sll1+addu+sll2 -> sll4+nop+nop)
    0x8016B59C  V = row * 12  ->  row << 4
    0x8016B160  ori 12 -> 16   object width/height fields (0xd, 0xe)
    0x8016B6E0  ori 12 -> 16   packet w/h fields (0x2a, 0x2b)
    0x8016B348  ori 12 -> 16   argument to 0x8016B4B0
    0x8016B394  ori 12 -> 16   argument pair to 0x8016B4B0
    0x8016B398  ori 12 -> 16

The x12 sequences shrink from three instructions to one, so the two freed slots
become NOPs -- the routine keeps its exact length and every branch target holds.
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

BASE = ROOT / "03_output/arc1_v235_cache_row36_TEST_ONLY_1654F31B.zip"
BASE_SHA256 = "EBFD500237DC1C2827915CF240847FBEC09F50C0998FEF983572C9DF41D4D09E"
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v238_glyph_16px_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v238_glyph_16px"

PSX = "PSX.EXE"
R2F = 0x8011A800
OLD, NEW = 12, 16
NOP = 0

# (address, register the x12 sequence targets, source register)
SHIFT_SITES = (
    (0x8016B58C, "U = col * 12"),
    (0x8016B59C, "V = row * 12"),
)
LITERAL_SITES = (
    (0x8016B160, "object width/height"),
    (0x8016B6E0, "packet w/h"),
    (0x8016B348, "arg to 0x8016B4B0"),
    (0x8016B394, "arg pair a0"),
    (0x8016B398, "arg pair a1"),
)


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
        raise SystemExit("base archive SHA256 differs")
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        before = {i.filename: archive.read(i.filename) for i in infos}
    members = dict(before)
    exe = bytearray(members[PSX])
    edits = []

    def word(addr: int) -> int:
        return struct.unpack_from("<I", exe, addr - R2F)[0]

    def put(addr: int, value: int, label: str, was: int) -> None:
        struct.pack_into("<I", exe, addr - R2F, value)
        edits.append((label, addr, was, value))

    # 1. x12 -> shift by 4.  sll rd,rt,1 ; addu rd,rd,rt ; sll rd,rd,2
    for addr, label in SHIFT_SITES:
        a, b, c = word(addr), word(addr + 4), word(addr + 8)
        if (a >> 26) or (a & 0x3F) or ((a >> 6) & 0x1F) != 1:
            raise SystemExit(f"{label}: 0x{addr:08X} is not `sll rd,rt,1` ({a:08X})")
        if (b >> 26) or (b & 0x3F) != 0x21:
            raise SystemExit(f"{label}: 0x{addr + 4:08X} is not `addu` ({b:08X})")
        if (c >> 26) or (c & 0x3F) or ((c >> 6) & 0x1F) != 2:
            raise SystemExit(f"{label}: 0x{addr + 8:08X} is not `sll rd,rd,2` ({c:08X})")
        rt, rd = (a >> 16) & 0x1F, (a >> 11) & 0x1F
        if ((b >> 21) & 0x1F, (b >> 16) & 0x1F, (b >> 11) & 0x1F) != (rd, rt, rd):
            raise SystemExit(f"{label}: addu operands are not (rd, rt) -> rd")
        put(addr, (rt << 16) | (rd << 11) | (4 << 6), label, a)   # sll rd, rt, 4
        put(addr + 4, NOP, label + " (freed)", b)
        put(addr + 8, NOP, label + " (freed)", c)

    # 2. literal 12 -> 16
    for addr, label in LITERAL_SITES:
        w = word(addr)
        if (w >> 26) != 0x0D or (w & 0xFFFF) != OLD:
            raise SystemExit(f"{label}: 0x{addr:08X} is not `ori rt,rs,12` ({w:08X})")
        put(addr, (w & ~0xFFFF) | NEW, label, w)

    members[PSX] = bytes(exe)
    if [n for n in members if members[n] != before[n]] != [PSX]:
        raise SystemExit("unexpected changed members")
    if len(members[PSX]) != len(before[PSX]):
        raise SystemExit("PSX.EXE size changed")
    diffs = [o for o, (a, b) in enumerate(zip(before[PSX], members[PSX])) if a != b]
    allowed = set()
    for _l, at, _w, _v in edits:
        allowed.update(range(at - R2F, at - R2F + 4))
    if not diffs or any(o not in allowed for o in diffs):
        raise SystemExit(f"changed outside guarded fields: {diffs[:16]}")

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    shown = []
    for addr, label in SHIFT_SITES:
        for i in md.disasm(bytes(exe[addr - R2F:addr - R2F + 12]), addr):
            shown.append(f"    {i.address:08X}  {i.mnemonic:8}{i.op_str}")
    if len(shown) != 6:
        raise SystemExit("shift sites did not disassemble to 3 instructions each")

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
        "v238 TEST ONLY - text renderer glyph cell 12px -> 16px",
        f"base={BASE.name}", f"output={out.name}", f"sha256={stamp}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        "font=UNCHANGED (still 12x12 completed syllables) -- letters will look wrong",
        "purpose=verify layout survives a 16px cell before drawing johab pieces",
        f"edits={len(edits)} words at {len(SHIFT_SITES) + len(LITERAL_SITES)} sites",
        f"PSX_changed_bytes={len(diffs)}",
        "untouched=struct address math (5 x12 sites), 0x44 struct walk,",
        "          11 packet w/h sites that read from data",
        "COMM.IMG=byte-identical PASS", "all_DAT_members=byte-identical PASS",
        "runtime=PENDING user cold boot",
        "expected=boots; glyphs garbled but spaced 16px; check line spacing,",
        "         cursor position, dialogue overflow, choice alignment",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))
    print("\n  shift sites")
    print("\n".join(shown))
    print("\n  edits")
    for label, at, was, now in edits:
        print(f"    0x{at:08X}  {was:08X} -> {now:08X}   {label}")


if __name__ == "__main__":
    main()
