"""v98: give every text object its full glyph capacity back.

v95 made room for the high-page DR_TPAGE by hooking the text-object initializer at
0x8016B148 and storing `limit - 1`. That works, but it is a global change to shared
code: every text object in the game permanently loses one glyph slot, so any string
that exactly fills its buffer loses its last character.

The object struct cannot absorb the primitive instead. Measured from the initializer
call sites, the structs sit exactly 68 bytes apart (0x801F9D44 -> 0x801F9D88), and the
initializer already fills 0..67: the header fields at 0..0x10 and two 12-byte low-page
DR_TPAGE slots at +44 and +56, written by the loop at 0x8016B178 which runs s0 = 44, 56
and stops at 68. There is no spare room.

The fix is to move the `- 1` out of the initializer and into the renderer. Instead of
shrinking the stored limit, the driver computes the primitive address from `limit - 1`
directly, which is the array's last slot:

    before  s1 = base + 52*stored_limit + parity*20      with stored_limit = limit-1
    after   s1 = base + 52*(limit - 1)  + parity*20      with the true limit stored

Both land on the same slot, but now the builder may fill all `limit` slots.

Two words change in the injected driver. The packet base load moves up into the
load-delay slot after `lh v0,0x4(s2)`, which frees its old slot for the subtraction:

    801A2150  nop            -> lw    s1,0x0(s2)
    801A2168  lw s1,0x0(s2)  -> addiu v1,v1,-52

Failure mode improves rather than disappearing. If a string ever fills all `limit`
slots, the tpage primitive shares the last slot with a real glyph and that one glyph
draws wrong. That is a cosmetic fault confined to the object, not the out-of-bounds
write into the next object's header that used to freeze the game.

Longest translated string measured across 05_docs is 58 slots against a 128-slot
dialogue object, so the restored capacity has real margin.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
V97 = ROOT / "03_output/ui_hud_e7_v97_high_tpage_measured_patch_only.zip"
V71 = ROOT / "03_output/ui_hud_e7_v71_leaf_font_ring_help_patch_only.zip"
OUTPUT = ROOT / "03_output/ui_hud_e7_v98_restore_object_capacity_patch_only.zip"
REPORT = ROOT / "01_work/analysis/ui_hud_e7_v98_restore_object_capacity/build_report.txt"

V97_SHA256 = "5DCD2E995D1BB4F1100489405DD7350F3492E35A686498A55FEE644742E1D6D4"
PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800

# (ram, expected v97 word, new word, must-equal-v71, label)
PATCH = [
    (0x8016B148, 0x0C068820, 0xAE260000, True,
     "initializer: jal 0x801A2080 -> sw a2,0x0(s1)   (hook removed)"),
    (0x8016B14C, 0x00000000, 0xA6240004, True,
     "initializer: nop           -> sh a0,0x4(s1)   (true limit stored again)"),
    (0x801A2080, 0xAE260000, 0x00000000, True, "helper word 0 cleared"),
    (0x801A2084, 0x2484FFFF, 0x00000000, True, "helper word 1 cleared (the -1)"),
    (0x801A2088, 0xA6240004, 0x00000000, True, "helper word 2 cleared"),
    (0x801A208C, 0x03E00008, 0x00000000, True, "helper word 3 cleared"),
    (0x801A2150, 0x00000000, 0x8E510000, False,
     "driver: nop           -> lw s1,0x0(s2)   (fills the lh load-delay slot)"),
    (0x801A2168, 0x8E510000, 0x2463FFCC, False,
     "driver: lw s1,0x0(s2) -> addiu v1,v1,-52 (52*limit becomes 52*(limit-1))"),
]

KEEP = [
    (0x801A214C, 0x86420004, "driver still reads the limit at object+0x04"),
    (0x801A2154, 0x00021840, "52*limit chain intact: sll v1,v0,1"),
    (0x801A2164, 0x00031880, "52*limit chain intact: sll v1,v1,2"),
    (0x801A216C, 0x00000000, "load-delay nop before addu s1,s1,v1"),
    (0x801A2170, 0x02238821, "addu s1,s1,v1"),
    (0x801A2174, 0x02348821, "addu s1,s1,s4"),
    (0x801A2194, 0x34E7001B, "v97 high-page tpage (tx=11 | ty) retained"),
    (0x801A2204, 0x90620029, "v92 classifier retained (V at packet 0x29)"),
    (0x8016B520, 0x84C20004, "glyph builder still reads the limit"),
    (0x8016B528, 0x00A2102A, "glyph builder still gates on count < limit"),
    (0x8016B764, 0x080688A8, "injected renderer entry retained"),
    (0x8016B5D8, 0x0807F8F1, "glyph-builder hook retained (U += 40)"),
]


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest().upper()


def clone(i: ZipInfo) -> ZipInfo:
    t = ZipInfo(i.filename, i.date_time)
    for a in ("compress_type", "comment", "extra", "create_system", "create_version",
              "extract_version", "flag_bits", "volume", "internal_attr", "external_attr"):
        setattr(t, a, getattr(i, a))
    return t


def word(buf, ram):
    return struct.unpack_from("<I", buf, ram - RAM_TO_FILE)[0]


def main() -> None:
    if sha256(V97.read_bytes()) != V97_SHA256:
        raise SystemExit("v97 archive hash differs")

    with ZipFile(V71, "r") as a:
        v71_exe = a.read(PSX)
    with ZipFile(V97, "r") as a:
        infos = a.infolist()
        members = {i.filename: a.read(i.filename) for i in infos}

    exe = bytearray(members[PSX])
    if struct.unpack_from("<8s", exe, 0)[0] != b"PS-X EXE":
        raise SystemExit("bad EXE header")

    for ram, cur, new, like71, label in PATCH:
        got = word(exe, ram)
        if got != cur:
            raise SystemExit(f"0x{ram:08X}: expected 0x{cur:08X}, got 0x{got:08X} ({label})")
        if like71 and word(v71_exe, ram) != new:
            raise SystemExit(
                f"0x{ram:08X}: v71 holds 0x{word(v71_exe, ram):08X}, not the 0x{new:08X} we restore"
            )
    for ram, val, label in KEEP:
        if word(exe, ram) != val:
            raise SystemExit(f"scope guard failed at 0x{ram:08X} ({label})")

    for ram, _, new, _, _ in PATCH:
        struct.pack_into("<I", exe, ram - RAM_TO_FILE, new)

    # R3000 hazard audit on the rewritten driver sequence
    seq = [(a, word(exe, a)) for a in range(0x801A214C, 0x801A2178, 4)]
    if seq[0][1] != 0x86420004 or seq[1][1] != 0x8E510000:
        raise SystemExit("driver head is not `lh v0,0x4(s2)` followed by `lw s1,0x0(s2)`")
    if seq[2][1] != 0x00021840:
        raise SystemExit("v0 is consumed too early after the lh")
    if word(exe, 0x801A2168) != 0x2463FFCC:
        raise SystemExit("the -52 adjustment is missing")
    if word(exe, 0x801A216C) != 0x00000000:
        raise SystemExit("the load-delay nop before addu s1,s1,v1 was lost")

    for ram, _, new, _, label in PATCH:
        if word(exe, ram) != new:
            raise SystemExit(f"readback failed at 0x{ram:08X} ({label})")
    for ram, val, label in KEEP:
        if word(exe, ram) != val:
            raise SystemExit(f"scope guard broken at 0x{ram:08X} ({label})")

    # the initializer must once more be byte-identical to the original game code
    for ram in (0x8016B148, 0x8016B14C):
        if word(exe, ram) != word(v71_exe, ram):
            raise SystemExit(f"0x{ram:08X} does not match the original v71 initializer")

    patched = bytes(exe)
    original = members[PSX]
    if len(patched) != len(original):
        raise SystemExit("EXE size changed")
    diff = [i for i, (x, y) in enumerate(zip(original, patched)) if x != y]
    allowed = set()
    for ram, _, _, _, _ in PATCH:
        allowed.update(range(ram - RAM_TO_FILE, ram - RAM_TO_FILE + 4))
    stray = [i for i in diff if i not in allowed]
    if stray:
        raise SystemExit(f"changes outside the approved words: {[hex(i) for i in stray[:8]]}")

    members[PSX] = patched
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as t:
        for i in infos:
            t.writestr(clone(i), members[i.filename])

    with ZipFile(OUTPUT, "r") as a, ZipFile(V97, "r") as src:
        if [i.filename for i in a.infolist()] != [i.filename for i in infos]:
            raise SystemExit("member order differs")
        for i in infos:
            out = a.read(i.filename)
            if out != members[i.filename]:
                raise SystemExit(f"member differs: {i.filename}")
            if i.filename != PSX and out != src.read(i.filename):
                raise SystemExit(f"unexpected change in {i.filename}")

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "Arc the Lad Korean patch v98 build report",
        "",
        f"base_v97={V97.name}",
        f"base_v97_sha256={V97_SHA256}",
        f"original_reference={V71.name}",
        f"output={OUTPUT.name}",
        f"output_sha256={sha256(OUTPUT.read_bytes())}",
        f"psx_sha256={sha256(patched)}",
        "",
        f"changed_members: {PSX} only",
        f"changed_bytes: {len(diff)} in {len(PATCH)} words",
        "",
        "word changes:",
    ]
    for ram, cur, new, like71, label in PATCH:
        tag = "  [restores the original game code]" if like71 else ""
        lines.append(f"- 0x{ram:08X} / file 0x{ram - RAM_TO_FILE:05X}: {cur:08X} -> {new:08X}   {label}{tag}")
    lines += [
        "",
        "effect: the text-object initializer at 0x8016B148 is byte-identical to the",
        "original game again, so every object keeps its full glyph capacity. The driver",
        "now derives the high-page tpage address from limit-1 itself, landing on the same",
        "final slot as before.",
        "",
        "common-path footprint after this build:",
        "  0x8016B148  initializer      REMOVED  (was the only change that cost capacity)",
        "  0x8016B764  renderer entry   retained",
        "  0x8016B5D8  glyph builder    retained (applies U += 40 for row-24 cells only)",
        "",
        "residual risk: if a string ever fills all `limit` slots the tpage primitive shares",
        "the last slot with a glyph and that glyph draws wrong. Cosmetic, object-local, and",
        "not the out-of-bounds write that used to freeze the game. Longest measured",
        "translated string is 58 slots against a 128-slot dialogue object.",
        "",
        "invariants held:",
    ]
    for ram, val, label in KEEP:
        lines.append(f"- 0x{ram:08X} == 0x{val:08X}   {label}")
    lines += [
        "",
        "static_verification=PASS",
        "runtime_verification=PENDING",
        "rollback baseline=99_backup/baselines/ui_hud_e7_v97_runtime_success_2026-07-31",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(OUTPUT)
    print(f"SHA256={sha256(OUTPUT.read_bytes())}")
    print(f"changed_bytes={len(diff)}")
    print(REPORT)


if __name__ == "__main__":
    main()
