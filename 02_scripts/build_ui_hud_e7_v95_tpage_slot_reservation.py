"""v95: restore the packet-slot reservation that the injected renderer depends on.

Root cause, established by byte comparison across v71/v73/v74/v91/v92/v93 and confirmed
by the v94 runtime result:

The injected driver writes its high-page DR_TPAGE primitive at
    packet_base + 52 * limit + parity * 20
where `limit` is the text object's slot count at object+0x04. The glyph builder at
0x8016B518 accepts a glyph only while `count < limit`, so slots 0..limit-1 are all
legal glyph storage and `base + 52*limit` is the first byte PAST the array.

v73 and v74 avoided this by hooking the text-object initializer at 0x8016B148 and
storing `limit - 1`, which leaves the final slot empty for exactly that primitive.
v76 removed that hook, judging the decrement to be a bug. From v76 onward every build
that keeps the injected renderer writes one slot out of bounds. For objects whose
following memory is live -- the item-name window -- that corrupts state and the game
stops. v94 disabled the renderer entirely and the freeze disappeared.

v95 restores the reservation, byte-for-byte from v74, on top of v93. It does not touch
the classifier: v93 keeps the v92 stateless `V == 32` test, which reads packet byte 0x29
and therefore never corrupts the sprite height. v73/v74 flagged P6 membership with bit
0x80 of packet byte 0x2B, which IS the height field, so those builds asked the GPU for
140-pixel-tall sprites. v95 is the first build with both halves correct.

Arithmetic proof of the fix:
    limit stored  = max - 1
    builder fills = slots 0 .. limit-1 = 0 .. max-2
    renderer uses = base + 52*limit    = slot max-1        <- the reserved empty slot
    within it     = parity*20 + 8 bytes <= 52              <- fits either buffer half
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
V93 = ROOT / "03_output/ui_hud_e7_v93_s3032_speaker_separator_patch_only.zip"
V74 = ROOT / "03_output/ui_hud_e7_v74_leaf_ra_trampoline_fix_patch_only.zip"
OUTPUT = ROOT / "03_output/ui_hud_e7_v95_tpage_slot_reservation_patch_only.zip"
REPORT = ROOT / "01_work/analysis/ui_hud_e7_v95_tpage_slot_reservation/build_report.txt"

V93_SHA256 = "7BCA52B59459F4F71A178D1D0A22454661AD358952C5E11B5EC06B614E038845"
PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800

# (ram, expected v93 word, new word, label) -- every new word is verified against v74
PATCH = [
    (0x8016B148, 0xAE260000, 0x0C068820, "init hook   : sw a2,0x0(s1) -> jal 0x801A2080"),
    (0x8016B14C, 0xA6240004, 0x00000000, "init hook   : sh a0,0x4(s1) -> nop (delay slot)"),
    (0x801A2080, 0x00000000, 0xAE260000, "helper[0]   : sw a2,0x0(s1)   (displaced)"),
    (0x801A2084, 0x00000000, 0x2484FFFF, "helper[1]   : addiu a0,a0,-1  (RESERVE ONE SLOT)"),
    (0x801A2088, 0x00000000, 0xA6240004, "helper[2]   : sh a0,0x4(s1)   (displaced, reduced)"),
    (0x801A208C, 0x00000000, 0x03E00008, "helper[3]   : jr ra"),
]

KEEP = [
    (0x801A2090, 0x00000000, "jr-ra delay slot must stay nop"),
    (0x8016B138, 0xAFBF0020, "enclosing function saves RA, so JAL is safe here"),
    (0x8016B520, 0x84C20004, "glyph builder still reads the limit at object+0x04"),
    (0x8016B528, 0x00A2102A, "glyph builder still gates on count < limit"),
    (0x801A214C, 0x86420004, "renderer still places the tpage prim at base+52*limit"),
    (0x801A2204, 0x90620029, "classifier still reads V at packet 0x29 (not the height byte)"),
    (0x8016B764, 0x080688A8, "injected renderer entry retained"),
    (0x8016B5D8, 0x0807F8F1, "glyph-builder P6 hook retained"),
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
    if sha256(V93.read_bytes()) != V93_SHA256:
        raise SystemExit("v93 archive hash differs")

    with ZipFile(V74, "r") as a:
        v74_exe = a.read(PSX)
    with ZipFile(V93, "r") as a:
        infos = a.infolist()
        members = {i.filename: a.read(i.filename) for i in infos}

    exe = bytearray(members[PSX])
    if struct.unpack_from("<8s", exe, 0)[0] != b"PS-X EXE":
        raise SystemExit("bad EXE header")

    for ram, cur, new, label in PATCH:
        got = word(exe, ram)
        if got != cur:
            raise SystemExit(f"0x{ram:08X}: expected 0x{cur:08X}, got 0x{got:08X} ({label})")
        ref = word(v74_exe, ram)
        if ref != new:
            raise SystemExit(f"0x{ram:08X}: v74 has 0x{ref:08X}, patch wants 0x{new:08X}")
    for ram, val, label in KEEP:
        if word(exe, ram) != val:
            raise SystemExit(f"scope guard failed at 0x{ram:08X} ({label})")

    # R3000 hazard: the helper clobbers a0. Confirm the caller never reads a0 again
    # before redefining it, from the return point to the function epilogue.
    a = 0x8016B150
    while a < 0x8016B150 + 0x200:
        ins = word(exe, a)
        op, rs, rt, rd = ins >> 26, (ins >> 21) & 31, (ins >> 16) & 31, (ins >> 11) & 31
        if ins == 0x03E00008:
            break
        reads = {rs} if op not in (0, 1) else {rs, rt}
        if op in (0x28, 0x29, 0x2B, 0x04, 0x05):
            reads.add(rt)
        if op == 0 and rd == 4:
            break            # a0 redefined, safe from here
        if op not in (0, 1) and rt == 4 and op in (0x08, 0x09, 0x0C, 0x0D, 0x23, 0x24, 0x25, 0x0F):
            break            # a0 redefined by an immediate/load form
        if 4 in reads:
            raise SystemExit(f"caller reads a0 at 0x{a:08X} after the helper clobbers it")
        a += 4

    for ram, _, new, _ in PATCH:
        struct.pack_into("<I", exe, ram - RAM_TO_FILE, new)

    for ram, _, new, label in PATCH:
        if word(exe, ram) != new:
            raise SystemExit(f"readback failed at 0x{ram:08X} ({label})")
        if word(exe, ram) != word(v74_exe, ram):
            raise SystemExit(f"0x{ram:08X} does not match v74")
    for ram, val, label in KEEP:
        if word(exe, ram) != val:
            raise SystemExit(f"scope guard broken at 0x{ram:08X} ({label})")

    patched = bytes(exe)
    original = members[PSX]
    if len(patched) != len(original):
        raise SystemExit("EXE size changed")
    diff = [i for i, (x, y) in enumerate(zip(original, patched)) if x != y]
    allowed = set()
    for ram, _, _, _ in PATCH:
        allowed.update(range(ram - RAM_TO_FILE, ram - RAM_TO_FILE + 4))
    stray = [i for i in diff if i not in allowed]
    if stray:
        raise SystemExit(f"changes outside the approved words: {[hex(i) for i in stray[:8]]}")

    members[PSX] = patched
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as t:
        for i in infos:
            t.writestr(clone(i), members[i.filename])

    with ZipFile(OUTPUT, "r") as a, ZipFile(V93, "r") as src:
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
        "Arc the Lad Korean patch v95 build report",
        "",
        f"base_v93={V93.name}",
        f"base_v93_sha256={V93_SHA256}",
        f"reference={V74.name}  (last build that reserved the slot)",
        f"output={OUTPUT.name}",
        f"output_sha256={sha256(OUTPUT.read_bytes())}",
        f"psx_sha256={sha256(patched)}",
        "",
        f"changed_members: {PSX} only",
        f"changed_bytes: {len(diff)} in {len(PATCH)} words",
        "",
        "word changes (each verified byte-identical to v74):",
    ]
    for ram, cur, new, label in PATCH:
        lines.append(f"- 0x{ram:08X} / file 0x{ram - RAM_TO_FILE:05X}: {cur:08X} -> {new:08X}   {label}")
    lines += [
        "",
        "invariants held:",
    ]
    for ram, val, label in KEEP:
        lines.append(f"- 0x{ram:08X} == 0x{val:08X}   {label}")
    lines += [
        "",
        "why this is the first build with both halves correct:",
        "  v73/v74  reserved the slot, but flagged P6 in packet byte 0x2B, the sprite",
        "           height field, producing 140-pixel-tall sprites.",
        "  v91-v93  read V at packet 0x29 so the height is intact, but lost the slot",
        "           reservation, so the tpage primitive landed out of bounds.",
        "  v95      keeps the v92 classifier and restores the v74 reservation.",
        "",
        "static_verification=PASS",
        "runtime_verification=PENDING",
        "rollback baseline=99_backup/baselines/ui_hud_e7_v94_runtime_success_2026-07-31",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(OUTPUT)
    print(f"SHA256={sha256(OUTPUT.read_bytes())}")
    print(f"changed_bytes={len(diff)}")
    print(REPORT)


if __name__ == "__main__":
    main()
