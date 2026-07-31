"""v92: replace the stateful P6 sidecar marker with a stateless per-packet classifier.

The v83-v91 P6 renderer decided high-page membership by calling a helper that read
a single global sidecar (active text-state pointer + 64-bit glyph bitmap). That
sidecar can only describe ONE text object, so any glyph belonging to a second
concurrent text object (item-name window vs dialogue vs HUD) was classified as
low-page and drawn from the wrong texture page.

The information the classifier needs is already in the glyph packet: the common
glyph builder at 0x8016B518 writes V = row * 12 into packet byte 0x29 with `sb`,
so row 24 (the only P6 row after the v86 repack) truncates to exactly 32, which is
also the correct within-high-page offset (24*12 - 256 = 32). No other valid row
produces V == 32.

v92 therefore computes pass membership inline from packet byte 0x29 and drops the
helper call. The pass tag changes from 0x80 to 1 so the comparison needs no shift,
which keeps the loop body at its original addresses -- only five words change.

The glyph-builder hook, the high-RAM helper image, the entry bootstrap and the
InitHeap reservation are intentionally left untouched. The helper still applies the
required `U += 40` for P6 cells; its sidecar writes simply become unread. This keeps
v92 a single-variable experiment over v91.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
V91 = ROOT / "03_output/ui_hud_e7_v91_v89_lifetime_yagun_slot_fix_patch_only.zip"
OUTPUT = ROOT / "03_output/ui_hud_e7_v92_stateless_p6_pass_classifier_patch_only.zip"
REPORT = ROOT / "01_work/analysis/ui_hud_e7_v92_stateless_p6_pass_classifier/build_report.txt"

V91_SHA256 = "60F0D550ECE295DA771440526E7B3B251F113A32DCA25CC8381DB442B9D80027"
PSX_MEMBER = "PSX.EXE"

# PS-X EXE load mapping: t_addr 0x8011B000 sits at file offset 0x800.
RAM_TO_FILE = 0x8011A800

# (ram address, expected v91 word, new word, disassembly before -> after)
PATCH = [
    (0x801A2204, 0x0C07F918, 0x90620029, "jal 0x801FE460      -> lbu v0,0x29(v1)"),
    (0x801A220C, 0x1455001C, 0x2442FFE0, "bne v0,s5,0x801A2280 -> addiu v0,v0,-32"),
    (0x801A2210, 0x00000000, 0x2C420001, "nop                 -> sltiu v0,v0,1"),
    (0x801A2214, 0x00000000, 0x1455001A, "nop                 -> bne v0,s5,0x801A2280"),
    (0x801A2140, 0x34150080, 0x34150001, "ori s5,zero,0x80    -> ori s5,zero,0x01"),
]

# Words that must NOT change, to prove the loop body did not shift.
INVARIANT = [
    (0x801A2208, 0x00000000, "load-delay nop between lbu and addiu"),
    (0x801A2218, 0x00742821, "addu a1,v1,s4 becomes the bne delay slot"),
    (0x801A221C, 0x9462002C, "loop body still starts here (no shift)"),
    (0x801A2280, 0x8642000A, "branch target unchanged"),
    (0x801A210C, 0x0000A821, "pass-0 tag still s5 = 0"),
    (0x8016B5A8, 0xA0A20029, "builder still stores V with sb at packet 0x29"),
    (0x8016B5D8, 0x0807F8F1, "glyph-builder hook retained (keeps U += 40)"),
    (0x801FE460 - 0x801FE3C4 + 0x801A86EC, 0x3C028020, "marker helper image retained but unread"),
]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone_info(source: ZipInfo) -> ZipInfo:
    target = ZipInfo(source.filename, source.date_time)
    for attr in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(target, attr, getattr(source, attr))
    return target


def word(buf: bytes, ram: int) -> int:
    return struct.unpack_from("<I", buf, ram - RAM_TO_FILE)[0]


def main() -> None:
    if sha256(V91.read_bytes()) != V91_SHA256:
        raise SystemExit("v91 archive hash differs")

    with ZipFile(V91, "r") as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}

    exe = bytearray(members[PSX_MEMBER])

    magic, = struct.unpack_from("<8s", exe, 0)
    t_addr, = struct.unpack_from("<I", exe, 0x18)
    if magic != b"PS-X EXE" or t_addr - 0x800 != RAM_TO_FILE:
        raise SystemExit(f"unexpected EXE header: {magic!r} t_addr=0x{t_addr:08X}")

    for ram, expect, _, label in PATCH:
        got = word(exe, ram)
        if got != expect:
            raise SystemExit(
                f"source word mismatch at 0x{ram:08X}: expected 0x{expect:08X}, got 0x{got:08X} ({label})"
            )
    for ram, expect, label in INVARIANT:
        got = word(exe, ram)
        if got != expect:
            raise SystemExit(
                f"invariant word mismatch at 0x{ram:08X}: expected 0x{expect:08X}, got 0x{got:08X} ({label})"
            )

    for ram, _, new, _ in PATCH:
        struct.pack_into("<I", exe, ram - RAM_TO_FILE, new)

    # readback
    for ram, _, new, label in PATCH:
        if word(exe, ram) != new:
            raise SystemExit(f"readback failed at 0x{ram:08X} ({label})")
    for ram, expect, label in INVARIANT:
        if word(exe, ram) != expect:
            raise SystemExit(f"invariant broken at 0x{ram:08X} ({label})")

    original = members[PSX_MEMBER]
    patched = bytes(exe)
    if len(patched) != len(original):
        raise SystemExit("PSX.EXE size changed")
    diff = [i for i, (a, b) in enumerate(zip(original, patched)) if a != b]
    allowed = set()
    for ram, _, _, _ in PATCH:
        allowed.update(range(ram - RAM_TO_FILE, ram - RAM_TO_FILE + 4))
    stray = [i for i in diff if i not in allowed]
    if stray:
        raise SystemExit(f"changes outside the approved words: {[hex(i) for i in stray[:8]]}")

    members[PSX_MEMBER] = patched

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as target:
        for info in infos:
            target.writestr(clone_info(info), members[info.filename])

    with ZipFile(OUTPUT, "r") as archive:
        built = archive.infolist()
        if [i.filename for i in built] != [i.filename for i in infos]:
            raise SystemExit("output member order differs")
        with ZipFile(V91, "r") as src:
            for info in infos:
                out = archive.read(info.filename)
                if out != members[info.filename]:
                    raise SystemExit(f"output member differs: {info.filename}")
                if info.filename != PSX_MEMBER and out != src.read(info.filename):
                    raise SystemExit(f"unexpected change in {info.filename}")

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "Arc the Lad Korean patch v92 build report",
        "",
        f"base_v91={V91.name}",
        f"base_v91_sha256={V91_SHA256}",
        f"output={OUTPUT.name}",
        f"output_sha256={sha256(OUTPUT.read_bytes())}",
        f"psx_sha256={sha256(patched)}",
        "",
        f"changed_members: {PSX_MEMBER} only",
        f"changed_bytes: {len(diff)} in {len(PATCH)} words",
        "",
        "word changes:",
    ]
    for ram, old, new, label in PATCH:
        lines.append(
            f"- RAM 0x{ram:08X} / file 0x{ram - RAM_TO_FILE:05X}: {old:08X} -> {new:08X}   {label}"
        )
    lines += [
        "",
        "invariants held:",
    ]
    for ram, expect, label in INVARIANT:
        lines.append(f"- RAM 0x{ram:08X} == 0x{expect:08X}   {label}")
    lines += [
        "",
        "mechanism: pass membership is now computed per packet as (packet[0x29] == 32),",
        "which is true only for physical row 24 (24*12 = 288, truncated by sb to 32,",
        "and 288 - 256 = 32 is the correct within-high-page V). The global sidecar is",
        "no longer read, so concurrent text objects can no longer lose their P6 flags.",
        "E7 icons share this packet array and use V = 130 / 228, neither of which is 32,",
        "so they stay in the low-page pass.",
        "",
        "static_verification=PASS",
        "runtime_verification=PENDING",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(OUTPUT)
    print(f"SHA256={sha256(OUTPUT.read_bytes())}")
    print(f"changed_bytes={len(diff)}")
    print(REPORT)


if __name__ == "__main__":
    main()
