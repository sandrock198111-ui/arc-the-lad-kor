"""v94: diagnostic build that disables the entire P6 rendering path.

Purpose is isolation, not release. The item-name freeze reproduces on both v91
(stateful sidecar marker) and v92 (stateless V==32 classifier), so the fault is not
in the classifier. What v91 and v92 share is the whole injected rendering path that
v73 introduced. v94 removes that path with the smallest possible edit so the freeze
can be attributed or cleared in one run.

Two hooks define the path. Both are restored to the exact bytes found in v71, the
last build before the dual-texture-page renderer existed:

  0x8016B764  j 0x801A22A0   -> addiu sp,sp,-48   (original renderer entry)
  0x8016B768  nop            -> sw ra,0x2C(sp)
  0x8016B5D8  j 0x801FE3C4   -> lbu v0,0xE(a2)    (common glyph builder)

Restoring the entry at 0x8016B764 makes the game use its own single-pass renderer, so
the injected driver, the two-pass loop, the marker helper and the sidecar all become
unreachable. Restoring 0x8016B5D8 removes the P6 hook from the common glyph builder,
which per the original design principle should never have been modified: that builder
has five call sites and serves dialogue, item names, load/save screens, HUD and the
E7 icon path alike.

Everything else is left byte-identical to v93 on purpose, including the v93 S3032
separator repair, the high-RAM helper image, the entry bootstrap and the row-24 glyph
lookup. Those become dead weight but changing them would add variables.

EXPECTED RESULT: the 56 row-24 glyph codes (including 잎 책 탄 테 폴) will render as
garbage, because their lookup entries still point at row 24 while the original renderer
only draws the low texture page. That is not the thing under test.

THE ONLY QUESTION v94 ANSWERS: does the item name still freeze?
  freeze gone      -> the fault is inside the injected rendering path
  freeze persists  -> the injected path is innocent; look at data or memory layout
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
V93 = ROOT / "03_output/ui_hud_e7_v93_s3032_speaker_separator_patch_only.zip"
V71 = ROOT / "03_output/ui_hud_e7_v71_leaf_font_ring_help_patch_only.zip"
OUTPUT = ROOT / "03_output/ui_hud_e7_v94_p6_path_disable_probe_patch_only.zip"
REPORT = ROOT / "01_work/analysis/ui_hud_e7_v94_p6_path_disable_probe/build_report.txt"

V93_SHA256 = "7BCA52B59459F4F71A178D1D0A22454661AD358952C5E11B5EC06B614E038845"
PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800

# (ram, expected v93 word, expected v71 word == the value we restore, label)
RESTORE = [
    (0x8016B764, 0x080688A8, 0x27BDFFD0, "renderer entry: j 0x801A22A0 -> addiu sp,sp,-48"),
    (0x8016B768, 0x00000000, 0xAFBF002C, "renderer entry: nop            -> sw ra,0x2C(sp)"),
    (0x8016B5D8, 0x0807F8F1, 0x90C2000E, "glyph builder: j 0x801FE3C4    -> lbu v0,0xE(a2)"),
]

# words that must stay exactly as v93 has them, proving scope
KEEP = [
    (0x801A2204, 0x90620029, "injected classifier left in place (now unreachable)"),
    (0x801A2140, 0x34150001, "injected pass tag left in place (now unreachable)"),
    (0x801757BC, 0x3C048020, "entry bootstrap untouched"),
    (0x801A7520, None, "glyph lookup table untouched"),
]


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    t = ZipInfo(info.filename, info.date_time)
    for a in ("compress_type", "comment", "extra", "create_system", "create_version",
              "extract_version", "flag_bits", "volume", "internal_attr", "external_attr"):
        setattr(t, a, getattr(info, a))
    return t


def word(buf, ram):
    return struct.unpack_from("<I", buf, ram - RAM_TO_FILE)[0]


def main() -> None:
    if sha256(V93.read_bytes()) != V93_SHA256:
        raise SystemExit("v93 archive hash differs")

    with ZipFile(V71, "r") as a:
        v71_exe = a.read(PSX)
    with ZipFile(V93, "r") as a:
        infos = a.infolist()
        members = {i.filename: a.read(i.filename) for i in infos}

    exe = bytearray(members[PSX])
    if struct.unpack_from("<8s", exe, 0)[0] != b"PS-X EXE":
        raise SystemExit("bad EXE header")

    for ram, cur, orig, label in RESTORE:
        got = word(exe, ram)
        if got != cur:
            raise SystemExit(f"0x{ram:08X}: expected v93 0x{cur:08X}, got 0x{got:08X} ({label})")
        ref = word(v71_exe, ram)
        if ref != orig:
            raise SystemExit(f"0x{ram:08X}: v71 reference is 0x{ref:08X}, expected 0x{orig:08X}")
    for ram, val, label in KEEP:
        if val is not None and word(exe, ram) != val:
            raise SystemExit(f"0x{ram:08X}: scope guard failed ({label})")

    for ram, _, orig, _ in RESTORE:
        struct.pack_into("<I", exe, ram - RAM_TO_FILE, orig)

    for ram, _, orig, label in RESTORE:
        if word(exe, ram) != orig:
            raise SystemExit(f"readback failed at 0x{ram:08X} ({label})")
        if word(exe, ram) != word(v71_exe, ram):
            raise SystemExit(f"0x{ram:08X} does not match v71 after restore")
    for ram, val, label in KEEP:
        if val is not None and word(exe, ram) != val:
            raise SystemExit(f"scope guard broken at 0x{ram:08X} ({label})")

    patched = bytes(exe)
    original = members[PSX]
    if len(patched) != len(original):
        raise SystemExit("EXE size changed")
    diff = [i for i, (x, y) in enumerate(zip(original, patched)) if x != y]
    allowed = set()
    for ram, _, _, _ in RESTORE:
        allowed.update(range(ram - RAM_TO_FILE, ram - RAM_TO_FILE + 4))
    stray = [i for i in diff if i not in allowed]
    if stray:
        raise SystemExit(f"changes outside the three approved words: {[hex(i) for i in stray[:8]]}")

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
        "Arc the Lad Korean patch v94 build report  (DIAGNOSTIC, not a release)",
        "",
        f"base_v93={V93.name}",
        f"base_v93_sha256={V93_SHA256}",
        f"original_reference={V71.name}  (last build before the dual-tpage renderer)",
        f"output={OUTPUT.name}",
        f"output_sha256={sha256(OUTPUT.read_bytes())}",
        f"psx_sha256={sha256(patched)}",
        "",
        f"changed_members: {PSX} only",
        f"changed_bytes: {len(diff)} in {len(RESTORE)} words",
        "",
        "restored to the exact v71 originals:",
    ]
    for ram, cur, orig, label in RESTORE:
        lines.append(f"- 0x{ram:08X} / file 0x{ram - RAM_TO_FILE:05X}: {cur:08X} -> {orig:08X}   {label}")
    lines += [
        "",
        "effect: the game uses its own single-pass text renderer again. The injected",
        "driver, two-pass loop, marker helper, sidecar and the P6 hook in the common",
        "glyph builder all become unreachable. The injected code, the high-RAM helper",
        "image, the entry bootstrap and the row-24 lookup remain in the archive but are",
        "no longer used.",
        "",
        "expected regression (not under test): the 56 row-24 glyph codes render as",
        "garbage because the lookup still points at the high texture page.",
        "",
        "question under test: does the item name still freeze?",
        "  freeze gone     -> fault is inside the injected rendering path",
        "  freeze persists -> injected path is innocent; look elsewhere",
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
