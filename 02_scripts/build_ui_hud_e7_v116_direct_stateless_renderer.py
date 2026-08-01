"""v116: bypass the obsolete sidecar gate at the common text-render entry.

The v115 savestate proves that the EA66 lookup resolves to physical glyph 3367,
the glyph builder emits two U=16/V=224 packets, and strip A is present in VRAM.
The missing piece is the high-page DR_TPAGE primitive.  The common renderer still
enters through the old sidecar trampoline at 0x801A22A0; its three sidecar words
are zero, so it always falls back to the original low-page renderer.

The two-pass renderer is already stateless per packet.  Redirecting the common
entry straight to 0x801A20B0 removes only that stale object-level gate.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
BASE_ZIP = ROOT / "03_output/ui_hud_e7_v115_no_t9_two_strips_patch_only.zip"
BASE_SHA256 = "506806E97A34083A451D05210A5A71559476AA0F02EC5F9AB988CE34B0898D26"
OUTPUT = ROOT / "03_output/ui_hud_e7_v116_direct_stateless_renderer_patch_only.zip"
REPORT = ROOT / "01_work/analysis/ui_hud_e7_v116_direct_stateless_renderer/build_report.txt"

PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800
RENDER_HOOK = 0x8016B764
RENDER_HOOK_DELAY = 0x8016B768
OLD_TRAMPOLINE = 0x801A22A0
STATELESS_DRIVER = 0x801A20B0


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def jump(target: int) -> int:
    return 0x08000000 | ((target & 0x0FFFFFFF) >> 2)


def word(buf: bytes, ram: int) -> int:
    return struct.unpack_from("<I", buf, ram - RAM_TO_FILE)[0]


def put_word(buf: bytearray, ram: int, value: int) -> None:
    struct.pack_into("<I", buf, ram - RAM_TO_FILE, value)


def clone_info(source: ZipInfo) -> ZipInfo:
    target = ZipInfo(source.filename, source.date_time)
    for attr in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(target, attr, getattr(source, attr))
    return target


def main() -> None:
    if sha256(BASE_ZIP.read_bytes()) != BASE_SHA256:
        raise SystemExit("base archive is not the verified v115 build")

    with ZipFile(BASE_ZIP, "r") as source:
        infos = source.infolist()
        members = {info.filename: source.read(info.filename) for info in infos}

    exe = bytearray(members[PSX])
    before = bytes(exe)
    old_jump = jump(OLD_TRAMPOLINE)
    new_jump = jump(STATELESS_DRIVER)

    guards = [
        (RENDER_HOOK, old_jump, "common renderer still enters the stale sidecar trampoline"),
        (RENDER_HOOK_DELAY, 0x00000000, "renderer hook delay slot"),
        (STATELESS_DRIVER, 0x27BDFFB0, "stateless two-pass driver prologue"),
        (OLD_TRAMPOLINE, 0x3C028020, "old sidecar trampoline retained as evidence"),
        (0x801A22D0, jump(STATELESS_DRIVER), "old trampoline's success branch"),
        (0x801A2140, 0x34150001, "high-pass classifier tag"),
    ]
    for ram, expected, label in guards:
        got = word(exe, ram)
        if got != expected:
            raise SystemExit(
                f"guard failed at 0x{ram:08X}: expected 0x{expected:08X}, "
                f"got 0x{got:08X} ({label})"
            )

    put_word(exe, RENDER_HOOK, new_jump)

    if word(exe, RENDER_HOOK) != new_jump:
        raise SystemExit("renderer-hook readback failed")
    if word(exe, RENDER_HOOK_DELAY) != 0:
        raise SystemExit("renderer-hook delay slot changed")
    if len(exe) != len(before):
        raise SystemExit("PSX.EXE size changed")

    diff = [i for i, (a, b) in enumerate(zip(before, exe)) if a != b]
    allowed = set(range(RENDER_HOOK - RAM_TO_FILE, RENDER_HOOK - RAM_TO_FILE + 4))
    if not diff or any(i not in allowed for i in diff):
        raise SystemExit("bytes changed outside the single approved hook word")

    members[PSX] = bytes(exe)
    if OUTPUT.exists():
        raise SystemExit(f"refusing to overwrite existing {OUTPUT.name}")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as target:
        for info in infos:
            target.writestr(clone_info(info), members[info.filename])

    with ZipFile(OUTPUT, "r") as built:
        if [info.filename for info in built.infolist()] != [info.filename for info in infos]:
            raise SystemExit("archive member order changed")
        for name, expected in members.items():
            if built.read(name) != expected:
                raise SystemExit(f"archive readback failed: {name}")

    lines = [
        "v116 direct stateless renderer entry",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {OUTPUT.name}",
        f"sha256  {sha256(OUTPUT.read_bytes())}",
        f"PSX.EXE {len(exe)} bytes, unchanged",
        "",
        "state evidence:",
        "  EA66 ('잎') lookup = physical index 3367 (row 40, col 1, plane 3)",
        "  two item-name packets exist at U=16, V=224, plane 3",
        "  strip A is uploaded, but no high-page DR_TPAGE exists",
        "  old sidecar words are all zero, so the old entry gate always falls back",
        "",
        "single word change:",
        f"  0x{RENDER_HOOK:08X}: {old_jump:08X} -> {new_jump:08X}",
        f"  j 0x{OLD_TRAMPOLINE:08X} -> j 0x{STATELESS_DRIVER:08X}",
        "",
        f"changed bytes: {len(diff)}; all inside that one word",
        "all other ZIP members: byte-identical to v115",
        "static verification: PASS",
        "runtime verification: PENDING",
        "",
        "runtime target after a cold boot:",
        "  item name '마력의 잎' renders its final glyph",
        "  ordinary dialogue/UI remains unchanged and progresses",
        "  a new savestate contains DR_TPAGE E100001F for the item-name object",
        "",
        "known separate issue: v103-based COMM.IMG still has the skill-range cursor regression",
        "rollback: v115 for this single change; v104 remains the accepted game baseline",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
