"""v102: bisection build. Keep v101's bootstrap, remove the VRAM upload.

v101 runs the new two-range bootstrap AND uploads 1080 bytes to the P6 rectangle
every frame. It hangs. The savestates show:

  - the fixed bootstrap is in place (clear ends at 0x801FE3C4, stub is the v100 one)
  - the relocated P6 helper at 0x801FE3C4 is correct
  - the glyph copy at 0x801CDE00 matches the source for 1026 of 1080 bytes
  - VRAM at the P6 rectangle matches to the same 1026 bytes, so the upload works
  - the 54 differing bytes are periodic, one every ten bytes within each row, which
    is a systematic offset rather than corruption and cannot explain a hang

So the two candidates are the bootstrap and the per-frame transfer, and only one of
them can be tested at a time. v102 keeps everything from v101 and replaces the single
`jal LoadImage` in the stub with a nop, leaving the stub to do nothing but call the
frame swap it displaced.

  runs normally -> the bootstrap is fine; the per-frame transfer is what hangs
  still hangs   -> the transfer is innocent; the bootstrap is what hangs

Either answer removes half the search space, and v98 remains the rollback.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
V101 = ROOT / "03_output/ui_hud_e7_v101_glyph_ram_upload_patch_only.zip"
OUTPUT = ROOT / "03_output/ui_hud_e7_v102_bisect_no_upload_patch_only.zip"
REPORT = ROOT / "01_work/analysis/ui_hud_e7_v102_bisect_no_upload/build_report.txt"

V101_SHA256 = "3DC4A81533311800D2A9848479A75255E76F501047C10BCFE4518F0E26A178EC"
PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800

LOADIMAGE = 0x80177E4C
STUB = 0x801A2074
CALL = STUB + 6 * 4           # the `jal LoadImage` inside the stub


def jal(t): return 0x0C000000 | ((t & 0x0FFFFFFF) >> 2)


KEEP = [
    (0x801757BC, 0x08064ED1, "entry still jumps to the new bootstrap"),
    (0x80193B44, 0x3C04801F, "bootstrap word 0"),
    (0x80193BA4, 0x3508E3C4, "clear ends at the helper start, not past it"),
    (0x8011C4AC, jal(STUB), "frame-swap hook still calls the stub"),
    (STUB + 9 * 4, jal(0x8011C814), "stub still tail-calls the frame swap"),
    (0x801A2194, 0x34E7001B, "v97 high-page tpage"),
    (0x801A2204, 0x90620029, "v92 classifier"),
]


def sha256(b): return hashlib.sha256(b).hexdigest().upper()


def clone(i: ZipInfo) -> ZipInfo:
    t = ZipInfo(i.filename, i.date_time)
    for a in ("compress_type", "comment", "extra", "create_system", "create_version",
              "extract_version", "flag_bits", "volume", "internal_attr", "external_attr"):
        setattr(t, a, getattr(i, a))
    return t


def word(buf, ram): return struct.unpack_from("<I", buf, ram - RAM_TO_FILE)[0]


def main() -> None:
    if sha256(V101.read_bytes()) != V101_SHA256:
        raise SystemExit("v101 archive hash differs")
    with ZipFile(V101, "r") as a:
        infos = a.infolist()
        members = {i.filename: a.read(i.filename) for i in infos}
    exe = bytearray(members[PSX])

    if word(exe, CALL) != jal(LOADIMAGE):
        raise SystemExit(f"0x{CALL:08X} is not `jal LoadImage`: 0x{word(exe, CALL):08X}")
    for ram, val, label in KEEP:
        if word(exe, ram) != val:
            raise SystemExit(f"scope guard failed at 0x{ram:08X} ({label})")

    struct.pack_into("<I", exe, CALL - RAM_TO_FILE, 0)

    if word(exe, CALL) != 0:
        raise SystemExit("readback failed")
    for ram, val, label in KEEP:
        if word(exe, ram) != val:
            raise SystemExit(f"scope guard broken at 0x{ram:08X} ({label})")

    patched, original = bytes(exe), members[PSX]
    diff = [i for i, (x, y) in enumerate(zip(original, patched)) if x != y]
    allowed = set(range(CALL - RAM_TO_FILE, CALL - RAM_TO_FILE + 4))
    stray = [i for i in diff if i not in allowed]
    if stray or len(patched) != len(original):
        raise SystemExit("unexpected change outside the single approved word")

    members[PSX] = patched
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as t:
        for i in infos:
            t.writestr(clone(i), members[i.filename])
    with ZipFile(OUTPUT, "r") as a, ZipFile(V101, "r") as src:
        for i in infos:
            out = a.read(i.filename)
            if i.filename != PSX and out != src.read(i.filename):
                raise SystemExit(f"unexpected change in {i.filename}")

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join([
        "Arc the Lad Korean patch v102 build report  (BISECTION)",
        "",
        f"base_v101={V101.name}",
        f"base_v101_sha256={V101_SHA256}",
        f"output={OUTPUT.name}",
        f"output_sha256={sha256(OUTPUT.read_bytes())}",
        f"psx_sha256={sha256(patched)}",
        "",
        f"changed_members: {PSX} only",
        f"changed_bytes: {len(diff)}  (one word)",
        f"0x{CALL:08X}: jal 0x{LOADIMAGE:08X} -> nop",
        "",
        "everything else is byte-identical to v101: the two-range bootstrap still runs,",
        "the glyph block is still relocated to 0x801CDE00, the stub is still hooked into",
        "the frame swap. Only the transfer itself is gone.",
        "",
        "  runs normally -> the bootstrap is fine, the per-frame transfer hangs",
        "  still hangs   -> the transfer is innocent, the bootstrap hangs",
        "",
        "measured from the v101 savestates, for reference:",
        "  P6 helper at 0x801FE3C4        correct",
        "  glyph copy at 0x801CDE00       1026/1080 bytes match the source",
        "  VRAM at the P6 rectangle       1026/1080, so the upload does reach VRAM",
        "  the 54 differing bytes repeat every ten bytes within each 90-byte row",
        "",
        "static_verification=PASS",
        "runtime_verification=PENDING",
        "rollback baseline=99_backup/baselines/ui_hud_e7_v98_runtime_success_2026-07-31",
    ]) + "\n", encoding="utf-8")
    print(OUTPUT)
    print(f"SHA256={sha256(OUTPUT.read_bytes())}")
    print(f"changed_bytes={len(diff)}")


if __name__ == "__main__":
    main()
