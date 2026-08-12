"""L diagnostic: disable only the per-frame glyph-strip upload in H_nohook.

H_nohook already restores the shared text-renderer entry to the original game code,
but it still redirects the frame-swap call through the v151 stub.  That stub calls the
resident routine which uploads strips A, B, C and D on every frame.  This diagnostic
restores exactly that one complete MIPS instruction:

    0x8011C4AC  jal 0x801A2074  ->  jal 0x8011C814

The v151 startup copy and reduced heap remain unchanged.  Therefore a clean runtime
result isolates the fixed VRAM uploads from the separate reduced-heap hypothesis.
This is a diagnostic patch, not a distributable Korean patch.
"""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/DIAG_exe_nohook.zip"
BASE_SHA256 = "46D556B26CD79D637952D371755CC3414F9BBB5370DE05EE873E1946522BFCF8"
OUT_DIR = ROOT / "03_output"
ANALYSIS = ROOT / "01_work/analysis/diag_l_disable_frame_upload"

FRAME_HOOK_AT = 0x1CAC
TEXT_ENTRY_AT = 0x50F64
BOOT_START_AT = 0x5AFBC
COPY_LENGTH_AT = 0x5AFCC
HEAP_BASE_AT = 0x5B010

HOOKED_FRAME_WORD = 0x0C06881D       # jal 0x801A2074
ORIGINAL_FRAME_WORD = 0x0C047205     # jal 0x8011C814
ORIGINAL_TEXT_ENTRY = 0x27BDFFD0
V151_BOOT_START = 0x3C048020
V151_COPY_LENGTH = 0x240614EC
V151_HEAP_BASE = 0x2484F8B0


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(out, attr, getattr(info, attr))
    return out


def word(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("H_nohook archive hash mismatch")

    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        if [info.filename for info in infos] != ["PSX.EXE"]:
            raise SystemExit("H_nohook must contain only PSX.EXE")
        exe = bytearray(archive.read("PSX.EXE"))

    guards = (
        (FRAME_HOOK_AT, HOOKED_FRAME_WORD, "frame hook"),
        (TEXT_ENTRY_AT, ORIGINAL_TEXT_ENTRY, "original text-renderer entry"),
        (BOOT_START_AT, V151_BOOT_START, "v151 startup copy"),
        (COPY_LENGTH_AT, V151_COPY_LENGTH, "v151 resident-copy length"),
        (HEAP_BASE_AT, V151_HEAP_BASE, "v151 heap boundary"),
    )
    for offset, expected, label in guards:
        actual = word(exe, offset)
        if actual != expected:
            raise SystemExit(
                f"{label} differs at file 0x{offset:X}: {actual:08X} != {expected:08X}"
            )

    before = bytes(exe)
    struct.pack_into("<I", exe, FRAME_HOOK_AT, ORIGINAL_FRAME_WORD)
    after = bytes(exe)

    changed = [index for index, (old, new) in enumerate(zip(before, after)) if old != new]
    if changed != [FRAME_HOOK_AT, FRAME_HOOK_AT + 1, FRAME_HOOK_AT + 2]:
        raise SystemExit(f"unexpected changed bytes: {changed}")
    if word(after, FRAME_HOOK_AT) != ORIGINAL_FRAME_WORD:
        raise SystemExit("frame hook readback failed")
    for offset, expected, label in guards[1:]:
        if word(after, offset) != expected:
            raise SystemExit(f"{label} changed unexpectedly")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    temporary = OUT_DIR / "DIAG_L_no_frame_upload_building.zip"
    if temporary.exists():
        raise SystemExit(f"refusing to overwrite existing output: {temporary.name}")
    with ZipFile(temporary, "w", ZIP_DEFLATED) as archive:
        archive.writestr(clone(infos[0]), after)
    stamp = digest(temporary.read_bytes())
    final = OUT_DIR / f"DIAG_L_no_frame_upload_{stamp[:8]}.zip"
    if final.exists():
        raise SystemExit(f"refusing to overwrite existing output: {final.name}")
    temporary.replace(final)

    report = [
        "L no-frame-upload diagnostic",
        "",
        f"base    {BASE.name}",
        f"output  {final.name}",
        f"sha256  {stamp}",
        "",
        f"one instruction restored at file 0x{FRAME_HOOK_AT:X} / RAM 0x8011C4AC",
        f"  {HOOKED_FRAME_WORD:08X}  jal 0x801A2074",
        f"  {ORIGINAL_FRAME_WORD:08X}  jal 0x8011C814",
        "changed bytes  3, all inside that complete four-byte instruction",
        "text renderer  original (inherited from H_nohook)",
        "startup copy  v151 unchanged",
        "heap boundary v151 unchanged",
        "COMM/DAT       supplied by the original control-disc tree",
        "",
        "runtime decision",
        "  clean: fixed per-frame VRAM uploads caused the monster corruption",
        "  corrupt: startup/reserved-RAM changes remain causal candidates",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
