"""K diagnostic: reproduce only v151's reduced game heap on the clean F control.

F_sizeonly is runtime-clean and differs from the pristine executable only by the
larger loaded-image size and its inert tail.  This build changes one complete MIPS
instruction at file offset 0x5B010:

    original  addiu a0,a0,-0x1C3C   -> heap boundary 0x801FE3C4
    K         addiu a0,a0,-0x0750   -> heap boundary 0x801FF8B0

The original startup clear, original renderer and original data remain in use.  No
resident block is copied and no patched code reads high RAM.  Therefore the runtime
result isolates heap capacity without the invalid dependencies in G, I or J.
"""
from __future__ import annotations

import hashlib
import struct
import sys
import zipfile
from pathlib import Path
from zipfile import ZipFile, ZipInfo

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/DIAG_exe_size_only.zip"
BASE_SHA256 = "D086BB7C5265375E694289B35E33067D28922F0996654FD60E975A44931334C8"
OUT_DIR = ROOT / "03_output"
ANALYSIS = ROOT / "01_work/analysis/diag_k_heap_only"

HEAP_WORD_AT = 0x5B010
ORIGINAL_WORD = 0x2484E3C4
V151_WORD = 0x2484F8B0
ORIGINAL_BOUNDARY = 0x801FE3C4
V151_BOUNDARY = 0x801FF8B0


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


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("F size-only control hash mismatch")

    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        if [info.filename for info in infos] != ["PSX.EXE"]:
            raise SystemExit("F control must contain only PSX.EXE")
        exe = bytearray(archive.read("PSX.EXE"))

    if len(exe) != 587_776:
        raise SystemExit(f"unexpected executable size: {len(exe)}")
    if struct.unpack_from("<I", exe, 0x1C)[0] != 0x8F000:
        raise SystemExit("F control does not have t_size 0x8F000")
    if struct.unpack_from("<I", exe, HEAP_WORD_AT)[0] != ORIGINAL_WORD:
        raise SystemExit("F control heap instruction is not original")

    before = bytes(exe)
    struct.pack_into("<I", exe, HEAP_WORD_AT, V151_WORD)
    after = bytes(exe)

    changed = [index for index, (old, new) in enumerate(zip(before, after)) if old != new]
    if changed != [HEAP_WORD_AT, HEAP_WORD_AT + 1]:
        raise SystemExit(f"unexpected changed bytes: {changed}")
    if struct.unpack_from("<I", after, HEAP_WORD_AT)[0] != V151_WORD:
        raise SystemExit("heap instruction readback failed")
    if before[:HEAP_WORD_AT] != after[:HEAP_WORD_AT] or before[HEAP_WORD_AT + 4:] != after[HEAP_WORD_AT + 4:]:
        raise SystemExit("bytes outside the one instruction changed")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    temp = OUT_DIR / "DIAG_K_heap_only_building.zip"
    with ZipFile(temp, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(clone(infos[0]), after)
    stamp = digest(temp.read_bytes())
    final = OUT_DIR / f"DIAG_K_heap_only_{stamp[:8]}.zip"
    if final.exists():
        raise SystemExit(f"refusing to overwrite existing output: {final.name}")
    temp.replace(final)

    report = [
        "K heap-only diagnostic",
        "",
        f"base    {BASE.name}",
        f"output  {final.name}",
        f"sha256  {stamp}",
        "",
        f"single instruction  file 0x{HEAP_WORD_AT:X}",
        f"  {ORIGINAL_WORD:08X} -> {V151_WORD:08X}",
        f"heap boundary  0x{ORIGINAL_BOUNDARY:08X} -> 0x{V151_BOUNDARY:08X}",
        f"capacity reduction  {V151_BOUNDARY - ORIGINAL_BOUNDARY} bytes",
        "changed bytes  2, both inside that complete 4-byte instruction",
        "startup copy   original",
        "renderer       original",
        "font/dialogue  original control-disc inputs",
        "",
        "runtime decision",
        "  corrupt: reduced heap is causal for this monster scene",
        "  clean: reject the reduced-heap hypothesis",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
