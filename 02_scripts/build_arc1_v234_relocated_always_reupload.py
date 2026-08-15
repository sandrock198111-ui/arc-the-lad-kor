#!/usr/bin/env python3
"""Build v234: v233 relocation + re-upload every frame (v227's one-word edit).

Why (hardware evidence, states HASH-C70DD0843775831D on v233):
  * The relocation itself works: packets read (U156+,V164), the old rect is
    byte-identical game art, and NO game/text cross-contamination remains.
  * But during the flight/worldmap scene the game writes ZEROES over the new
    rect (the transparent top of its cloud texture: rows y400..447 of page
    15,1 go fully blank).  The occupancy map could never see this - it
    accumulates non-zero writes only.  So glyph pixels vanish (31/252 ink),
    and because the cache-hit test trusts `owners` alone, untouched slots are
    never re-uploaded afterwards (64->193/252 slow recovery = the reported
    vertical fragments and blanks).

Fix: neutralize the cache-hit early-out `0x801FF49C beq t7,t4,+` so every
active slot re-uploads each frame.  v227 proved this exact edit boots and
renders fine outside the worldmap; its worldmap flicker came from competing
with game ART at the old rect.  At (999,420) the game writes only zeroes,
so the worst case is a one-frame blank right after the scene loads.

Base: v233 zip.  One word changes; everything else byte-identical.
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

BASE = ROOT / "03_output/arc1_v233_cache_relocation_TEST_ONLY_EA0E5B9E.zip"
BASE_SHA256 = "A8EBDA3BAF68953ED3839F03F0D8E29B9F74133B60BD4542C3EA3B113C0C7D13"
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v234_relocated_always_reupload_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v234_relocated_always_reupload"
ANALYSIS.mkdir(parents=True, exist_ok=True)
PSX = "PSX.EXE"
R2F = 0x8011A800
HIT_BRANCH_RAM = 0x801FF49C
# the resident image is copied from the EXE at boot; patch the copy source
import build_arc1_v171_ui_asset_recovery as v171  # noqa: E402

old = v171.old


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
        raise SystemExit("GUARD: v233 base sha mismatch")
    with ZipFile(BASE) as z:
        infos = z.infolist()
        members = {i.filename: z.read(i.filename) for i in infos}
    exe = bytearray(members[PSX])

    src = old.file_at(v171.SOURCE_BASE)
    at = src + (HIT_BRANCH_RAM - v171.RESIDENT_BASE)
    word = struct.unpack_from("<I", exe, at)[0]
    # beq t7,t4: op 4, rs=t7(15), rt=t4(12)
    if (word >> 26) != 0x04 or ((word >> 21) & 31) != 15 or ((word >> 16) & 31) != 12:
        raise SystemExit(f"GUARD: word at hit branch is 0x{word:08X}, not beq t7,t4")
    struct.pack_into("<I", exe, at, 0)  # nop

    base_exe = members[PSX]
    diff = [i for i, (a, b) in enumerate(zip(base_exe, bytes(exe))) if a != b]
    if diff != [i for i in range(at, at + 4) if base_exe[i] != bytes(exe)[i]]:
        raise SystemExit(f"GUARD: unexpected diff {[hex(x) for x in diff[:8]]}")

    members[PSX] = bytes(exe)
    payload = b"".join(members[n] for n in sorted(members))
    tag = digest(payload)[:8]
    out = OUT_DIR / f"{OUT_STEM}_{tag}.zip"
    with ZipFile(out, "w", ZIP_DEFLATED) as z:
        for info in infos:
            z.writestr(clone(info), members[info.filename])
    report = [
        f"base={BASE.name}",
        f"patched resident copy source: 0x{HIT_BRANCH_RAM:08X} beq t7,t4 -> nop"
        f" (file 0x{at:X}, was 0x{word:08X})",
        "effect: every active cache slot re-uploads each frame; survives the"
        " flight scene's zero-fill over (999,420)",
        f"exe_changed_bytes={len(diff)}",
        f"zip={out.name}",
        f"zip_sha256={digest(out.read_bytes())}",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n",
                                               encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
