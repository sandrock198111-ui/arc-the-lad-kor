"""Build v172 by restoring the two-byte E9/EA decoder advance.

v171's packed lookup returned the correct glyph but left T9 uninitialised on the
lookup branch.  The shared finish block therefore stored A1+T9 as the next text
pointer; at boot T9 was effectively zero and the first UI token was consumed over
and over.  The missing instruction fits in the lookup branch's existing delay slot,
so this successor changes exactly one PSX.EXE word and no memory budget or layout.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v165_failclosed_cache as old  # noqa: E402


BASE = ROOT / "03_output/arc1_v171_native_ui_assets_28slot_cache_18E5C2DC.zip"
BASE_SHA256 = "18E5C2DC2B84ECCD9A91E742983996EAB35E28F20BA86EB2A0124F497424E8AC"
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v172_lookup_width_fix"
ANALYSIS = ROOT / "01_work/analysis/arc1_v172_lookup_width_fix"
REPORT = ANALYSIS / "build_report.txt"

PSX = "PSX.EXE"
FIX_RUNTIME = 0x801FF318
FIX_SOURCE_RAM = old.SOURCE_BASE + (FIX_RUNTIME - old.RESIDENT_BASE)
BEFORE = old.NOP
AFTER = old.i_type(0x0D, old.ZERO, old.T9, 2)  # ori t9,zero,2
DECODER, DECODER_BYTES = 0x801FF30C, 568
FRAME, FRAME_BYTES = 0x801FF634, 636


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v171 base archive hash differs")
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}
    before_members = dict(members)
    exe = bytearray(members[PSX])
    if old.word(exe, FIX_SOURCE_RAM) != BEFORE:
        raise SystemExit("v171 lookup branch delay word differs")
    old.put_word(exe, FIX_SOURCE_RAM, AFTER)
    if old.word(exe, FIX_SOURCE_RAM) != AFTER:
        raise SystemExit("lookup-width fix did not read back")
    members[PSX] = bytes(exe)

    changed = [name for name in members if members[name] != before_members[name]]
    if changed != [PSX]:
        raise SystemExit(f"changed member set differs: {changed}")
    changed_offsets = [
        at for at, pair in enumerate(zip(before_members[PSX], members[PSX]))
        if pair[0] != pair[1]
    ]
    expected_offsets = {
        old.source_at(FIX_RUNTIME) + delta
        for delta, (a, b) in enumerate(zip(BEFORE.to_bytes(4, "little"),
                                          AFTER.to_bytes(4, "little")))
        if a != b
    }
    if set(changed_offsets) != expected_offsets:
        raise SystemExit("PSX.EXE diff escaped the lookup delay instruction")

    temporary = OUT_DIR / f"{OUT_STEM}_building.zip"
    if temporary.exists():
        raise SystemExit(f"refusing to reuse temporary output: {temporary.name}")
    with ZipFile(temporary, "w", ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(old.clone(info), members[info.filename])
    with ZipFile(temporary) as archive:
        if archive.namelist() != [info.filename for info in infos]:
            raise SystemExit("archive member order changed")
        for name, expected in members.items():
            if archive.read(name) != expected:
                raise SystemExit(f"archive roundtrip differs: {name}")
    stamp = digest(temporary.read_bytes())
    output = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {output.name}")
    temporary.replace(output)

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    lines = [
        "v172 E9/EA lookup-width repair",
        "",
        f"base={BASE.name}", f"base_sha256={BASE_SHA256}",
        f"output={output.name}", f"sha256={stamp}",
        "changed_members=PSX.EXE", "changed_other_members=0",
        f"runtime_word=0x{FIX_RUNTIME:08X}",
        f"source_file_offset=0x{old.source_at(FIX_RUNTIME):X}",
        f"before=0x{BEFORE:08X} NOP",
        f"after=0x{AFTER:08X} ori t9,zero,2",
        "lookup_token_advance=2 bytes",
        "resident_size=unchanged 5356/5356",
        f"decoder 0x{DECODER:08X} / {DECODER_BYTES} bytes",
        f"frame routine 0x{FRAME:08X} / {FRAME_BYTES} bytes",
        "archive_member_order=PASS", "archive_member_lengths=PASS",
        "archive_roundtrip=PASS", "runtime=PENDING user cold boot",
        "rollback=v170", "v171=REJECTED boot stops after BIOS",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(REPORT)


if __name__ == "__main__":
    main()
