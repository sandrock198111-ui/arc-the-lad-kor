"""v161: recode only pointer-proven PSX.EXE strings.

v159/v160 passed the whole file range 0x78000..0x82FFF through the glyph-token
rewriter.  That range contains strings *and* their 32-bit pointer tables.  In
particular, the high byte 0x80 of every audited RAM pointer was mistaken for a
one-byte glyph and changed to 0x7D, preventing the game from booting.

This build keeps v160's dynamic cache, COMM.IMG and translated data files.  It
restores the affected executable range byte-for-byte from the runtime-proven v151
and copies v160's recoded bytes back only into strings reached through the project's
543 explicit UI/system/world pointer records.
"""
from __future__ import annotations

import hashlib
import struct
import sys
import zipfile
from pathlib import Path
from zipfile import ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from build_ui_full_v26 import PSX_LOAD_BASE, TABLES  # noqa: E402
from build_ui_safe_v33 import SYSTEM_TEXTS, UI_FIXES, WORLD_TABLE  # noqa: E402


BASE = ROOT / "03_output/arc1_v160_dynamic_cache_ram_shadow_53521478.zip"
BASE_SHA256 = "53521478B42D9684B8111F883E905ED45D498484C9087BD330AC4B21F0987F2E"
V151 = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
V151_SHA256 = "A4358FEE5FEA4964C9DD376B630894EB5EC133EFEEDD9E5E85BBC5FDD8CA1A46"

OUT_DIR = ROOT / "03_output"
OUT_PREFIX = "arc1_v161_bounded_exe_text"
ANALYSIS = ROOT / "01_work/analysis/arc1_v161_bounded_exe_text"
REPORT = ANALYSIS / "build_report.txt"

PSX = "PSX.EXE"
POOL_LO, POOL_HI = 0x78000, 0x83000
MAX_STRING_BYTES = 512


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


def pointer_records() -> dict[int, str]:
    records: dict[int, str] = {}
    for key, (count, _segment, pointer_table) in TABLES.items():
        for index in range(count):
            records[pointer_table + index * 4] = f"{key}[{index}]"
    for pointer, _source, _text in SYSTEM_TEXTS:
        records[pointer] = "system"
    for pointer, _source, _japanese, _korean, _missing in WORLD_TABLE:
        records[pointer] = "world"
    for pointer, _source, _text in UI_FIXES:
        records[pointer] = "ui_fix"
    return records


def target(exe: bytes, pointer: int) -> int:
    return struct.unpack_from("<I", exe, pointer)[0] - PSX_LOAD_BASE


def string_span(exe: bytes, start: int) -> tuple[int, int]:
    if not POOL_LO <= start < POOL_HI:
        raise SystemExit(f"pointer target 0x{start:X} is outside the audited pool")
    end = exe.find(b"\0", start, min(POOL_HI, start + MAX_STRING_BYTES + 1))
    if end < 0:
        raise SystemExit(f"invalid string at 0x{start:X}")
    return start, end


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v160 archive hash differs")
    if digest(V151.read_bytes()) != V151_SHA256:
        raise SystemExit("v151 archive hash differs")

    with zipfile.ZipFile(BASE) as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}
    with zipfile.ZipFile(V151) as archive:
        old_exe = archive.read(PSX)
    new_exe = members[PSX]
    if len(new_exe) != len(old_exe):
        raise SystemExit("PSX.EXE size differs between v151 and v160")

    records = pointer_records()
    if len(records) != 543:
        raise SystemExit(f"audited pointer count changed: {len(records)}")

    spans: dict[tuple[int, int], list[tuple[int, str]]] = {}
    for pointer, label in sorted(records.items()):
        old_target = target(old_exe, pointer)
        span = string_span(old_exe, old_target)
        if new_exe[span[1]] != 0:
            raise SystemExit(f"v160 moved the terminator for {label} at 0x{old_target:X}")
        spans.setdefault(span, []).append((pointer, label))

    pointer_bytes = {
        byte for pointer in records for byte in range(pointer, pointer + 4)
    }
    text_bytes = {byte for start, end in spans for byte in range(start, end)}
    overlap = sorted(pointer_bytes & text_bytes)
    if overlap:
        raise SystemExit(f"a pointer overlaps a string at 0x{overlap[0]:X}")

    # Restore all mixed text/numeric data, then copy only proven string payloads from
    # v160.  NUL terminators stay from v151 and pointer words are never copied.
    out_exe = bytearray(new_exe)
    out_exe[POOL_LO:POOL_HI] = old_exe[POOL_LO:POOL_HI]
    for start, end in spans:
        out_exe[start:end] = new_exe[start:end]

    # Dependency-complete guards: only the mixed pool may differ from v160; inside it
    # each byte is either a proven v160 string byte or an exact v151 byte.
    outside_changes = [
        offset for offset, (before, after) in enumerate(zip(new_exe, out_exe))
        if before != after and not POOL_LO <= offset < POOL_HI
    ]
    if outside_changes:
        raise SystemExit(f"v161 changed PSX.EXE outside the pool at 0x{outside_changes[0]:X}")
    for offset in range(POOL_LO, POOL_HI):
        expected = new_exe[offset] if offset in text_bytes else old_exe[offset]
        if out_exe[offset] != expected:
            raise SystemExit(f"bounded-pool reconstruction differs at 0x{offset:X}")
    damaged_before = sum(
        new_exe[pointer:pointer + 4] != old_exe[pointer:pointer + 4]
        for pointer in records
    )
    damaged_after = sum(
        out_exe[pointer:pointer + 4] != old_exe[pointer:pointer + 4]
        for pointer in records
    )
    if damaged_before != len(records) or damaged_after:
        raise SystemExit(
            f"pointer restoration differs: v160={damaged_before}, v161={damaged_after}"
        )

    changed_from_v160 = sum(a != b for a, b in zip(new_exe, out_exe))
    retained_text_changes = sum(
        old_exe[offset] != out_exe[offset] for offset in text_bytes
    )
    restored_nontext_changes = sum(
        old_exe[offset] != new_exe[offset]
        for offset in range(POOL_LO, POOL_HI) if offset not in text_bytes
    )
    members[PSX] = bytes(out_exe)

    # Build to a temporary unique name and then add the immutable digest suffix.
    temp = OUT_DIR / f"{OUT_PREFIX}.building.zip"
    if temp.exists():
        raise SystemExit(f"stale temporary output exists: {temp}")
    with zipfile.ZipFile(temp, "w") as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    sha = digest(temp.read_bytes())
    output = OUT_DIR / f"{OUT_PREFIX}_{sha[:8]}.zip"
    if output.exists():
        temp.unlink()
        raise SystemExit(f"refusing to overwrite existing output: {output}")
    temp.rename(output)

    report = "\n".join(
        [
            "v161 bounded PSX.EXE text recoding",
            "",
            f"base={BASE.name}",
            f"output={output.name}",
            f"sha256={sha}",
            f"pointer_records={len(records)}",
            f"unique_string_spans={len(spans)}",
            f"proven_string_bytes={len(text_bytes)}",
            f"v160_damaged_pointer_records={damaged_before}",
            f"v161_damaged_pointer_records={damaged_after}",
            f"retained_intentional_text_diff_bytes={retained_text_changes}",
            f"restored_nontext_diff_bytes={restored_nontext_changes}",
            f"PSX_bytes_changed_from_v160={changed_from_v160}",
            "all_nontext_pool_bytes_equal_v151=PASS",
            "all_proven_string_bytes_equal_v160=PASS",
            "all_other_patch_members_equal_v160=PASS",
            "runtime=PENDING",
            "rollback=v151",
            "",
        ]
    )
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(report, encoding="utf-8")
    print(report, end="")


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    main()
