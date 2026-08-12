"""Independently verify v161's bounded PSX.EXE reconstruction."""
from __future__ import annotations

import hashlib
import struct
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from build_ui_full_v26 import PSX_LOAD_BASE, TABLES  # noqa: E402
from build_ui_safe_v33 import SYSTEM_TEXTS, UI_FIXES, WORLD_TABLE  # noqa: E402


V151 = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
V160 = ROOT / "03_output/arc1_v160_dynamic_cache_ram_shadow_53521478.zip"
BUILD = ROOT / "03_output/arc1_v161_bounded_exe_text_B2EA377E.zip"
BUILD_SHA256 = "B2EA377E1E43C1954F42A63F375B8D7B5997A6B736988C315B4C06C76A5F44E3"
REPORT = ROOT / "01_work/analysis/arc1_v161_bounded_exe_text/independent_verification.txt"

PSX = "PSX.EXE"
POOL_LO, POOL_HI = 0x78000, 0x83000


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def load(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as archive:
        return {
            info.filename: archive.read(info.filename)
            for info in archive.infolist() if not info.is_dir()
        }


def pointers() -> set[int]:
    out: set[int] = set()
    for count, _segment, table in TABLES.values():
        out.update(table + index * 4 for index in range(count))
    out.update(row[0] for row in SYSTEM_TEXTS)
    out.update(row[0] for row in WORLD_TABLE)
    out.update(row[0] for row in UI_FIXES)
    return out


def target(exe: bytes, pointer: int) -> int:
    return struct.unpack_from("<I", exe, pointer)[0] - PSX_LOAD_BASE


def main() -> None:
    if digest(BUILD.read_bytes()) != BUILD_SHA256:
        raise SystemExit("v161 archive hash differs")
    old, base, new = load(V151), load(V160), load(BUILD)
    if set(new) != set(base):
        raise SystemExit("archive member set differs from v160")
    changed_members = [name for name in base if base[name] != new[name]]
    if changed_members != [PSX]:
        raise SystemExit(f"members changed from v160: {changed_members}")

    old_exe, base_exe, new_exe = old[PSX], base[PSX], new[PSX]
    if not len(old_exe) == len(base_exe) == len(new_exe):
        raise SystemExit("PSX.EXE size changed")
    outside = [
        offset for offset, (before, after) in enumerate(zip(base_exe, new_exe))
        if before != after and not POOL_LO <= offset < POOL_HI
    ]
    if outside:
        raise SystemExit(f"v161 differs from v160 outside pool at 0x{outside[0]:X}")

    pointer_set = pointers()
    if len(pointer_set) != 543:
        raise SystemExit(f"independent pointer count differs: {len(pointer_set)}")
    spans: set[tuple[int, int]] = set()
    for pointer in sorted(pointer_set):
        if new_exe[pointer:pointer + 4] != old_exe[pointer:pointer + 4]:
            raise SystemExit(f"pointer not restored at 0x{pointer:X}")
        start = target(old_exe, pointer)
        if not POOL_LO <= start < POOL_HI:
            raise SystemExit(f"pointer target outside pool at 0x{pointer:X}")
        end = old_exe.find(b"\0", start, min(POOL_HI, start + 513))
        if end < 0:
            raise SystemExit(f"unterminated string at 0x{start:X}")
        if base_exe[end] != 0 or new_exe[end] != 0:
            raise SystemExit(f"terminator moved at 0x{start:X}")
        spans.add((start, end))

    text = {offset for start, end in spans for offset in range(start, end)}
    pointer_bytes = {
        offset for pointer in pointer_set for offset in range(pointer, pointer + 4)
    }
    if text & pointer_bytes:
        raise SystemExit("pointer bytes overlap proven text")
    for offset in range(POOL_LO, POOL_HI):
        expected = base_exe[offset] if offset in text else old_exe[offset]
        if new_exe[offset] != expected:
            raise SystemExit(f"pool provenance differs at 0x{offset:X}")

    damaged_base = sum(
        base_exe[p:p + 4] != old_exe[p:p + 4] for p in pointer_set
    )
    damaged_new = sum(
        new_exe[p:p + 4] != old_exe[p:p + 4] for p in pointer_set
    )
    changed = sum(a != b for a, b in zip(base_exe, new_exe))
    lines = [
        "v161 independent bounded-text verification",
        "",
        f"archive_sha256={digest(BUILD.read_bytes())}",
        f"archive_members={len(new)}",
        f"changed_members_from_v160={','.join(changed_members)}",
        f"pointer_records={len(pointer_set)}",
        f"unique_string_spans={len(spans)}",
        f"proven_string_bytes={len(text)}",
        f"v160_damaged_pointer_records={damaged_base}",
        f"v161_damaged_pointer_records={damaged_new}",
        f"PSX_bytes_changed_from_v160={changed}",
        "nontext_pool_equals_v151=PASS",
        "proven_text_equals_v160=PASS",
        "outside_pool_equals_v160=PASS",
        "result=PASS",
        "",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines), end="")


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    main()
