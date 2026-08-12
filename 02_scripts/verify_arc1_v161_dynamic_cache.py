"""Run the dynamic-cache verifier over pointer-proven executable strings only."""
from __future__ import annotations

import struct
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v160_dynamic_cache_ram_shadow as build  # noqa: E402
import verify_arc1_v159_dynamic_cache as verify  # noqa: E402
import verify_arc1_v160_dynamic_cache_ram_shadow as shadow  # noqa: E402
from build_ui_full_v26 import PSX_LOAD_BASE, TABLES  # noqa: E402
from build_ui_safe_v33 import SYSTEM_TEXTS, UI_FIXES, WORLD_TABLE  # noqa: E402


BUILD = ROOT / "03_output/arc1_v161_bounded_exe_text_B2EA377E.zip"
BUILD_SHA = "B2EA377E1E43C1954F42A63F375B8D7B5997A6B736988C315B4C06C76A5F44E3"
V151 = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
REPORT = ROOT / "01_work/analysis/arc1_v161_bounded_exe_text/dynamic_cache_verification.txt"
POOL_LO, POOL_HI = 0x78000, 0x83000


def pointer_set() -> set[int]:
    out: set[int] = set()
    for count, _segment, table in TABLES.values():
        out.update(table + index * 4 for index in range(count))
    out.update(row[0] for row in SYSTEM_TEXTS)
    out.update(row[0] for row in WORLD_TABLE)
    out.update(row[0] for row in UI_FIXES)
    return out


with zipfile.ZipFile(V151) as archive:
    canonical_exe = archive.read(verify.PSX)

canonical_spans: set[tuple[int, int]] = set()
for pointer in pointer_set():
    start = struct.unpack_from("<I", canonical_exe, pointer)[0] - PSX_LOAD_BASE
    if not POOL_LO <= start < POOL_HI:
        raise SystemExit(f"canonical pointer outside pool: 0x{pointer:X}")
    end = canonical_exe.find(b"\0", start, min(POOL_HI, start + 513))
    if end < 0:
        raise SystemExit(f"canonical string is unterminated: 0x{start:X}")
    canonical_spans.add((start, end))


def bounded_text_units(members: dict[str, bytes], ranges: list[tuple[str, int, int]]):
    """Match the original verifier but replace its whole-pool scan with 469 spans."""
    for name, offset, size in ranges:
        if name in members and offset + size <= len(members[name]):
            yield f"body:{name}:0x{offset:X}", members[name][offset:offset + size]

    for name, slots in verify.active_slots(members, ranges).items():
        if name not in members:
            raise ValueError(f"assigned-slot file missing: {name}")
        data = members[name]
        if len(data) < verify.SLOT_BASE + verify.SLOT_COUNT * verify.SLOT_SIZE:
            raise ValueError(f"assigned-slot bank missing: {name}")
        for slot in slots:
            at = verify.SLOT_BASE + slot * verify.SLOT_SIZE
            block = data[at:at + verify.SLOT_SIZE]
            if 0 not in block[:verify.SLOT_SIZE - 1]:
                raise ValueError(f"assigned slot has no terminator: {name}:{slot}")
            end = block.index(0)
            if not end:
                raise ValueError(f"assigned slot is empty: {name}:{slot}")
            yield f"slot:{name}:{slot}", block[:end]

    exe = members[verify.PSX]
    for start, end in sorted(canonical_spans):
        yield f"exe:0x{start:X}", exe[start:end]


verify.BUILD = BUILD
verify.BUILD_SHA = BUILD_SHA
verify.REPORT = REPORT
verify.VERSION_LABEL = "v161"
verify.EXPECTED_FRAME_CALLS = (verify.LOADIMAGE, verify.FRAMESWAP)
verify.expected_cache_state = shadow.expected_cache_state
verify.build_frame = build.base.build_frame
verify.text_units = bounded_text_units


if __name__ == "__main__":
    verify.main()
