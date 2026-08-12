"""Independent static verification for the v160 RAM-shadow glyph cache."""
from __future__ import annotations

from pathlib import Path

import build_arc1_v160_dynamic_cache_ram_shadow as build
import verify_arc1_v159_dynamic_cache as verify


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "03_output/arc1_v160_dynamic_cache_ram_shadow_53521478.zip"
BUILD_SHA = "53521478B42D9684B8111F883E905ED45D498484C9087BD330AC4B21F0987F2E"
REPORT = ROOT / "01_work/analysis/arc1_v160_dynamic_cache_ram_shadow/independent_verification.txt"


def expected_cache_state(font: bytes,
                         cache_rows: list[dict[str, str]]) -> bytes:
    """Independently reconstruct the five-cell shadow from final COMM.IMG bytes."""
    if len(cache_rows) != verify.CACHE_N:
        raise SystemExit("cache slot count differs")
    out = bytearray()
    for first in range(0, verify.CACHE_N, verify.PLANES):
        group = cache_rows[first:first + verify.PLANES]
        slots = [int(row["cache_slot"]) for row in group]
        planes = [int(row["plane"]) for row in group]
        rows = [int(row["row"]) for row in group]
        columns = [int(row["column"]) for row in group]
        if slots != list(range(first, first + verify.PLANES)) or \
                planes != list(range(verify.PLANES)) or \
                len(set(rows)) != 1 or len(set(columns)) != 1:
            raise SystemExit(f"cache cell grouping differs at slot {first}")
        pixel_x = columns[0] * verify.CELL
        for y in range(verify.CELL):
            at = (rows[0] * verify.CELL + y) * 0x380 + pixel_x // 2
            out += font[at:at + verify.CELL // 2]
    expected_size = verify.CACHE_N // verify.PLANES * verify.CELL * (verify.CELL // 2)
    if len(out) != expected_size:
        raise SystemExit("cache shadow size differs")
    return bytes(out)


verify.BUILD = BUILD
verify.BUILD_SHA = BUILD_SHA
verify.REPORT = REPORT
verify.VERSION_LABEL = "v160"
verify.EXPECTED_FRAME_CALLS = (verify.LOADIMAGE, verify.FRAMESWAP)
verify.expected_cache_state = expected_cache_state
verify.build_frame = build.base.build_frame


if __name__ == "__main__":
    verify.main()
