"""Fail closed when an active savestate VRAM reader uses a fixed origin.

Historical builders may mention old offsets in comments because reproducing them is
part of the project record.  This audit covers only tools that consume DuckStation
state blobs today.  Each must reach the shared structural ``GPU-VRAM`` locator,
directly or through ``extract_savestate_vram.load``.
"""
from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "01_work/analysis/vram_occupancy_map/vram_reader_audit.txt"

READERS = {
    "02_scripts/extract_savestate_vram.py": "defines locate_vram",
    "02_scripts/extract_savestate_vram_by_font.py": "imports locate_vram",
    "02_scripts/map_vram_occupancy_all_states.py": "imports locate_vram",
    "02_scripts/identify_vram_occupancy_outliers.py": "uses map.locate -> locate_vram",
    "02_scripts/verify_savestate_vram_origin.py": "imports locate_vram",
    "02_scripts/analyze_arc1_v162_runtime.py": "imports locate_vram",
    "02_scripts/analyze_arc1_v163_runtime.py": "imports locate_vram",
    "02_scripts/verify_arc1_v162_strip_a_dynamic_cache.py": "imports locate_vram",
    "02_scripts/audit_vram_page15_free_space.py": "uses extract_savestate_vram.load",
}

REQUIRED = {
    "02_scripts/extract_savestate_vram.py": "GPU_VRAM_MARKER",
    "02_scripts/extract_savestate_vram_by_font.py": "locate_vram",
    "02_scripts/map_vram_occupancy_all_states.py": "locate_vram",
    "02_scripts/identify_vram_occupancy_outliers.py": "from map_vram_occupancy_all_states import",
    "02_scripts/verify_savestate_vram_origin.py": "locate_vram",
    "02_scripts/analyze_arc1_v162_runtime.py": "locate_vram",
    "02_scripts/analyze_arc1_v163_runtime.py": "locate_vram",
    "02_scripts/verify_arc1_v162_strip_a_dynamic_cache.py": "locate_vram",
    "02_scripts/audit_vram_page15_free_space.py": "from extract_savestate_vram import VRAM_W, load",
}

FORBIDDEN = ("0x202058", "GPU+689", "GPU+1329", "VRAM_DUMP_OFFSET")


def main() -> None:
    rows: list[str] = []
    failures: list[str] = []
    for relative, route in READERS.items():
        path = ROOT / relative
        if not path.exists():
            failures.append(f"missing reader: {relative}")
            continue
        text = path.read_text(encoding="utf-8")
        required = REQUIRED[relative]
        bad = [token for token in FORBIDDEN if token in text]
        if required not in text:
            failures.append(f"{relative}: missing route token {required!r}")
        if bad:
            failures.append(f"{relative}: fixed-origin token(s) {', '.join(bad)}")
        rows.append(f"{'FAIL' if required not in text or bad else 'PASS'}  {relative}  [{route}]")

    status = "PASS" if not failures else "FAIL"
    lines = [
        "DuckStation VRAM-reader origin audit",
        f"status={status}",
        f"active_readers={len(READERS)}",
        f"failures={len(failures)}",
        "",
        *rows,
        "",
        "Historical build scripts are intentionally outside this active-reader list.",
        "Exact .vram.bin consumers must validate a 1024x512x16-bit input but do not",
        "locate an origin themselves.",
    ]
    if failures:
        lines.extend(("", "failures:", *failures))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
