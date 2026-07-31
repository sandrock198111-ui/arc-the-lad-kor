#!/usr/bin/env python3
"""Independent static audit for the v0.40 sparse glyph-store probe."""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
BUILD_PATH = ROOT / "02_scripts" / "build_ui_glyph_store_v40.py"


def load_build_module():
    spec = importlib.util.spec_from_file_location("glyph_store_v40_build", BUILD_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load v0.40 build module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def main() -> None:
    build = load_build_module()
    if digest(build.BASE.read_bytes()) != build.BASE_HASH:
        raise SystemExit("FAIL: v0.39 base hash differs")

    with ZipFile(build.BASE) as archive:
        before = {name: archive.read(name) for name in archive.namelist()}
    with ZipFile(build.OUTPUT) as archive:
        after = {name: archive.read(name) for name in archive.namelist()}

    if before.keys() != after.keys():
        raise SystemExit("FAIL: ZIP member set differs")
    changed = [name for name in before if before[name] != after[name]]
    if changed != [build.FONT_TARGET, build.PSX_TARGET]:
        raise SystemExit(f"FAIL: unexpected changed members {changed}")

    map_rows = list(csv.DictReader(build.GLYPH_MAP.open(encoding="utf-8-sig")))
    if len(map_rows) != 278:
        raise SystemExit(f"FAIL: glyph map count {len(map_rows)}")
    codes = [bytes.fromhex(row["code_hex"]) for row in map_rows]
    indices = [int(row["physical_index"]) for row in map_rows]
    if len(set(codes)) != len(codes) or len(set(indices)) != len(indices):
        raise SystemExit("FAIL: duplicate sparse code or physical index")
    if any(code[0] not in range(0xE1, 0xE9) or code[1] in (0, 0xFF) for code in codes):
        raise SystemExit("FAIL: sparse code outside E1-E8/01-FE")
    if any(index not in build.safe_physical_indices() for index in indices):
        raise SystemExit("FAIL: glyph outside declared safe planes")

    records = list(csv.DictReader(build.READBACK.open(encoding="utf-8-sig")))
    if len(records) != 503:
        raise SystemExit(f"FAIL: readback record count {len(records)}")
    preserved = [row for row in records if row["status"] == "preserved_v25_missing_glyph"]
    if len(preserved) != 17:
        raise SystemExit(f"FAIL: preserved Japanese count {len(preserved)}")
    if any(row["encoded_hex"] != row["v40_encoded_hex"] for row in preserved):
        raise SystemExit("FAIL: preserved Japanese payload changed")

    base_psx = before[build.PSX_TARGET]
    out_psx = after[build.PSX_TARGET]
    for _, (count, _, pointer_table) in build.TABLES.items():
        size = count * 4
        if base_psx[pointer_table:pointer_table + size] != out_psx[pointer_table:pointer_table + size]:
            raise SystemExit("FAIL: UI pointer table changed")

    # v0.39 regions that must not regress.
    protected_comm_ranges = (
        (128 * build.ROW_BYTES, 160 * build.ROW_BYTES),  # battle cursor neighborhood
    )
    base_comm = before[build.FONT_TARGET]
    out_comm = after[build.FONT_TARGET]
    for start, end in protected_comm_ranges:
        if base_comm[start:end] != out_comm[start:end]:
            raise SystemExit("FAIL: protected battle-cursor source changed")

    protected_psx = (
        (0x80214, 0x80215),
        (0x820A8, 0x820BC),
        (0x823AC, 0x823C0),
    )
    for start, end in protected_psx:
        if base_psx[start:end] != out_psx[start:end]:
            raise SystemExit(f"FAIL: protected PSX range changed at 0x{start:X}")

    print("PASS: v0.40 sparse glyph-store static audit")
    print(f"output_zip_sha256={digest(build.OUTPUT.read_bytes())}")
    print(f"allocated_glyphs={len(map_rows)}")
    print(f"changed_members={','.join(changed)}")
    print("runtime_status=UNVERIFIED_PROBE")


if __name__ == "__main__":
    main()
