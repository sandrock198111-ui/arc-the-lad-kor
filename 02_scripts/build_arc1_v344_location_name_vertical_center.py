#!/usr/bin/env python3
"""Build V344: vertically center 16px location names in their 24px banner.

The dedicated location-name renderer at 0x8016C5A4 retained the original
12px layout: a 24px-high banner and a +6 text-Y inset.  V343 runtime evidence
shows the current 16px glyph packets at banner_y+6, leaving 6px above and 2px
below.  V344 changes only that inset from 6 to 4, yielding 4px/4px margins.

The banner rectangle, location-name table, dialogue renderer, icons, DAT files,
COMM.IMG, and every other V343 byte remain unchanged.
"""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = ROOT / "03_output/arc1_v343_ra_safe_w16_hook_TEST_ONLY_CA08BDEB.zip"
BASE_SHA256 = "CA08BDEB840C5BCC1D76D33D1D48F98EDAD6D764D3DFD48A70E186CBF35099D4"
BASE_PSX_SHA256 = "0CC93BE511AEA6074662728BE59838696BB418EFBE8C9641A669DFF629AFE8DE"
OUTPUT_STEM = "arc1_v344_location_name_vertical_center_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v343"
ANALYSIS = ROOT / "01_work/analysis/arc1_v344_location_name_vertical_center"
PSX = "PSX.EXE"

RAM_TO_FILE = 0x8011A800
LOCATION_RENDERER_RAM = 0x8016C5A4
LOCATION_RENDERER_FILE = LOCATION_RENDERER_RAM - RAM_TO_FILE
LOCATION_RENDERER_SIZE = 0x78
LOCATION_TEXT_Y_RAM = 0x8016C5E8
LOCATION_TEXT_Y_FILE = LOCATION_TEXT_Y_RAM - RAM_TO_FILE
LOCATION_TABLE_FILE = 0x82170
LOCATION_COUNT = 55

OLD_TEXT_Y = 0x34020006       # ori v0,zero,6
NEW_TEXT_Y = 0x34020004       # ori v0,zero,4
BANNER_Y_WORD = 0x34050074    # ori a1,zero,116
BANNER_H_WORD = 0x34070018    # ori a3,zero,24
TEXT_H_WORD = 0x3406000C      # ori a2,zero,12 (object room; packet H is 16)
TEXT_X_INSET_WORD = 0x34070008
class BuildError(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def word(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def read_archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        return names, {name: archive.read(name) for name in names}


def write_archive(path: Path, names: list[str], members: dict[str, bytes]) -> None:
    with ZipFile(path, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for name in names:
            info = ZipInfo(name, date_time=(2026, 8, 30, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, members[name], compress_type=ZIP_DEFLATED, compresslevel=9)


def changed_offsets(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise BuildError("member size changed")
    return {
        offset
        for offset, (old, new) in enumerate(zip(before, after, strict=True))
        if old != new
    }


def location_table_census(exe: bytes) -> tuple[int, int, int]:
    pointers = [word(exe, LOCATION_TABLE_FILE + index * 4) for index in range(LOCATION_COUNT)]
    nonempty = 0
    max_tokens = 0
    for pointer in pointers:
        at = pointer - RAM_TO_FILE
        if not 0 <= at < len(exe):
            raise BuildError(f"location pointer outside PSX.EXE: 0x{pointer:08X}")
        end = exe.find(b"\0", at)
        if end < 0:
            raise BuildError(f"unterminated location string: 0x{pointer:08X}")
        if end > at:
            nonempty += 1
            cursor = at
            tokens = 0
            while cursor < end:
                cursor += 1 if exe[cursor] < 0xDD else 2
                tokens += 1
            max_tokens = max(max_tokens, tokens)
    return len(pointers), nonempty, max_tokens


def main() -> None:
    if not BASE.is_file() or sha(BASE.read_bytes()) != BASE_SHA256:
        raise BuildError("V343 base archive hash drift")
    names, base = read_archive(BASE)
    if len(names) != 164 or sha(base[PSX]) != BASE_PSX_SHA256:
        raise BuildError("V343 member topology or PSX hash drift")

    exe = bytearray(base[PSX])
    anchors = {
        LOCATION_TEXT_Y_FILE: OLD_TEXT_Y,
        0x51DDC: BANNER_Y_WORD,
        0x51DE4: BANNER_H_WORD,
        0x51DFC: TEXT_H_WORD,
        0x51E04: TEXT_X_INSET_WORD,
    }
    for offset, expected in anchors.items():
        if word(exe, offset) != expected:
            raise BuildError(f"location-renderer anchor drift at 0x{offset:X}")
    table_count, nonempty_count, max_tokens = location_table_census(exe)
    if (table_count, nonempty_count) != (55, 54):
        raise BuildError("location table census drift")

    struct.pack_into("<I", exe, LOCATION_TEXT_Y_FILE, NEW_TEXT_Y)
    if word(exe, 0x51DDC) != BANNER_Y_WORD or word(exe, 0x51DE4) != BANNER_H_WORD:
        raise BuildError("banner geometry changed")

    final = dict(base)
    final[PSX] = bytes(exe)
    changed_members = [name for name in names if final[name] != base[name]]
    if changed_members != [PSX]:
        raise BuildError(f"unexpected changed members: {changed_members}")
    actual = changed_offsets(base[PSX], final[PSX])
    if actual != {LOCATION_TEXT_Y_FILE}:
        raise BuildError(f"Expected-Write mismatch: {sorted(actual)}")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    tmp_full = ROOT / "03_output" / f"{OUTPUT_STEM}.zip"
    tmp_delta = ROOT / "03_output" / f"{DELTA_STEM}.zip"
    write_archive(tmp_full, names, final)
    write_archive(tmp_delta, [PSX], {PSX: final[PSX]})
    full_hash = sha(tmp_full.read_bytes())
    delta_hash = sha(tmp_delta.read_bytes())
    final_full = tmp_full.with_name(f"{OUTPUT_STEM}_{full_hash[:8]}.zip")
    final_delta = tmp_delta.with_name(f"{DELTA_STEM}_{delta_hash[:8]}.zip")
    for target in (final_full, final_delta):
        if target.exists():
            target.unlink()
    tmp_full.replace(final_full)
    tmp_delta.replace(final_delta)

    with (ANALYSIS / "expected_writes.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.DictWriter(
            handle, fieldnames=("member", "offset", "before", "after", "reason")
        )
        writer.writeheader()
        writer.writerow({
            "member": PSX,
            "offset": f"0x{LOCATION_TEXT_Y_FILE:X}",
            "before": f"{base[PSX][LOCATION_TEXT_Y_FILE]:02X}",
            "after": f"{final[PSX][LOCATION_TEXT_Y_FILE]:02X}",
            "reason": "location_name_text_y_inset_6_to_4",
        })

    manifest = {
        "version": "V344",
        "status": "STATIC_PASS_RUNTIME_PENDING",
        "base": {"file": BASE.name, "sha256": BASE_SHA256, "runtime": "PASS_GAMEPLAY"},
        "output": {"file": final_full.name, "sha256": full_hash},
        "delta": {"file": final_delta.name, "sha256": delta_hash},
        "changed_members_vs_v343": [PSX],
        "changed_psx_bytes": len(actual),
        "location_renderer": {
            "ram": f"0x{LOCATION_RENDERER_RAM:08X}",
            "text_y_word_ram": f"0x{LOCATION_TEXT_Y_RAM:08X}",
            "before_inset": 6,
            "after_inset": 4,
            "banner_height": 24,
            "glyph_height": 16,
            "resulting_margins": [4, 4],
            "location_entries": table_count,
            "nonempty_entries": nonempty_count,
            "max_tokens": max_tokens,
        },
        "runtime_evidence": {
            "state": "HASH-367FC88B8ECDBD3B_1.sav",
            "sha256": "430000D1C22F996AB68B7D73B7F4AF2C32DA2C37ED0C575E8DFABFA17F99CCCB",
            "game_id": "V343",
            "visible_text": "정령의 산",
            "packet_y": 122,
            "banner_y": 116,
        },
        "preserved": [
            "V343 RA-safe W16 control flow byte exact",
            "all DAT and COMM members byte exact",
            "banner rectangle and every icon path byte exact",
            "dialogue/item/skill/battle UI geometry byte exact",
        ],
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V344 location-name vertical-center build",
        f"base={BASE.name} sha256={BASE_SHA256}",
        f"output={final_full.name} sha256={full_hash}",
        f"delta={final_delta.name} sha256={delta_hash}",
        f"PSX.EXE sha256={sha(final[PSX])}",
        "changed_members_vs_v343=PSX.EXE",
        "changed_PSX_bytes=1; Expected-Write exact",
        "location banner=24px; glyph=16px; text inset 6->4; margins 4px/4px",
        "55 location entries (54 nonempty) share the dedicated renderer",
        "all DAT/COMM, banner geometry, dialogue, icons, and other V343 bytes preserved",
        "runtime=V343 gameplay PASS; V344 alignment PENDING cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    (ANALYSIS / "runtime_checklist.txt").write_text(
        "V344 cold-boot checklist\n"
        "1. Enter a scene that displays a location banner (for example 정령의 산).\n"
        "2. Confirm the location glyph cell moved from Y=122 to Y=120 while the banner stayed at Y=116.\n"
        "3. Confirm the banner has equal 4px top/bottom cell margins.\n"
        "4. Confirm dialogue, item/skill names, battle help, and icons match V343.\n",
        encoding="utf-8",
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
