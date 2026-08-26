#!/usr/bin/env python3
"""Build V320B: keep V320's data/font fixes and restore V319's EXE pointer pool.

V320 treated every zero-delimited run in PSX.EXE 0x78000..0x82FFF as text.
That range is mixed data: the existing pointer audit catalogs 4,262 pointer
words there and elsewhere.  V320 changed 3,126 of those words, including the
live 0x801354F0 pointer at file offset 0x7E5F8.  The failed V320R resume state
captured PC/EPC 0xD30B54F0, exactly the corrupted value stored at that offset.

This diagnostic repair changes one member relative to V320:

* PSX.EXE[0x78000:0x83000] is restored byte-for-byte from V319R.

V320's changes outside that mixed pool remain intact: the physical-space
comparison, packed E9/EA lookup aliases, and resident decoder trampoline.
All DAT members and COMM.IMG also remain byte-identical to V320.  The builder
fails unless every cataloged pointer returns to its V319 value and the complete
diff is explained by the pool restoration.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "03_output"
ANALYSIS_DIR = ROOT / "01_work/analysis/arc1_v320b_exe_pointer_restore"

V319 = OUTPUT_DIR / "arc1_v319_pilgi16_integration_TEST_ONLY_07418C00.zip"
V319_SHA256 = "07418C0024C4059C550E1584FC29340C6B97D9CF9B9DE778CA1FE38ACCB74A49"
V320 = OUTPUT_DIR / "arc1_v320_hanme_static_recovery_TEST_ONLY_96626CCB.zip"
V320_SHA256 = "96626CCB445BD6F1F249FCB21EA15CE2EAD6B94BE95DED3DC366B38BE9D234F3"

POINTER_CATALOG = ROOT / "01_work/analysis/ui_safe_v33/nonstory_psx_pointer_audit.csv"
POINTER_CATALOG_SHA256 = "F01995739AF704597813A3E86CD7B4F09FF6AA08B8C531346AC6F790375AC4A9"

OUTPUT_STEM = "arc1_v320b_hanme_exe_pointer_restore_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v320"
PSX = "PSX.EXE"

EXPECTED_MEMBERS = 164
EXPECTED_EXE_SIZE = 587_776
V319_EXE_SHA256 = "F47F75756964C1312A6D0F1C61BF0548F433398EC0928E059DFC97D3E3CAE33E"
V320_EXE_SHA256 = "FDF9C1E517BDA9FE69214727D54B2BD603EB7586AB192EDB3639A35298FF2BE7"
V320B_EXE_SHA256 = "3D477AF6E97860485D89ADA92932FA90FA05B0834B583072E7A0946D2912D291"

POOL_START = 0x78000
POOL_END = 0x83000
CRASH_POINTER_OFFSET = 0x7E5F8
V319_CRASH_POINTER = 0x801354F0
V320_CRASH_POINTER = 0xD30B54F0

EXPECTED_POINTER_ROWS = 4_262
EXPECTED_BROKEN_CATALOG_POINTERS = 3_126
EXPECTED_BROKEN_ALIGNED_POINTERS = 3_993
EXPECTED_POOL_DIFF_BYTES = 17_145
EXPECTED_REMAINING_DIFF_BYTES = 299

# The only intentional V320 changes outside the mixed EXE pool.
OUTSIDE_ALLOWED = (
    (0x50D24, 0x50D28, "space physical-index comparison"),
    (0x8CD20, 0x8CF5A, "packed E9/EA lookup aliases"),
    (0x8EE84, 0x8EE88, "resident decoder one-byte branch"),
    (0x8EE8C, 0x8EE94, "resident decoder stock trampoline"),
)


class BuildError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def clone_zipinfo(info: ZipInfo) -> ZipInfo:
    clone = ZipInfo(info.filename, info.date_time)
    for attribute in (
        "compress_type",
        "comment",
        "extra",
        "create_system",
        "create_version",
        "extract_version",
        "flag_bits",
        "volume",
        "internal_attr",
        "external_attr",
    ):
        setattr(clone, attribute, getattr(info, attribute))
    return clone


def read_archive(path: Path) -> tuple[list[ZipInfo], dict[str, bytes]]:
    with ZipFile(path) as archive:
        infos = archive.infolist()
        if any(info.is_dir() for info in infos):
            raise BuildError(f"directory member in {path.name}")
        if len({info.filename for info in infos}) != len(infos):
            raise BuildError(f"duplicate member in {path.name}")
        members = {info.filename: archive.read(info.filename) for info in infos}
    return infos, members


def make_zip(infos: list[ZipInfo], members: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with ZipFile(stream, "w", ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone_zipinfo(info), members[info.filename])
    return stream.getvalue()


def plausible_pointer(value: int) -> bool:
    return (
        0x80010000 <= value < 0x80200000
        or 0xA0000000 <= value < 0xA0200000
        or 0xBFC00000 <= value < 0xBFC80000
    )


def load_pointer_catalog() -> list[dict[str, str]]:
    if sha256_file(POINTER_CATALOG) != POINTER_CATALOG_SHA256:
        raise BuildError("pointer catalog hash drift")
    with POINTER_CATALOG.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != EXPECTED_POINTER_ROWS:
        raise BuildError(f"pointer catalog row drift: {len(rows)}")
    offsets = [int(row["pointer_offset"], 0) for row in rows]
    if len(set(offsets)) != len(offsets):
        raise BuildError("pointer catalog contains duplicate offsets")
    return rows


def changed_offsets(left: bytes, right: bytes) -> set[int]:
    if len(left) != len(right):
        raise BuildError("cannot compare different-sized executables")
    return {offset for offset, pair in enumerate(zip(left, right)) if pair[0] != pair[1]}


def main() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    if sha256_file(V319) != V319_SHA256:
        raise BuildError("V319 input hash drift")
    if sha256_file(V320) != V320_SHA256:
        raise BuildError("V320 input hash drift")

    infos319, members319 = read_archive(V319)
    infos320, members320 = read_archive(V320)
    names319 = [info.filename for info in infos319]
    names320 = [info.filename for info in infos320]
    if names319 != names320 or len(names320) != EXPECTED_MEMBERS:
        raise BuildError("V319/V320 member order or count drift")
    if PSX not in members319:
        raise BuildError("PSX.EXE missing")
    for name in names320:
        if len(members319[name]) != len(members320[name]):
            raise BuildError(f"member size drift: {name}")

    exe319 = members319[PSX]
    exe320 = members320[PSX]
    if len(exe319) != EXPECTED_EXE_SIZE or len(exe320) != EXPECTED_EXE_SIZE:
        raise BuildError("PSX.EXE size drift")
    if sha256_bytes(exe319) != V319_EXE_SHA256:
        raise BuildError("V319 PSX.EXE hash drift")
    if sha256_bytes(exe320) != V320_EXE_SHA256:
        raise BuildError("V320 PSX.EXE hash drift")

    old_crash = struct.unpack_from("<I", exe319, CRASH_POINTER_OFFSET)[0]
    bad_crash = struct.unpack_from("<I", exe320, CRASH_POINTER_OFFSET)[0]
    if (old_crash, bad_crash) != (V319_CRASH_POINTER, V320_CRASH_POINTER):
        raise BuildError(
            f"crash-pointer evidence drift: {old_crash:08X}->{bad_crash:08X}"
        )

    pointer_rows = load_pointer_catalog()
    broken_rows: list[dict[str, object]] = []
    for row in pointer_rows:
        offset = int(row["pointer_offset"], 0)
        if offset + 4 > len(exe319):
            raise BuildError(f"pointer outside executable: 0x{offset:X}")
        if exe319[offset : offset + 4] != exe320[offset : offset + 4]:
            broken_rows.append(
                {
                    "pointer_offset": offset,
                    "v319": struct.unpack_from("<I", exe319, offset)[0],
                    "v320": struct.unpack_from("<I", exe320, offset)[0],
                    "category": row["category"],
                    "confirmed_text_pool": row["confirmed_text_pool"],
                }
            )
    if len(broken_rows) != EXPECTED_BROKEN_CATALOG_POINTERS:
        raise BuildError(f"broken catalog-pointer census drift: {len(broken_rows)}")

    broken_aligned = []
    for offset in range(POOL_START, POOL_END, 4):
        old = struct.unpack_from("<I", exe319, offset)[0]
        new = struct.unpack_from("<I", exe320, offset)[0]
        if old != new and plausible_pointer(old):
            broken_aligned.append((offset, old, new))
    if len(broken_aligned) != EXPECTED_BROKEN_ALIGNED_POINTERS:
        raise BuildError(f"broken aligned-pointer census drift: {len(broken_aligned)}")

    diff319_320 = changed_offsets(exe319, exe320)
    pool_diffs = {offset for offset in diff319_320 if POOL_START <= offset < POOL_END}
    if len(pool_diffs) != EXPECTED_POOL_DIFF_BYTES:
        raise BuildError(f"mixed-pool diff census drift: {len(pool_diffs)}")
    outside_diffs = diff319_320 - pool_diffs
    allowed_outside = {
        offset
        for start, end, _label in OUTSIDE_ALLOWED
        for offset in range(start, end)
    }
    if not outside_diffs <= allowed_outside:
        first = min(outside_diffs - allowed_outside)
        raise BuildError(f"unexplained V320 EXE change outside pool: 0x{first:X}")
    if len(outside_diffs) != EXPECTED_REMAINING_DIFF_BYTES:
        raise BuildError(f"remaining intended diff census drift: {len(outside_diffs)}")

    exe320b = bytearray(exe320)
    exe320b[POOL_START:POOL_END] = exe319[POOL_START:POOL_END]
    exe320b = bytes(exe320b)
    if sha256_bytes(exe320b) != V320B_EXE_SHA256:
        raise BuildError("V320B PSX.EXE hash drift")
    if exe320b[:POOL_START] != exe320[:POOL_START] or exe320b[POOL_END:] != exe320[POOL_END:]:
        raise BuildError("V320B changed bytes outside the restored pool")
    if changed_offsets(exe320, exe320b) != pool_diffs:
        raise BuildError("V320B expected-write set differs from the pool repair")
    if changed_offsets(exe319, exe320b) != outside_diffs:
        raise BuildError("V320B retained an unexplained change against V319")
    if struct.unpack_from("<I", exe320b, CRASH_POINTER_OFFSET)[0] != V319_CRASH_POINTER:
        raise BuildError("live crash pointer was not restored")

    remaining_pointer_changes = []
    for row in pointer_rows:
        offset = int(row["pointer_offset"], 0)
        if exe319[offset : offset + 4] != exe320b[offset : offset + 4]:
            remaining_pointer_changes.append(offset)
    if remaining_pointer_changes:
        raise BuildError(
            f"cataloged pointer still changed at 0x{remaining_pointer_changes[0]:X}"
        )
    remaining_aligned = []
    for offset in range(POOL_START, POOL_END, 4):
        old = struct.unpack_from("<I", exe319, offset)[0]
        new = struct.unpack_from("<I", exe320b, offset)[0]
        if plausible_pointer(old) and old != new:
            remaining_aligned.append(offset)
    if remaining_aligned:
        raise BuildError(f"aligned pointer still changed at 0x{remaining_aligned[0]:X}")

    members320b = dict(members320)
    members320b[PSX] = exe320b
    changed_members = [name for name in names320 if members320[name] != members320b[name]]
    if changed_members != [PSX]:
        raise BuildError(f"V320B changed-member set drift: {changed_members}")

    full1 = make_zip(infos320, members320b)
    full2 = make_zip(infos320, members320b)
    if full1 != full2:
        raise BuildError("full ZIP rebuild is not deterministic")
    full_sha = sha256_bytes(full1)
    full_path = OUTPUT_DIR / f"{OUTPUT_STEM}_{full_sha[:8]}.zip"
    if full_path.exists():
        if full_path.read_bytes() != full1:
            raise BuildError(f"refusing to overwrite different output: {full_path}")
    else:
        full_path.write_bytes(full1)

    psx_info = next(info for info in infos320 if info.filename == PSX)
    delta1 = make_zip([psx_info], {PSX: exe320b})
    delta2 = make_zip([psx_info], {PSX: exe320b})
    if delta1 != delta2:
        raise BuildError("delta ZIP rebuild is not deterministic")
    delta_sha = sha256_bytes(delta1)
    delta_path = OUTPUT_DIR / f"{DELTA_STEM}_{delta_sha[:8]}.zip"
    if delta_path.exists():
        if delta_path.read_bytes() != delta1:
            raise BuildError(f"refusing to overwrite different output: {delta_path}")
    else:
        delta_path.write_bytes(delta1)

    ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
    manifest_path = ANALYSIS_DIR / "restored_pointer_manifest.csv"
    with manifest_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "pointer_offset",
                "v319_value",
                "v320_value",
                "v320b_value",
                "category",
                "confirmed_text_pool",
            ),
        )
        writer.writeheader()
        for item in broken_rows:
            writer.writerow(
                {
                    "pointer_offset": f"0x{int(item['pointer_offset']):X}",
                    "v319_value": f"0x{int(item['v319']):08X}",
                    "v320_value": f"0x{int(item['v320']):08X}",
                    "v320b_value": f"0x{int(item['v319']):08X}",
                    "category": item["category"],
                    "confirmed_text_pool": item["confirmed_text_pool"],
                }
            )

    report = {
        "build": "V320B TEST ONLY - V320 mixed EXE pointer-pool restore",
        "input_v319": V319.name,
        "input_v319_sha256": V319_SHA256,
        "input_v320": V320.name,
        "input_v320_sha256": V320_SHA256,
        "output": full_path.name,
        "output_sha256": full_sha,
        "delta_from_v320": delta_path.name,
        "delta_sha256": delta_sha,
        "psx_exe_sha256": V320B_EXE_SHA256,
        "changed_members_from_v320": changed_members,
        "restored_pool": [f"0x{POOL_START:X}", f"0x{POOL_END:X}"],
        "restored_pool_diff_bytes": len(pool_diffs),
        "catalog_pointer_rows": len(pointer_rows),
        "catalog_pointers_corrupted_in_v320": len(broken_rows),
        "catalog_pointers_changed_in_v320b": 0,
        "aligned_plausible_pointers_corrupted_in_v320": len(broken_aligned),
        "aligned_plausible_pointers_changed_in_v320b": 0,
        "crash_pointer": {
            "file_offset": f"0x{CRASH_POINTER_OFFSET:X}",
            "v319": f"0x{V319_CRASH_POINTER:08X}",
            "v320": f"0x{V320_CRASH_POINTER:08X}",
            "v320b": f"0x{V319_CRASH_POINTER:08X}",
        },
        "v320_changes_preserved_outside_pool": len(outside_diffs),
        "runtime": "PENDING user cold boot; V320R is rejected",
    }
    (ANALYSIS_DIR / "build_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (ANALYSIS_DIR / "build_report.txt").write_text(
        "\n".join(
            (
                "V320B TEST ONLY - V320 mixed EXE pointer-pool restore",
                f"input={V320.name} ({V320_SHA256})",
                f"rollback_source={V319.name} ({V319_SHA256})",
                f"output={full_path.name}",
                f"sha256={full_sha}",
                f"delta={delta_path.name}",
                f"delta_sha256={delta_sha}",
                f"PSX.EXE_sha256={V320B_EXE_SHA256}",
                f"changed_members_from_v320={','.join(changed_members)}",
                f"restored_pool=0x{POOL_START:X}..0x{POOL_END - 1:X}",
                f"restored_pool_diff_bytes={len(pool_diffs)}",
                f"pointer_catalog={len(pointer_rows)} rows; V320 broken={len(broken_rows)}; V320B changed=0",
                f"aligned_pointer_scan=V320 broken {len(broken_aligned)}; V320B changed 0",
                f"crash_pointer=0x{CRASH_POINTER_OFFSET:X}: {V320_CRASH_POINTER:08X}->{V319_CRASH_POINTER:08X}",
                f"V320_changes_preserved_outside_pool={len(outside_diffs)} bytes",
                "DAT_and_COMM=byte-identical to V320",
                "runtime=PENDING user cold boot; V320R is rejected",
            )
        )
        + "\n",
        encoding="utf-8",
    )

    print("V320B TEST ONLY - EXE pointer-pool restore")
    print(f"  full    {full_path.name}")
    print(f"  sha256  {full_sha}")
    print(f"  delta   {delta_path.name}")
    print(f"  sha256  {delta_sha}")
    print(f"  PSX.EXE {V320B_EXE_SHA256}")
    print(f"  restored pointer words {len(broken_rows):,}/{len(pointer_rows):,}")
    print(f"  restored aligned candidates {len(broken_aligned):,}")
    print("  V320B pointer changes vs V319: 0")
    print("  runtime PENDING user cold boot")


if __name__ == "__main__":
    main()
