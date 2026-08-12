#!/usr/bin/env python3
"""Reproduce the three documented v183-v185 targeted PSX.EXE repairs.

The original v183-v185 patch archives are not available locally.  This builder
starts from the verified v182 archive and applies only the byte writes recorded
in the three contemporaneous reports.  Every write has an old-byte guard and
every stage verifies that PSX.EXE is the sole changed archive member.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile, ZipInfo


V182_SHA256 = "685DAACCC22431D0D45C4AEC4F4D0938CE8A5596856312F7D8898BD8D8DB7920"

STAGES = (
    (
        "arc1_v183_levelup_stat_assembly_fix.zip",
        (
            (0x82534, struct.pack("<I", 0x8019D073), struct.pack("<I", 0x8019FCD4)),
            (0x854D4, bytes(2), bytes.fromhex("9C 00")),
            (0x82538, struct.pack("<I", 0x8019D069), struct.pack("<I", 0x8019FCF0)),
            (0x854F0, bytes(6), bytes.fromhex("9C DF D0 DF D1 00")),
        ),
    ),
    (
        "arc1_v184_levelup_skillname_encoding_fix.zip",
        (
            (
                0x80DC9,
                bytes.fromhex("DF 97 9C E9 19 DE 74 E9 B2 DF 41 00"),
                bytes.fromhex("E9 71 9C E9 19 E9 3F E9 B2 E9 3B 00"),
            ),
        ),
    ),
    (
        "arc1_v185_acquisition_closing_bracket_fix.zip",
        (
            (0x82474, struct.pack("<I", 0x8019CC8B), struct.pack("<I", 0x8019FCF8)),
            (
                0x854F8,
                bytes(14),
                bytes.fromhex("5A 65 9C C3 46 9C C8 91 61 45 78 E0 60 00"),
            ),
        ),
    ),
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in (
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
        setattr(out, attr, getattr(info, attr))
    return out


def byte_diff(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise SystemExit("PSX.EXE size changed")
    return {i for i, (a, b) in enumerate(zip(before, after)) if a != b}


def build_stage(
    base: Path,
    output: Path,
    writes: tuple[tuple[int, bytes, bytes], ...],
) -> None:
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {output}")

    with ZipFile(base, "r") as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}
    if "PSX.EXE" not in members:
        raise SystemExit(f"PSX.EXE is absent from {base}")

    old_exe = members["PSX.EXE"]
    exe = bytearray(old_exe)
    expected_diff: set[int] = set()
    for offset, old, new in writes:
        got = bytes(exe[offset : offset + len(old)])
        if got != old:
            raise SystemExit(
                f"{base.name} 0x{offset:X}: expected {old.hex(' ')}, got {got.hex(' ')}"
            )
        if len(old) != len(new):
            raise SystemExit(f"0x{offset:X}: in-place write changed length")
        exe[offset : offset + len(new)] = new
        expected_diff.update(offset + i for i, (a, b) in enumerate(zip(old, new)) if a != b)

    new_exe = bytes(exe)
    actual_diff = byte_diff(old_exe, new_exe)
    if actual_diff != expected_diff:
        raise SystemExit(
            f"unexpected PSX.EXE diff: expected {len(expected_diff)}, got {len(actual_diff)}"
        )
    members["PSX.EXE"] = new_exe

    with ZipFile(output, "w") as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])

    with ZipFile(base, "r") as before, ZipFile(output, "r") as after:
        if before.namelist() != after.namelist():
            raise SystemExit("archive member order changed")
        changed = [name for name in before.namelist() if before.read(name) != after.read(name)]
        if changed != ["PSX.EXE"]:
            raise SystemExit(f"unexpected changed members: {changed}")
        if after.read("PSX.EXE") != new_exe:
            raise SystemExit("PSX.EXE archive readback failed")

    print(f"{output.name}")
    print(f"  base_sha256   {sha256(base.read_bytes())}")
    print(f"  output_sha256 {sha256(output.read_bytes())}")
    print(f"  PSX.EXE_sha256 {sha256(new_exe)}")
    print(f"  changed_bytes {len(actual_diff)}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("base", type=Path, help="verified v182 patch ZIP")
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()

    if not args.base.is_file():
        raise SystemExit(f"base not found: {args.base}")
    got = sha256(args.base.read_bytes())
    if got != V182_SHA256:
        raise SystemExit(f"v182 SHA256 mismatch: {got}")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    base = args.base
    for filename, writes in STAGES:
        output = args.output_dir / filename
        build_stage(base, output, writes)
        base = output


if __name__ == "__main__":
    main()
