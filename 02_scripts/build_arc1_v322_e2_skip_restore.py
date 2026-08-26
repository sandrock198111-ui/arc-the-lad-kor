#!/usr/bin/env python3
"""Build V322: restore E2 inline-skip metadata erased by V321.

V321 rewrote five external text slots with a helper that zero-filled all 128
bytes.  Byte +0x7F is not padding: the E2 completion hook reads it as the
number of preserved inline bytes to skip.  This build changes only those five
metadata bytes.  Text payloads, inline control wrappers, font, EXE, geometry,
and every other archive member stay byte-identical to V321.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/arc1_v321_text_identity_repair_TEST_ONLY_1B04A832.zip"
BASE_SHA256 = "1B04A832B33BF061A1AAC8BEE1186B53D6FE977ACA5295C6B5A019CD0759DDFF"
BASE_MEMBER_SHA256 = {
    "1/S1031.DAT": "B43DEA92E1D74C2E4457F1D9A15E7535E6B22C70BF831A17C4E56D45EA547C19",
    "D/SD011.DAT": "44E5F0887E93F54E9F387967251C2F2ABA552A5AA2DA887778E16974BCA67683",
}

OUTPUT_DIR = ROOT / "03_output"
ANALYSIS_DIR = ROOT / "01_work/analysis/arc1_v322_e2_skip_restore"
OUTPUT_STEM = "arc1_v322_e2_skip_restore_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v321"
EXPECTED_MEMBERS = 164
SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
METADATA_OFFSET = 0x7F

# member, slot, E2 command offset, command bytes, skipped bytes, resume prefix
CALLERS = (
    (
        "1/S1031.DAT", 0, 0x4787A, bytes.fromhex("E2 81"),
        bytes.fromhex("E6 01 90 94 9C 9C 9C"), bytes.fromhex("00 00"),
    ),
    (
        "D/SD011.DAT", 10, 0x47B60, bytes.fromhex("E2 8B"),
        bytes.fromhex("9C 9C 9C 9C 9C 9C 9C 9C 9C 9C"), bytes.fromhex("E4 1F"),
    ),
    (
        "D/SD011.DAT", 11, 0x47B70, bytes.fromhex("E2 8C"),
        bytes.fromhex("9C 9C 9C 9C 9C 9C 9C 9C 9C"), bytes.fromhex("E4 33"),
    ),
    (
        "D/SD011.DAT", 12, 0x47D58, bytes.fromhex("E2 8D"),
        bytes.fromhex("9C 9C 9C 9C"), bytes.fromhex("E6 01"),
    ),
    (
        "D/SD011.DAT", 0, 0x47D62, bytes.fromhex("E2 81"),
        bytes.fromhex("9C 9C 9C 9C 9C 9C 9C 9C 9C 9C 9C"), bytes.fromhex("E4 79"),
    ),
)


class BuildError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def clone_zipinfo(info: ZipInfo) -> ZipInfo:
    clone = ZipInfo(info.filename, info.date_time)
    for attribute in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(clone, attribute, getattr(info, attribute))
    return clone


def read_archive(path: Path) -> tuple[list[ZipInfo], dict[str, bytes]]:
    with ZipFile(path) as archive:
        infos = archive.infolist()
        members = {
            info.filename: archive.read(info.filename)
            for info in infos
            if not info.is_dir()
        }
    if len(members) != EXPECTED_MEMBERS or len(members) != len(set(members)):
        raise BuildError("base archive topology drift")
    return infos, members


def write_archive(
    stem: str,
    infos: list[ZipInfo],
    members: dict[str, bytes],
    selected: set[str] | None,
) -> tuple[Path, str]:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    temporary = OUTPUT_DIR / f".{stem}.{os.getpid()}.building.zip"
    if temporary.exists():
        raise BuildError(f"temporary output exists: {temporary}")
    try:
        with ZipFile(temporary, "w", ZIP_DEFLATED, compresslevel=1) as archive:
            for info in infos:
                if info.is_dir():
                    if selected is None:
                        archive.writestr(clone_zipinfo(info), b"")
                    continue
                if selected is None or info.filename in selected:
                    archive.writestr(clone_zipinfo(info), members[info.filename])
        digest = sha256_file(temporary)
        final = OUTPUT_DIR / f"{stem}_{digest[:8]}.zip"
        if final.exists():
            if sha256_file(final) != digest:
                raise BuildError(f"existing output differs: {final}")
            temporary.unlink()
        else:
            temporary.replace(final)
        return final, digest
    finally:
        if temporary.exists():
            temporary.unlink()


def main() -> None:
    if not BASE.is_file() or sha256_file(BASE) != BASE_SHA256:
        raise BuildError(f"V321 base hash mismatch: {BASE}")
    infos, before = read_archive(BASE)
    for name, expected in BASE_MEMBER_SHA256.items():
        if sha256_bytes(before[name]) != expected:
            raise BuildError(f"base member hash drift: {name}")

    members = {name: bytearray(data) for name, data in before.items()}
    expected_offsets: dict[str, set[int]] = {}
    evidence_rows: list[dict[str, object]] = []
    for member, slot, site, command, skipped, resume_prefix in CALLERS:
        data = members[member]
        metadata = SLOT_BASE + slot * SLOT_SIZE + METADATA_OFFSET
        skip = len(skipped)
        resume = site + len(command) + skip

        if bytes(data[site : site + len(command)]) != command:
            raise BuildError(f"E2 command drift: {member}:0x{site:X}")
        if bytes(data[site + len(command) : resume]) != skipped:
            raise BuildError(f"preserved inline skip span drift: {member}:0x{site:X}")
        if bytes(data[resume : resume + len(resume_prefix)]) != resume_prefix:
            raise BuildError(f"E2 resume target drift: {member}:0x{resume:X}")
        if data[metadata] != 0:
            raise BuildError(f"V321 erased-metadata premise drift: {member} slot {slot}")
        if not 1 <= skip <= 0x7E:
            raise BuildError(f"invalid skip length: {member} slot {slot}: {skip}")

        data[metadata] = skip
        expected_offsets.setdefault(member, set()).add(metadata)
        evidence_rows.append(
            {
                "member": member,
                "slot": slot,
                "metadata_offset": f"0x{metadata:X}",
                "v321_value": 0,
                "v322_value": skip,
                "caller_offset": f"0x{site:X}",
                "resume_offset": f"0x{resume:X}",
                "skipped_9c_count": skipped.count(0x9C),
                "resume_prefix_hex": resume_prefix.hex(" ").upper(),
            }
        )

    final = {name: bytes(data) for name, data in members.items()}
    changed_members = [name for name in before if before[name] != final[name]]
    if set(changed_members) != set(expected_offsets):
        raise BuildError(f"changed member set drift: {changed_members}")
    if any(len(before[name]) != len(final[name]) for name in before):
        raise BuildError("member size changed")
    for name in changed_members:
        actual = {
            offset
            for offset, (old, new) in enumerate(zip(before[name], final[name], strict=True))
            if old != new
        }
        if actual != expected_offsets[name]:
            raise BuildError(f"Expected-Write mismatch: {name}: {sorted(actual)}")
    for member, slot, site, command, skipped, resume_prefix in CALLERS:
        data = final[member]
        metadata = SLOT_BASE + slot * SLOT_SIZE + METADATA_OFFSET
        if data[metadata] != len(skipped):
            raise BuildError(f"metadata readback failed: {member} slot {slot}")
        # This equation is the actual completion contract: after E2 consumes
        # its two-byte command, metadata lands exactly on the preserved token.
        if site + 2 + data[metadata] != site + 2 + len(skipped):
            raise BuildError(f"resume arithmetic failed: {member} slot {slot}")

    output_path, output_hash = write_archive(OUTPUT_STEM, infos, final, None)
    delta_path, delta_hash = write_archive(
        DELTA_STEM, infos, final, set(expected_offsets)
    )
    with ZipFile(output_path) as archive:
        names = [info.filename for info in archive.infolist() if not info.is_dir()]
        if names != [info.filename for info in infos if not info.is_dir()]:
            raise BuildError("output ZIP topology drift")
        if any(archive.read(name) != final[name] for name in final):
            raise BuildError("output ZIP round-trip mismatch")
    with ZipFile(delta_path) as archive:
        if set(archive.namelist()) != set(expected_offsets):
            raise BuildError("delta ZIP topology drift")

    ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
    with (ANALYSIS_DIR / "restored_skip_metadata.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=evidence_rows[0].keys())
        writer.writeheader()
        writer.writerows(evidence_rows)
    manifest = {
        "build": "V322 TEST_ONLY E2 skip metadata restore",
        "base": {"path": str(BASE), "sha256": BASE_SHA256},
        "output": {"path": str(output_path), "sha256": output_hash},
        "delta": {"path": str(delta_path), "sha256": delta_hash},
        "changed_members": changed_members,
        "changed_offsets": {
            name: [f"0x{offset:X}" for offset in sorted(offsets)]
            for name, offsets in expected_offsets.items()
        },
        "restored_skip_values": [row["v322_value"] for row in evidence_rows],
        "inherited": "V321 font, text payloads, PSX.EXE, geometry, UI, and inline wrappers byte-identical",
        "runtime": "PENDING user cold boot; do not load V321 savestate",
        "release_status": "DIAGNOSTIC; DO NOT DISTRIBUTE",
    }
    (ANALYSIS_DIR / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V322 TEST ONLY - E2 skip metadata restore",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output_path.name}",
        f"sha256={output_hash}",
        f"delta={delta_path.name}",
        f"delta_sha256={delta_hash}",
        f"changed_members={','.join(changed_members)}",
        "changed_bytes=5 (slot +0x7F only)",
        "skip_values=7,10,9,4,11",
        "PSX.EXE/COMM.IMG/text payloads/inline wrappers=byte-identical to V321",
        "runtime=PENDING user cold boot; TEST_ONLY",
    ]
    (ANALYSIS_DIR / "build_report.txt").write_text(
        "\n".join(report) + "\n", encoding="utf-8"
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
