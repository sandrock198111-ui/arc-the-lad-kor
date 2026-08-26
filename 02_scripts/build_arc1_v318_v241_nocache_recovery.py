#!/usr/bin/env python3
"""Recover the broad v241 16px build while disabling dynamic-cache rendering.

This is deliberately a lineage-recovery build, not a new narrow PoC.  It keeps
v241's translated DAT/UI data, E2 slots, 15-column 16px atlas, and width-stable
code rewrite byte-for-byte.  Only the three runtime entries that can reach the
failed completed-glyph cache/high-page path are restored to the pristine stock
renderer:

* the pre-DrawOT cache uploader call (the world-map VRAM corrupter),
* the cache-row packet U helper, and
* the cache-only high-page renderer entry.

The dormant decoder/resident bytes are intentionally left in place so this
recovery changes the smallest possible executable surface.  With the uploader
unreachable they cannot write cache pixels to VRAM.  A later production
builder will regenerate the same result from the pristine archive in one pass.

TEST ONLY until broad dialogue, UI, battle, and world-map runtime checks pass.
"""

from __future__ import annotations

import hashlib
import os
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = ROOT / "03_output/arc1_v241_halfwidth_TEST_ONLY_CEC05368.zip"
BASE_SHA256 = "CEC0536802239A2B54E383D3C53CF9D648703A25D70F633703FF3E1F900113E1"
ORIGINAL = ROOT / "00_original/arc.zip"
ORIGINAL_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"

OUTPUT_DIR = ROOT / "03_output"
ANALYSIS_DIR = ROOT / "01_work/analysis/arc1_v318_v241_nocache_recovery"
OUTPUT_STEM = "arc1_v318_v241_nocache_recovery_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_PSX_delta_from_v241"

PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800

LATE_UPLOAD_HOOK = 0x8011C860
PACKET_HOOK = 0x8016B5D8
RENDER_HOOK = 0x8016B764

# Frozen v241 words.  Their meanings and targets were established by the
# v164/v171 cache lineage and are rechecked before any output is written.
EXPECTED_V241 = {
    LATE_UPLOAD_HOOK: (0x0C07FD9A, 0x26040070),
    PACKET_HOOK: (0x0806741D, 0x00000000),
    RENDER_HOOK: (0x0806882C, 0x00000000),
}

# The cache wrapper target encoded by 0x0C07FD9A.  After recovery there must be
# no remaining direct JAL to it in the executable text.
CACHE_UPLOAD_JAL = 0x0C07FD9A


class BuildError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def file_offset(address: int) -> int:
    return address - RAM_TO_FILE


def words(blob: bytes | bytearray, address: int, count: int = 2) -> tuple[int, ...]:
    return struct.unpack_from(f"<{count}I", blob, file_offset(address))


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


def write_archive(
    path: Path,
    infos: list[ZipInfo],
    members: dict[str, bytes],
    selected: set[str] | None,
) -> tuple[Path, str]:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.building")
    if temporary.exists():
        raise BuildError(f"temporary output already exists: {temporary}")
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
        final = path.with_name(f"{path.stem}_{digest[:8]}.zip")
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
    if sha256_file(BASE) != BASE_SHA256:
        raise BuildError("v241 recovery base hash mismatch")
    if sha256_file(ORIGINAL) != ORIGINAL_SHA256:
        raise BuildError("pristine Japanese archive hash mismatch")

    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        if len({info.filename for info in infos}) != len(infos):
            raise BuildError("v241 archive has duplicate member names")
        before = {
            info.filename: archive.read(info.filename)
            for info in infos
            if not info.is_dir()
        }
    with ZipFile(ORIGINAL) as archive:
        original_infos = archive.infolist()
        pristine = {
            info.filename: archive.read(info.filename)
            for info in original_infos
            if not info.is_dir()
        }

    # v241 is the historical 164-member patch archive, while arc.zip is the
    # complete 533-member source.  Preserve the patch topology exactly and use
    # the pristine archive only as the byte authority for restored code.
    if not set(before) <= set(pristine):
        raise BuildError("v241 patch contains a member absent from the original")

    exe_before = before[PSX]
    exe = bytearray(exe_before)
    pristine_exe = pristine[PSX]
    if len(exe) != 587_776:
        raise BuildError(f"unexpected v241 executable size: {len(exe)}")
    if len(pristine_exe) != 581_632:
        raise BuildError(f"unexpected pristine executable size: {len(pristine_exe)}")

    for address, expected in EXPECTED_V241.items():
        actual = words(exe, address)
        if actual != expected:
            raise BuildError(
                f"v241 hook drift at 0x{address:08X}: "
                f"{actual!r} != {expected!r}"
            )

    stock_words = {
        LATE_UPLOAD_HOOK: words(pristine_exe, LATE_UPLOAD_HOOK),
        PACKET_HOOK: words(pristine_exe, PACKET_HOOK),
        RENDER_HOOK: words(pristine_exe, RENDER_HOOK),
    }
    expected_stock = {
        LATE_UPLOAD_HOOK: (0x0C05DB87, 0x26040070),
        PACKET_HOOK: (0x90C2000E, 0x00000000),
        RENDER_HOOK: (0x27BDFFD0, 0xAFBF002C),
    }
    if stock_words != expected_stock:
        raise BuildError(f"pristine renderer words drifted: {stock_words!r}")

    for address, replacement in stock_words.items():
        struct.pack_into("<2I", exe, file_offset(address), *replacement)

    # The only cache-upload call in the executable text must be the one just
    # removed.  Resident bytes may still contain data equal to this word, so
    # this scan is deliberately limited to the declared PS-X EXE text payload.
    text_size = struct.unpack_from("<I", exe, 0x1C)[0]
    text = bytes(exe[0x800:0x800 + text_size])
    upload_word = struct.pack("<I", CACHE_UPLOAD_JAL)
    if text.count(upload_word):
        raise BuildError("a direct cache-upload JAL remains after recovery")

    members = dict(before)
    members[PSX] = bytes(exe)
    changed_members = [name for name in members if members[name] != before[name]]
    if changed_members != [PSX]:
        raise BuildError(f"unexpected changed members: {changed_members}")

    actual_diffs = {
        offset
        for offset, (left, right) in enumerate(zip(exe_before, exe))
        if left != right
    }
    allowed = set()
    for address in EXPECTED_V241:
        allowed.update(range(file_offset(address), file_offset(address) + 8))
    if not actual_diffs or not actual_diffs <= allowed:
        raise BuildError("PSX.EXE changed outside the three guarded hook pairs")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    recovery_path, recovery_hash = write_archive(
        OUTPUT_DIR / OUTPUT_STEM,
        infos,
        members,
        selected=None,
    )
    delta_path, delta_hash = write_archive(
        OUTPUT_DIR / DELTA_STEM,
        infos,
        members,
        selected={PSX},
    )

    with ZipFile(recovery_path) as archive:
        if archive.read(PSX) != members[PSX] or len(archive.infolist()) != len(infos):
            raise BuildError("recovery patch archive round-trip failed")
    with ZipFile(delta_path) as archive:
        if archive.namelist() != [PSX] or archive.read(PSX) != members[PSX]:
            raise BuildError("PSX delta archive round-trip failed")

    ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
    report = [
        "v318 TEST ONLY - broad v241 16px lineage with dynamic-cache paths disabled",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={recovery_path.name}",
        f"sha256={recovery_hash}",
        f"PSX_delta_from_v241={delta_path.name}",
        f"PSX_delta_sha256={delta_hash}",
        f"PSX.EXE_sha256={sha256_bytes(members[PSX])}",
        f"changed_members={changed_members}",
        f"PSX_changed_bytes={len(actual_diffs)}",
        f"preserved=v241 patch members {len(infos)}/{len(infos)}; DAT/UI/E2/COMM.IMG and 16px global atlas byte-for-byte",
        "restored=pre-DrawOT DrawOT call; stock packet W/H tail; stock renderer prologue",
        "cache_upload_direct_calls_after=0",
        "runtime=PENDING user cold boot",
        "primary_gate=world map must not be corrupted; broad dialogue must match v241",
        "known_risk=unrewritten E9/EA outside v241's declared rewrite ranges may be blank",
    ]
    (ANALYSIS_DIR / "build_report.txt").write_text(
        "\n".join(report) + "\n", encoding="utf-8"
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
