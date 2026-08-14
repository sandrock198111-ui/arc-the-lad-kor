#!/usr/bin/env python3
"""Build v211 diagnostic: move the 28-slot dynamic cache away from world map art.

The v210 world-map states prove that page 15,1 V=160..255 is sampled by two
128x96 game sprites.  The dynamic cache currently uploads at absolute y=480
(texture V=224), wholly inside that range.  This diagnostic moves the virtual
cache row from 40 to 32, which changes both the generated packet V and upload
rectangle to absolute y=384 (texture V=128).  U, CLUT, cache contents, script
members and COMM.IMG remain byte-identical to v210.

This is deliberately a probe, not a release: the alternate row has not been
proved globally unused.  Every write is guarded against the exact v210 bytes.
"""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32  # noqa: E402
import build_arc1_v171_ui_asset_recovery as v171  # noqa: E402
import build_arc1_v190_dynamic_owner_repair as v190  # noqa: E402


BASE = ROOT / "03_output/arc1_v210_sd031_slots_controls.zip"
BASE_SHA256 = "7FB963135C753CBF509F9E722BF826856B04D456D29743A0B1D8CB5A9B34CAF9"
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v211_cache_row32_worldmap_probe_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis/arc1_v211_cache_row32_worldmap_probe"
REPORT = ANALYSIS / "build_report.txt"

PSX = "PSX.EXE"
OLD_ROW, NEW_ROW = 40, 32
OLD_Y, NEW_Y = 480, 384
OLD_V, NEW_V = 224, 128

old = v171.old


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    result = ZipInfo(info.filename, info.date_time)
    for attr in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(result, attr, getattr(info, attr))
    return result


def find_one_word(blob: bytes | bytearray, start: int, size: int, word: int, label: str) -> int:
    hits = [
        offset
        for offset in range(start, start + size, 4)
        if struct.unpack_from("<I", blob, offset)[0] == word
    ]
    if len(hits) != 1:
        raise SystemExit(f"{label}: expected one guarded word, found {len(hits)}")
    return hits[0]


def patch_word(blob: bytearray, offset: int, before: int, after: int, label: str) -> None:
    actual = struct.unpack_from("<I", blob, offset)[0]
    if actual != before:
        raise SystemExit(f"{label}: 0x{actual:08X}, expected 0x{before:08X}")
    struct.pack_into("<I", blob, offset, after)


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v210 base archive SHA256 differs")

    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        before = {info.filename: archive.read(info.filename) for info in infos}
    members = dict(before)
    exe = bytearray(members[PSX])

    layout, _blobs, code_base = v190.resident_layout()
    decoder = code_base
    decoder_size = len(v190.build_decoder(decoder, layout))
    huffman = (decoder + decoder_size + 3) & ~3
    huffman_size = len(v190.build_huffman(huffman, layout))
    frame = (huffman + huffman_size + 3) & ~3
    frame_size = len(v190.build_frame(frame, huffman, layout))
    if (decoder, decoder_size, huffman, huffman_size, frame, frame_size) != (
        0x801FF348, 568, 0x801FF580, 232, 0x801FF668, 584,
    ):
        raise SystemExit("current resident layout differs from the frozen v190 layout")

    source_at = old.file_at(v171.SOURCE_BASE)
    decoder_at = source_at + decoder - v171.RESIDENT_BASE
    frame_at = source_at + frame - v171.RESIDENT_BASE
    rect_at = source_at + layout["upload_rect"][0] - v171.RESIDENT_BASE

    low_row_at = old.file_at(v171.LOW_HELPER)
    low_classifier_at = old.file_at(v171.LOW_CLASSIFIER)
    old_row_word = old.i_type(0x09, v171.T0, v171.A3, -OLD_ROW)
    new_row_word = old.i_type(0x09, v171.T0, v171.A3, -NEW_ROW)
    patch_word(exe, low_row_at, old_row_word, new_row_word, "low helper row")

    classifier_v_at = find_one_word(
        exe, low_classifier_at, 36,
        old.i_type(0x09, v171.V0, v171.V0, -OLD_V),
        "low classifier V",
    )
    patch_word(
        exe, classifier_v_at,
        old.i_type(0x09, v171.V0, v171.V0, -OLD_V),
        old.i_type(0x09, v171.V0, v171.V0, -NEW_V),
        "low classifier V",
    )

    decoder_base_at = find_one_word(
        exe, decoder_at, decoder_size,
        old.i_type(0x09, v171.T6, v171.V1, OLD_ROW * old.IPR),
        "decoder cache index base",
    )
    patch_word(
        exe, decoder_base_at,
        old.i_type(0x09, v171.T6, v171.V1, OLD_ROW * old.IPR),
        old.i_type(0x09, v171.T6, v171.V1, NEW_ROW * old.IPR),
        "decoder cache index base",
    )

    frame_v_at = find_one_word(
        exe, frame_at, frame_size,
        old.i_type(0x09, v171.T5, v171.T5, -OLD_V),
        "frame cache V",
    )
    patch_word(
        exe, frame_v_at,
        old.i_type(0x09, v171.T5, v171.T5, -OLD_V),
        old.i_type(0x09, v171.T5, v171.T5, -NEW_V),
        "frame cache V",
    )

    rect_before = struct.unpack_from("<4H", exe, rect_at)
    if rect_before != (v171.CACHE_X, OLD_Y, 3, old.CELL):
        raise SystemExit(f"upload rectangle differs: {rect_before}")
    struct.pack_into("<H", exe, rect_at + 2, NEW_Y)
    if struct.unpack_from("<4H", exe, rect_at) != (v171.CACHE_X, NEW_Y, 3, old.CELL):
        raise SystemExit("upload rectangle readback differs")

    members[PSX] = bytes(exe)
    changed = [name for name in members if members[name] != before[name]]
    if changed != [PSX]:
        raise SystemExit(f"unexpected changed members: {changed}")
    if any(len(members[name]) != len(before[name]) for name in members):
        raise SystemExit("archive member length changed")

    diffs = [
        offset for offset, (left, right) in enumerate(zip(before[PSX], members[PSX]))
        if left != right
    ]
    allowed_words = {low_row_at, classifier_v_at, decoder_base_at, frame_v_at}
    allowed_bytes = {rect_at + 2, rect_at + 3}
    for offset in allowed_words:
        allowed_bytes.update(range(offset, offset + 4))
    if not diffs or any(offset not in allowed_bytes for offset in diffs):
        raise SystemExit(f"PSX.EXE changed outside guarded fields: {diffs[:20]}")

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    for label, offset, size, address in (
        ("low_helper", low_row_at, 36, v171.LOW_HELPER),
        ("low_classifier", low_classifier_at, 36, v171.LOW_CLASSIFIER),
        ("decoder", decoder_at, decoder_size, decoder),
        ("frame", frame_at, frame_size, frame),
    ):
        decoded = list(md.disasm(bytes(exe[offset:offset + size]), address))
        if sum(item.size for item in decoded) != size:
            raise SystemExit(f"Capstone did not consume all of {label}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    temporary = OUT_DIR / f"{OUT_STEM}_building.zip"
    if temporary.exists():
        raise SystemExit(f"refusing to overwrite temporary output: {temporary}")
    with ZipFile(temporary, "w", ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    with ZipFile(temporary) as archive:
        if archive.namelist() != [info.filename for info in infos]:
            raise SystemExit("archive member order changed")
        for name, expected in members.items():
            if archive.read(name) != expected:
                raise SystemExit(f"archive roundtrip differs: {name}")
    stamp = digest(temporary.read_bytes())
    output = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {output}")
    temporary.replace(output)

    report = [
        "v211 TEST ONLY - fixed cache row32 world-map overlap probe",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output.name}",
        f"sha256={stamp}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        "confirmed_v210_collision=world map page15,1 V160..255 contains cache V224",
        f"cache_virtual_row={OLD_ROW}->{NEW_ROW}",
        f"cache_upload_y={OLD_Y}->{NEW_Y}",
        f"cache_texture_v={OLD_V}->{NEW_V}",
        f"cache_x={v171.CACHE_X} unchanged",
        f"cache_u={v171.CACHE_U} unchanged",
        "cache_slots=28 unchanged",
        "dynamic_sources=unchanged",
        "lookup_table=unchanged",
        "COMM.IMG=byte-identical to v210 PASS",
        "all_DAT_members=byte-identical to v210 PASS",
        f"PSX_changed_bytes={len(diffs)}",
        f"low_helper_patch_file=0x{low_row_at:X}",
        f"low_classifier_patch_file=0x{classifier_v_at:X}",
        f"decoder_patch_file=0x{decoder_base_at:X}",
        f"frame_patch_file=0x{frame_v_at:X}",
        f"upload_rect_file=0x{rect_at:X}",
        f"decoder 0x{decoder:08X} / {decoder_size} bytes",
        f"frame routine 0x{frame:08X} / {frame_size} bytes",
        f"huffman 0x{huffman:08X} / {huffman_size} bytes",
        "resident_used=5356/5356",
        "resident_free=0",
        "archive_member_order=PASS",
        "archive_member_lengths=PASS",
        "archive_roundtrip=PASS",
        "capstone_disassembly=PASS",
        "emulator_run=NO",
        "runtime=PENDING user cold boot",
        "expected=world map clean; Korean text remains visible",
        "known_risk=y384 is not globally proven free; this build is a probe only",
        "rollback=v210 for byte comparison; v208/v194 for earlier stable checkpoints",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))
    print(REPORT)


if __name__ == "__main__":
    main()
