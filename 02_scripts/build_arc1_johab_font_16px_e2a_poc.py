#!/usr/bin/env python3
"""Build the first visible Pilgi 16px + E2 bank-A integration proof.

The input is the hash-pinned relocated D941 dialogue-font build.  That build is
itself regenerated from the untouched Japanese ``00_original/arc.zip`` and has
already moved its 16px wrapper/table away from the historical E2 and UI caves.

This PoC changes one additional scene span only:

* ``1/S1011.DAT`` at ``0x4799E`` has a seven-byte text span followed by the
  original ``E6 01`` line break;
* the first two bytes become ``E2 81`` (bank-A slot 0);
* the remaining five original bytes stay byte-identical and are skipped by the
  completion handler using metadata ``slot[0x7F] = 5``;
* the external slot contains ``가 나 고 구 과 워`` encoded entirely with the
  already runtime-validated D941 16px component codes.

The visible text advances 11 times at 14 pixels (six syllables and five custom
spaces), so it occupies 154 pixels and remains within the measured 168-pixel
dialogue width.  Its 34 encoded bytes cannot fit in the original seven-byte
span, making the E2 expansion visible without adding new font shapes.

This is TEST ONLY.  It is not a production compiler and deliberately does not
add bank B, multiple chained slots, bulk dialogue, speaker formatting, or UI.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import os
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_johab_font_poc as common  # noqa: E402
import build_arc1_johab_font_16px_poc as font16  # noqa: E402
import build_arc1_v297_e2_expand as legacy_e2  # noqa: E402


try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


BASE = (
    ROOT
    / "03_output/arc1_johab_font_16px_relocated_pilgi_TEST_ONLY_79880948.zip"
)
BASE_SHA256 = "798809489438B0081BA795F83D56322E433ABF40CA8600DD3F38E9FEB8A61064"
ORIGINAL = ROOT / "00_original/arc.zip"
OUTPUT_DIR = ROOT / "03_output"
ANALYSIS_DIR = ROOT / "01_work/analysis/johab_font_16px_e2a_poc"
OUTPUT_STEM = "arc1_johab_font_16px_e2a_pilgi_TEST_ONLY"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
FONT_TEST_DAT = "1/S1071.DAT"
E2_TEST_DAT = "1/S1011.DAT"
EXPECTED_CHANGED_FROM_ORIGINAL = {PSX, COMM, FONT_TEST_DAT, E2_TEST_DAT}

BASE_PSX_SHA256 = "6BD8A1172D28466C7A3D9E99DDCFFDA21BB5E973A045F57317CCE281B06DA93E"
BASE_S1011_SHA256 = "C40D2EF6E383BBE5B1BF87DDB8E89EA877680452AC41917562712A8507023C22"

LOOKUP_HANDLER = 0x8018FCD0
COMPLETION_HANDLER = 0x8018FD28
CAVE_END = 0x8018FDC5
E2_CALL = 0x8016BC84
COMPLETION_HOOK = 0x8016BDC0
ORIGINAL_LOOKUP = 0x8015EA44
COMPLETION_TARGET = 0x8016BE44

EXPECTED_LOOKUP_SHA256 = "A24158697E17239305E04EDFDD3FEA5C5972E227811825A230FAF9D5D4123351"
EXPECTED_COMPLETION_SHA256 = "D2DEC5B3F2CA8055836DF1572CA3DB418B58A238C1B36E9F5927F94871F2A9CB"

SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT = 0
SLOT_OFFSET = SLOT_BASE + SLOT * SLOT_SIZE
SLOT_DISK_ID = 0x81
SLOT_METADATA_OFFSET = 0x7F

SITE_OFFSET = 0x4799E
SPAN_LENGTH = 7
SKIP_LENGTH = SPAN_LENGTH - 2
ORIGINAL_SPAN = bytes.fromhex("DA 2A DD 92 49 32 58")
ORIGINAL_LINEBREAK = b"\xE6\x01"
ORIGINAL_BODY_LENGTH = 42

VISIBLE_TEXT = "가 나 고 구 과 워"
TOKEN_BY_CHAR = {
    "가": bytes.fromhex("E0 99 E0 3B"),
    "나": bytes.fromhex("E0 99 E0 3A"),
    "고": bytes.fromhex("E0 92 E0 3E"),
    "구": bytes.fromhex("E0 94 E0 44"),
    "과": bytes.fromhex("E0 97 E0 39"),
    "워": bytes.fromhex("E0 96 E0 3C"),
    " ": bytes.fromhex("E0 46"),
}
PAYLOAD = b"".join(TOKEN_BY_CHAR[ch] for ch in VISIBLE_TEXT)
EXPECTED_PAYLOAD = bytes.fromhex(
    "E0 99 E0 3B E0 46 E0 99 E0 3A E0 46 E0 92 E0 3E "
    "E0 46 E0 94 E0 44 E0 46 E0 97 E0 39 E0 46 E0 96 E0 3C"
)
GLYPH_PACKETS = 17
ADVANCING_PACKETS = 11
PIXEL_WIDTH = ADVANCING_PACKETS * 14
WINDOW_WIDTH = 168


class BuildError(RuntimeError):
    """A static guard failed; no final output should be trusted."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def jal_word(address: int) -> int:
    if address & 3:
        raise BuildError(f"unaligned JAL target: 0x{address:08X}")
    return 0x0C000000 | ((address >> 2) & 0x03FFFFFF)


def changed_offsets(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise BuildError("member size changed")
    return {index for index, (left, right) in enumerate(zip(before, after)) if left != right}


def validate_load_delays(blob: bytes, address: int, label: str) -> None:
    def gpr_reads(word: int) -> set[int]:
        op = word >> 26
        rs = (word >> 21) & 0x1F
        rt = (word >> 16) & 0x1F
        if op == 0:
            function = word & 0x3F
            if function in {0x00, 0x02, 0x03}:       # fixed shifts
                return {rt}
            if function in {0x08, 0x09, 0x11, 0x13}: # jr/jalr/mthi/mtlo
                return {rs}
            if function in {0x10, 0x12}:             # mfhi/mflo
                return set()
            return {rs, rt}
        if op in {0x02, 0x03, 0x0F}:                 # j/jal/lui
            return set()
        if op in {0x04, 0x05}:                       # beq/bne
            return {rs, rt}
        if op in {0x01, 0x06, 0x07}:                 # regimm/blez/bgtz
            return {rs}
        if op in {0x28, 0x29, 0x2A, 0x2B, 0x2E}:    # stores
            return {rs, rt}
        return {rs}                                   # immediates and loads

    words = struct.unpack(f"<{len(blob) // 4}I", blob)
    load_ops = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26}
    for index, word in enumerate(words[:-1]):
        if word >> 26 not in load_ops:
            continue
        loaded = (word >> 16) & 0x1F
        if loaded in gpr_reads(words[index + 1]):
            raise BuildError(
                f"{label} R3000 load-delay hazard at 0x{address + index * 4:08X}"
            )


def decode_indices(payload: bytes) -> list[int]:
    indices: list[int] = []
    cursor = 0
    while cursor < len(payload):
        lead = payload[cursor]
        if lead < 0xDD or lead > 0xE0 or cursor + 1 >= len(payload):
            raise BuildError(f"unexpected E2 payload token at byte {cursor}: 0x{lead:02X}")
        trail = payload[cursor + 1]
        if not 1 <= trail <= 0xFE:
            raise BuildError(f"invalid two-byte glyph trail at byte {cursor + 1}")
        indices.append((lead - 0xDD) * 255 + trail + 0xDB)
        cursor += 2
    return indices


def write_zip(path: Path, infos, members: dict[str, bytes], selected: set[str] | None) -> str:
    temporary = path.with_name(f".{path.stem}_{os.getpid()}.building.zip")
    if temporary.exists():
        raise BuildError(f"temporary output already exists: {temporary}")
    try:
        with ZipFile(temporary, "w", ZIP_DEFLATED, compresslevel=1) as archive:
            for info in infos:
                if info.is_dir():
                    if selected is None:
                        archive.writestr(common.clone_zipinfo(info), b"")
                    continue
                if selected is None or info.filename in selected:
                    archive.writestr(common.clone_zipinfo(info), members[info.filename])
        digest = common.sha256_file(temporary)
        final = path.with_name(f"{path.stem}_{digest[:8]}.zip")
        if final.exists():
            if common.sha256_file(final) != digest:
                raise BuildError(f"existing output hash differs: {final}")
            temporary.unlink()
        else:
            temporary.replace(final)
        return digest
    finally:
        if temporary.exists():
            temporary.unlink()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", type=Path, default=BASE)
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR)
    parser.add_argument("--analysis-dir", type=Path, default=ANALYSIS_DIR)
    args = parser.parse_args()

    if common.sha256_file(args.base) != BASE_SHA256:
        raise BuildError(f"relocated D941 base hash mismatch: {args.base}")
    if common.sha256_file(ORIGINAL) != common.BASE_ZIP_SHA256:
        raise BuildError("Japanese original ZIP hash mismatch")

    with ZipFile(args.base) as archive:
        infos = archive.infolist()
        if len({info.filename for info in infos}) != len(infos):
            raise BuildError("base ZIP contains duplicate names")
        base_members = {
            info.filename: archive.read(info.filename)
            for info in infos
            if not info.is_dir()
        }
    with ZipFile(ORIGINAL) as archive:
        original_infos = archive.infolist()
        original_members = {
            info.filename: archive.read(info.filename)
            for info in original_infos
            if not info.is_dir()
        }

    if [info.filename for info in infos] != [info.filename for info in original_infos]:
        raise BuildError("base ZIP member order/name topology differs from the original")
    if set(base_members) != set(original_members):
        raise BuildError("base/original member sets differ")
    if any(len(base_members[name]) != len(original_members[name]) for name in base_members):
        raise BuildError("a base member size differs from the original")
    base_changed = {
        name for name in base_members if base_members[name] != original_members[name]
    }
    if base_changed != {PSX, COMM, FONT_TEST_DAT}:
        raise BuildError(f"relocated D941 changed-member set drifted: {sorted(base_changed)}")
    if sha256_bytes(base_members[PSX]) != BASE_PSX_SHA256:
        raise BuildError("relocated D941 PSX.EXE hash mismatch")
    if sha256_bytes(base_members[E2_TEST_DAT]) != BASE_S1011_SHA256:
        raise BuildError("relocated D941 S1011 hash mismatch")

    if PAYLOAD != EXPECTED_PAYLOAD or len(PAYLOAD) != 34 or b"\x00" in PAYLOAD:
        raise BuildError("visible E2 payload drifted")
    indices = decode_indices(PAYLOAD)
    if len(indices) != GLYPH_PACKETS:
        raise BuildError(f"payload packet count drifted: {len(indices)}")
    advancing = sum(
        font16.ADVANCE_START <= index < font16.ADVANCE_START + font16.ADVANCE_COUNT
        for index in indices
    )
    nonadvancing = sum(
        font16.REST_START <= index < font16.REST_START + font16.REST_COUNT
        for index in indices
    )
    if (advancing, nonadvancing) != (ADVANCING_PACKETS, 6):
        raise BuildError(f"payload advance classes drifted: {(advancing, nonadvancing)}")
    if PIXEL_WIDTH != 154 or PIXEL_WIDTH > WINDOW_WIDTH:
        raise BuildError(f"visible E2 line does not fit: {PIXEL_WIDTH}/{WINDOW_WIDTH}px")

    # Tie every reused code back to the already validated S1071 diagnostic data.
    diagnostic = base_members[FONT_TEST_DAT]
    for ch, token in TOKEN_BY_CHAR.items():
        if token not in diagnostic[0x478D6:0x479C5]:
            raise BuildError(f"D941 diagnostic no longer contains token for {ch!r}")

    lookup = legacy_e2.lookup_handler()
    completion = legacy_e2.completion_handler()
    if len(lookup) != 84 or sha256_bytes(lookup) != EXPECTED_LOOKUP_SHA256:
        raise BuildError("v0.11/v297 lookup handler bytes drifted")
    if len(completion) != 108 or sha256_bytes(completion) != EXPECTED_COMPLETION_SHA256:
        raise BuildError("v0.11/v297 completion handler bytes drifted")
    validate_load_delays(lookup, LOOKUP_HANDLER, "lookup")
    validate_load_delays(completion, COMPLETION_HANDLER, "completion")
    if LOOKUP_HANDLER + len(lookup) > COMPLETION_HANDLER:
        raise BuildError("lookup/completion handlers overlap")
    if COMPLETION_HANDLER + len(completion) > CAVE_END:
        raise BuildError("completion handler exceeds the E2 cave")
    if legacy_e2.disk_id(SLOT) != SLOT_DISK_ID:
        raise BuildError("bank-A slot/disk-ID mapping drifted")

    scratch = dict(base_members)
    exe = bytearray(base_members[PSX])
    cave_start = common.file_offset(exe, LOOKUP_HANDLER)
    cave_end = common.file_offset(exe, CAVE_END)
    if any(exe[cave_start:cave_end]):
        raise BuildError("relocated base did not restore the E2 cave to zero")
    if struct.unpack_from("<I", exe, common.file_offset(exe, E2_CALL))[0] != jal_word(ORIGINAL_LOOKUP):
        raise BuildError("E2 lookup call is not the original JAL")
    if struct.unpack_from("<I", exe, common.file_offset(exe, COMPLETION_HOOK))[0] != common.j_word(COMPLETION_TARGET):
        raise BuildError("E2 completion hook is not the original jump")
    if struct.unpack_from("<I", exe, common.file_offset(exe, COMPLETION_HOOK + 4))[0] != 0:
        raise BuildError("E2 completion hook delay slot is not NOP")

    exe[cave_start:cave_start + len(lookup)] = lookup
    completion_offset = common.file_offset(exe, COMPLETION_HANDLER)
    exe[completion_offset:completion_offset + len(completion)] = completion
    struct.pack_into("<I", exe, common.file_offset(exe, E2_CALL), jal_word(LOOKUP_HANDLER))
    struct.pack_into(
        "<I", exe, common.file_offset(exe, COMPLETION_HOOK), common.j_word(COMPLETION_HANDLER)
    )
    scratch[PSX] = bytes(exe)

    dat = bytearray(base_members[E2_TEST_DAT])
    if dat[SLOT_OFFSET:SLOT_OFFSET + SLOT_SIZE] != bytes(SLOT_SIZE):
        raise BuildError("S1011 bank-A slot 0 is not empty")
    if dat[SITE_OFFSET:SITE_OFFSET + SPAN_LENGTH] != ORIGINAL_SPAN:
        raise BuildError("S1011 target span differs from the Japanese original")
    if dat[SITE_OFFSET + SPAN_LENGTH:SITE_OFFSET + SPAN_LENGTH + 2] != ORIGINAL_LINEBREAK:
        raise BuildError("S1011 linebreak after the target span differs")
    if dat[SITE_OFFSET + ORIGINAL_BODY_LENGTH] != 0:
        raise BuildError("S1011 body terminator moved")

    dat[SLOT_OFFSET:SLOT_OFFSET + len(PAYLOAD)] = PAYLOAD
    dat[SLOT_OFFSET + len(PAYLOAD)] = 0
    dat[SLOT_OFFSET + SLOT_METADATA_OFFSET] = SKIP_LENGTH
    dat[SITE_OFFSET:SITE_OFFSET + 2] = bytes((0xE2, SLOT_DISK_ID))
    scratch[E2_TEST_DAT] = bytes(dat)

    # Expected-write validation against the relocated base.
    psx_diff = changed_offsets(base_members[PSX], scratch[PSX])
    allowed_psx = set(range(cave_start, cave_end))
    allowed_psx |= set(range(common.file_offset(exe, E2_CALL), common.file_offset(exe, E2_CALL) + 4))
    allowed_psx |= set(
        range(common.file_offset(exe, COMPLETION_HOOK), common.file_offset(exe, COMPLETION_HOOK) + 4)
    )
    if not psx_diff or not psx_diff <= allowed_psx:
        raise BuildError("PSX.EXE changed outside the declared E2 writes")
    dat_diff = changed_offsets(base_members[E2_TEST_DAT], scratch[E2_TEST_DAT])
    allowed_dat = set(range(SLOT_OFFSET, SLOT_OFFSET + SLOT_SIZE))
    allowed_dat |= {SITE_OFFSET, SITE_OFFSET + 1}
    if not dat_diff or not dat_diff <= allowed_dat:
        raise BuildError("S1011 changed outside slot 0 and the two-byte redirect")
    if scratch[E2_TEST_DAT][SITE_OFFSET + 2:SITE_OFFSET + SPAN_LENGTH] != ORIGINAL_SPAN[2:]:
        raise BuildError("inline tail bytes were modified instead of deferred-skipped")
    if scratch[E2_TEST_DAT][SITE_OFFSET + SPAN_LENGTH:SITE_OFFSET + SPAN_LENGTH + 2] != ORIGINAL_LINEBREAK:
        raise BuildError("linebreak was swallowed by the E2 redirect")
    if scratch[E2_TEST_DAT][SLOT_OFFSET:SLOT_OFFSET + len(PAYLOAD)] != PAYLOAD:
        raise BuildError("E2 payload readback differs")
    if scratch[E2_TEST_DAT][SLOT_OFFSET + len(PAYLOAD)] != 0:
        raise BuildError("E2 payload is not zero-terminated")
    if scratch[E2_TEST_DAT][SLOT_OFFSET + SLOT_METADATA_OFFSET] != SKIP_LENGTH:
        raise BuildError("E2 skip metadata readback differs")

    output_changed = {
        name for name in scratch if scratch[name] != original_members[name]
    }
    if output_changed != EXPECTED_CHANGED_FROM_ORIGINAL:
        raise BuildError(f"final changed-member set drifted: {sorted(output_changed)}")
    if any(len(scratch[name]) != len(original_members[name]) for name in scratch):
        raise BuildError("a final member size changed")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    full_seed = args.output_dir / OUTPUT_STEM
    full_hash = write_zip(full_seed, infos, scratch, None)
    patch_seed = args.output_dir / f"{OUTPUT_STEM}_patch"
    patch_hash = write_zip(patch_seed, infos, scratch, EXPECTED_CHANGED_FROM_ORIGINAL)
    full_output = args.output_dir / f"{OUTPUT_STEM}_{full_hash[:8]}.zip"
    patch_output = args.output_dir / f"{OUTPUT_STEM}_patch_{patch_hash[:8]}.zip"

    with ZipFile(full_output) as archive:
        if archive.testzip() is not None:
            raise BuildError("full ZIP CRC test failed")
        for name in EXPECTED_CHANGED_FROM_ORIGINAL:
            if archive.read(name) != scratch[name]:
                raise BuildError(f"full ZIP readback differs: {name}")
    with ZipFile(patch_output) as archive:
        patch_names = {info.filename for info in archive.infolist() if not info.is_dir()}
        if patch_names != EXPECTED_CHANGED_FROM_ORIGINAL or archive.testzip() is not None:
            raise BuildError("patch-only ZIP member/CRC validation failed")
        for name in EXPECTED_CHANGED_FROM_ORIGINAL:
            if archive.read(name) != scratch[name]:
                raise BuildError(f"patch ZIP readback differs: {name}")

    args.analysis_dir.mkdir(parents=True, exist_ok=True)
    with (args.analysis_dir / "expected_writes.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(("member", "region", "start", "end_exclusive", "allowed_bytes", "actual_diff_bytes"))
        writer.writerow((PSX, "E2 handlers", f"0x{cave_start:X}", f"0x{cave_end:X}", cave_end - cave_start, len(psx_diff & set(range(cave_start, cave_end)))))
        writer.writerow((PSX, "E2 lookup hook", f"0x{common.file_offset(exe, E2_CALL):X}", f"0x{common.file_offset(exe, E2_CALL) + 4:X}", 4, len(psx_diff & set(range(common.file_offset(exe, E2_CALL), common.file_offset(exe, E2_CALL) + 4)))))
        writer.writerow((PSX, "E2 completion hook", f"0x{common.file_offset(exe, COMPLETION_HOOK):X}", f"0x{common.file_offset(exe, COMPLETION_HOOK) + 4:X}", 4, len(psx_diff & set(range(common.file_offset(exe, COMPLETION_HOOK), common.file_offset(exe, COMPLETION_HOOK) + 4)))))
        writer.writerow((E2_TEST_DAT, "bank-A slot 0", f"0x{SLOT_OFFSET:X}", f"0x{SLOT_OFFSET + SLOT_SIZE:X}", SLOT_SIZE, len(dat_diff & set(range(SLOT_OFFSET, SLOT_OFFSET + SLOT_SIZE)))))
        writer.writerow((E2_TEST_DAT, "inline E2 redirect", f"0x{SITE_OFFSET:X}", f"0x{SITE_OFFSET + 2:X}", 2, len(dat_diff & {SITE_OFFSET, SITE_OFFSET + 1})))

    report = "\n".join(
        (
            "Arc the Lad 1 Pilgi 16px + E2 bank-A single-span PoC",
            "status=TEST_ONLY STATIC PASS; runtime=PENDING cold boot S1011",
            f"base={args.base.name}",
            f"base_sha256={BASE_SHA256}",
            f"visible_text={VISIBLE_TEXT}",
            f"payload={len(PAYLOAD)}B/{GLYPH_PACKETS} packets; width={PIXEL_WIDTH}/{WINDOW_WIDTH}px",
            f"site={E2_TEST_DAT} 0x{SITE_OFFSET:X}; original_span={SPAN_LENGTH}B; redirect=E2 {SLOT_DISK_ID:02X}",
            f"slot=0x{SLOT_OFFSET:X}; terminator=+0x{len(PAYLOAD):X}; metadata[0x7F]={SKIP_LENGTH}",
            f"controls=original E6 01 preserved at 0x{SITE_OFFSET + SPAN_LENGTH:X}",
            f"handlers=0x{LOOKUP_HANDLER:08X} ({len(lookup)}B), 0x{COMPLETION_HANDLER:08X} ({len(completion)}B)",
            f"hooks=0x{E2_CALL:08X}, 0x{COMPLETION_HOOK:08X}",
            f"changed_from_relocated_base={PSX},{E2_TEST_DAT}",
            f"changed_from_original={','.join(sorted(EXPECTED_CHANGED_FROM_ORIGINAL))}",
            f"full_output={full_output.name}",
            f"full_sha256={full_hash}",
            f"patch_output={patch_output.name}",
            f"patch_sha256={patch_hash}",
            "next=package with original layout; cold boot; verify visible E2 line and natural next line",
        )
    ) + "\n"
    (args.analysis_dir / "build_report.txt").write_text(report, encoding="utf-8")
    print(report, end="")


if __name__ == "__main__":
    main()
