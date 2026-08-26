#!/usr/bin/env python3
"""Build V323: restore the complete skill-range cursor outside COMM.IMG.

V322's static 16 px Hangul atlas legitimately occupies the old cursor source
at texture page 5,0 U=0..96/V=128..160.  There is no 97x33 rectangle inside
the COMM upload which is both statically blank and free of sampled runtime
writes.  V323 therefore keeps COMM.IMG byte-identical and does three things:

* RLE-compress the original 100x33 4bpp cursor source into the zero EXE tail.
* Upload it in five small synchronous LoadImage calls to page 15,1,
  U=0..99/V=191..223 whenever the range object is initialized.
* Move only this object's texture-page descriptor and nine-entry UV table.

The largest temporary buffer is 400 bytes on the normal call stack.  The
historic 5,356-byte resident block and its frozen heap boundary are untouched.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/arc1_v322_e2_skip_restore_TEST_ONLY_480924F9.zip"
BASE_SHA256 = "480924F970C441BA819BC1F2FA003ED430FA76509ED138C8B33F444044057B32"
ORIGINAL = ROOT / "00_original/arc.zip"
ORIGINAL_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"

OUTPUT_DIR = ROOT / "03_output"
ANALYSIS_DIR = ROOT / "01_work/analysis/arc1_v323_skill_range_relocation"
OUTPUT_STEM = "arc1_v323_skill_range_relocation_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v322"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
EXPECTED_MEMBERS = 164
RAM_TO_FILE = 0x8011A800
EXPECTED_PSX_SHA256 = "8E295D22D60C2427F4702618108E9836F7615A5D4BF384CB84FD2F10F9A6218E"
EXPECTED_COMM_SHA256 = "C81F48B805F3FF973C08DE14DE232DD2620612483FC0778A79BA2D2DC26E185B"
EXPECTED_ORIGINAL_COMM_SHA256 = "6C7565B6C326A99A29266482868F17A144FF7D15B871D7D8F8B852EC41014A26"

# Range-object initializer.  The displaced two words load s1=0x801F52BC;
# the helper deliberately leaves that same value in s1 before returning.
INIT_HOOK = 0x8011E614
INIT_HOOK_WORDS = (0x3C11801F, 0x263152BC)
LOADIMAGE = 0x80177E4C

# V322's loaded zero tail: file 0x8F3D8..0x8F7FF / RAM 0x801A9BD8..0x801A9FFF.
CAVE_FILE = 0x8F3D8
CAVE_RAM = 0x801A9BD8
CAVE_SIZE = 0x428
EXPECTED_HELPER_SIZE = 324
EXPECTED_RLE_SIZE = 652
EXPECTED_RLE_SHA256 = "94CED131CFC00C7B4A249009DEA5BE2361ABC6DAF6C244EE9B6D134F621C7133"
EXPECTED_RAW_SHA256 = "B0005B318220FC61C11C3290837A7DF245646254FFA5CEBE7EA9A11932C7F421"

# Exclusive range-cursor graphics descriptor and UV table.
DESCRIPTOR_RAM = 0x8018F740
DESCRIPTOR_FILE = DESCRIPTOR_RAM - RAM_TO_FILE
DESCRIPTOR_SIZE = 48
DESCRIPTOR_SHA256 = "2636A0D98CE28457E66B83B2CB483FBE2675C21EB3643213B8FD305AC9CC505D"
UV_RAM = 0x8018F8F8
UV_FILE = UV_RAM - RAM_TO_FILE
UV_SIZE = 9 * 16
UV_SHA256 = "C705D0C86A6A60E6D15ABE6BAC9A788ACF5CE36AB9FFBDCA8B8963CDC5943360"
BASE_UV = (
    (0, 128, 32, 128, 0, 160, 32, 160),
    (32, 128, 64, 128, 32, 160, 64, 160),
    (32, 160, 32, 128, 64, 160, 64, 128),
    (64, 160, 32, 160, 64, 128, 32, 128),
    (64, 128, 64, 160, 32, 128, 32, 160),
    (96, 128, 96, 160, 64, 128, 64, 160),
    (64, 128, 96, 128, 64, 160, 96, 160),
    (64, 160, 64, 128, 96, 160, 96, 128),
    (96, 160, 64, 160, 96, 128, 64, 128),
)

# Source/destination geometry.  100 pixels is 25 VRAM halfwords and covers
# the complete U=0..96 source union plus three harmless alignment pixels.
COMM_ROW_BYTES = 896
SOURCE_X = 0
SOURCE_Y = 128
UPLOAD_WORDS_PER_ROW = 25
UPLOAD_ROWS = 33
CHUNK_ROWS = 8
DEST_X_HALFWORD = 960
DEST_Y = 447
DEST_TPAGE_X = 960
DEST_TPAGE_Y = 256
DEST_U = 0
DEST_V = 191
UV_V_DELTA = DEST_V - SOURCE_Y


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
            for info in infos if not info.is_dir()
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


def file_offset(address: int) -> int:
    return address - RAM_TO_FILE


def i_type(op: int, rs: int, rt: int, immediate: int) -> int:
    return (op << 26) | (rs << 21) | (rt << 16) | (immediate & 0xFFFF)


def r_type(rs: int, rt: int, rd: int, shift: int, function: int) -> int:
    return (rs << 21) | (rt << 16) | (rd << 11) | (shift << 6) | function


def jal(address: int) -> int:
    return 0x0C000000 | ((address >> 2) & 0x03FFFFFF)


@dataclass
class BranchFixup:
    index: int
    op: int
    rs: int
    rt: int
    label: str


class Assembler:
    def __init__(self, address: int) -> None:
        self.address = address
        self.words: list[int] = []
        self.labels: dict[str, int] = {}
        self.fixups: list[BranchFixup] = []

    def emit(self, word: int) -> None:
        self.words.append(word & 0xFFFFFFFF)

    def label(self, name: str) -> None:
        if name in self.labels:
            raise BuildError(f"duplicate label: {name}")
        self.labels[name] = len(self.words)

    def branch(self, op: int, rs: int, rt: int, label: str) -> None:
        self.fixups.append(BranchFixup(len(self.words), op, rs, rt, label))
        self.emit(0)

    def finish(self) -> bytes:
        words = list(self.words)
        for fixup in self.fixups:
            if fixup.label not in self.labels:
                raise BuildError(f"undefined label: {fixup.label}")
            pc = self.address + fixup.index * 4
            target = self.address + self.labels[fixup.label] * 4
            delta = (target - (pc + 4)) // 4
            if not -0x8000 <= delta <= 0x7FFF:
                raise BuildError(f"branch out of range: {fixup.label}")
            words[fixup.index] = i_type(fixup.op, fixup.rs, fixup.rt, delta)
        return struct.pack(f"<{len(words)}I", *words)


def encode_chunk(words: list[int]) -> bytes:
    """PackBits variant: literal, zero-run, or repeated-word run (max 64)."""
    out = bytearray()
    offset = 0
    while offset < len(words):
        end = offset + 1
        while (
            end < len(words)
            and words[end] == words[offset]
            and end - offset < 64
        ):
            end += 1
        repeated = end - offset
        if words[offset] == 0:
            out.append(0x80 | (repeated - 1))
            offset = end
            continue
        if repeated >= 2:
            out.append(0xC0 | (repeated - 1))
            out.extend(struct.pack("<H", words[offset]))
            offset = end
            continue

        start = offset
        offset += 1
        while offset < len(words) and offset - start < 64:
            end = offset + 1
            while (
                end < len(words)
                and words[end] == words[offset]
                and end - offset < 64
            ):
                end += 1
            if words[offset] == 0 or end - offset >= 2:
                break
            offset += 1
        count = offset - start
        out.append(count - 1)
        out.extend(struct.pack(f"<{count}H", *words[start:offset]))
    return bytes(out)


def decode_chunk(stream: bytes, offset: int, word_count: int) -> tuple[list[int], int]:
    words: list[int] = []
    while len(words) < word_count:
        control = stream[offset]
        offset += 1
        count = (control & 0x3F) + 1
        if not control & 0x80:
            for _ in range(count):
                words.append(struct.unpack_from("<H", stream, offset)[0])
                offset += 2
        elif not control & 0x40:
            words.extend([0] * count)
        else:
            value = struct.unpack_from("<H", stream, offset)[0]
            offset += 2
            words.extend([value] * count)
        if len(words) > word_count:
            raise BuildError("RLE run crosses an upload chunk boundary")
    return words, offset


def cursor_art(original_comm: bytes) -> tuple[bytes, bytes, list[int]]:
    words: list[int] = []
    for y in range(SOURCE_Y, SOURCE_Y + UPLOAD_ROWS):
        at = y * COMM_ROW_BYTES + SOURCE_X // 2
        words.extend(struct.unpack_from(f"<{UPLOAD_WORDS_PER_ROW}H", original_comm, at))
    raw = struct.pack(f"<{len(words)}H", *words)
    chunks: list[bytes] = []
    chunk_heights: list[int] = []
    for row in range(0, UPLOAD_ROWS, CHUNK_ROWS):
        height = min(CHUNK_ROWS, UPLOAD_ROWS - row)
        start = row * UPLOAD_WORDS_PER_ROW
        end = start + height * UPLOAD_WORDS_PER_ROW
        chunks.append(encode_chunk(words[start:end]))
        chunk_heights.append(height)
    encoded = b"".join(chunks)
    if len(raw) != 1650 or sha256_bytes(raw) != EXPECTED_RAW_SHA256:
        raise BuildError("original cursor source drift")
    if len(encoded) != EXPECTED_RLE_SIZE or sha256_bytes(encoded) != EXPECTED_RLE_SHA256:
        raise BuildError("cursor RLE drift")

    decoded: list[int] = []
    offset = 0
    for height in chunk_heights:
        chunk, offset = decode_chunk(
            encoded, offset, height * UPLOAD_WORDS_PER_ROW
        )
        decoded.extend(chunk)
    if offset != len(encoded) or struct.pack(f"<{len(decoded)}H", *decoded) != raw:
        raise BuildError("cursor RLE round-trip mismatch")
    return raw, encoded, chunk_heights


# MIPS registers.
ZERO, A0, A1 = 0, 4, 5
T0, T1, T2, T3, T4, T5, T6 = 8, 9, 10, 11, 12, 13, 14
S0, S1, S2, S3, S4 = 16, 17, 18, 19, 20
SP, RA = 29, 31
NOP = 0


def build_upload_helper(address: int, data_address: int) -> bytes:
    """Decode at most eight rows into 400 stack bytes, then upload synchronously."""
    asm = Assembler(address)
    asm.emit(i_type(0x09, SP, SP, -0x1D0))
    for register, offset in (
        (RA, 0x1CC), (S0, 0x1C8), (S2, 0x1C4), (S3, 0x1C0), (S4, 0x1BC),
    ):
        asm.emit(i_type(0x2B, SP, register, offset))
    asm.emit(i_type(0x0F, ZERO, S0, data_address >> 16))
    asm.emit(i_type(0x0D, S0, S0, data_address & 0xFFFF))
    asm.emit(i_type(0x0D, ZERO, S2, UPLOAD_ROWS))
    asm.emit(i_type(0x0D, ZERO, S3, DEST_Y))
    asm.emit(i_type(0x0D, ZERO, T0, DEST_X_HALFWORD))
    asm.emit(i_type(0x29, SP, T0, 0))
    asm.emit(i_type(0x0D, ZERO, T0, UPLOAD_WORDS_PER_ROW))
    asm.emit(i_type(0x29, SP, T0, 4))

    asm.label("chunk")
    asm.emit(i_type(0x0B, S2, T0, CHUNK_ROWS + 1))
    asm.branch(0x05, T0, ZERO, "chunk_rows_ready")
    asm.emit(r_type(S2, ZERO, S4, 0, 0x21))
    asm.emit(i_type(0x0D, ZERO, S4, CHUNK_ROWS))
    asm.label("chunk_rows_ready")
    asm.emit(i_type(0x29, SP, S3, 2))
    asm.emit(i_type(0x29, SP, S4, 6))
    asm.emit(i_type(0x09, SP, T0, 8))
    # End = buffer + rows * 50 bytes.
    asm.emit(r_type(ZERO, S4, T2, 5, 0x00))
    asm.emit(r_type(ZERO, S4, T3, 4, 0x00))
    asm.emit(r_type(T2, T3, T2, 0, 0x21))
    asm.emit(r_type(ZERO, S4, T3, 1, 0x00))
    asm.emit(r_type(T2, T3, T2, 0, 0x21))
    asm.emit(r_type(T0, T2, T1, 0, 0x21))

    asm.label("token")
    asm.emit(i_type(0x24, S0, T2, 0))
    asm.emit(i_type(0x09, S0, S0, 1))  # independent load-delay slot
    asm.emit(i_type(0x0C, T2, T4, 0x3F))
    asm.emit(i_type(0x0C, T2, T3, 0x80))
    asm.branch(0x04, T3, ZERO, "literal")
    asm.emit(i_type(0x09, T4, T4, 1))
    asm.emit(i_type(0x0C, T2, T3, 0x40))
    asm.branch(0x05, T3, ZERO, "repeat")
    asm.emit(NOP)

    asm.label("zero_loop")
    asm.emit(i_type(0x29, T0, ZERO, 0))
    asm.emit(i_type(0x09, T4, T4, -1))
    asm.branch(0x05, T4, ZERO, "zero_loop")
    asm.emit(i_type(0x09, T0, T0, 2))
    asm.branch(0x04, ZERO, ZERO, "run_done")
    asm.emit(NOP)

    asm.label("repeat")
    asm.emit(i_type(0x24, S0, T5, 0))
    asm.emit(i_type(0x24, S0, T6, 1))
    asm.emit(i_type(0x09, S0, S0, 2))
    asm.emit(r_type(ZERO, T6, T6, 8, 0x00))
    asm.emit(r_type(T5, T6, T5, 0, 0x25))
    asm.label("repeat_loop")
    asm.emit(i_type(0x29, T0, T5, 0))
    asm.emit(i_type(0x09, T4, T4, -1))
    asm.branch(0x05, T4, ZERO, "repeat_loop")
    asm.emit(i_type(0x09, T0, T0, 2))
    asm.branch(0x04, ZERO, ZERO, "run_done")
    asm.emit(NOP)

    asm.label("literal")
    asm.label("literal_loop")
    asm.emit(i_type(0x24, S0, T5, 0))
    asm.emit(i_type(0x24, S0, T6, 1))
    asm.emit(i_type(0x09, S0, S0, 2))
    asm.emit(r_type(ZERO, T6, T6, 8, 0x00))
    asm.emit(r_type(T5, T6, T5, 0, 0x25))
    asm.emit(i_type(0x29, T0, T5, 0))
    asm.emit(i_type(0x09, T4, T4, -1))
    asm.branch(0x05, T4, ZERO, "literal_loop")
    asm.emit(i_type(0x09, T0, T0, 2))

    asm.label("run_done")
    asm.branch(0x05, T0, T1, "token")
    asm.emit(NOP)
    # LoadImage reads ceil(width*height/2) 32-bit words.  Zero its harmless
    # padding halfword for the final odd 25-halfword chunk.
    asm.emit(i_type(0x29, T1, ZERO, 0))
    asm.emit(r_type(SP, ZERO, A0, 0, 0x21))
    asm.emit(jal(LOADIMAGE))
    asm.emit(i_type(0x09, SP, A1, 8))
    asm.emit(r_type(S3, S4, S3, 0, 0x21))
    asm.emit(r_type(S2, S4, S2, 0, 0x23))
    asm.branch(0x05, S2, ZERO, "chunk")
    asm.emit(NOP)

    # Reproduce the two instructions displaced at INIT_HOOK.
    asm.emit(i_type(0x0F, ZERO, S1, 0x801F))
    asm.emit(i_type(0x09, S1, S1, 0x52BC))
    # Restore RA early enough to satisfy the R3000 load delay before jr.
    for register, offset in (
        (RA, 0x1CC), (S4, 0x1BC), (S3, 0x1C0), (S2, 0x1C4), (S0, 0x1C8),
    ):
        asm.emit(i_type(0x23, SP, register, offset))
    asm.emit(r_type(RA, ZERO, ZERO, 0, 0x08))
    asm.emit(i_type(0x09, SP, SP, 0x1D0))
    return asm.finish()


def main() -> None:
    if not BASE.is_file() or sha256_file(BASE) != BASE_SHA256:
        raise BuildError(f"V322 base hash mismatch: {BASE}")
    if not ORIGINAL.is_file() or sha256_file(ORIGINAL) != ORIGINAL_SHA256:
        raise BuildError(f"original archive hash mismatch: {ORIGINAL}")
    infos, before = read_archive(BASE)
    with ZipFile(ORIGINAL) as archive:
        original_comm = archive.read(COMM)
    if sha256_bytes(before[PSX]) != EXPECTED_PSX_SHA256:
        raise BuildError("V322 PSX.EXE hash drift")
    if sha256_bytes(before[COMM]) != EXPECTED_COMM_SHA256:
        raise BuildError("V322 COMM.IMG hash drift")
    if sha256_bytes(original_comm) != EXPECTED_ORIGINAL_COMM_SHA256:
        raise BuildError("original COMM.IMG hash drift")

    raw, encoded, chunk_heights = cursor_art(original_comm)
    exe = bytearray(before[PSX])
    if any(exe[CAVE_FILE : CAVE_FILE + CAVE_SIZE]):
        raise BuildError("V322 executable tail cave is no longer zero")
    if struct.unpack_from("<2I", exe, file_offset(INIT_HOOK)) != INIT_HOOK_WORDS:
        raise BuildError("range initializer hook premise drift")
    if sha256_bytes(bytes(exe[DESCRIPTOR_FILE : DESCRIPTOR_FILE + DESCRIPTOR_SIZE])) != DESCRIPTOR_SHA256:
        raise BuildError("range texture descriptor drift")
    if sha256_bytes(bytes(exe[UV_FILE : UV_FILE + UV_SIZE])) != UV_SHA256:
        raise BuildError("range UV table drift")
    uv_entries = tuple(
        struct.unpack_from("<8H", exe, UV_FILE + index * 16)
        for index in range(9)
    )
    if uv_entries != BASE_UV:
        raise BuildError("range UV entries differ from the nine-tile specification")

    provisional = build_upload_helper(CAVE_RAM, CAVE_RAM)
    if len(provisional) != EXPECTED_HELPER_SIZE:
        raise BuildError(f"upload helper size drift: {len(provisional)}")
    data_ram = CAVE_RAM + len(provisional)
    helper = build_upload_helper(CAVE_RAM, data_ram)
    if len(helper) != len(provisional):
        raise BuildError("helper size changed after fixing the data address")
    payload = helper + encoded
    if len(payload) > CAVE_SIZE:
        raise BuildError(f"EXE cave overflow by {len(payload) - CAVE_SIZE} bytes")

    struct.pack_into("<2I", exe, file_offset(INIT_HOOK), jal(CAVE_RAM), NOP)
    exe[CAVE_FILE : CAVE_FILE + len(payload)] = payload
    struct.pack_into("<I", exe, DESCRIPTOR_FILE + 0x10, DEST_TPAGE_X)
    struct.pack_into("<I", exe, DESCRIPTOR_FILE + 0x14, DEST_TPAGE_Y)
    relocated_uv: list[tuple[int, ...]] = []
    for index, entry in enumerate(BASE_UV):
        values = list(entry)
        for item in (1, 3, 5, 7):
            values[item] += UV_V_DELTA
            if not 0 <= values[item] <= 0xFF:
                raise BuildError("relocated UV exceeds its byte field")
        relocated_uv.append(tuple(values))
        struct.pack_into("<8H", exe, UV_FILE + index * 16, *values)

    # Semantic readback before packaging.
    if struct.unpack_from("<2I", exe, file_offset(INIT_HOOK)) != (jal(CAVE_RAM), 0):
        raise BuildError("initializer hook readback failed")
    if bytes(exe[CAVE_FILE : CAVE_FILE + len(helper)]) != helper:
        raise BuildError("helper readback failed")
    if bytes(exe[CAVE_FILE + len(helper) : CAVE_FILE + len(payload)]) != encoded:
        raise BuildError("RLE readback failed")
    if any(exe[CAVE_FILE + len(payload) : CAVE_FILE + CAVE_SIZE]):
        raise BuildError("unused EXE cave tail changed")
    descriptor = struct.unpack_from("<12I", exe, DESCRIPTOR_FILE)
    if descriptor[4:6] != (DEST_TPAGE_X, DEST_TPAGE_Y):
        raise BuildError("texture-page descriptor readback failed")
    final_uv = tuple(
        struct.unpack_from("<8H", exe, UV_FILE + index * 16)
        for index in range(9)
    )
    if final_uv != tuple(relocated_uv):
        raise BuildError("UV relocation readback failed")

    final = dict(before)
    final[PSX] = bytes(exe)
    changed_members = [name for name in before if before[name] != final[name]]
    if changed_members != [PSX]:
        raise BuildError(f"changed member set drift: {changed_members}")
    if final[COMM] != before[COMM] or sha256_bytes(final[COMM]) != EXPECTED_COMM_SHA256:
        raise BuildError("COMM.IMG changed")
    if any(len(before[name]) != len(final[name]) for name in before):
        raise BuildError("archive member size changed")

    actual_offsets = {
        offset
        for offset, (old, new) in enumerate(zip(before[PSX], final[PSX], strict=True))
        if old != new
    }
    allowed_offsets = (
        set(range(file_offset(INIT_HOOK), file_offset(INIT_HOOK) + 8))
        | set(range(CAVE_FILE, CAVE_FILE + len(payload)))
        | set(range(DESCRIPTOR_FILE + 0x10, DESCRIPTOR_FILE + 0x18))
        | set(range(UV_FILE, UV_FILE + UV_SIZE))
    )
    if not actual_offsets or not actual_offsets <= allowed_offsets:
        raise BuildError("PSX.EXE Expected-Write range violation")

    output_path, output_hash = write_archive(OUTPUT_STEM, infos, final, None)
    delta_path, delta_hash = write_archive(DELTA_STEM, infos, final, {PSX})
    with ZipFile(output_path) as archive:
        names = [info.filename for info in archive.infolist() if not info.is_dir()]
        if names != [info.filename for info in infos if not info.is_dir()]:
            raise BuildError("output ZIP topology drift")
        if any(archive.read(name) != final[name] for name in final):
            raise BuildError("output ZIP round-trip mismatch")
    with ZipFile(delta_path) as archive:
        if archive.namelist() != [PSX] or archive.read(PSX) != final[PSX]:
            raise BuildError("delta ZIP mismatch")

    ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
    (ANALYSIS_DIR / "cursor_texture_raw.bin").write_bytes(raw)
    (ANALYSIS_DIR / "cursor_texture_rle.bin").write_bytes(encoded)
    with (ANALYSIS_DIR / "expected_writes.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow(("file_offset", "ram_address", "before", "after", "region"))
        for offset in sorted(actual_offsets):
            if file_offset(INIT_HOOK) <= offset < file_offset(INIT_HOOK) + 8:
                region = "initializer_hook"
            elif CAVE_FILE <= offset < CAVE_FILE + len(payload):
                region = "upload_helper_and_rle"
            elif DESCRIPTOR_FILE + 0x10 <= offset < DESCRIPTOR_FILE + 0x18:
                region = "range_tpage_descriptor"
            else:
                region = "range_uv_table"
            writer.writerow(
                (f"0x{offset:X}", f"0x{RAM_TO_FILE + offset:08X}",
                 f"{before[PSX][offset]:02X}", f"{final[PSX][offset]:02X}", region)
            )

    manifest = {
        "build": "V323 TEST_ONLY skill-range texture relocation",
        "base": {"path": str(BASE), "sha256": BASE_SHA256},
        "output": {"path": str(output_path), "sha256": output_hash},
        "delta": {"path": str(delta_path), "sha256": delta_hash},
        "changed_members": changed_members,
        "changed_psx_bytes": len(actual_offsets),
        "source": {
            "comm_rect": [SOURCE_X, SOURCE_Y, 100, UPLOAD_ROWS],
            "raw_bytes": len(raw),
            "raw_sha256": sha256_bytes(raw),
            "rle_bytes": len(encoded),
            "rle_sha256": sha256_bytes(encoded),
        },
        "runtime_upload": {
            "hook": f"0x{INIT_HOOK:08X}",
            "helper": f"0x{CAVE_RAM:08X}",
            "helper_bytes": len(helper),
            "data": f"0x{data_ram:08X}",
            "stack_frame_bytes": 0x1D0,
            "rectangles": [
                [DEST_X_HALFWORD, DEST_Y + sum(chunk_heights[:index]),
                 UPLOAD_WORDS_PER_ROW, height]
                for index, height in enumerate(chunk_heights)
            ],
        },
        "texture": {
            "tpage_xy": [DEST_TPAGE_X, DEST_TPAGE_Y],
            "page": [15, 1],
            "uv_union": [DEST_U, DEST_V, 97, 33],
            "uv_v_delta": UV_V_DELTA,
            "clut": "unchanged",
        },
        "preserved": "COMM.IMG, all DAT, resident 5356-byte block, heap boundary, V322 text/font/E2/UI",
        "runtime": "PENDING user cold boot and expanded skill-range test",
        "release_status": "DIAGNOSTIC; DO NOT DISTRIBUTE",
    }
    (ANALYSIS_DIR / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V323 TEST ONLY - relocate complete skill-range cursor texture",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output_path.name}",
        f"sha256={output_hash}",
        f"delta={delta_path.name}",
        f"delta_sha256={delta_hash}",
        "changed_members=PSX.EXE only",
        f"PSX_changed_bytes={len(actual_offsets)}",
        "COMM.IMG/all_DAT=byte-identical to V322 PASS",
        f"cursor_source=original COMM x0..99,y128..160 raw {len(raw)}B",
        f"cursor_RLE={len(encoded)}B ({sha256_bytes(encoded)})",
        f"helper=0x{CAVE_RAM:08X}/{len(helper)}B; cave_used={len(payload)}/{CAVE_SIZE}B",
        "upload=page15,1 U0..99,V191..223 via five synchronous LoadImage calls",
        "range_UV=original + (0,63); CLUT unchanged",
        "temporary_stack=464B helper + 48B LoadImage; resident/heap unchanged",
        "runtime=PENDING user cold boot; TEST_ONLY",
    ]
    (ANALYSIS_DIR / "build_report.txt").write_text(
        "\n".join(report) + "\n", encoding="utf-8"
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
