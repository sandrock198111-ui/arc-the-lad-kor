"""Build dependency-complete v160 boot-isolation controls.

The older N1/N2 controls restored the first two v151 decoder instructions but left
v159/v160's resident data at the address of v151's lookup table.  They therefore
mixed an old decoder with a different table and cannot isolate the boot failure.

Q1 keeps the complete v160 decoder/table/cache relationship and disables only the
per-frame cache uploader.

Q2 additionally changes every dynamic lookup entry to glyph index zero.  This keeps
the new two-byte decoder active while ensuring that its owner/active/cache branch is
never entered.

Both outputs are full v160 patch archives.  They are diagnostics, not release builds.
"""
from __future__ import annotations

import hashlib
import struct
import sys
import zipfile
from pathlib import Path
from zipfile import ZipInfo


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/arc1_v160_dynamic_cache_ram_shadow_53521478.zip"
BASE_SHA256 = "53521478B42D9684B8111F883E905ED45D498484C9087BD330AC4B21F0987F2E"

OUT_Q1 = ROOT / "03_output/DIAG_Q1_v160_frame_off_dependency_complete.zip"
OUT_Q2 = ROOT / "03_output/DIAG_Q2_v160_dynamic_branch_off_dependency_complete.zip"

PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800
FRAME_HOOK = 0x8011C4AC
DECODER_HOOK = 0x801A74B8
LOOKUP_RAM = 0x801A7520
LOOKUP_N = 409
RESIDENT_LO, RESIDENT_HI = 0x801FE3C4, 0x801FF8B0

STOCK_FRAME_CALL = 0x0C047205  # jal 0x8011C814
EXPECTED_DECODER = 0x801FF060
EXPECTED_FRAME = 0x801FF1A0
BLANK_GLYPH_INDEX = 0


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def file_at(address: int) -> int:
    return address - RAM_TO_FILE


def word(data: bytes | bytearray, address: int) -> int:
    return struct.unpack_from("<I", data, file_at(address))[0]


def jump_target(address: int, instruction: int) -> int:
    return ((address + 4) & 0xF0000000) | ((instruction & 0x03FFFFFF) << 2)


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(out, attr, getattr(info, attr))
    return out


def write_archive(path: Path, infos: list[ZipInfo], members: dict[str, bytes],
                  note: str) -> None:
    if path.exists():
        raise SystemExit(f"refusing to overwrite existing diagnostic: {path}")
    payload = dict(members)
    if "TEST_INFO.txt" in payload:
        payload["TEST_INFO.txt"] += ("\n\n" + note + "\n").encode("utf-8")
    with zipfile.ZipFile(path, "w") as archive:
        for info in infos:
            archive.writestr(clone(info), payload[info.filename])


def main() -> None:
    if not BASE.exists():
        raise SystemExit(f"missing frozen v160 archive: {BASE}")
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v160 archive hash differs; refusing to build")

    with zipfile.ZipFile(BASE) as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}
    if PSX not in members:
        raise SystemExit("PSX.EXE is absent from v160 archive")

    original = members[PSX]
    frame_word = word(original, FRAME_HOOK)
    decoder_word = word(original, DECODER_HOOK)
    if frame_word >> 26 != 0x03 or jump_target(FRAME_HOOK, frame_word) != EXPECTED_FRAME:
        raise SystemExit(f"v160 frame hook differs: 0x{frame_word:08X}")
    if decoder_word >> 26 != 0x02 or \
            jump_target(DECODER_HOOK, decoder_word) != EXPECTED_DECODER:
        raise SystemExit(f"v160 decoder hook differs: 0x{decoder_word:08X}")
    if not RESIDENT_LO <= EXPECTED_DECODER < EXPECTED_FRAME < RESIDENT_HI:
        raise SystemExit("expected resident routines escape the reserved block")

    # Q1: one instruction only.  Decoder, lookup table and resident state stay paired.
    q1 = bytearray(original)
    struct.pack_into("<I", q1, file_at(FRAME_HOOK), STOCK_FRAME_CALL)
    if word(q1, DECODER_HOOK) != decoder_word:
        raise SystemExit("Q1 changed the decoder hook")
    if q1[file_at(LOOKUP_RAM):file_at(LOOKUP_RAM) + LOOKUP_N * 2] != \
            original[file_at(LOOKUP_RAM):file_at(LOOKUP_RAM) + LOOKUP_N * 2]:
        raise SystemExit("Q1 changed the lookup table")
    q1_members = dict(members)
    q1_members[PSX] = bytes(q1)
    write_archive(
        OUT_Q1, infos, q1_members,
        "Q1 diagnostic: v160 decoder/table/cache intact; frame uploader disabled.",
    )

    # Q2: frame uploader remains off and every high-bit entry becomes a safe static
    # index.  The decoder's dynamic owner/active/cache path is consequently unreachable.
    q2 = bytearray(q1)
    lookup = list(struct.unpack_from(f"<{LOOKUP_N}H", q2, file_at(LOOKUP_RAM)))
    dynamic_slots = [slot for slot, entry in enumerate(lookup) if entry & 0x8000]
    if not dynamic_slots:
        raise SystemExit("v160 lookup table contains no dynamic entries")
    for slot in dynamic_slots:
        struct.pack_into(
            "<H", q2, file_at(LOOKUP_RAM) + slot * 2, BLANK_GLYPH_INDEX,
        )
    if any(entry & 0x8000 for entry in struct.unpack_from(
            f"<{LOOKUP_N}H", q2, file_at(LOOKUP_RAM))):
        raise SystemExit("Q2 still contains a dynamic lookup entry")
    if word(q2, DECODER_HOOK) != decoder_word or word(q2, FRAME_HOOK) != STOCK_FRAME_CALL:
        raise SystemExit("Q2 hook relationship differs")
    q2_members = dict(members)
    q2_members[PSX] = bytes(q2)
    write_archive(
        OUT_Q2, infos, q2_members,
        f"Q2 diagnostic: Q1 plus {len(dynamic_slots)} dynamic lookup aliases mapped "
        "to static glyph index zero.",
    )

    print("dependency-complete v160 boot controls")
    print(f"  base decoder  0x{EXPECTED_DECODER:08X}")
    print(f"  base frame    0x{EXPECTED_FRAME:08X}")
    print(f"  Q1 changes    frame hook only")
    print(f"  Q2 changes    frame hook + {len(dynamic_slots)} dynamic lookup aliases")
    for path in (OUT_Q1, OUT_Q2):
        print(f"  {path.name}")
        print(f"    sha256 {digest(path.read_bytes())}")


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    main()
