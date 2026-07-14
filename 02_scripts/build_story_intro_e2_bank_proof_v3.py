from __future__ import annotations

import csv
import hashlib
import struct
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/story_intro_longtext_e2_pointer_proof_v2_patch_only.zip"
BASE_HASH = "C45EB983E310541AD148076E359166CE02729D65EB8F53E0DA6D24B27845FF2C"
BASE_CHARMAP = ROOT / "05_docs/korean_charmap.csv"
EXTENDED = ROOT / "05_docs/korean_charmap_extended.csv"
CORPUS = ROOT / "01_work/analysis/story_corpus/story_corpus.csv"
PSX_SOURCE = ROOT / "01_work/PSX.EXE"
OUTPUT = ROOT / "03_output/story_intro_longtext_e2_bank_proof_v3_patch_only.zip"

PSX_TARGET = "PSX.EXE"
PSX_HASH = "947EBF893F2D46207EC7E32CA514E4EA670E0BED34EF2144B5F7FB0FDD15BC67"
LOAD_ADDRESS = 0x8011B000
E2_CALL_ADDRESS = 0x8016BC84
E2_LOOKUP_ADDRESS = 0x8015EA44
HANDLER_ADDRESS = 0x8018FCD0
HANDLER_LIMIT = 0x8018FDC5

CUSTOM_INTERNAL_FIRST = 0x80
CUSTOM_INTERNAL_END = 0x90
CUSTOM_DISK_FIRST = CUSTOM_INTERNAL_FIRST + 1
SLOT_SIZE = 0x80
RAM_BANK_BASE = 0x80110000

LONG_FILE = "1/S1011.DAT"
LONG_OFFSET = 0x479FC
LONG_CAPACITY = 36
V2_STORAGE_OFFSET = 0x47700
V2_STORAGE_LIMIT = 0x47800
V3_SLOT_OFFSET = 0x45000
V3_SLOT_ADDRESS = RAM_BANK_BASE + CUSTOM_INTERNAL_FIRST * SLOT_SIZE
LONG_TEXT = "그리고 신의 피를 잇는 일족의 딸이라는 이유로 왕자와 결혼해야 해..."
FILLER = 0x9C


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def file_offset(address: int) -> int:
    return address - LOAD_ADDRESS + 0x800


def jump(address: int) -> int:
    return 0x08000000 | ((address >> 2) & 0x03FFFFFF)


def jal(address: int) -> int:
    return 0x0C000000 | ((address >> 2) & 0x03FFFFFF)


def encode(text: str, mapping: dict[str, bytes]) -> bytes:
    output = bytearray()
    for char in text:
        if char == " ":
            output.append(FILLER)
        else:
            output.extend(mapping[char])
    return bytes(output)


def handler_words() -> tuple[int, ...]:
    # Only E2's call site enters this handler. Direct character/monster lookups are untouched.
    return (
        0x308800FF,              # andi  t0,a0,00FF
        0x2D090080,              # sltiu t1,t0,0080
        0x15200008,              # bne   t1,zero,normal
        0x2D090090,              # sltiu t1,t0,0090 (delay)
        0x11200006,              # beq   t1,zero,normal
        0x2508FF80,              # addiu t0,t0,-0080 (delay)
        0x000811C0,              # sll   v0,t0,7
        0x3C098011,              # lui   t1,8011
        0x00491021,              # addu  v0,v0,t1
        0x03E00008,              # jr    ra
        0x00000000,              # nop
        jump(E2_LOOKUP_ADDRESS), # normal: preserve the original E2 name lookup
        0x00000000,              # nop
    )


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("v2 proof base hash differs")

    mapping: dict[str, bytes] = {}
    for path in (BASE_CHARMAP, EXTENDED):
        for row in load_csv(path):
            mapping[row["char"]] = bytes.fromhex(row["code_hex"])
    missing = sorted(char for char in set(LONG_TEXT) if char not in mapping and char != " ")
    if missing:
        raise SystemExit(f"missing glyph mappings: {''.join(missing)}")
    for row in load_csv(CORPUS):
        body = bytes.fromhex(row["original_hex"])
        for position in range(len(body) - 1):
            if body[position] == 0xE2 and CUSTOM_DISK_FIRST <= body[position + 1] <= CUSTOM_INTERNAL_END:
                raise SystemExit("custom E2 disk ID occurs in the original parsed corpus")

    with zipfile.ZipFile(BASE) as archive:
        files = {item.filename: archive.read(item.filename) for item in archive.infolist()}
    if len(files) != 39 or PSX_TARGET not in files:
        raise SystemExit("unexpected v2 proof base")

    story = bytearray(files[LONG_FILE])
    if story[LONG_OFFSET:LONG_OFFSET + 2] != b"\xE2\x6C":
        raise SystemExit("v2 inline command differs")
    if any(story[V3_SLOT_OFFSET:V3_SLOT_OFFSET + SLOT_SIZE]):
        raise SystemExit("v3 S1011 slot is not empty")

    long_payload = encode(LONG_TEXT, mapping) + b"\x00"
    if len(long_payload) > SLOT_SIZE:
        raise SystemExit("proof text exceeds one v3 bank slot")
    if any(byte >= 0xE1 for byte in long_payload[:-1]):
        raise SystemExit("v3 secondary text contains a control byte")
    story[V2_STORAGE_OFFSET:V2_STORAGE_LIMIT] = b"\x00" * (V2_STORAGE_LIMIT - V2_STORAGE_OFFSET)
    story[V3_SLOT_OFFSET:V3_SLOT_OFFSET + len(long_payload)] = long_payload
    story[LONG_OFFSET:LONG_OFFSET + LONG_CAPACITY] = bytes((FILLER,)) * LONG_CAPACITY
    story[LONG_OFFSET:LONG_OFFSET + 2] = bytes((0xE2, CUSTOM_DISK_FIRST))
    files[LONG_FILE] = bytes(story)

    psx = bytearray(PSX_SOURCE.read_bytes())
    if digest(psx) != PSX_HASH:
        raise SystemExit("PSX.EXE source hash differs")
    call_offset = file_offset(E2_CALL_ADDRESS)
    original_call = struct.unpack_from("<I", psx, call_offset)[0]
    if original_call != jal(E2_LOOKUP_ADDRESS):
        raise SystemExit(f"unexpected E2 call: 0x{original_call:08X}")
    if struct.unpack_from("<I", psx, call_offset + 4)[0] != 0:
        raise SystemExit("E2 call delay slot differs")

    cave_offset = file_offset(HANDLER_ADDRESS)
    cave_size = HANDLER_LIMIT - HANDLER_ADDRESS
    wrapper = struct.pack("<13I", *handler_words())
    if len(wrapper) > cave_size or any(psx[cave_offset:cave_offset + cave_size]):
        raise SystemExit("v3 handler cave differs or is too small")
    struct.pack_into("<I", psx, call_offset, jal(HANDLER_ADDRESS))
    psx[cave_offset:cave_offset + len(wrapper)] = wrapper
    if struct.unpack_from("<I", psx, call_offset)[0] != jal(HANDLER_ADDRESS):
        raise SystemExit("v3 E2 call hook verification failed")
    if psx[cave_offset:cave_offset + len(wrapper)] != wrapper:
        raise SystemExit("v3 handler verification failed")
    files[PSX_TARGET] = bytes(psx)

    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            item = zipfile.ZipInfo(name, date_time=(2026, 7, 14, 0, 0, 0))
            item.compress_type = zipfile.ZIP_DEFLATED
            item.external_attr = 0o100644 << 16
            archive.writestr(item, files[name], compresslevel=9)
    with zipfile.ZipFile(OUTPUT) as archive:
        names = archive.namelist()
        if len(names) != 39 or len(set(names)) != 39:
            raise SystemExit("v3 ZIP must contain 39 unique files")
        if archive.read(PSX_TARGET) != psx or archive.read(LONG_FILE) != story:
            raise SystemExit("v3 ZIP payload differs")

    report_path = ROOT / "01_work/analysis/story_intro_e2_bank_proof_v3_report.txt"
    report_path.write_text(
        f"base_sha256={BASE_HASH}\n"
        f"e2_call_address=0x{E2_CALL_ADDRESS:08X}\n"
        f"handler_address=0x{HANDLER_ADDRESS:08X}\n"
        f"custom_internal_range=0x{CUSTOM_INTERNAL_FIRST:02X}-0x{CUSTOM_INTERNAL_END - 1:02X}\n"
        f"proof_command=E2 {CUSTOM_DISK_FIRST:02X}\n"
        f"slot_size={SLOT_SIZE}\n"
        f"slot_file_offset=0x{V3_SLOT_OFFSET:X}\n"
        f"slot_ram_address=0x{V3_SLOT_ADDRESS:08X}\n"
        f"external_text_bytes={len(long_payload) - 1}\n"
        f"psx_sha256={digest(psx)}\n"
        f"zip_sha256={digest(OUTPUT.read_bytes())}\n",
        encoding="utf-8",
    )
    print(f"external_text_bytes={len(long_payload) - 1} handler_bytes={len(wrapper)} files={len(files)}")
    print(OUTPUT)
    print(digest(OUTPUT.read_bytes()))


if __name__ == "__main__":
    main()
