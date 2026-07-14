from __future__ import annotations

import csv
import hashlib
import struct
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/story_intro_longtext_e2ff_proof_patch_only.zip"
BASE_HASH = "D9A1ED41CA127931572754FFABC3456331E2696F437F63294F015AF3F968975A"
BASE_CHARMAP = ROOT / "05_docs/korean_charmap.csv"
EXTENDED = ROOT / "05_docs/korean_charmap_extended.csv"
PSX_SOURCE = ROOT / "01_work/PSX.EXE"
OUTPUT = ROOT / "03_output/story_intro_longtext_e2_pointer_proof_v2_patch_only.zip"

PSX_TARGET = "PSX.EXE"
PSX_HASH = "947EBF893F2D46207EC7E32CA514E4EA670E0BED34EF2144B5F7FB0FDD15BC67"
LOAD_ADDRESS = 0x8011B000
NAME_TABLE_ADDRESS = 0x8019C34C
PROOF_NAME_INDEX = 107
PROOF_COMMAND = bytes((0xE2, PROOF_NAME_INDEX + 1))

LONG_FILE = "1/S1011.DAT"
LONG_OFFSET = 0x479FC
LONG_CAPACITY = 36
STORAGE_OFFSET = 0x47700
STORAGE_ADDRESS = 0x80116700
STORAGE_LIMIT = 0x47800
LONG_TEXT = (
    "그리고 신의 피를 잇는|"
    "일족의 딸이라는 이유로|"
    "왕자와 결혼해야 해..."
)
FILLER = 0x9C
LINEBREAK = b"\xE6\x01"


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def file_offset(address: int) -> int:
    return address - LOAD_ADDRESS + 0x800


def encode(text: str, mapping: dict[str, bytes]) -> bytes:
    output = bytearray()
    for char in text:
        if char == "|":
            output.extend(LINEBREAK)
        elif char == " ":
            output.append(FILLER)
        else:
            output.extend(mapping[char])
    return bytes(output)


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("failed proof base hash differs")

    mapping: dict[str, bytes] = {}
    for path in (BASE_CHARMAP, EXTENDED):
        for row in load_csv(path):
            mapping[row["char"]] = bytes.fromhex(row["code_hex"])
    missing = sorted(char for char in set(LONG_TEXT) if char not in mapping and char not in " |")
    if missing:
        raise SystemExit(f"missing glyph mappings: {''.join(missing)}")

    with zipfile.ZipFile(BASE) as archive:
        files = {item.filename: archive.read(item.filename) for item in archive.infolist()}
    if len(files) != 39 or PSX_TARGET not in files:
        raise SystemExit("unexpected failed proof base")

    story = bytearray(files[LONG_FILE])
    if story[LONG_OFFSET:LONG_OFFSET + 2] != b"\xE2\xFF":
        raise SystemExit("failed proof inline command differs")
    if any(story[STORAGE_OFFSET:STORAGE_LIMIT]):
        raise SystemExit("S1011 storage window is not empty")

    long_payload = encode(LONG_TEXT, mapping) + b"\x00"
    if STORAGE_OFFSET + len(long_payload) > STORAGE_LIMIT:
        raise SystemExit("external text exceeds the S1011 storage window")
    story[STORAGE_OFFSET:STORAGE_OFFSET + len(long_payload)] = long_payload
    story[LONG_OFFSET:LONG_OFFSET + LONG_CAPACITY] = bytes((FILLER,)) * LONG_CAPACITY
    story[LONG_OFFSET:LONG_OFFSET + len(PROOF_COMMAND)] = PROOF_COMMAND
    files[LONG_FILE] = bytes(story)

    psx = bytearray(PSX_SOURCE.read_bytes())
    if digest(psx) != PSX_HASH:
        raise SystemExit("PSX.EXE source hash differs")
    hook_offset = file_offset(0x8015EA44)
    if psx[hook_offset:hook_offset + 8] != bytes.fromhex("1A80033C4CC36324"):
        raise SystemExit("original E2 lookup prologue differs")
    pointer_offset = file_offset(NAME_TABLE_ADDRESS) + PROOF_NAME_INDEX * 4
    original_pointer = struct.unpack_from("<I", psx, pointer_offset)[0]
    if original_pointer != 0x8019C340:
        raise SystemExit(f"unexpected proof name pointer: 0x{original_pointer:08X}")
    struct.pack_into("<I", psx, pointer_offset, STORAGE_ADDRESS)
    if struct.unpack_from("<I", psx, pointer_offset)[0] != STORAGE_ADDRESS:
        raise SystemExit("proof pointer verification failed")
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
            raise SystemExit("proof ZIP must contain 39 unique files")
        if archive.read(PSX_TARGET) != psx or archive.read(LONG_FILE) != story:
            raise SystemExit("proof ZIP payload differs")

    report_path = ROOT / "01_work/analysis/story_intro_e2_pointer_proof_v2_report.txt"
    report_path.write_text(
        f"base_sha256={BASE_HASH}\n"
        f"proof_command={PROOF_COMMAND.hex(' ').upper()}\n"
        f"proof_name_index={PROOF_NAME_INDEX}\n"
        f"original_name_pointer=0x{original_pointer:08X}\n"
        f"storage_file_offset=0x{STORAGE_OFFSET:X}\n"
        f"storage_ram_address=0x{STORAGE_ADDRESS:08X}\n"
        f"external_text_bytes={len(long_payload) - 1}\n"
        f"psx_sha256={digest(psx)}\n"
        f"zip_sha256={digest(OUTPUT.read_bytes())}\n",
        encoding="utf-8",
    )
    print(f"external_text_bytes={len(long_payload) - 1} files={len(files)}")
    print(OUTPUT)
    print(digest(OUTPUT.read_bytes()))


if __name__ == "__main__":
    main()
