from __future__ import annotations

import csv
import hashlib
import struct
import zipfile
from pathlib import Path

from build_story_sf0b1_return_full import (
    BASE_CHARMAP,
    CURSOR_RESERVED_CELLS,
    FILLER,
    FONT_TARGET,
    glyph_index,
    write_glyph_plane,
)


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/story_intro_longtext_e2_bank_proof_v3_patch_only.zip"
BASE_HASH = "FA84E7A9169C481BFBBD5B18F5285EA132598E2137B84F261935EB1B5AC26416"
MANIFEST = ROOT / "05_docs/story_intro_e2_expanded_translation.csv"
EXTENDED = ROOT / "05_docs/korean_charmap_extended.csv"
CORPUS = ROOT / "01_work/analysis/story_corpus/story_corpus.csv"
OUTPUT = ROOT / "03_output/story_intro_e2_expanded_v05_cumulative_patch_only.zip"
REPORT = ROOT / "01_work/analysis/story_intro_e2_expanded_v05_report.txt"

PSX_TARGET = "PSX.EXE"
TARGET_COUNTS = {"1/S1071.DAT": 4, "1/S1011.DAT": 9}
SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT_COUNT = 16
CUSTOM_DISK_FIRST = 0x81
HANDLER_CALL_OFFSET = 0x51484
HANDLER_JAL = 0x0C063F34
LOAD_ADDRESS = 0x8011B000
HANDLER_ADDRESS = 0x8018FCD0
HANDLER_LIMIT = 0x8018FDC5
LOOKUP_ADDRESS = 0x8015EA44
E2_COMPLETION_ADDRESS = 0x8016BDC0
E2_COMPLETION_TARGET = 0x8016BE44
COMPLETION_HELPER_ADDRESS = 0x8018FD20


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def file_offset(address: int) -> int:
    return address - LOAD_ADDRESS + 0x800


def jump(address: int) -> int:
    return 0x08000000 | ((address >> 2) & 0x03FFFFFF)


def old_handler() -> bytes:
    return struct.pack(
        "<13I",
        0x308800FF, 0x2D090080, 0x15200008, 0x2D090090,
        0x11200006, 0x2508FF80, 0x000811C0, 0x3C098011,
        0x00491021, 0x03E00008, 0x00000000,
        jump(LOOKUP_ADDRESS), 0x00000000,
    )


def completion_handler() -> bytes:
    # This runs only after the secondary string pointer reaches its terminator.
    # The byte before s0+0x14 is the E2 disk ID because inline parsing paused
    # immediately after E2 nn while the secondary string was displayed.
    return struct.pack(
        "<14I",
        0x8E080014,                    # lw    t0,14(s0)
        0x9109FFFF,                    # lbu   t1,-1(t0) (disk E2 ID)
        0x2529FF7F,                    # addiu t1,t1,-0081
        0x2D2A0010,                    # sltiu t2,t1,0010
        0x11400006,                    # beq   t2,zero,done
        0x000949C0,                    # sll   t1,t1,7 (delay)
        0x3C0A8011,                    # lui   t2,8011
        0x012A4821,                    # addu  t1,t1,t2 (slot base)
        0x912A007F,                    # lbu   t2,7F(t1) (inline skip)
        0x010A4021,                    # addu  t0,t0,t2
        0xAE080014,                    # sw    t0,14(s0)
        0x34020001,                    # done: ori v0,zero,1
        jump(E2_COMPLETION_TARGET),    # resume original completion path
        0x00000000,              # nop
    )


def cursor_code(code: bytes) -> bool:
    row, remainder = divmod(glyph_index(code), 84)
    column, _ = divmod(remainder, 4)
    # The confirmed cursor source is x=0..31, y=128..159. A 12x12 glyph
    # in row 10 overlaps its top four pixels even though the older coarse
    # reservation starts at row 11, so reject by exact rectangle overlap.
    glyph_left = column * 12
    glyph_top = row * 12
    return glyph_left < 32 and glyph_left + 12 > 0 and glyph_top < 160 and glyph_top + 12 > 128


def encode(text: str, mapping: dict[str, bytes]) -> bytes:
    payload = bytearray()
    for char in text:
        payload.extend(bytes((FILLER,)) if char == " " else mapping[char])
    return bytes(payload)


def contains_control(payload: bytes) -> bool:
    position = 0
    while position < len(payload):
        if 0xDD <= payload[position] <= 0xE0:
            if position + 1 >= len(payload):
                return True
            position += 2
        elif payload[position] >= 0xE1:
            return True
        else:
            position += 1
    return False


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_HASH:
        raise SystemExit("v3 cumulative base hash differs")

    manifest = rows(MANIFEST)
    counts = {name: sum(item["file"] == name for item in manifest) for name in TARGET_COUNTS}
    if counts != TARGET_COUNTS or len(manifest) != 13:
        raise SystemExit(f"unexpected intro manifest: {counts}")

    mapping: dict[str, bytes] = {}
    for path in (BASE_CHARMAP, EXTENDED):
        for item in rows(path):
            mapping[item["char"]] = bytes.fromhex(item["code_hex"])
    extended = rows(EXTENDED)
    occupied = set(mapping.values())

    parsed_codes: set[bytes] = set()
    for item in rows(CORPUS):
        body = bytes.fromhex(item["original_hex"])
        position = 0
        while position < len(body):
            if 0xDD <= body[position] <= 0xE0 and position + 1 < len(body):
                parsed_codes.add(body[position:position + 2])
                position += 2
            else:
                position += 1

    missing = sorted({char for item in manifest for char in item["text"] if char not in mapping and char != " "})
    candidates = [
        bytes((first, second))
        for first in range(0xE0, 0xDC, -1)
        for second in range(0xFF, -1, -1)
        if bytes((first, second)) not in occupied
        and bytes((first, second)) not in parsed_codes
        and not cursor_code(bytes((first, second)))
    ]
    if len(candidates) < len(missing):
        raise SystemExit(f"not enough safe glyph codes: {len(missing)} > {len(candidates)}")
    additions = []
    for char, code in zip(missing, candidates):
        mapping[char] = code
        additions.append({
            "char": char,
            "code_hex": code.hex().upper(),
            "slot_note": "intro E2 expanded v0.1",
        })

    with zipfile.ZipFile(BASE) as archive:
        files = {item.filename: archive.read(item.filename) for item in archive.infolist()}
    if len(files) != 39 or set(TARGET_COUNTS) - files.keys():
        raise SystemExit("unexpected v3 cumulative file set")
    psx = bytearray(files[PSX_TARGET])
    if struct.unpack_from("<I", psx, HANDLER_CALL_OFFSET)[0] != HANDLER_JAL:
        raise SystemExit("dedicated E2 handler call is missing")
    handler_offset = file_offset(HANDLER_ADDRESS)
    handler_size = HANDLER_LIMIT - HANDLER_ADDRESS
    if psx[handler_offset:handler_offset + len(old_handler())] != old_handler():
        raise SystemExit("v3 E2 handler bytes differ")
    if any(psx[handler_offset + len(old_handler()):handler_offset + handler_size]):
        raise SystemExit("v3 E2 handler cave tail is not empty")
    completion_offset = file_offset(E2_COMPLETION_ADDRESS)
    if struct.unpack_from("<I", psx, completion_offset)[0] != jump(E2_COMPLETION_TARGET):
        raise SystemExit("original E2 completion jump differs")
    if struct.unpack_from("<I", psx, completion_offset + 4)[0] != 0:
        raise SystemExit("original E2 completion delay slot differs")
    helper = completion_handler()
    helper_offset = file_offset(COMPLETION_HELPER_ADDRESS)
    if helper_offset < handler_offset + len(old_handler()) or helper_offset + len(helper) > handler_offset + handler_size:
        raise SystemExit("completion helper does not fit handler cave")
    psx[handler_offset:handler_offset + handler_size] = b"\x00" * handler_size
    psx[handler_offset:handler_offset + len(old_handler())] = old_handler()
    psx[helper_offset:helper_offset + len(helper)] = helper
    struct.pack_into("<I", psx, completion_offset, jump(COMPLETION_HELPER_ADDRESS))
    files[PSX_TARGET] = bytes(psx)

    base_font = files[FONT_TARGET]
    font = bytearray(base_font)
    # The v3 cumulative font already contains every earlier accepted mapping.
    # Re-render this batch on every run so a second deterministic build still
    # writes glyphs that were appended to the CSV by the first successful run.
    batch_glyphs = [item for item in extended if item["slot_note"] == "intro E2 expanded v0.1"] + additions
    for item in batch_glyphs:
        write_glyph_plane(font, bytes.fromhex(item["code_hex"]), item["char"])
    cursor = lambda data: b"".join(data[y * 0x380:y * 0x380 + 16] for y in range(128, 160))
    if cursor(font) != cursor(base_font):
        raise SystemExit("battle cursor texture regression")
    files[FONT_TARGET] = bytes(font)

    targets = {name: bytearray(files[name]) for name in TARGET_COUNTS}
    report_lines = []
    used_slots: dict[str, set[int]] = {name: set() for name in TARGET_COUNTS}
    for item in manifest:
        name = item["file"]
        offset = int(item["offset"], 0)
        capacity = int(item["capacity"])
        slot = int(item["slot"])
        if not 0 <= slot < SLOT_COUNT or slot in used_slots[name]:
            raise SystemExit(f"invalid or duplicate slot: {name} {slot}")
        used_slots[name].add(slot)

        end = offset + capacity
        if targets[name][end:end + 2] != b"\x00\x00":
            raise SystemExit(f"missing dialogue boundary: {name} 0x{offset:X}")
        payload = encode(item["text"], mapping)
        if len(payload) + 2 > SLOT_SIZE:
            raise SystemExit(f"E2 slot overflow: {name} slot {slot} {len(payload) + 2}/{SLOT_SIZE}")
        if contains_control(payload):
            raise SystemExit(f"secondary string contains a control byte: {name} slot {slot}")

        slot_offset = SLOT_BASE + slot * SLOT_SIZE
        targets[name][slot_offset:slot_offset + SLOT_SIZE] = b"\x00" * SLOT_SIZE
        targets[name][slot_offset:slot_offset + len(payload)] = payload
        targets[name][slot_offset + SLOT_SIZE - 1] = capacity - 2
        # Preserve the original bounded-body end. The skip-aware E2 handler
        # advances s0+0x14 from offset+2 to this original end before returning.
        targets[name][offset:offset + 2] = bytes((0xE2, CUSTOM_DISK_FIRST + slot))
        report_lines.append(
            f"{name} 0x{offset:X} slot={slot} command=E2 {CUSTOM_DISK_FIRST + slot:02X} "
            f"skip={capacity - 2} bytes={len(payload) + 2}/{SLOT_SIZE} text={item['text']}"
        )

    files.update({name: bytes(data) for name, data in targets.items()})
    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=(2026, 7, 14, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, files[name], compresslevel=9)

    with zipfile.ZipFile(BASE) as before, zipfile.ZipFile(OUTPUT) as after:
        names = after.namelist()
        if len(names) != 39 or len(set(names)) != 39:
            raise SystemExit("output must contain 39 unique files")
        changed = []
        for name in before.namelist():
            if before.read(name) != after.read(name):
                changed.append(name)
        expected_changed = {PSX_TARGET, FONT_TARGET, *TARGET_COUNTS}
        if set(changed) != expected_changed:
            raise SystemExit(f"unexpected cumulative changes: {changed}")

    if additions:
        with EXTENDED.open("a", encoding="utf-8", newline="") as handle:
            csv.DictWriter(handle, fieldnames=["char", "code_hex", "slot_note"]).writerows(additions)

    REPORT.write_text(
        "\n".join(report_lines)
        + f"\nbatch_glyphs={len(batch_glyphs)}\n"
        + f"new_glyphs_added={len(additions)}\n"
        + f"changed_files={','.join(sorted(expected_changed))}\n"
        + f"sha256={digest(OUTPUT.read_bytes())}\n",
        encoding="utf-8",
    )
    print(f"entries={len(manifest)} new_glyphs={len(additions)} files={len(files)}")
    print(OUTPUT)
    print(digest(OUTPUT.read_bytes()))


if __name__ == "__main__":
    main()
