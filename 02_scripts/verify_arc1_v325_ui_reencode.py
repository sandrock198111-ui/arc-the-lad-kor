#!/usr/bin/env python3
"""Independent static verification for the V325 Hanme16 UI rebuild."""

from __future__ import annotations

import csv
import hashlib
import json
import pickle
import struct
import sys
from collections import defaultdict
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import build_arc1_v320_hanme_static_recovery as v320  # noqa: E402
import build_arc1_v320c_hanme_official_beol as v320c  # noqa: E402
import build_arc1_v324_static_ui_cursor_recovery as v324  # noqa: E402


BASE = ROOT / "03_output/arc1_v324_static_ui_cursor_recovery_TEST_ONLY_06F7C289.zip"
FINAL = ROOT / "03_output/arc1_v325_ui_reencode_TEST_ONLY_7828AA04.zip"
DELTA = ROOT / "03_output/arc1_v325_ui_reencode_TEST_ONLY_delta_from_v324_3A531423.zip"
BASE_SHA256 = "06F7C289B593AB2767BA3D3ABC256ACCFD21781F60DF46A18F1D3FF58D67FD4B"
FINAL_SHA256 = "7828AA04F6A0684981332924C30B4139ABFCA5065138FA899C4D429E87C74CD1"
DELTA_SHA256 = "3A531423DBA076557BA67548E0161813CBA8CB01D253DD70C79F753DC2E3EE7B"

TABLE = ROOT / "05_docs/ui_full_v42.csv"
SYSTEM = ROOT / "05_docs/ui_system_v39.csv"
NONSTORY = ROOT / "05_docs/ui_nonstory_system_v39.csv"
WORLD = ROOT / "05_docs/ui_world_name_v39.csv"
PIECES = ROOT / "01_work/analysis/hangul_johab_16px/pieces_1bpp.bin"
ASCII = ROOT / "01_work/analysis/hangul_johab_16px/ascii_16px.pkl"
UI_AUDIT = ROOT / "01_work/analysis/arc1_v325_ui_reencode/ui_reencode.csv"
ANALYSIS = ROOT / "01_work/analysis/arc1_v325_ui_reencode"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
RAM_TO_FILE = 0x8011A800
POOL_SEGMENTS = (
    (0x80224, 0x804A4), (0x805A4, 0x80A94), (0x80B94, 0x80C9C),
    (0x80D1C, 0x80F14), (0x80F94, 0x811C0), (0x812AC, 0x81708),
    (0x817F4, 0x81B4C), (0x81CFC, 0x81E38), (0x81F04, 0x82134),
)
HUD_POINTERS = (0x823AC, 0x823B0, 0x823B4, 0x823B8, 0x823BC)
NEW_GLYPHS = {"%": 403, "뱀": 762, "센": 819, "첩": 823, "탑": 865}
ICON_TOKENS = {"{결정버튼}": b"\xE7\x02", "{취소버튼}": b"\xE7\x03"}
PRIORITY = {"table": 0, "system": 1, "nonstory": 2, "world": 3}
SPECS = (
    ("table", TABLE, "korean", 503),
    ("system", SYSTEM, "korean", 40),
    ("nonstory", NONSTORY, "korean", 128),
    ("world", WORLD, "korean_target", 7),
)


class VerifyError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha256_file(path: Path) -> str:
    return sha256(path.read_bytes())


def read_zip(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        return names, {name: archive.read(name) for name in names}


def csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def raw_string(data: bytes, start: int) -> bytes:
    end = data.find(b"\x00", start, min(len(data), start + 513))
    if end < 0:
        raise VerifyError(f"unterminated string at 0x{start:X}")
    return data[start:end]


def pointer_target(exe: bytes, pointer: int) -> int:
    target = struct.unpack_from("<I", exe, pointer)[0] - RAM_TO_FILE
    if not 0 <= target < len(exe):
        raise VerifyError(f"bad pointer 0x{pointer:X}->0x{target:X}")
    return target


def normalize(text: str) -> str:
    for old, new in (
        ("LV +1", "레벨 1"), ("LV 1", "레벨 1"),
        ("LV 상승", "레벨 상승"), ("레벨 +1", "레벨 1"),
    ):
        text = text.replace(old, new)
    return text


def expected_records() -> dict[int, str]:
    gathered: dict[int, list[tuple[str, str]]] = defaultdict(list)
    total = 0
    for category, path, field, expected in SPECS:
        rows = csv_rows(path)
        if len(rows) != expected:
            raise VerifyError(f"manifest row drift: {path.name}/{len(rows)}")
        total += len(rows)
        for row in rows:
            gathered[int(row["pointer_offset"], 0)].append((category, row[field]))
    if total != 678 or len(gathered) != 671:
        raise VerifyError(f"manifest census mismatch: {total}/{len(gathered)}")
    conflicts = {p for p, v in gathered.items() if len({text for _c, text in v}) > 1}
    if conflicts != {0x80F1C}:
        raise VerifyError(f"manifest conflicts changed: {conflicts}")
    result: dict[int, str] = {}
    for pointer, values in gathered.items():
        if pointer in HUD_POINTERS:
            continue
        _category, text = min(values, key=lambda item: PRIORITY[item[0]])
        if pointer == 0x825D8:
            text = "몬스터 도감"
        result[pointer] = normalize(text)
    if len(result) != 666 or result[0x80F1C] != "레벨 1 상승":
        raise VerifyError("rebuilt record census/precedence mismatch")
    return result


def resolve(exe: bytes, token: bytes) -> int | None:
    if len(token) == 1:
        return token[0] - 1 if 1 <= token[0] <= 0xDC else None
    if len(token) != 2:
        return None
    lead, trail = token
    if lead in (0xE9, 0xEA) and 1 <= trail <= 0xFE:
        slot = (lead - 0xE9) * 254 + trail - 1
        return v320.lookup_get(exe, slot) if slot < v320.LOOKUP_SLOTS else None
    if 0xDD <= lead <= 0xE0 and 1 <= trail <= 0xFF:
        return (lead - 0xDD) * 255 + trail + 0xDB
    return None


def verify_semantics(
    exe: bytes,
    comm: bytes,
    text: str,
    payload: bytes,
    pieces: tuple[tuple[int, ...], ...],
    ascii_rows: dict[str, object],
) -> tuple[int, int]:
    text_at = 0
    byte_at = 0
    spaces = 0
    while text_at < len(text):
        marker_hit = False
        for marker, expected_token in ICON_TOKENS.items():
            if text.startswith(marker, text_at):
                if payload[byte_at : byte_at + 2] != expected_token:
                    raise VerifyError(f"icon token mismatch in {text!r}")
                text_at += len(marker)
                byte_at += 2
                marker_hit = True
                break
        if marker_hit:
            continue
        if byte_at >= len(payload):
            raise VerifyError(f"payload ends early: {text!r}")
        char = text[text_at]
        width = 1 if payload[byte_at] < 0xDD else 2
        token = payload[byte_at : byte_at + width]
        if len(token) != width or token == b"\x9C":
            raise VerifyError(f"invalid/legacy token at character boundary: {text!r}")
        physical = resolve(exe, token)
        if physical is None or not 0 <= physical < 960:
            raise VerifyError(f"non-static token {token.hex()} in {text!r}")
        if char == " ":
            if token != b"\xA1" or physical != 160 or any(v320.read_plane(comm, 160)):
                raise VerifyError("space is not A1/blank physical160")
            spaces += 1
        elif 0xAC00 <= ord(char) <= 0xD7A3:
            expected = v320c.compose(pieces, char, official=True)
            if v320.read_plane(comm, physical) != expected:
                raise VerifyError(f"Hangul bitmap mismatch: {char}/{physical}")
        else:
            if char not in ascii_rows:
                raise VerifyError(f"non-ASCII UI symbol lacks reference: {char!r}")
            expected = v320.validate_rows(ascii_rows[char], f"ASCII {char!r}")
            if v320.read_plane(comm, physical) != expected:
                raise VerifyError(f"ASCII bitmap mismatch: {char!r}/{physical}")
        text_at += 1
        byte_at += width
    if byte_at != len(payload):
        raise VerifyError(f"payload has trailing token(s): {text!r}")
    return spaces, byte_at


def allowed_psx_offsets(records: dict[int, str]) -> set[int]:
    allowed: set[int] = set()
    for start, end in POOL_SEGMENTS:
        allowed.update(range(start, end))
    for pointer in records:
        allowed.update(range(pointer, pointer + 4))
    return allowed


def main() -> None:
    if sha256_file(BASE) != BASE_SHA256 or sha256_file(FINAL) != FINAL_SHA256:
        raise VerifyError("base/final ZIP hash mismatch")
    if sha256_file(DELTA) != DELTA_SHA256:
        raise VerifyError("delta ZIP hash mismatch")
    base_names, before = read_zip(BASE)
    final_names, after = read_zip(FINAL)
    delta_names, delta = read_zip(DELTA)
    if base_names != final_names or len(final_names) != 164:
        raise VerifyError("ZIP topology drift")
    changed = {name for name in final_names if before[name] != after[name]}
    if changed != {PSX, COMM} or set(delta_names) != changed:
        raise VerifyError(f"changed/delta member mismatch: {changed}/{delta_names}")
    if any(len(before[name]) != len(after[name]) for name in final_names):
        raise VerifyError("member size changed")
    if any(delta[name] != after[name] for name in delta_names):
        raise VerifyError("delta member content mismatch")

    records = expected_records()
    audit_rows = csv_rows(UI_AUDIT)
    if len(audit_rows) != 666 or {int(row["pointer_offset"], 0) for row in audit_rows} != set(records):
        raise VerifyError("UI audit pointer census mismatch")
    audit_by_pointer = {int(row["pointer_offset"], 0): row for row in audit_rows}
    pieces = v320c.load_pieces(PIECES.read_bytes())
    ascii_rows = pickle.loads(ASCII.read_bytes())
    unique_payloads: set[bytes] = set()
    intervals: dict[int, bytes] = {}
    total_spaces = 0
    for pointer, text in records.items():
        row = audit_by_pointer[pointer]
        if row["korean"] != text:
            raise VerifyError(f"manifest text mismatch at 0x{pointer:X}")
        target = pointer_target(after[PSX], pointer)
        if target != int(row["string_offset"], 0):
            raise VerifyError(f"pointer target mismatch at 0x{pointer:X}")
        if not any(start <= target < end for start, end in POOL_SEGMENTS):
            raise VerifyError(f"pointer target outside verified pools: 0x{pointer:X}")
        payload = raw_string(after[PSX], target)
        reported = bytes.fromhex(row["encoded_hex"]) if row["encoded_hex"] else b""
        if payload != reported or len(payload) != int(row["encoded_bytes"]):
            raise VerifyError(f"payload/readback mismatch at 0x{pointer:X}")
        spaces, _length = verify_semantics(after[PSX], after[COMM], text, payload, pieces, ascii_rows)
        if spaces != int(row["space_count"]) or (spaces and row["space_code"] != "A1"):
            raise VerifyError(f"space census mismatch at 0x{pointer:X}")
        total_spaces += spaces
        unique_payloads.add(payload)
        if target in intervals and intervals[target] != payload:
            raise VerifyError(f"payload alias conflict at 0x{target:X}")
        intervals[target] = payload
        if after[PSX][target + len(payload)] != 0:
            raise VerifyError(f"missing terminator at 0x{target:X}")
    required = sum(len(payload) + 1 for payload in unique_payloads)
    if len(unique_payloads) != 561 or required != 5590 or total_spaces != 697:
        raise VerifyError(f"payload/space census mismatch: {len(unique_payloads)}/{required}/{total_spaces}")
    spans = sorted((start, start + len(payload) + 1) for start, payload in intervals.items())
    for (_s1, e1), (s2, _e2) in zip(spans, spans[1:]):
        if e1 > s2:
            raise VerifyError("allocated strings overlap")
    occupied = {offset for start, end in spans for offset in range(start, end)}
    pool_offsets = {offset for start, end in POOL_SEGMENTS for offset in range(start, end)}
    if any(after[PSX][offset] for offset in pool_offsets - occupied):
        raise VerifyError("unused UI pool byte is not zero")

    psx_diff = {i for i, (old, new) in enumerate(zip(before[PSX], after[PSX])) if old != new}
    if len(psx_diff) != 7284 or not psx_diff <= allowed_psx_offsets(records):
        raise VerifyError("PSX diff escaped UI pools/pointers")
    comm_diff = {i for i, (old, new) in enumerate(zip(before[COMM], after[COMM])) if old != new}
    if len(comm_diff) != 226:
        raise VerifyError(f"COMM byte diff mismatch: {len(comm_diff)}")
    changed_planes = {
        index
        for index in range(v320.COLS * v320.FULL_ROWS * v320.PLANES)
        if v320.read_plane(before[COMM], index) != v320.read_plane(after[COMM], index)
    }
    if changed_planes != set(NEW_GLYPHS.values()):
        raise VerifyError(f"unexpected COMM planes changed: {changed_planes}")
    for char, physical in NEW_GLYPHS.items():
        expected = (
            v320.validate_rows(ascii_rows[char], f"ASCII {char}")
            if char == "%"
            else v320c.compose(pieces, char, official=True)
        )
        if v320.read_plane(after[COMM], physical) != expected:
            raise VerifyError(f"new glyph mismatch: {char}/{physical}")
    for y in range(512):
        start = y * v320.ROW_BYTES + 120
        end = (y + 1) * v320.ROW_BYTES
        if before[COMM][start:end] != after[COMM][start:end]:
            raise VerifyError(f"COMM x>=240 changed at row {y}")

    preserved = (
        (v324.SOURCE_FILE, v324.SOURCE_FILE + v324.COPY_SIZE),
        (v324.file_offset(v324.LOOKUP_RAM), v324.file_offset(v324.LOOKUP_RAM) + v324.LOOKUP_BYTES),
        (v324.DESCRIPTOR_FILE, v324.DESCRIPTOR_FILE + v324.DESCRIPTOR_SIZE),
        (v324.UV_FILE, v324.UV_FILE + v324.UV_SIZE),
        (v324.BAD_V323_CAVE_FILE, v324.BAD_V323_CAVE_FILE + v324.BAD_V323_CAVE_SIZE),
    )
    if any(before[PSX][start:end] != after[PSX][start:end] for start, end in preserved):
        raise VerifyError("V324 resident lookup/cursor range changed")
    for pointer in HUD_POINTERS:
        if before[PSX][pointer : pointer + 4] != after[PSX][pointer : pointer + 4]:
            raise VerifyError(f"HUD pointer changed: 0x{pointer:X}")
        old_target = pointer_target(before[PSX], pointer)
        new_target = pointer_target(after[PSX], pointer)
        if old_target != new_target or raw_string(before[PSX], old_target) != raw_string(after[PSX], new_target):
            raise VerifyError(f"HUD binary payload changed: 0x{pointer:X}")
    dat_members = [name for name in final_names if name.upper().endswith(".DAT")]
    if not dat_members or any(before[name] != after[name] for name in dat_members):
        raise VerifyError("DAT preservation failed")

    result = {
        "status": "PASS",
        "base_sha256": BASE_SHA256,
        "final_sha256": FINAL_SHA256,
        "delta_sha256": DELTA_SHA256,
        "members": len(final_names),
        "changed_members": sorted(changed),
        "changed_bytes": {PSX: len(psx_diff), COMM: len(comm_diff)},
        "ui_records": len(records),
        "unique_payloads": len(unique_payloads),
        "pool_required": required,
        "pool_free": 6076 - required,
        "spaces_A1": total_spaces,
        "changed_planes": sorted(changed_planes),
        "dat_members_preserved": len(dat_members),
        "runtime": "PENDING user cold boot and UI traversal",
    }
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = "\n".join(f"{key}={value}" for key, value in result.items()) + "\n"
    (ANALYSIS / "independent_verification.txt").write_text(report, encoding="utf-8")
    print("V325 independent verification PASS")
    print(f"ZIP={FINAL.name} SHA256={FINAL_SHA256}")
    print(f"members={len(final_names)} changed={','.join(sorted(changed))}")
    print(f"UI={len(records)} pointers/{len(unique_payloads)} payloads; pool={required}/6076")
    print(f"spaces=A1 x{total_spaces}; changed_planes={','.join(map(str, sorted(changed_planes)))}")
    print(f"DAT preserved={len(dat_members)}; runtime=PENDING")


if __name__ == "__main__":
    main()
