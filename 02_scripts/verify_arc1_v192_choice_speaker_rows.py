#!/usr/bin/env python3
"""Independently verify the v192 choice-speaker archive."""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v171_ui_asset_recovery as v171  # noqa: E402
import build_arc1_v186_runtime_text_choice_fixes as v186  # noqa: E402
import build_arc1_v191_yagun_choice_local_fixes as v191  # noqa: E402
import verify_arc1_v191_yagun_choice_local_fixes as v191_verify  # noqa: E402


BASE = ROOT / "03_output/arc1_v191_yagun_choice_local_fixes_682EC28A.zip"
BASE_SHA256 = "682EC28A565FAD7E66C4D70A79D66B6F63C227FA079047C9903CB1B808325690"
GEOMETRY = ROOT / "03_output/arc1_v190_dynamic_owner_repair_4AC51D4F.zip"
GEOMETRY_SHA256 = "4AC51D4F38F38B65782DBD5AAE5A7DA03369A57D6E7DBF3F437E4EDB29556619"
EXPECTED = ROOT / "03_output/arc1_v192_choice_speaker_rows_899DDD9A.zip"
EXPECTED_SHA256 = "899DDD9A4D22B80AD9229605461C25ABA0FE79FAC6B1533D2A9AE1ABC5B22A35"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
E5 = bytes.fromhex("E5 03")
E6 = bytes.fromhex("E6 01")

TARGETS = (
    ("1/S1023.DAT", 0x47952, 0, "어머니: 아버지가 남긴 편지를 읽을래?"),
    ("21/S2042.DAT", 0x47FF0, 11, "초핀: 더 도와드릴까요?"),
    ("31/S3012.DAT", 0x47FF0, 0, "초핀: 제가 도와드릴 일이 있습니까?"),
    ("31/S3022.DAT", 0x48822, 35, "병사: 출발하시겠습니까?"),
    ("7/S7021.DAT", 0x48D26, 7, "대회 위원: 출전하시겠습니까?"),
    ("7/S7022.DAT", 0x489B6, 7, "대회 위원: 1회전 준비됐습니까?"),
    ("7/S7023.DAT", 0x48A4E, 7, "대회 위원: 2회전 준비됐습니까?"),
    ("7/S7024.DAT", 0x48AAE, 7, "대회 위원: 준결승 준비됐습니까?"),
    ("7/S7025.DAT", 0x48AC2, 7, "대회 위원: 결승 준비됐습니까?"),
    ("7/S7026.DAT", 0x48D28, 7, "대회 위원: 오브 쟁탈전 준비됐습니까?"),
    ("7/S7028.DAT", 0x48028, 14, "대회 위원: 출전하시겠습니까?"),
    ("7/S7028.DAT", 0x48B70, 15, "대회 위원: 정말 출전하시겠습니까?"),
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def slot_payload(data: bytes, slot: int) -> tuple[bytes, int]:
    start = v186.SLOT_BASE + slot * v186.SLOT_SIZE
    block = data[start:start + v186.SLOT_SIZE]
    end = block.find(b"\0")
    if end < 0 or any(block[end:v186.SLOT_SIZE - 1]):
        raise SystemExit(f"slot termination/tail differs: {slot}")
    return block[:end], block[-1]


def main() -> None:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else EXPECTED
    if digest(BASE) != BASE_SHA256 or digest(GEOMETRY) != GEOMETRY_SHA256:
        raise SystemExit("base archive hash differs")
    if digest(target) != EXPECTED_SHA256:
        raise SystemExit("v192 archive hash differs")
    with ZipFile(BASE) as archive:
        names = archive.namelist()
        base = {name: archive.read(name) for name in names}
    with ZipFile(GEOMETRY) as archive:
        geometry = {name: archive.read(name) for name in archive.namelist()}
    with ZipFile(target) as archive:
        if archive.namelist() != names:
            raise SystemExit("archive member order differs")
        made = {name: archive.read(name) for name in names}

    if made[PSX] != base[PSX] or made[COMM] != base[COMM]:
        raise SystemExit("PSX.EXE or COMM.IMG changed")
    if any(len(made[name]) != len(base[name]) for name in names):
        raise SystemExit("archive member length changed")

    raw_bodies = {
        (member, offset): raw
        for member, bodies in v186.choice_bodies().items()
        for offset, raw in bodies
    }
    mapping = v171.current_char_mapping()
    mapping[":"] = bytes.fromhex("DF 80")
    runtime_decode = v191_verify.runtime_decoder(made[PSX])

    def decode(payload: bytes) -> str:
        result: list[str] = []
        for token in v186.tokens(payload):
            if token == b"\x12":
                result.append("1")
            elif token == b"\x13":
                result.append("2")
            else:
                result.append(runtime_decode(token))
        return "".join(result)
    target_keys = {(member, offset) for member, offset, _slot, _text in TARGETS}

    for member, offset, slot, text in TARGETS:
        raw = raw_bodies[(member, offset)]
        body = made[member][offset:offset + len(raw)]
        stock = geometry[member][offset:offset + len(raw)]
        if v186.structural.markers(body) != v186.structural.markers(stock):
            raise SystemExit(f"marker geometry differs: {member} 0x{offset:X}")
        e6 = [position for position, token in v186.structural.markers(stock) if token == E6]
        e5 = [position for position, token in v186.structural.markers(stock) if token == E5]
        if len(e6) < 3 or len(e5) != 2:
            raise SystemExit(f"stock target geometry differs: {member} 0x{offset:X}")
        first_break, second_break = e6[:2]
        if body[second_break:] != stock[second_break:]:
            raise SystemExit(f"option tail differs: {member} 0x{offset:X}")
        payload, completion = slot_payload(made[member], slot)
        if decode(payload) != text or payload != v186.encode_text(text, mapping):
            raise SystemExit(f"prompt runtime readback differs: {member} 0x{offset:X}")
        if completion != first_break - 2:
            raise SystemExit(f"slot completion differs: {member} 0x{offset:X}")
        if v191.slot_references(made[member], slot) != [offset]:
            raise SystemExit(f"slot owner differs: {member} slot {slot}")
        rows = v186.structural.drawn_rows(body, made[member])
        widths = [v186.structural.row_width(row) for row in rows]
        if len(rows) != 4 or widths[1] != 0 or max(widths) > v186.ROW_PIXELS:
            raise SystemExit(f"target row layout differs: {member} 0x{offset:X} {widths}")
        stock_rows = v186.structural.drawn_rows(stock, geometry[member])
        if widths[2:] != [v186.structural.row_width(row) for row in stock_rows][2:]:
            raise SystemExit(f"option widths differ: {member} 0x{offset:X}")

    checked = 0
    changed = 0
    for member, bodies in v186.choice_bodies().items():
        if member not in made:
            continue
        for offset, raw in bodies:
            key = (member, offset)
            current = made[member][offset:offset + len(raw)]
            old_geometry = geometry[member][offset:offset + len(raw)]
            if v186.structural.markers(current) != v186.structural.markers(old_geometry):
                raise SystemExit(f"whole-game marker mismatch: {member} 0x{offset:X}")
            if key in target_keys:
                changed += 1
            elif current != base[member][offset:offset + len(raw)]:
                raise SystemExit(f"undeclared choice mutation: {member} 0x{offset:X}")
            checked += 1
    if (checked, changed) != (357, 12):
        raise SystemExit(f"choice count differs: {checked}/{changed}")

    expected_changed = sorted({member for member, _offset, _slot, _text in TARGETS})
    actual_changed = sorted(name for name in names if made[name] != base[name])
    if actual_changed != expected_changed:
        raise SystemExit(f"changed member set differs: {actual_changed}")

    print("v192 independent verification PASS")
    print(f"archive={target.name}")
    print(f"sha256={EXPECTED_SHA256}")
    print("speaker_prompts=12/12 runtime-map readback")
    print("choice_E5_E6_geometry=v190 exact 357/357")
    print("target_option_tails=v190 byte-identical 12/12")
    print("other_choices=v191 byte-identical 345/345")
    print("PSX.EXE/COMM.IMG=v191 byte-identical")
    print("emulator_run=NO")


if __name__ == "__main__":
    main()
