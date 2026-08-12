#!/usr/bin/env python3
"""Independently verify the v191 local dialogue/choice archive."""
from __future__ import annotations

import csv
import hashlib
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v171_ui_asset_recovery as v171  # noqa: E402
import build_arc1_v186_runtime_text_choice_fixes as v186  # noqa: E402
import build_arc1_v189_dialogue_timing_choice_rows as v189  # noqa: E402
import verify_arc1_v171_ui_asset_recovery as v171_verify  # noqa: E402


BASE = ROOT / "03_output/arc1_v190_dynamic_owner_repair_4AC51D4F.zip"
BASE_SHA256 = "4AC51D4F38F38B65782DBD5AAE5A7DA03369A57D6E7DBF3F437E4EDB29556619"
EXPECTED = ROOT / "03_output/arc1_v191_yagun_choice_local_fixes_682EC28A.zip"
EXPECTED_SHA256 = "682EC28A565FAD7E66C4D70A79D66B6F63C227FA079047C9903CB1B808325690"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
S3012 = "31/S3012.DAT"
S2042 = "21/S2042.DAT"
S3031 = "31/S3031.DAT"
S3032 = "31/S3032.DAT"
CHOICE_OFFSET = 0x47FF0
CHOICE_SIZE = 53
SLOT_BASE = v186.SLOT_BASE
SLOT_SIZE = v186.SLOT_SIZE

EXPECTED_TEXT = {
    (S3031, 37): "야군: 하지만 그건 아이들에게는 무리입니다. 너무 위험합니다.",
    (S3031, 40): "야군: 최근에는 이 근처에도 몬스터가 나타나고 있습니다.",
    (S3032, 7): "야군: 다만 저곳은 우리도 애를 먹고 있는 곳입니다.",
    (S3032, 6): "야군: 만일 무슨 일이 있어도 우리는 책임을 지지 않습니다.",
    (S3012, 0): "초핀: 제가 도와드릴 일이 있습니까?",
}
EXPECTED_COMPLETION = {
    (S3031, 37): 36,
    (S3031, 40): 28,
    (S3032, 7): 30,
    (S3032, 6): 32,
    (S3012, 0): 23,
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def slot_payload(data: bytes, slot: int) -> tuple[bytes, int]:
    start = SLOT_BASE + slot * SLOT_SIZE
    block = data[start:start + SLOT_SIZE]
    end = block.find(b"\0")
    if end < 0 or any(block[end:SLOT_SIZE - 1]):
        raise SystemExit(f"slot {slot} termination/tail differs")
    return block[:end], block[-1]


def runtime_decoder(exe: bytes):
    ranges = v171_verify.direct_ranges(exe)
    lookup = v171_verify.packed_lookup(exe)
    with (
        ROOT / "01_work/analysis/arc1_v190_dynamic_owner_repair/source_manifest.csv"
    ).open(encoding="utf-8-sig", newline="") as handle:
        dynamic = {int(row["source_id"]): row["char"] for row in csv.DictReader(handle)}
    with (
        ROOT / "01_work/analysis/dynamic_cache_v153_widthsafe/glyph_assignments.csv"
    ).open(encoding="utf-8-sig", newline="") as handle:
        static = {
            int(row["physical_index"]): row["char"]
            for row in csv.DictReader(handle)
            if row["kind"] == "static" and row["physical_index"]
        }
    static.update({155: " ", 857: ":", 1055: "?", 1080: "."})

    def decode(payload: bytes) -> str:
        result: list[str] = []
        for token in v186.tokens(payload):
            if len(token) == 1:
                index = token[0] - 1
                source = ranges.get(index)
                char = dynamic.get(source) if source is not None else static.get(index)
            else:
                lead, trail = token
                if 0xDD <= lead <= 0xE8:
                    index = (lead - 0xDD) * 255 + trail + 0xDB
                    source = ranges.get(index)
                    char = dynamic.get(source) if source is not None else static.get(index)
                elif lead in (0xE9, 0xEA):
                    virtual = (lead - 0xE9) * 254 + trail - 1
                    if not 0 <= virtual < len(lookup):
                        raise SystemExit(f"lookup token outside table: {token.hex(' ')}")
                    value = lookup[virtual]
                    char = dynamic.get(value - 1536) if value >= 1536 else static.get(value)
                else:
                    char = None
            if char is None:
                raise SystemExit(f"runtime map cannot decode token {token.hex(' ')}")
            result.append(char)
        return "".join(result)

    return decode


def main() -> None:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else EXPECTED
    if digest(BASE) != BASE_SHA256 or digest(target) != EXPECTED_SHA256:
        raise SystemExit("v190 base or v191 target hash differs")
    with ZipFile(BASE) as archive:
        base_names = archive.namelist()
        base = {name: archive.read(name) for name in base_names}
    with ZipFile(target) as archive:
        if archive.namelist() != base_names:
            raise SystemExit("archive member order differs")
        made = {name: archive.read(name) for name in archive.namelist()}

    changed = sorted(name for name in made if made[name] != base[name])
    expected_changed = sorted((S3012, S2042, S3031, S3032))
    if changed != expected_changed:
        raise SystemExit(f"changed member set differs: {changed}")
    if made[PSX] != base[PSX] or made[COMM] != base[COMM]:
        raise SystemExit("PSX.EXE or COMM.IMG changed")
    if any(len(made[name]) != len(base[name]) for name in base):
        raise SystemExit("archive member length differs")

    mapping = v171.current_char_mapping()
    mapping[":"] = bytes.fromhex("DF 80")
    decode = runtime_decoder(made[PSX])
    for (member, slot), text in EXPECTED_TEXT.items():
        payload, completion = slot_payload(made[member], slot)
        expected = v186.encode_text(text, mapping)
        if payload != expected or decode(payload) != text:
            raise SystemExit(f"slot text/readback differs: {member} slot {slot}")
        if completion != EXPECTED_COMPLETION[(member, slot)]:
            raise SystemExit(f"slot completion differs: {member} slot {slot}")

    # S3012 must call slot 0 from body +0 and resume at the surviving +25 E6.
    s3012 = made[S3012]
    body3012 = s3012[CHOICE_OFFSET:CHOICE_OFFSET + CHOICE_SIZE]
    if body3012[:2] != bytes.fromhex("E2 81"):
        raise SystemExit("S3012 slot redirect is not at body start")
    if body3012[25:27] != bytes.fromhex("E6 01"):
        raise SystemExit("S3012 first choice row break differs")

    # S2042's inline first row and both copies' complete option tails.
    prompt2042 = v186.encode_text("초핀: 더 도와드릴까요?", mapping)
    body2042 = made[S2042][CHOICE_OFFSET:CHOICE_OFFSET + CHOICE_SIZE]
    if body2042[:len(prompt2042)] != prompt2042:
        raise SystemExit("S2042 inline prompt differs")
    for member, body in ((S3012, body3012), (S2042, body2042)):
        if made[member][CHOICE_OFFSET + 25:CHOICE_OFFSET + CHOICE_SIZE] != \
                base[member][CHOICE_OFFSET + 25:CHOICE_OFFSET + CHOICE_SIZE]:
            raise SystemExit(f"choice option tail differs: {member}")
        markers = v186.structural.markers(body)
        if [p for p, token in markers if token == bytes.fromhex("E5 03")] != [27, 38]:
            raise SystemExit(f"choice E5 positions differ: {member}")
        if [p for p, token in markers if token == bytes.fromhex("E6 01")] != [25, 36]:
            raise SystemExit(f"choice E6 positions differ: {member}")
        rows = v186.structural.drawn_rows(body, made[member])
        widths = [v186.structural.row_width(row) for row in rows]
        if len(rows) != 3 or max(widths) > 228:
            raise SystemExit(f"choice visual rows differ: {member} {widths}")

    checked = 0
    changed_choices = 0
    targets = {(S3012, CHOICE_OFFSET), (S2042, CHOICE_OFFSET)}
    for member, bodies in v186.choice_bodies().items():
        if member not in made:
            continue
        for offset, raw in bodies:
            left = base[member][offset:offset + len(raw)]
            right = made[member][offset:offset + len(raw)]
            if left != right:
                if (member, offset) not in targets:
                    raise SystemExit(f"undeclared choice changed: {member} 0x{offset:X}")
                changed_choices += 1
            checked += 1
    if (checked, changed_choices) != (357, 2):
        raise SystemExit(f"choice audit count differs: {checked}/{changed_choices}")

    print("v191 independent verification PASS")
    print(f"archive={target.name}")
    print(f"sha256={EXPECTED_SHA256}")
    print("Yagun_slots=4/4 runtime-map readback")
    print("choice_targets=2; untouched=355/355")
    print("PSX.EXE/COMM.IMG=v190 byte-identical")
    print(f"changed_members={','.join(changed)}")
    print("emulator_run=NO")


if __name__ == "__main__":
    main()
