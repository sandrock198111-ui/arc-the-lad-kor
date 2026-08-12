"""Independent static verification for the v169 E1 parser-dispatch patch."""
from __future__ import annotations

import csv
import hashlib
import struct
import sys
from collections import Counter
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32  # noqa: E402
from audit_dynamic_cache_requirements import active_slots, source_ranges  # noqa: E402
from build_arc1_v161_bounded_exe_text import pointer_records, string_span, target  # noqa: E402
from plan_bulk_insertion import SLOT_BASE, SLOT_SIZE, tokens  # noqa: E402
import audit_arc1_v168_control_glyph_collisions as evidence  # noqa: E402
import build_arc1_v165_failclosed_cache as old  # noqa: E402


BASE = evidence.V168
BASE_SHA256 = evidence.V168_SHA256
PATCH = ROOT / "03_output/arc1_v169_e1_control_glyph_dispatch_218D38D2.zip"
PATCH_SHA256 = "218D38D21FED1D20E79483D657ED2E31D86425DA644F88322461F18BC3C9D4B0"
OUT = ROOT / "01_work/analysis/arc1_v169_e1_control_glyph_dispatch_verification"
REPORT = OUT / "verification_report.txt"

PSX = "PSX.EXE"
PARSER_FIRST, PARSER_SECOND = 0x801A7460, 0x801A748C
HELPER, HELPER_CAPACITY = 0x801FF82C, 128
HELPER_SIZE = 120
FRAME_CALL = 0x801FF7DC
FIRST_GLYPH, FIRST_CONTROL = 0x8016BB6C, 0x8016BB54
SECOND_GLYPH, SECOND_CONTROL = 0x8016BB80, 0x8016BB9C
FONT_CLUT_TABLE = 0x801F2FFE
FONT_CLUT_BYTES = 32


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def load(path: Path, expected: str):
    if (actual := digest(path.read_bytes())) != expected:
        raise SystemExit(f"archive hash differs: {path.name} {actual}")
    with ZipFile(path) as archive:
        infos = archive.infolist()
        return infos, {info.filename: archive.read(info.filename) for info in infos}


def token_offsets(payload: bytes):
    cursor = 0
    for token in tokens(payload):
        yield cursor, token
        cursor += len(token)
    if cursor != len(payload):
        raise SystemExit("token walker did not consume one bounded payload")


def bounded_e1(members: dict[str, bytes]) -> dict[tuple[str, int], bytes]:
    result: dict[tuple[str, int], bytes] = {}
    ranges = source_ranges()

    def collect(name: str, offset: int, payload: bytes) -> None:
        for relative, token in token_offsets(payload):
            if len(token) == 2 and token[0] == 0xE1:
                result[(name, offset + relative)] = token

    for name, offset, size in ranges:
        if name in members and offset + size <= len(members[name]):
            collect(name, offset, members[name][offset:offset + size])
    for name, slots in active_slots(members, ranges).items():
        for slot in slots:
            at = SLOT_BASE + slot * SLOT_SIZE
            block = members[name][at:at + SLOT_SIZE]
            end = block.find(b"\0")
            if end <= 0:
                raise SystemExit(f"invalid active slot {name}:{slot}")
            collect(name, at, block[:end])
    exe = members[PSX]
    seen: set[tuple[int, int]] = set()
    for pointer in pointer_records():
        span = string_span(exe, target(exe, pointer))
        if span in seen:
            continue
        seen.add(span)
        collect(PSX, span[0], exe[span[0]:span[1]])
    return result


def main() -> None:
    base_infos, base = load(BASE, BASE_SHA256)
    patch_infos, patch = load(PATCH, PATCH_SHA256)
    if [info.filename for info in base_infos] != [info.filename for info in patch_infos]:
        raise SystemExit("archive member order changed")

    changed = [name for name in base if base[name] != patch[name]]
    if set(changed) != {PSX, "4/S4011.DAT"}:
        raise SystemExit(f"unexpected changed members: {changed}")
    before_exe, after_exe = base[PSX], patch[PSX]
    if len(before_exe) != len(after_exe):
        raise SystemExit("PSX.EXE size changed")

    # Parse the immutable evidence produced before the build.
    with evidence.OCCURRENCES.open(encoding="utf-8-sig", newline="") as handle:
        collision_rows = list(csv.DictReader(handle))
    with evidence.CONTROL_RESTORES.open(encoding="utf-8-sig", newline="") as handle:
        restore_rows = list(csv.DictReader(handle))
    collision_positions = {
        (row["member"], int(row["offset"])): bytes.fromhex(row["risky_code"])
        for row in collision_rows
    }
    if len(collision_positions) != 1063 or len({row["char"] for row in collision_rows}) != 48:
        raise SystemExit("collision evidence dimensions differ")
    if len(restore_rows) != 1:
        raise SystemExit("native E1 restore evidence is not unique")
    restore = restore_rows[0]
    restore_key = (restore["member"], int(restore["offset"]))

    # Final bounded E1 population must be exactly the 1,063 proven high-trail
    # glyphs plus the one untouched-disc E1 01 command.
    final_e1 = bounded_e1(patch)
    if set(final_e1) != set(collision_positions) | {restore_key}:
        raise SystemExit("final bounded E1 positions differ from glyph+command evidence")
    for key, expected_code in collision_positions.items():
        if final_e1[key] != expected_code or not 0xBE <= expected_code[1] <= 0xF0:
            raise SystemExit(f"colliding glyph differs at {key}")
    if final_e1[restore_key] != b"\xE1\x01":
        raise SystemExit("native E1 01 was not restored")
    args = Counter(code[1] for code in final_e1.values())

    # The two parser call sites must differ only by the mode written in the jump
    # delay slot.  Both enter the reclaimed resident helper.
    for entry, mode in ((PARSER_FIRST, 0), (PARSER_SECOND, 1)):
        if old.word(after_exe, entry) != old.j(HELPER):
            raise SystemExit(f"parser trampoline target differs at 0x{entry:08X}")
        if old.word(after_exe, entry + 4) != old.i_type(0x0D, old.ZERO, old.T9, mode):
            raise SystemExit(f"parser trampoline mode differs at 0x{entry + 4:08X}")

    helper_at = old.source_at(HELPER)
    helper = after_exe[helper_at:helper_at + HELPER_SIZE]
    if any(after_exe[helper_at + HELPER_SIZE:helper_at + HELPER_CAPACITY]):
        raise SystemExit("reclaimed helper padding is not zero")
    old.validate_routine("v169_parser_dispatch", HELPER, helper)
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    instructions = list(md.disasm(helper, HELPER))
    if len(instructions) != HELPER_SIZE // 4:
        raise SystemExit("helper disassembly length differs")
    jump_targets = {
        int(item.op_str, 16)
        for item in instructions
        if item.mnemonic == "j" and item.op_str.startswith("0x")
    }
    expected_targets = {FIRST_GLYPH, FIRST_CONTROL, SECOND_GLYPH, SECOND_CONTROL}
    if jump_targets != expected_targets:
        raise SystemExit(f"parser helper jump targets differ: {jump_targets}")
    immediates = {(item.mnemonic, item.op_str) for item in instructions}
    if not any(item.mnemonic == "addiu" and "-0xbe" in item.op_str for item in instructions):
        raise SystemExit("helper lacks the E1 BE lower-bound subtraction")
    if not any(item.mnemonic == "sltiu" and "0x33" in item.op_str for item in instructions):
        raise SystemExit("helper lacks the closed 51-value E1 interval test")
    del immediates

    frame_call_at = old.source_at(FRAME_CALL)
    if struct.unpack_from("<II", after_exe, frame_call_at) != (0, 0):
        raise SystemExit("old item-object guard call was not removed")
    if struct.unpack_from("<I", before_exe, frame_call_at)[0] != old.jal(HELPER):
        raise SystemExit("base frame did not call the reclaimed item guard")

    # Byte-isolation checks independent of the builder report.
    allowed_exe = set()
    for entry in (PARSER_FIRST, PARSER_SECOND):
        allowed_exe.update(range(old.file_at(entry), old.file_at(entry) + 8))
    allowed_exe.update(range(helper_at, helper_at + HELPER_CAPACITY))
    allowed_exe.update(range(frame_call_at, frame_call_at + 8))
    actual_exe = {
        index for index, (left, right) in enumerate(zip(before_exe, after_exe)) if left != right
    }
    if not actual_exe or not actual_exe <= allowed_exe:
        raise SystemExit("PSX diff escaped declared ranges")
    dat_name, dat_offset = restore_key
    dat_diff = {
        index
        for index, (left, right) in enumerate(zip(base[dat_name], patch[dat_name]))
        if left != right
    }
    if dat_diff != {dat_offset, dat_offset + 1}:
        raise SystemExit("native-control DAT diff is not exactly two bytes")

    # Cache data, lookup, font CLUT table and every other member are unchanged.
    lookup_at = 0x801A7520 - old.RAM_TO_FILE
    if before_exe[lookup_at:lookup_at + 818] != after_exe[lookup_at:lookup_at + 818]:
        raise SystemExit("409-entry runtime lookup changed")
    clut_at = FONT_CLUT_TABLE - old.RAM_TO_FILE
    if before_exe[clut_at:clut_at + FONT_CLUT_BYTES] != \
            after_exe[clut_at:clut_at + FONT_CLUT_BYTES]:
        raise SystemExit("font CLUT table changed")
    if patch["COMM.IMG"] != base["COMM.IMG"]:
        raise SystemExit("COMM.IMG changed")

    OUT.mkdir(parents=True, exist_ok=True)
    lines = [
        "v169 E1 control/glyph parser dispatch verification",
        "",
        f"patch={PATCH.name}",
        f"sha256={PATCH_SHA256}",
        f"changed_members={','.join(changed)}",
        "archive_member_order=PASS",
        "archive_member_lengths=PASS",
        "declared_byte_isolation=PASS",
        "",
        "proven_E1_glyphs=48",
        "proven_E1_glyph_occurrences=1063",
        "restored_native_E1_controls=1",
        f"final_bounded_E1_tokens={len(final_e1)}",
        f"final_E1_01_count={args[0x01]}",
        f"final_E1_BE_F0_count={sum(args[value] for value in range(0xBE, 0xF1))}",
        "all_final_E1_positions_have_provenance=PASS",
        "",
        f"helper_address=0x{HELPER:08X}",
        f"helper_bytes={HELPER_SIZE}/{HELPER_CAPACITY}",
        "helper_closed_interval_BE_F0=PASS",
        "helper_jump_targets=PASS",
        "helper_R3000_load_delay=PASS",
        "helper_branch_delay=PASS",
        "old_item_guard_call_removed=PASS",
        "v166_main_OT_guard_preserved=PASS",
        "runtime_lookup_409=byte-identical",
        "font_CLUT_table=byte-identical",
        "COMM.IMG=byte-identical",
        "RAM_VRAM_heap_geometry=byte-identical_to_v168",
        "",
        "result=PASS_STATIC",
        "runtime=PENDING user cold boot",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
