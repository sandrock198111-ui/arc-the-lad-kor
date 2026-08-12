"""Build v169: separate proven E1 Hangul codes from the native E1 command.

v168 uses 48 direct Hangul codes in E1 BE..F0.  The text parser classifies E1
before the glyph-index decoder, so those 1,063 proven glyph occurrences were
mistaken for a style command.  The resulting style byte indexed beyond the
16-entry font CLUT table and made the same item name alternate between text and
game graphics.

This build replaces the ineffective v167/v168 item-object guard with a bounded
parser dispatcher in the exact same 128-byte resident window.  E1 BE..F0 goes
to the existing glyph path; E1 values outside that interval keep the native
command path.  E9/EA and pre-E1 behavior remains byte-for-byte equivalent to
the old classifier.  The one native E1 01 command that v159 accidentally
rewrote is restored from the untouched disc.

No RAM, VRAM, heap, executable size, cache slot, font, translation capacity or
disc member layout grows.
"""
from __future__ import annotations

import csv
import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32  # noqa: E402
import audit_arc1_v168_control_glyph_collisions as audit  # noqa: E402
import build_arc1_v165_failclosed_cache as old  # noqa: E402


BASE = audit.V168
BASE_SHA256 = audit.V168_SHA256
OUT_STEM = "arc1_v169_e1_control_glyph_dispatch"
OUT_DIR = ROOT / "03_output"
ANALYSIS = ROOT / "01_work/analysis/arc1_v169_e1_control_glyph_dispatch"
REPORT = ANALYSIS / "build_report.txt"
DISASSEMBLY = ANALYSIS / "parser_dispatch_disassembly.txt"
EXPECTED_WRITES = ANALYSIS / "expected_writes.csv"

PSX = "PSX.EXE"
PARSER_FIRST = 0x801A7460
PARSER_SECOND = 0x801A748C
FIRST_GLYPH = 0x8016BB6C
FIRST_CONTROL = 0x8016BB54
SECOND_GLYPH = 0x8016BB80
SECOND_CONTROL = 0x8016BB9C

# v168's bounded item-object scanner is disproven by runtime states and occupies
# the only 128-byte resident window.  Its frame call is removed before reuse.
RECLAIMED_HELPER = 0x801FF82C
RECLAIMED_BYTES = 128
FRAME = 0x801FF594
FRAME_BYTES = 664

E1_GLYPH_MIN = 0xBE
E1_GLYPH_MAX = 0xF0
E1_GLYPH_COUNT = E1_GLYPH_MAX - E1_GLYPH_MIN + 1


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def build_parser_dispatch(address: int) -> bytes:
    """Route both parser call sites, with T9 selecting first/second return."""
    asm = old.Assembler(address)

    # E1 is ambiguous only because v153 assigned Hangul to E1 BE..F0.  Load the
    # following byte from the live text pointer and test that closed interval.
    asm.emit(old.i_type(0x09, old.V0, old.T0, -0xE1))
    asm.branch(0x05, old.T0, old.ZERO, "normal")
    asm.emit(old.i_type(0x23, old.S0, old.T0, 0x14))      # branch delay: text pointer
    asm.emit(old.NOP)                                    # R3000 lw delay
    asm.emit(old.i_type(0x24, old.T0, old.T1, 1))        # E1 argument
    asm.emit(old.NOP)                                    # R3000 lbu delay
    asm.emit(old.i_type(0x09, old.T1, old.T1, -E1_GLYPH_MIN))
    asm.emit(old.i_type(0x0B, old.T1, old.T0, E1_GLYPH_COUNT))
    asm.branch(0x05, old.T0, old.ZERO, "glyph")
    asm.emit(old.NOP)
    asm.branch(0x04, old.ZERO, old.ZERO, "control")
    asm.emit(old.NOP)

    # Preserve the v151-v168 classifier for every non-E1 lead:
    # E9/EA or anything below E1 is a glyph; E2..E8 and EB+ are controls.
    asm.label("normal")
    asm.emit(old.i_type(0x09, old.V0, old.T0, -0xE9))
    asm.emit(old.i_type(0x0B, old.T0, old.T0, 2))
    asm.branch(0x05, old.T0, old.ZERO, "glyph")
    asm.emit(old.i_type(0x0B, old.V0, old.T0, 0xE1))
    asm.branch(0x05, old.T0, old.ZERO, "glyph")
    asm.emit(old.NOP)

    asm.label("control")
    asm.branch(0x05, old.T9, old.ZERO, "control_second")
    asm.emit(old.NOP)
    asm.emit(old.j(FIRST_CONTROL))
    asm.emit(old.NOP)
    asm.label("control_second")
    asm.emit(old.j(SECOND_CONTROL))
    asm.emit(old.NOP)

    asm.label("glyph")
    asm.branch(0x05, old.T9, old.ZERO, "glyph_second")
    asm.emit(old.NOP)
    asm.emit(old.j(FIRST_GLYPH))
    asm.emit(old.NOP)
    asm.label("glyph_second")
    asm.emit(old.j(SECOND_GLYPH))
    asm.emit(old.NOP)
    return asm.finish()


def expected_route(lead: int, trail: int) -> str:
    if lead == 0xE1:
        return "glyph" if E1_GLYPH_MIN <= trail <= E1_GLYPH_MAX else "control"
    if lead in (0xE9, 0xEA) or lead < 0xE1:
        return "glyph"
    return "control"


def main() -> None:
    # Regenerate all provenance evidence from hash-locked inputs before writing.
    audit.main()
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v168 base archive hash differs")

    with audit.OCCURRENCES.open(encoding="utf-8-sig", newline="") as handle:
        collisions = list(csv.DictReader(handle))
    with audit.CONTROL_RESTORES.open(encoding="utf-8-sig", newline="") as handle:
        restores = list(csv.DictReader(handle))
    if len(collisions) != 1063 or len({row["char"] for row in collisions}) != 48:
        raise SystemExit("collision provenance is not exactly 1,063 occurrences / 48 Hangul")
    if len(restores) != 1:
        raise SystemExit("native E1 control restore is not unique")
    for row in collisions:
        code = bytes.fromhex(row["risky_code"])
        if expected_route(code[0], code[1]) != "glyph":
            raise SystemExit(f"colliding glyph would not route as glyph: {row}")
    restored_code = bytes.fromhex(restores[0]["planned_code"])
    if restored_code != b"\xE1\x01" or expected_route(*restored_code) != "control":
        raise SystemExit("native E1 01 would not route as a control")
    for lead in range(0x100):
        for trail in (0x01, 0xBD, 0xBE, 0xF0, 0xF1, 0xFE):
            route = expected_route(lead, trail)
            if lead == 0xE1 and route != (
                "glyph" if E1_GLYPH_MIN <= trail <= E1_GLYPH_MAX else "control"
            ):
                raise SystemExit("closed E1 interval classifier differs")

    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}
    before = dict(members)
    exe = bytearray(members[PSX])
    before_exe = bytes(exe)

    # Frozen entry guards.  These are the two v151 classifiers that currently
    # send every E1 token to the command parser.
    expected_classifier_prefix = (
        old.i_type(0x09, old.V0, old.T0, -0xE9),
        old.i_type(0x0B, old.T0, old.T0, 2),
    )
    for entry in (PARSER_FIRST, PARSER_SECOND):
        if (old.word(exe, entry), old.word(exe, entry + 4)) != expected_classifier_prefix:
            raise SystemExit(f"v168 parser classifier differs at 0x{entry:08X}")

    helper = build_parser_dispatch(RECLAIMED_HELPER)
    if len(helper) > RECLAIMED_BYTES:
        raise SystemExit(
            f"parser dispatcher exceeds reclaimed guard by {len(helper) - RECLAIMED_BYTES} bytes"
        )
    routine_notes = old.validate_routine("parser_dispatch", RECLAIMED_HELPER, helper)

    resident_source = old.source_at(RECLAIMED_HELPER)
    old_guard = bytes(exe[resident_source:resident_source + RECLAIMED_BYTES])
    if not any(old_guard):
        raise SystemExit("v168 item-object guard window is unexpectedly blank")

    # Find and remove exactly one frame call to the old item-object guard.
    frame_source = old.source_at(FRAME)
    frame_blob = bytes(exe[frame_source:frame_source + FRAME_BYTES])
    guard_call = struct.pack("<I", old.jal(RECLAIMED_HELPER))
    call_relative = frame_blob.find(guard_call)
    if call_relative < 0 or frame_blob.find(guard_call, call_relative + 1) >= 0:
        raise SystemExit("v168 frame does not contain one unique item-guard call")
    call_address = FRAME + call_relative
    if struct.unpack_from("<I", frame_blob, call_relative + 4)[0] != old.NOP:
        raise SystemExit("item-guard call delay slot is not NOP")
    struct.pack_into("<II", exe, frame_source + call_relative, old.NOP, old.NOP)

    exe[resident_source:resident_source + RECLAIMED_BYTES] = (
        helper + bytes(RECLAIMED_BYTES - len(helper))
    )
    old.put_word(exe, PARSER_FIRST, old.j(RECLAIMED_HELPER))
    old.put_word(exe, PARSER_FIRST + 4, old.i_type(0x0D, old.ZERO, old.T9, 0))
    old.put_word(exe, PARSER_SECOND, old.j(RECLAIMED_HELPER))
    old.put_word(exe, PARSER_SECOND + 4, old.i_type(0x0D, old.ZERO, old.T9, 1))
    members[PSX] = bytes(exe)

    # Restore only the native command proven by the untouched archive.
    restore = restores[0]
    member = restore["member"]
    offset = int(restore["offset"])
    old_code = bytes.fromhex(restore["v168_code"])
    new_code = bytes.fromhex(restore["planned_code"])
    data = bytearray(members[member])
    if data[offset:offset + len(old_code)] != old_code:
        raise SystemExit(f"native E1 restore guard differs at {member}:0x{offset:X}")
    data[offset:offset + len(new_code)] = new_code
    members[member] = bytes(data)

    changed_members = [name for name in members if members[name] != before[name]]
    if changed_members != [member, PSX] and changed_members != [PSX, member]:
        raise SystemExit(f"v169 changed unexpected members: {changed_members}")
    if len(exe) != len(before_exe):
        raise SystemExit("PSX.EXE size changed")

    allowed_exe = set()
    for entry in (PARSER_FIRST, PARSER_SECOND):
        allowed_exe.update(range(old.file_at(entry), old.file_at(entry) + 8))
    allowed_exe.update(range(resident_source, resident_source + RECLAIMED_BYTES))
    allowed_exe.update(range(frame_source + call_relative, frame_source + call_relative + 8))
    actual_exe = {
        index for index, (left, right) in enumerate(zip(before_exe, exe)) if left != right
    }
    if not actual_exe or not actual_exe <= allowed_exe:
        raise SystemExit("PSX.EXE changed outside declared parser/guard ranges")
    member_diff = {
        index
        for index, (left, right) in enumerate(zip(before[member], members[member]))
        if left != right
    }
    if member_diff != set(range(offset, offset + len(new_code))):
        raise SystemExit("native E1 member changed outside the two-byte command")

    # Existing cache geometry and memory boundaries remain frozen.
    for address, expected, label in (
        (old.MEMCPY_LEN_AT, old.word(before_exe, old.MEMCPY_LEN_AT), "startup copy"),
        (old.HEAP_BASE_AT, old.word(before_exe, old.HEAP_BASE_AT), "heap boundary"),
        (old.LATE_HOOK, old.word(before_exe, old.LATE_HOOK), "pre-DrawOT hook"),
        (old.RENDER_HOOK, old.word(before_exe, old.RENDER_HOOK), "renderer hook"),
    ):
        if old.word(exe, address) != expected:
            raise SystemExit(f"v169 changed frozen {label}")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    instructions = list(md.disasm(helper, RECLAIMED_HELPER))
    if sum(item.size for item in instructions) != len(helper):
        raise SystemExit("Capstone could not decode the full parser dispatcher")
    DISASSEMBLY.write_text(
        "\n".join(
            f"{item.address:08X}  {item.mnemonic:<8} {item.op_str}"
            for item in instructions
        )
        + "\n",
        encoding="utf-8",
    )
    with EXPECTED_WRITES.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("member", "offset_or_ram", "length", "purpose"))
        writer.writerow((PSX, f"0x{PARSER_FIRST:08X}", 8, "first parser trampoline"))
        writer.writerow((PSX, f"0x{PARSER_SECOND:08X}", 8, "second parser trampoline"))
        writer.writerow((PSX, f"0x{RECLAIMED_HELPER:08X}", RECLAIMED_BYTES,
                         "reclaimed item guard -> parser dispatcher"))
        writer.writerow((PSX, f"0x{call_address:08X}", 8, "remove old item-guard call"))
        writer.writerow((member, f"0x{offset:X}", len(new_code), "restore native E1 01"))

    temporary = OUT_DIR / f"{OUT_STEM}_building.zip"
    if temporary.exists():
        raise SystemExit(f"refusing to reuse temporary output: {temporary.name}")
    with ZipFile(temporary, "w", ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(old.clone(info), members[info.filename])
    with ZipFile(temporary) as archive:
        if archive.namelist() != [info.filename for info in infos]:
            raise SystemExit("archive member order changed")
        for name, expected in members.items():
            if archive.read(name) != expected:
                raise SystemExit(f"archive roundtrip differs: {name}")
    stamp = digest(temporary.read_bytes())
    output = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {output.name}")
    temporary.replace(output)

    lines = [
        "v169 E1 control/glyph parser dispatch",
        "",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output.name}",
        f"sha256={stamp}",
        f"changed_members={PSX},{member}",
        "",
        "root_cause=E1 BE..F0 Hangul intercepted as native E1 style command",
        "observed_effect=style byte E5/DF indexed beyond 16-entry CLUT table",
        "proven_colliding_Hangul=48",
        "proven_colliding_occurrences=1063",
        f"glyph_interval=E1 {E1_GLYPH_MIN:02X}..{E1_GLYPH_MAX:02X}",
        "native_command_restored=4/S4011.DAT:0x485F6 E1 01",
        "",
        f"parser_dispatch_address=0x{RECLAIMED_HELPER:08X}",
        f"parser_dispatch_bytes={len(helper)}/{RECLAIMED_BYTES}",
        f"removed_item_guard_call=0x{call_address:08X}",
        "removed_guard_reason=runtime-disproven stale object hypothesis",
        "main_OT_persistent_guard=v166 unchanged",
        "cache_slots=24 unchanged",
        "cache_VRAM=x961..978,y480..491 unchanged",
        "resident_reservation=5356 unchanged",
        "heap_boundary=0x801FF8B0 unchanged",
        "startup_copy=5356 unchanged",
        "PSX.EXE_size=unchanged",
        "",
        *routine_notes,
        "collision_provenance=1063/1063 PASS",
        "native_control_restore=1/1 PASS",
        "closed_interval_dispatch=PASS",
        "declared_member_diff=PASS",
        "archive_roundtrip=PASS",
        "runtime=PENDING user cold boot",
        "rollback=v168",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
