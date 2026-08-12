"""Build v166: preserve persistent text packets across cache frames.

v165c fixed the known COMM.IMG/non-text collisions, but its scratch-cell
uploader and one-frame active mask made two assumptions which the game does not
make:

* rebuilding one active plane may clear the other three planes in that cell;
* every displayed text packet is decoded again before the next frame.

The user supplied v165c states disprove both assumptions.  This build changes
only the resident frame routine.  Whenever one cache cell is uploaded, all
currently owned planes in that cell are reconstructed.  Immediately before
DrawOT the routine scans the final ordering table and leaves exactly the cache
slots referenced by live row-40 text sprites protected for the next frame.

The cache destination, decoder, lookup table, COMM.IMG, translation data,
5,356-byte resident reservation, heap boundary and hook addresses are unchanged.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32  # noqa: E402
import build_arc1_v165_failclosed_cache as old  # noqa: E402


BASE = ROOT / "03_output/arc1_v165c_failclosed_24slot_cache_checkpoint_fix_D1ADC357.zip"
BASE_SHA256 = "D1ADC3570E8690CAE66CCDD54ED1686DA081D1E0A908B3E3BB6B7083ECE8F618"
OUT_STEM = "arc1_v166_persistent_ot_guard_fullcell"
ANALYSIS = ROOT / "01_work/analysis/arc1_v166_persistent_ot_guard"
REPORT = ANALYSIS / "build_report.txt"
DISASSEMBLY = ANALYSIS / "frame_disassembly.txt"

FRAME = 0x801FF5F0
HUFFMAN = 0x801FF4A8
OT_WALK_LIMIT = 4096
RAM_LIMIT = 0x00200000
FONT_CLUT_MIN = 0x7FC0


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def build_frame(address: int, layout: dict[str, tuple[int, int]]) -> bytes:
    """Upload complete owned cells and retain live OT slot protection."""
    owners = layout["owners"][0]
    active = layout["active_mask"][0]
    rect = layout["upload_rect"][0]
    scratch = layout["cell_scratch"][0]
    decoded = layout["decoded_glyph_rows"][0]
    expand = layout["nibble_expand"][0]

    asm = old.Assembler(address)
    asm.emit(old.i_type(0x09, old.SP, old.SP, -0x50))
    for reg, offset in (
        (old.RA, 0x4C), (old.S0, 0x48), (old.S1, 0x44), (old.S2, 0x40),
        (old.S3, 0x3C), (old.S4, 0x38), (old.S5, 0x34), (old.S6, 0x30),
        (old.S7, 0x2C),
    ):
        asm.emit(old.i_type(0x2B, old.SP, reg, offset))
    asm.emit(old.i_type(0x2B, old.SP, old.A0, 0x20))

    # This mask contains both slots decoded in this frame and live slots retained
    # from the preceding OT scan.  Do not clear it until the final OT is known.
    old.load_address(asm, old.T0, active)
    asm.emit(old.i_type(0x23, old.T0, old.S0, 0))
    asm.emit(old.NOP)
    asm.branch(0x04, old.S0, old.ZERO, "protect")
    asm.emit(old.NOP)
    old.load_address(asm, old.S1, owners)
    old.load_address(asm, old.S2, scratch)
    old.load_address(asm, old.S3, decoded)
    old.load_address(asm, old.S4, rect)
    asm.emit(old.move(old.S5, old.ZERO))

    asm.label("cell_loop")
    asm.emit(old.i_type(0x0C, old.S0, old.S7, 0x0F))
    asm.emit(old.r_type(old.ZERO, old.S0, old.S0, 4, 0x02))
    asm.branch(0x04, old.S7, old.ZERO, "cell_next")
    asm.emit(old.NOP)

    # Start from a blank complete 3x12-word cell.
    asm.emit(old.move(old.T0, old.S2))
    asm.emit(old.i_type(0x0D, old.ZERO, old.T1, 18))
    asm.label("clear_loop")
    asm.emit(old.i_type(0x2B, old.T0, old.ZERO, 0))
    asm.emit(old.i_type(0x09, old.T0, old.T0, 4))
    asm.emit(old.i_type(0x09, old.T1, old.T1, -1))
    asm.branch(0x05, old.T1, old.ZERO, "clear_loop")
    asm.emit(old.NOP)

    # Reconstruct every owned plane in this cell, not only the planes touched by
    # the current decoder pass.  Persistent packets can still reference them.
    asm.emit(old.move(old.S6, old.ZERO))
    asm.label("plane_loop")
    asm.emit(old.r_type(old.ZERO, old.S5, old.T0, 3, 0x00))
    asm.emit(old.r_type(old.ZERO, old.S6, old.T1, 1, 0x00))
    asm.emit(old.r_type(old.T0, old.T1, old.T0, 0, 0x21))
    asm.emit(old.r_type(old.S1, old.T0, old.T0, 0, 0x21))
    asm.emit(old.i_type(0x25, old.T0, old.A0, 0))
    asm.emit(old.move(old.A1, old.S3))                   # load-delay spacer
    asm.emit(old.i_type(0x09, old.A0, old.T8, 1))       # 0xFFFF + 1 == 0
    asm.branch(0x04, old.T8, old.ZERO, "plane_next")
    asm.emit(old.NOP)
    asm.emit(old.jal(HUFFMAN))
    asm.emit(old.NOP)

    old.load_address(asm, old.A2, expand)
    asm.emit(old.move(old.T0, old.S3))
    asm.emit(old.move(old.T1, old.S2))
    asm.emit(old.i_type(0x0D, old.ZERO, old.T2, old.CELL))
    asm.label("row_loop")
    asm.emit(old.i_type(0x25, old.T0, old.T3, 0))
    asm.emit(old.i_type(0x09, old.T0, old.T0, 2))
    asm.emit(old.i_type(0x0D, old.ZERO, old.T4, 8))
    asm.emit(old.i_type(0x0D, old.ZERO, old.T5, 3))
    asm.label("nibble_loop")
    asm.emit(old.r_type(old.T4, old.T3, old.T6, 0, 0x06))
    asm.emit(old.i_type(0x0C, old.T6, old.T6, 0x0F))
    asm.emit(old.r_type(old.ZERO, old.T6, old.T6, 1, 0x00))
    asm.emit(old.r_type(old.A2, old.T6, old.T6, 0, 0x21))
    asm.emit(old.i_type(0x25, old.T6, old.T6, 0))
    asm.emit(old.i_type(0x25, old.T1, old.T7, 0))
    asm.emit(old.r_type(old.S6, old.T6, old.T6, 0, 0x04))
    asm.emit(old.r_type(old.T7, old.T6, old.T7, 0, 0x25))
    asm.emit(old.i_type(0x29, old.T1, old.T7, 0))
    asm.emit(old.i_type(0x09, old.T1, old.T1, 2))
    asm.emit(old.i_type(0x09, old.T4, old.T4, -4))
    asm.emit(old.i_type(0x09, old.T5, old.T5, -1))
    asm.branch(0x05, old.T5, old.ZERO, "nibble_loop")
    asm.emit(old.NOP)
    asm.emit(old.i_type(0x09, old.T2, old.T2, -1))
    asm.branch(0x05, old.T2, old.ZERO, "row_loop")
    asm.emit(old.NOP)

    asm.label("plane_next")
    asm.emit(old.i_type(0x09, old.S6, old.S6, 1))
    asm.emit(old.i_type(0x0B, old.S6, old.T0, old.PLANES))
    asm.branch(0x05, old.T0, old.ZERO, "plane_loop")
    asm.emit(old.NOP)

    asm.emit(old.r_type(old.ZERO, old.S5, old.T0, 1, 0x00))
    asm.emit(old.r_type(old.T0, old.S5, old.T0, 0, 0x21))
    asm.emit(old.i_type(0x09, old.T0, old.T0, old.CACHE_X))
    asm.emit(old.i_type(0x29, old.S4, old.T0, 0))
    asm.emit(old.move(old.A0, old.S4))
    asm.emit(old.move(old.A1, old.S2))
    asm.emit(old.jal(old.LOADIMAGE))
    asm.emit(old.NOP)

    asm.label("cell_next")
    asm.emit(old.i_type(0x09, old.S5, old.S5, 1))
    asm.emit(old.i_type(0x0B, old.S5, old.T0, old.CACHE_CELLS))
    asm.branch(0x05, old.T0, old.ZERO, "cell_loop")
    asm.emit(old.NOP)

    # The decoder is not called again for every displayed packet.  Walk the
    # completed OT and retain exactly the row-40 cache slots still referenced by
    # live text sprites.  U mod 12 == 4 plus V=224 and the stock text CLUT family
    # distinguishes these packets without relying on a guessed texture owner.
    asm.label("protect")
    asm.emit(old.i_type(0x23, old.SP, old.T1, 0x20))     # OT root pointer
    asm.emit(old.move(old.T8, old.ZERO))                 # retained mask
    asm.emit(old.i_type(0x23, old.T1, old.T1, 0))       # first DMA tag
    old.load_address(asm, old.T2, RAM_LIMIT)             # load-delay spacer
    asm.emit(old.r_type(old.ZERO, old.T1, old.T1, 8, 0x00))
    asm.emit(old.r_type(old.ZERO, old.T1, old.T1, 8, 0x02))
    asm.emit(old.i_type(0x0D, old.ZERO, old.T9, OT_WALK_LIMIT))

    asm.label("ot_loop")
    asm.branch(0x04, old.T1, old.ZERO, "ot_done")
    asm.emit(old.NOP)
    asm.emit(old.r_type(old.T1, old.T2, old.T3, 0, 0x2B))
    asm.branch(0x04, old.T3, old.ZERO, "ot_done")
    asm.emit(old.NOP)
    old.load_address(asm, old.T3, 0x80000000)
    asm.emit(old.r_type(old.T3, old.T1, old.T3, 0, 0x25))
    asm.emit(old.i_type(0x23, old.T3, old.T4, 0))
    asm.emit(old.i_type(0x24, old.T3, old.T5, 7))        # tag load spacer
    asm.emit(old.r_type(old.ZERO, old.T4, old.T6, 24, 0x02))
    asm.emit(old.i_type(0x09, old.T6, old.T6, -4))
    asm.branch(0x05, old.T6, old.ZERO, "ot_next")
    asm.emit(old.i_type(0x0C, old.T5, old.T5, 0xFC))
    asm.emit(old.i_type(0x0D, old.ZERO, old.T6, 0x64))
    asm.branch(0x05, old.T5, old.T6, "ot_next")
    asm.emit(old.NOP)
    asm.emit(old.i_type(0x24, old.T3, old.T5, 13))
    asm.emit(old.NOP)
    asm.emit(old.i_type(0x09, old.T5, old.T5, -old.CACHE_V))
    asm.branch(0x05, old.T5, old.ZERO, "ot_next")
    asm.emit(old.NOP)
    asm.emit(old.i_type(0x24, old.T3, old.T6, 12))
    asm.emit(old.NOP)
    asm.emit(old.i_type(0x09, old.T6, old.T6, -old.CACHE_U))
    asm.emit(old.i_type(0x0B, old.T6, old.T5, old.CACHE_CELLS * old.CELL))
    asm.branch(0x04, old.T5, old.ZERO, "ot_next")
    asm.emit(old.move(old.T7, old.ZERO))

    asm.label("u_loop")
    asm.branch(0x04, old.T6, old.ZERO, "u_ready")
    asm.emit(old.NOP)
    asm.emit(old.i_type(0x09, old.T6, old.T6, -old.CELL))
    asm.emit(old.i_type(0x09, old.T7, old.T7, old.PLANES))
    asm.emit(old.i_type(0x0B, old.T6, old.T5, old.CACHE_CELLS * old.CELL))
    asm.branch(0x05, old.T5, old.ZERO, "u_loop")
    asm.emit(old.NOP)
    asm.branch(0x04, old.ZERO, old.ZERO, "ot_next")
    asm.emit(old.NOP)

    asm.label("u_ready")
    asm.emit(old.i_type(0x25, old.T3, old.T5, 14))
    asm.emit(old.NOP)
    asm.emit(old.i_type(0x09, old.T5, old.T5, -FONT_CLUT_MIN))
    asm.emit(old.i_type(0x0B, old.T5, old.T6, 16))
    asm.branch(0x04, old.T6, old.ZERO, "ot_next")
    asm.emit(old.i_type(0x0C, old.T5, old.T5, 3))
    asm.emit(old.r_type(old.T7, old.T5, old.T7, 0, 0x21))
    asm.emit(old.i_type(0x0D, old.ZERO, old.T5, 1))
    asm.emit(old.r_type(old.T7, old.T5, old.T5, 0, 0x04))
    asm.emit(old.r_type(old.T8, old.T5, old.T8, 0, 0x25))

    asm.label("ot_next")
    asm.emit(old.r_type(old.ZERO, old.T4, old.T1, 8, 0x00))
    asm.emit(old.r_type(old.ZERO, old.T1, old.T1, 8, 0x02))
    asm.emit(old.i_type(0x09, old.T9, old.T9, -1))
    asm.branch(0x05, old.T9, old.ZERO, "ot_loop")
    asm.emit(old.NOP)

    asm.label("ot_done")
    old.load_address(asm, old.T0, active)
    asm.emit(old.i_type(0x2B, old.T0, old.T8, 0))

    asm.emit(old.i_type(0x23, old.SP, old.A0, 0x20))
    asm.emit(old.NOP)
    asm.emit(old.jal(old.DRAWOT))
    asm.emit(old.NOP)
    for reg, offset in (
        (old.RA, 0x4C), (old.S0, 0x48), (old.S1, 0x44), (old.S2, 0x40),
        (old.S3, 0x3C), (old.S4, 0x38), (old.S5, 0x34), (old.S6, 0x30),
        (old.S7, 0x2C),
    ):
        asm.emit(old.i_type(0x23, old.SP, reg, offset))
    asm.emit(old.i_type(0x09, old.SP, old.SP, 0x50))
    asm.emit(old.JR_RA)
    asm.emit(old.NOP)
    return asm.finish()


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v165c base archive hash differs")
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}

    before_members = dict(members)
    exe = bytearray(members[old.PSX])
    layout = old.read_layout()
    if old.word(exe, old.LATE_HOOK) != old.jal(FRAME):
        raise SystemExit("v165c late hook does not target the frozen frame address")
    frame = build_frame(FRAME, layout)
    routine_notes = old.validate_routine("frame", FRAME, frame)
    frame_capacity = old.HEAP_BASE - FRAME
    if len(frame) > frame_capacity:
        raise SystemExit(
            f"persistent OT frame exceeds resident budget by {len(frame) - frame_capacity} bytes"
        )
    source = old.source_at(FRAME)
    exe[source:source + frame_capacity] = frame + bytes(frame_capacity - len(frame))
    members[old.PSX] = bytes(exe)

    changed = sorted(
        name for name in members if members[name] != before_members[name]
    )
    if changed != [old.PSX]:
        raise SystemExit(f"v166 member isolation differs: {changed}")
    diff = {
        index for index, (left, right) in enumerate(
            zip(before_members[old.PSX], members[old.PSX])
        ) if left != right
    }
    allowed = set(range(source, source + frame_capacity))
    if not diff or not diff <= allowed:
        raise SystemExit("PSX.EXE changed outside the resident frame window")

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    instructions = list(md.disasm(frame, FRAME))
    if sum(item.size for item in instructions) != len(frame):
        raise SystemExit("Capstone could not decode the complete v166 frame")
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    DISASSEMBLY.write_text(
        "\n".join(
            f"{item.address:08X}  {item.mnemonic:<8} {item.op_str}"
            for item in instructions
        ) + "\n",
        encoding="utf-8",
    )

    temporary = old.OUT_DIR / f"{OUT_STEM}_building.zip"
    if temporary.exists():
        raise SystemExit(f"refusing to reuse temporary output: {temporary.name}")
    with ZipFile(temporary, "w", ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(old.clone(info), members[info.filename])
    with ZipFile(temporary) as archive:
        if [info.filename for info in archive.infolist()] != [info.filename for info in infos]:
            raise SystemExit("archive member order changed")
        for name, expected in members.items():
            if archive.read(name) != expected:
                raise SystemExit(f"archive readback differs: {name}")
    stamp = digest(temporary.read_bytes())
    output = old.OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {output.name}")
    temporary.replace(output)

    lines = [
        "v166 persistent-OT cache guard and complete-cell reconstruction",
        "",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output.name}",
        f"sha256={stamp}",
        "changed_members=PSX.EXE only",
        "COMM.IMG_and_all_translation_members=byte-identical_to_v165c",
        f"frame_address=0x{FRAME:08X}",
        f"frame_bytes={len(frame)}",
        f"frame_capacity={frame_capacity}",
        f"resident_free_bytes={frame_capacity - len(frame)}",
        *routine_notes,
        "resident_reservation=5356 unchanged",
        "heap_boundary=0x801FF8B0 unchanged",
        "cache_destination=x961..978,y480..491 unchanged",
        "cache_policy=all owned planes rebuilt for each active cell",
        "persistent_policy=final OT cache sprites protected into next frame",
        f"OT_walk_limit={OT_WALK_LIMIT}",
        "OT_filter=DMA4 SPRT U(mod12)=4 V224 CLUT7FC0..7FCF",
        "25th_current-frame_miss=fail-closed behavior unchanged",
        "archive_roundtrip=PASS",
        "capstone_disassembly=PASS",
        "runtime_verification=PENDING",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
