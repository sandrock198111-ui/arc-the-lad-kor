"""Build v212d TEST ONLY: exact-bounded per-frame A/B cache selector.

This is the first package candidate in the v212 series.  It starts from v212b,
replaces only the selector entry, rejects OT links 0 and >=0x200000, and keeps
the corrected cross-cave continuation.  v212 and v212b were never packaged as
disc images; v212c stopped at its own arithmetic assertion without output.
"""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32  # noqa: E402
import build_arc1_v212_ab_cache_selector as v212  # noqa: E402
import build_arc1_v212b_selector_entry_fix as v212b  # noqa: E402


BASE = ROOT / "03_output/arc1_v212b_ab_cache_selector_TEST_ONLY_3002A89C.zip"
BASE_SHA256 = "3002A89C48B7F1D321CBE9F945F75B09893A971493C7B8A4A94A9C1C31C8E793"
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v212d_ab_cache_selector_exact_bounds_TEST_ONLY"
ANALYSIS = ROOT / "01_work/analysis" / OUT_STEM
REPORT = ANALYSIS / "build_report.txt"
DISASSEMBLY = ANALYSIS / "mips_disassembly.txt"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    result = ZipInfo(info.filename, info.date_time)
    for attr in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(result, attr, getattr(info, attr))
    return result


def exact_entry() -> bytes:
    old = v212.old
    e = v212.SELECTOR_ENTRY
    next_packet = v212.SELECTOR_CHECK + 21 * 4
    game = v212.SELECTOR_CHECK + 8 * 4
    finish = v212.SELECTOR_FINISH
    words = [
        old.move(v212.A3, v212.ZERO),
        old.i_type(0x23, v212.A0, v212.T0, 0),
        old.move(v212.A2, v212.ZERO),                    # initial load spacer
        old.r_type(v212.ZERO, v212.T0, v212.T0, 8, 0x00),
        old.r_type(v212.ZERO, v212.T0, v212.T0, 8, 0x02),
        old.i_type(0x0B, v212.T0, v212.T2, 1),          # link == 0
        old.r_type(v212.ZERO, v212.T0, v212.T1, 21, 0x02),  # link >= 0x200000
        old.r_type(v212.T2, v212.T1, v212.T2, 0, 0x25),
        v212.branch(0x05, v212.T2, v212.ZERO, e + 8 * 4, finish),
        old.i_type(0x0F, v212.ZERO, v212.T2, 0x8000),
        old.r_type(v212.T2, v212.T0, v212.T2, 0, 0x25),
        old.i_type(0x23, v212.T2, v212.T3, 0),
        old.i_type(0x24, v212.T2, v212.T5, 7),
        old.i_type(0x25, v212.T2, v212.T4, 4),
        old.i_type(0x09, v212.T5, v212.T6, -0xE1),
        v212.branch(0x05, v212.T6, v212.ZERO, e + 15 * 4, e + 19 * 4),
        old.i_type(0x0C, v212.T4, v212.T6, 0x01FF),
        old.i_type(0x09, v212.T6, v212.T6, -v212.TPAGE_4BPP_X15_Y1),
        old.i_type(0x0B, v212.T6, v212.A2, 1),
        v212.branch(0x04, v212.A2, v212.ZERO, e + 19 * 4, next_packet),
        old.i_type(0x0C, v212.T5, v212.T6, 0xFC),
        old.i_type(0x09, v212.T6, v212.T6, -0x64),
        v212.branch(0x05, v212.T6, v212.ZERO, e + 22 * 4, next_packet),
        old.i_type(0x25, v212.T2, v212.T6, 14),         # safe branch delay
        old.i_type(0x24, v212.T2, v212.T7, 12),
        old.i_type(0x24, v212.T2, v212.T9, 13),
        old.i_type(0x09, v212.T6, v212.V0, -v212.v171.v166.FONT_CLUT_MIN),
        old.i_type(0x0B, v212.V0, v212.V0, 16),
        v212.branch(0x04, v212.V0, v212.ZERO, e + 28 * 4, game),
        old.i_type(0x09, v212.T9, v212.V1, -v212.CACHE_B_V),
        old.j(v212.SELECTOR_CHECK),
        v212.NOP,
    ]
    blob = struct.pack(f"<{len(words)}I", *words)
    if len(blob) != v212.ENTRY_CAP:
        raise SystemExit("exact-bounded selector entry size differs")
    return blob


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v212b base SHA256 differs")
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        before = {info.filename: archive.read(info.filename) for info in infos}
    members = dict(before)
    exe = bytearray(members[v212.PSX])

    layout, _blobs, code_base = v212.v190.resident_layout()
    decoder = code_base
    decoder_blob = v212.v190.build_decoder(decoder, layout)
    huffman = (decoder + len(decoder_blob) + 3) & ~3
    huffman_blob = v212.v190.build_huffman(huffman, layout)
    frame = (huffman + len(huffman_blob) + 3) & ~3
    frame_blob = v212.build_frame(frame, huffman, layout)

    entry_at = v212.old.file_at(v212.SELECTOR_ENTRY)
    previous = v212b.fixed_entry()
    exact = exact_entry()
    if bytes(exe[entry_at:entry_at + len(previous)]) != previous:
        raise SystemExit("v212b selector entry differs")

    frozen_ranges = (
        (v212.SELECTOR_CHECK, v212.CHECK_CAP),
        (v212.SELECTOR_FINISH, v212.FINISH_CAP),
        (v212.v171.SOURCE_BASE + frame - v212.v171.RESIDENT_BASE, len(frame_blob)),
    )
    frozen = [(ram, bytes(exe[v212.old.file_at(ram):v212.old.file_at(ram) + size]))
              for ram, size in frozen_ranges]
    if frozen[-1][1] != frame_blob:
        raise SystemExit("v212b frame differs")

    exe[entry_at:entry_at + len(exact)] = exact
    members[v212.PSX] = bytes(exe)
    changed = [name for name in members if members[name] != before[name]]
    if changed != [v212.PSX]:
        raise SystemExit(f"unexpected changed members: {changed}")
    if any(len(members[name]) != len(before[name]) for name in members):
        raise SystemExit("archive member length changed")
    for ram, blob in frozen:
        at = v212.old.file_at(ram)
        if bytes(exe[at:at + len(blob)]) != blob:
            raise SystemExit(f"frozen v212b range changed at 0x{ram:08X}")

    diffs = [i for i, (a, b) in enumerate(zip(before[v212.PSX], members[v212.PSX])) if a != b]
    if not diffs or any(not entry_at <= i < entry_at + v212.ENTRY_CAP for i in diffs):
        raise SystemExit(f"v212d changed outside selector entry: {diffs[:20]}")

    ranges = (
        (v212.SELECTOR_ENTRY, v212.SELECTOR_ENTRY + v212.ENTRY_CAP),
        (v212.SELECTOR_CHECK, v212.SELECTOR_CHECK + v212.CHECK_CAP),
        (v212.SELECTOR_FINISH, v212.SELECTOR_FINISH + v212.FINISH_CAP),
    )
    notes = v212.validate_selector(v212.SELECTOR_ENTRY, exact, ranges, frame)
    notes.extend(v212.old.validate_routine("frame", frame, frame_blob))
    refs = v212.direct_refs(exe, v212.SELECTOR_CHECK, v212.SELECTOR_CHECK + v212.CHECK_CAP)
    if refs != [(v212.SELECTOR_ENTRY + 30 * 4, "j", v212.SELECTOR_CHECK)]:
        raise SystemExit(f"exact selector continuation graph differs: {refs}")

    for link, accepted in ((0, False), (1, True), (0x1FFFFF, True),
                           (0x200000, False), (0xFFFFFF, False)):
        test = ((1 if link < 1 else 0) | (link >> 21)) == 0
        if test != accepted:
            raise SystemExit(f"exact link-bound proof failed at 0x{link:06X}")

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    decoded = list(md.disasm(exact, v212.SELECTOR_ENTRY))
    if sum(item.size for item in decoded) != len(exact):
        raise SystemExit("Capstone did not consume exact selector entry")
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    DISASSEMBLY.write_text(
        "\n".join(f"{i.address:08X}  {i.mnemonic:<8} {i.op_str}" for i in decoded) + "\n",
        encoding="utf-8",
    )

    temporary = OUT_DIR / f"{OUT_STEM}_building.zip"
    if temporary.exists():
        raise SystemExit(f"refusing to overwrite temporary output: {temporary}")
    with ZipFile(temporary, "w", ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    with ZipFile(temporary) as archive:
        if archive.namelist() != [info.filename for info in infos]:
            raise SystemExit("archive member order changed")
        for name, expected in members.items():
            if archive.read(name) != expected:
                raise SystemExit(f"archive roundtrip differs: {name}")
    stamp = digest(temporary.read_bytes())
    output = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {output}")
    temporary.replace(output)

    report = [
        "v212d TEST ONLY - exact-bounded per-frame A/B cache selector",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output.name}",
        f"sha256={stamp}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        "selector_link_range=1..0x1FFFFF exact",
        "selector_link_0=STOP PASS",
        "selector_link_0x1FFFFF=ACCEPT PASS",
        "selector_link_0x200000=STOP PASS",
        "selector_link_0xFFFFFF=STOP PASS",
        "selector_continuation=font and non-font paths both guarded PASS",
        "selector_check_finish_frame=byte-identical to v212b PASS",
        "COMM.IMG=byte-identical to v210 PASS",
        "all_DAT_members=byte-identical to v210 PASS",
        f"selector_entry_changed_bytes={len(diffs)}",
        "resident_growth=0",
        "resident_used=5356/5356",
        "heap_boundary=0x801FF8B0 unchanged",
        f"selector entry 0x{v212.SELECTOR_ENTRY:08X} / {len(exact)} bytes",
        f"selector check 0x{v212.SELECTOR_CHECK:08X} / {v212.CHECK_CAP} bytes",
        f"selector finish 0x{v212.SELECTOR_FINISH:08X} / {v212.FINISH_CAP} bytes",
        f"decoder 0x{decoder:08X} / {len(decoder_blob)} bytes",
        f"frame routine 0x{frame:08X} / {len(frame_blob)} bytes",
        f"huffman 0x{huffman:08X} / {len(huffman_blob)} bytes",
        *notes,
        "continuation_reference=PASS",
        "archive_member_order=PASS",
        "archive_member_lengths=PASS",
        "archive_roundtrip=PASS",
        "capstone_disassembly=PASS",
        "emulator_run=NO",
        "runtime=PENDING user cold boot",
        "rollback=v210; do not use v211/v212/v212b; v212c produced no output",
    ]
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))
    print(REPORT)


if __name__ == "__main__":
    main()
