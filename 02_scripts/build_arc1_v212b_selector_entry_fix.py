"""Build v212b: fix v212's missing cross-cave selector continuation.

v212's static audit exposed that its entry fragment could fall through into
non-code bytes when a font CLUT matched.  No disc image was packaged from it.
This guarded successor changes only the 128-byte selector entry, keeps v212's
frame/check/finish code byte-identical, and writes a new uniquely named ZIP.
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


BASE = ROOT / "03_output/arc1_v212_ab_cache_selector_TEST_ONLY_067F6FC6.zip"
BASE_SHA256 = "067F6FC6B3F9F8F2806A7B9670D215515E5861BDFB8C44D0D019DD1F9ECE623F"
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v212b_ab_cache_selector_TEST_ONLY"
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


def fixed_entry() -> bytes:
    old = v212.old
    e = v212.SELECTOR_ENTRY
    next_packet = v212.SELECTOR_CHECK + 21 * 4
    game = v212.SELECTOR_CHECK + 8 * 4
    finish = v212.SELECTOR_FINISH
    words = [
        old.move(v212.A3, v212.ZERO),
        old.i_type(0x23, v212.A0, v212.T0, 0),
        old.move(v212.A2, v212.ZERO),
        old.r_type(v212.ZERO, v212.T0, v212.T0, 8, 0x00),
        old.r_type(v212.ZERO, v212.T0, v212.T0, 8, 0x02),
        v212.branch(0x04, v212.T0, v212.ZERO, e + 5 * 4, finish),
        old.i_type(0x0F, v212.ZERO, v212.T2, 0x8000),
        old.r_type(v212.T2, v212.T0, v212.T2, 0, 0x25),
        old.i_type(0x23, v212.T2, v212.T3, 0),
        old.i_type(0x24, v212.T2, v212.T5, 7),
        old.i_type(0x25, v212.T2, v212.T4, 4),
        old.i_type(0x09, v212.T5, v212.T6, -0xE1),
        v212.branch(0x05, v212.T6, v212.ZERO, e + 12 * 4, e + 16 * 4),
        old.i_type(0x0C, v212.T4, v212.T6, 0x01FF),
        old.i_type(0x09, v212.T6, v212.T6, -v212.TPAGE_4BPP_X15_Y1),
        old.i_type(0x0B, v212.T6, v212.A2, 1),
        v212.branch(0x04, v212.A2, v212.ZERO, e + 16 * 4, next_packet),
        old.i_type(0x0C, v212.T5, v212.T6, 0xFC),
        old.i_type(0x09, v212.T6, v212.T6, -0x64),
        v212.branch(0x05, v212.T6, v212.ZERO, e + 19 * 4, next_packet),
        v212.NOP,
        old.i_type(0x25, v212.T2, v212.T6, 14),
        old.i_type(0x24, v212.T2, v212.T7, 12),
        old.i_type(0x24, v212.T2, v212.T9, 13),
        old.i_type(0x09, v212.T6, v212.V0, -v212.v171.v166.FONT_CLUT_MIN),
        old.i_type(0x0B, v212.V0, v212.V0, 16),
        v212.branch(0x04, v212.V0, v212.ZERO, e + 26 * 4, game),
        old.i_type(0x09, v212.T9, v212.V1, -v212.CACHE_B_V),
        old.j(v212.SELECTOR_CHECK),
        v212.NOP,
        v212.NOP,
        v212.NOP,
    ]
    blob = struct.pack(f"<{len(words)}I", *words)
    if len(blob) != v212.ENTRY_CAP:
        raise SystemExit("fixed selector entry size differs")
    return blob


def main() -> None:
    if digest(BASE.read_bytes()) != BASE_SHA256:
        raise SystemExit("v212 failed-probe base SHA256 differs")
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
    rect = layout["upload_rect"][0]
    broken_entry = v212.selector_blobs(frame, rect)[0]
    fixed = fixed_entry()
    entry_at = v212.old.file_at(v212.SELECTOR_ENTRY)
    if bytes(exe[entry_at:entry_at + len(broken_entry)]) != broken_entry:
        raise SystemExit("v212 selector entry differs from the known failed fragment")
    if broken_entry == fixed:
        raise SystemExit("fixed selector unexpectedly equals failed selector")

    check_at = v212.old.file_at(v212.SELECTOR_CHECK)
    finish_at = v212.old.file_at(v212.SELECTOR_FINISH)
    frame_source_at = v212.old.file_at(v212.v171.SOURCE_BASE) + frame - v212.v171.RESIDENT_BASE
    frozen = {
        "check": bytes(exe[check_at:check_at + v212.CHECK_CAP]),
        "finish": bytes(exe[finish_at:finish_at + v212.FINISH_CAP]),
        "frame": bytes(exe[frame_source_at:frame_source_at + len(frame_blob)]),
    }
    if frozen["frame"] != frame_blob:
        raise SystemExit("v212 frame source differs")

    exe[entry_at:entry_at + len(fixed)] = fixed
    members[v212.PSX] = bytes(exe)
    changed = [name for name in members if members[name] != before[name]]
    if changed != [v212.PSX]:
        raise SystemExit(f"unexpected changed members: {changed}")
    if any(len(members[name]) != len(before[name]) for name in members):
        raise SystemExit("archive member length changed")
    if bytes(exe[check_at:check_at + v212.CHECK_CAP]) != frozen["check"] \
            or bytes(exe[finish_at:finish_at + v212.FINISH_CAP]) != frozen["finish"] \
            or bytes(exe[frame_source_at:frame_source_at + len(frame_blob)]) != frozen["frame"]:
        raise SystemExit("v212 check/finish/frame changed")

    diffs = [i for i, (a, b) in enumerate(zip(before[v212.PSX], members[v212.PSX])) if a != b]
    if not diffs or any(not entry_at <= i < entry_at + v212.ENTRY_CAP for i in diffs):
        raise SystemExit(f"v212b changed outside selector entry: {diffs[:20]}")

    ranges = (
        (v212.SELECTOR_ENTRY, v212.SELECTOR_ENTRY + v212.ENTRY_CAP),
        (v212.SELECTOR_CHECK, v212.SELECTOR_CHECK + v212.CHECK_CAP),
        (v212.SELECTOR_FINISH, v212.SELECTOR_FINISH + v212.FINISH_CAP),
    )
    notes = v212.validate_selector(v212.SELECTOR_ENTRY, fixed, ranges, frame)
    notes.extend(v212.old.validate_routine("frame", frame, frame_blob))

    refs = v212.direct_refs(exe, v212.SELECTOR_CHECK, v212.SELECTOR_CHECK + v212.CHECK_CAP)
    if refs != [(v212.SELECTOR_ENTRY + 28 * 4, "j", v212.SELECTOR_CHECK)]:
        raise SystemExit(f"fixed selector continuation graph differs: {refs}")
    if struct.unpack_from("<I", exe, entry_at + 30 * 4)[0] != 0 \
            or struct.unpack_from("<I", exe, entry_at + 31 * 4)[0] != 0:
        raise SystemExit("selector entry does not end with two guarded NOPs")

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    decoded = list(md.disasm(fixed, v212.SELECTOR_ENTRY))
    if sum(item.size for item in decoded) != len(fixed):
        raise SystemExit("Capstone did not consume the fixed selector entry")
    disassembly = [
        f"{item.address:08X}  {item.mnemonic:<8} {item.op_str}" for item in decoded
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    DISASSEMBLY.write_text("\n".join(disassembly) + "\n", encoding="utf-8")

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
        "v212b TEST ONLY - corrected A/B cache selector entry",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output.name}",
        f"sha256={stamp}",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
        "v212_failure=font-CLUT path fell through after 0x80193BC0",
        "v212b_fix=font path jumps to selector_check; non-font path branches to game check",
        f"selector_entry_changed_bytes={len(diffs)}",
        "selector_check=byte-identical to v212 PASS",
        "selector_finish=byte-identical to v212 PASS",
        "frame=byte-identical to v212 PASS",
        "COMM.IMG=byte-identical to v210 PASS",
        "all_DAT_members=byte-identical to v210 PASS",
        "resident_growth=0",
        "resident_used=5356/5356",
        "heap_boundary=0x801FF8B0 unchanged",
        f"selector entry 0x{v212.SELECTOR_ENTRY:08X} / {len(fixed)} bytes",
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
        "rollback=v210; do not use v211 or v212",
    ]
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))
    print(REPORT)


if __name__ == "__main__":
    main()
