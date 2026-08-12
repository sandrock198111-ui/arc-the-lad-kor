"""v164 diagnostic: upload the completed-glyph cache immediately before DrawOT.

v163 uploads the cache at 0x8011C4AC and then calls the stock frame routine.
That stock routine still runs the game update at 0x801299F8 and display setup
before submitting the ordering table.  This probe changes only the call topology:

    0x8011C4AC  restore the stock frame call
    0x8011C860  call the resident cache wrapper instead of DrawOT
    wrapper tail call DrawOT instead of recursively calling the stock frame

The resident cache implementation, glyph data, classifier, COMM.IMG and every
non-EXE member remain byte-identical to the frozen v163 archive.  This is a
cold-boot diagnostic, not a release build.
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

import build_arc1_v163_text_clut_classifier as base  # noqa: E402


BASE_ZIP = ROOT / "03_output/arc1_v163_text_clut_classifier_773E3B82.zip"
BASE_SHA256 = "773E3B82B58FBE9C836C96F34EA03C122847EC8BBD691AE4FDCFBA00D778FE63"
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v164_predrawot_cache_upload_probe"
ANALYSIS = ROOT / "01_work/analysis/arc1_v164_predrawot_cache_upload_probe"
REPORT = ANALYSIS / "build_report.txt"
WRITES_CSV = ANALYSIS / "expected_writes.csv"
HOOK_WORDS = ANALYSIS / "hook_words.txt"
RUNTIME_REQUEST = ANALYSIS / "runtime_test_request.txt"

PSX = base.PSX
RAM_TO_FILE = base.base.RAM_TO_FILE
SOURCE_BASE = base.base.SOURCE_BASE
RESIDENT_BASE = base.base.RESIDENT_BASE

EARLY_HOOK = 0x8011C4AC
EARLY_DELAY = EARLY_HOOK + 4
LATE_HOOK = 0x8011C860
LATE_DELAY = LATE_HOOK + 4
FRAME = base.base.FRAME
FRAME_N = base.base.FRAME_N
FRAME_TAIL_CALL = 0x801FF3AC
FRAME_TAIL_DELAY = FRAME_TAIL_CALL + 4
STOCK_FRAME = 0x8011C814
LOADIMAGE = 0x80177E4C
DRAWOT = 0x80176E1C
FRAME_SYNC_CALL = 0x8011C49C
GPU_SYNC = 0x80176BA8

NOP = 0x00000000
LATE_DELAY_WORD = 0x26040070             # addiu a0,s0,0x70
FRAME_PROLOGUE = 0x27BDFFB0              # addiu sp,sp,-0x50
FRAME_EPILOGUE = 0x27BD0050              # addiu sp,sp,0x50


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def jal(target: int) -> int:
    return 0x0C000000 | ((target >> 2) & 0x03FFFFFF)


def file_at(address: int) -> int:
    return address - RAM_TO_FILE


def resident_source_at(address: int) -> int:
    return SOURCE_BASE - RAM_TO_FILE + address - RESIDENT_BASE


def word_at(exe: bytes | bytearray, address: int, *, resident: bool = False) -> int:
    at = resident_source_at(address) if resident else file_at(address)
    return struct.unpack_from("<I", exe, at)[0]


def main() -> None:
    if digest(BASE_ZIP.read_bytes()) != BASE_SHA256:
        raise SystemExit("base archive is not the frozen v163 build")

    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}
    original_members = dict(members)
    exe = bytearray(members[PSX])
    before = bytes(exe)

    # Fixed-revision guards.  Verify every displaced call and delay slot before
    # applying the three Expected Writes.
    guards = (
        (FRAME_SYNC_CALL, jal(GPU_SYNC), False, "GPU sync before stock frame"),
        (EARLY_HOOK, jal(FRAME), False, "v163 early cache wrapper hook"),
        (EARLY_DELAY, NOP, False, "early hook delay slot"),
        (LATE_HOOK, jal(DRAWOT), False, "stock DrawOT call"),
        (LATE_DELAY, LATE_DELAY_WORD, False, "stock DrawOT argument delay slot"),
        (FRAME, FRAME_PROLOGUE, True, "resident wrapper prologue"),
        (0x801FF38C, jal(LOADIMAGE), True, "resident cache LoadImage"),
        (FRAME_TAIL_CALL, jal(STOCK_FRAME), True, "v163 wrapper tail call"),
        (FRAME_TAIL_DELAY, NOP, True, "wrapper tail delay slot"),
        (0x801FF3D8, FRAME_EPILOGUE, True, "resident wrapper epilogue"),
    )
    for address, expected, resident, label in guards:
        got = word_at(exe, address, resident=resident)
        if got != expected:
            raise SystemExit(
                f"guard failed at 0x{address:08X}: "
                f"0x{got:08X} != 0x{expected:08X} ({label})"
            )

    writes = (
        (EARLY_HOOK, jal(FRAME), jal(STOCK_FRAME), False,
         "restore early stock-frame call"),
        (LATE_HOOK, jal(DRAWOT), jal(FRAME), False,
         "invoke cache wrapper immediately before DrawOT"),
        (FRAME_TAIL_CALL, jal(STOCK_FRAME), jal(DRAWOT), True,
         "wrapper preserves displaced DrawOT call"),
    )

    # Plan and verify every write against the immutable v163 bytes first.
    planned: list[tuple[int, int, int, int, bool, str]] = []
    for address, expected, replacement, resident, reason in writes:
        at = resident_source_at(address) if resident else file_at(address)
        got = struct.unpack_from("<I", before, at)[0]
        if got != expected:
            raise SystemExit(
                f"expected-write precondition failed at 0x{address:08X}: "
                f"0x{got:08X} != 0x{expected:08X}"
            )
        planned.append((address, at, expected, replacement, resident, reason))

    for _address, at, _expected, replacement, _resident, _reason in planned:
        struct.pack_into("<I", exe, at, replacement)

    for address, _at, _expected, replacement, resident, reason in planned:
        got = word_at(exe, address, resident=resident)
        if got != replacement:
            raise SystemExit(f"write readback failed at 0x{address:08X} ({reason})")

    # Delay slots and the v163 text classifier must remain untouched.
    if word_at(exe, EARLY_DELAY) != NOP:
        raise SystemExit("early delay slot changed")
    if word_at(exe, LATE_DELAY) != LATE_DELAY_WORD:
        raise SystemExit("late DrawOT argument delay slot changed")
    if word_at(exe, FRAME_TAIL_DELAY, resident=True) != NOP:
        raise SystemExit("wrapper tail delay slot changed")
    classifier_at = resident_source_at(base.CLASSIFIER)
    classifier = base.build_classifier()
    if exe[classifier_at:classifier_at + len(classifier)] != classifier:
        raise SystemExit("v163 text-CLUT classifier changed")

    members[PSX] = bytes(exe)
    if any(name != PSX and members[name] != original_members[name] for name in members):
        raise SystemExit("a non-PSX member changed")

    # Exact final-diff check: every changed byte must be explained by one of the
    # three planned words, including bytes that happen to be equal in old/new.
    expected_changed: set[int] = set()
    for _address, at, expected, replacement, _resident, _reason in planned:
        old_bytes = struct.pack("<I", expected)
        new_bytes = struct.pack("<I", replacement)
        expected_changed.update(at + i for i in range(4) if old_bytes[i] != new_bytes[i])
    changed = {i for i, (left, right) in enumerate(zip(before, exe)) if left != right}
    if changed != expected_changed:
        missing = sorted(expected_changed - changed)
        extra = sorted(changed - expected_changed)
        raise SystemExit(f"final EXE diff differs: missing={missing} extra={extra}")
    if len(exe) != len(before):
        raise SystemExit("PSX.EXE size changed")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    temporary = OUT_DIR / f"{OUT_STEM}_building.zip"
    if temporary.exists():
        raise SystemExit(f"refusing to reuse temporary output: {temporary.name}")
    with ZipFile(temporary, "w", ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(base.base.clone(info), members[info.filename])
    with ZipFile(temporary) as archive:
        if [info.filename for info in archive.infolist()] != [info.filename for info in infos]:
            raise SystemExit("archive member order changed")
        for name, expected in members.items():
            if archive.read(name) != expected:
                raise SystemExit(f"archive readback differs: {name}")

    stamp = digest(temporary.read_bytes())
    output = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {output.name}")
    temporary.replace(output)

    with WRITES_CSV.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("runtime_address", "file_offset", "resident", "before", "after", "reason"))
        for address, at, expected, replacement, resident, reason in planned:
            writer.writerow((f"0x{address:08X}", f"0x{at:X}", int(resident),
                             f"0x{expected:08X}", f"0x{replacement:08X}", reason))

    hook_lines = [
        f"0x{EARLY_HOOK:08X}  {word_at(exe, EARLY_HOOK):08X}  jal stock_frame",
        f"0x{EARLY_DELAY:08X}  {word_at(exe, EARLY_DELAY):08X}  nop",
        f"0x{LATE_HOOK:08X}  {word_at(exe, LATE_HOOK):08X}  jal cache_wrapper",
        f"0x{LATE_DELAY:08X}  {word_at(exe, LATE_DELAY):08X}  addiu a0,s0,0x70",
        f"0x{FRAME_TAIL_CALL:08X}  "
        f"{word_at(exe, FRAME_TAIL_CALL, resident=True):08X}  jal DrawOT",
        f"0x{FRAME_TAIL_DELAY:08X}  "
        f"{word_at(exe, FRAME_TAIL_DELAY, resident=True):08X}  nop",
    ]
    HOOK_WORDS.write_text("\n".join(hook_lines) + "\n", encoding="utf-8")

    lines = [
        "v164 pre-DrawOT cache-upload diagnostic",
        "",
        f"base={BASE_ZIP.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output.name}",
        f"sha256={stamp}",
        f"archive_members={len(members)}",
        f"PSX.EXE_bytes={len(exe)}",
        f"changed_EXE_bytes={len(changed)}",
        "changed_non_EXE_members=0",
        "",
        f"early_hook=0x{EARLY_HOOK:08X}: cache_wrapper -> stock_frame",
        f"late_hook=0x{LATE_HOOK:08X}: DrawOT -> cache_wrapper",
        f"wrapper_tail=0x{FRAME_TAIL_CALL:08X}: stock_frame -> DrawOT",
        "call_order=GPU sync -> stock frame/update/display setup -> cache LoadImage -> DrawOT",
        "cache_geometry_and_data=byte_identical_to_v163",
        "text_CLUT_classifier=byte_identical_to_v163",
        "COMM.IMG_and_all_non_EXE_members=byte_identical_to_v163",
        f"frame routine 0x{FRAME:08X} / {FRAME_N} bytes",
        "",
        "static_verification=PENDING separate verifier",
        "runtime_verification=PENDING user cold boot",
        "classification=diagnostic_only_not_release",
        "rollback=v163",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    runtime_lines = [
        "v164 runtime test request",
        f"patch={output.name}",
        f"sha256={stamp}",
        "baseline=v163; only three call words differ",
        "setup=build a fresh image, cold boot, load the memory-card save",
        "do_not=load a v163-or-earlier savestate directly",
        "checks=BIOS/title; Korean text; load cursor/icons; battle monsters; 잎/택/랜; progression",
        "pass=all checks clean and progression continues",
        "boot_fail=pre-DrawOT LoadImage timing is unsafe; reject this hook",
        "hangul_missing=active-mask production precedes/follows a different boundary",
        "graphics_damage=cache destination or static placement remains in conflict",
        "status=diagnostic only; even PASS does not approve v163 static cells",
    ]
    RUNTIME_REQUEST.write_text("\n".join(runtime_lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
