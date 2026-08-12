"""Independent static verification for the v164 pre-DrawOT upload probe."""
from __future__ import annotations

import csv
import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v164_predrawot_cache_upload_probe as build  # noqa: E402


REPORT = build.ANALYSIS / "independent_verification.txt"

# Independent fixed-revision oracle words.  These are not imported from the
# builder so a shared target-address mistake cannot make both sides pass.
OLD_EARLY = 0x0C07FC68                 # jal 0x801FF1A0
NEW_EARLY = 0x0C047205                 # jal 0x8011C814
OLD_LATE = 0x0C05DB87                  # jal 0x80176E1C
NEW_LATE = 0x0C07FC68                  # jal 0x801FF1A0
OLD_TAIL = 0x0C047205                  # jal 0x8011C814
NEW_TAIL = 0x0C05DB87                  # jal 0x80176E1C
LOADIMAGE_CALL = 0x0C05DF93            # jal 0x80177E4C
NOP = 0x00000000
LATE_DELAY = 0x26040070                # addiu a0,s0,0x70


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def read_archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        names = [info.filename for info in archive.infolist()]
        return names, {name: archive.read(name) for name in names}


def u32(data: bytes, at: int) -> int:
    return struct.unpack_from("<I", data, at)[0]


def jal_target(word: int, pc: int) -> int | None:
    if word >> 26 != 3:
        return None
    return ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)


def main() -> None:
    if digest(build.BASE_ZIP.read_bytes()) != build.BASE_SHA256:
        raise SystemExit("frozen v163 archive hash differs")
    outputs = sorted(build.OUT_DIR.glob(f"{build.OUT_STEM}_????????.zip"))
    if len(outputs) != 1:
        raise SystemExit(f"expected exactly one v164 archive, found {len(outputs)}")
    output = outputs[0]

    base_names, old = read_archive(build.BASE_ZIP)
    names, current = read_archive(output)
    if names != base_names:
        raise SystemExit("archive member order or names changed")
    if any(current[name] != old[name] for name in names if name != build.PSX):
        raise SystemExit("a non-PSX member differs from v163")

    old_exe, exe = old[build.PSX], current[build.PSX]
    if len(exe) != len(old_exe):
        raise SystemExit("PSX.EXE size changed")

    expected = (
        (build.EARLY_HOOK, build.file_at(build.EARLY_HOOK), OLD_EARLY, NEW_EARLY,
         "restore stock frame"),
        (build.LATE_HOOK, build.file_at(build.LATE_HOOK), OLD_LATE, NEW_LATE,
         "late cache wrapper"),
        (build.FRAME_TAIL_CALL, build.resident_source_at(build.FRAME_TAIL_CALL),
         OLD_TAIL, NEW_TAIL, "preserve DrawOT"),
    )
    expected_changed: set[int] = set()
    for address, at, old_word, new_word, label in expected:
        if u32(old_exe, at) != old_word:
            raise SystemExit(f"independent old-word guard failed at 0x{address:08X} ({label})")
        if u32(exe, at) != new_word:
            raise SystemExit(f"independent new-word guard failed at 0x{address:08X} ({label})")
        old_bytes, new_bytes = struct.pack("<I", old_word), struct.pack("<I", new_word)
        expected_changed.update(at + i for i in range(4) if old_bytes[i] != new_bytes[i])

    changed = {i for i, (left, right) in enumerate(zip(old_exe, exe)) if left != right}
    if changed != expected_changed:
        raise SystemExit(
            f"unexplained EXE diff: missing={sorted(expected_changed-changed)} "
            f"extra={sorted(changed-expected_changed)}"
        )

    delay_oracles = (
        (build.file_at(build.EARLY_DELAY), NOP, "early delay"),
        (build.file_at(build.LATE_DELAY), LATE_DELAY, "late argument delay"),
        (build.resident_source_at(build.FRAME_TAIL_DELAY), NOP, "wrapper tail delay"),
    )
    for at, expected_word, label in delay_oracles:
        if u32(exe, at) != expected_word or u32(old_exe, at) != expected_word:
            raise SystemExit(f"{label} differs")

    # Verify the new non-recursive call topology independently.
    if jal_target(u32(exe, build.file_at(build.EARLY_HOOK)), build.EARLY_HOOK) != build.STOCK_FRAME:
        raise SystemExit("early hook does not call the stock frame")
    if jal_target(u32(exe, build.file_at(build.LATE_HOOK)), build.LATE_HOOK) != build.FRAME:
        raise SystemExit("pre-DrawOT site does not call the cache wrapper")
    if jal_target(
        u32(exe, build.resident_source_at(build.FRAME_TAIL_CALL)),
        build.FRAME_TAIL_CALL,
    ) != build.DRAWOT:
        raise SystemExit("cache wrapper does not preserve the displaced DrawOT")

    frame_at = build.resident_source_at(build.FRAME)
    frame = exe[frame_at:frame_at + build.FRAME_N]
    frame_calls: list[tuple[int, int]] = []
    for offset in range(0, len(frame), 4):
        pc = build.FRAME + offset
        target = jal_target(u32(frame, offset), pc)
        if target is not None:
            frame_calls.append((pc, target))
    targets = [target for _pc, target in frame_calls]
    if build.LOADIMAGE not in targets or build.DRAWOT not in targets:
        raise SystemExit("wrapper is missing LoadImage or DrawOT")
    if build.STOCK_FRAME in targets:
        raise SystemExit("wrapper still calls the stock frame recursively")
    if targets.index(build.LOADIMAGE) > targets.index(build.DRAWOT):
        raise SystemExit("DrawOT occurs before cache LoadImage")
    if u32(exe, build.resident_source_at(0x801FF38C)) != LOADIMAGE_CALL:
        raise SystemExit("known LoadImage call word differs")

    # All v163 cache data and classifier bytes must remain untouched.
    classifier_at = build.resident_source_at(build.base.CLASSIFIER)
    classifier_n = len(build.base.build_classifier())
    if exe[classifier_at:classifier_at + classifier_n] != \
            old_exe[classifier_at:classifier_at + classifier_n]:
        raise SystemExit("v163 classifier changed")

    with build.WRITES_CSV.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != 3:
        raise SystemExit("expected-write manifest does not contain three writes")
    manifest_addresses = {int(row["runtime_address"], 16) for row in rows}
    if manifest_addresses != {build.EARLY_HOOK, build.LATE_HOOK, build.FRAME_TAIL_CALL}:
        raise SystemExit("expected-write manifest address set differs")

    stamp = digest(output.read_bytes())
    lines = [
        "v164 pre-DrawOT cache-upload independent verification: PASS",
        f"archive={output.name}",
        f"archive_sha256={stamp}",
        f"archive_members={len(names)}",
        f"PSX.EXE_bytes={len(exe)}",
        f"changed_EXE_bytes={len(changed)}",
        "changed_non_EXE_members=0",
        "expected_write_words=3/3",
        "delay_slots=3/3",
        "early_call=stock_frame",
        "late_call=cache_wrapper",
        "wrapper_call_order=LoadImage_before_DrawOT",
        "wrapper_stock_frame_recursion=0",
        "v163_cache_data_and_classifier=byte_identical",
        "runtime_verification=PENDING user cold boot",
        "release_status=DIAGNOSTIC_ONLY",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
