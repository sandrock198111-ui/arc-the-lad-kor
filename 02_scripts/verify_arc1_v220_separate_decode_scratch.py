#!/usr/bin/env python3
"""Run v219 fail-closed regressions plus exact v220 upload-pixel checks."""
from __future__ import annotations

from zipfile import ZipFile

import build_arc1_v219_failclosed_borrow_restore as build
import build_arc1_v220_separate_decode_scratch as v220
import verify_arc1_v219_failclosed_borrow_restore as verify


def parent_delta() -> None:
    old_matches = sorted(build.build.OUT_DIR.glob(
        "arc1_v219b_failclosed_borrow_restore_TEST_ONLY_????????.zip"
    ))
    new_matches = sorted(build.build.OUT_DIR.glob(f"{v220.OUT_STEM}_????????.zip"))
    if len(old_matches) != 1 or len(new_matches) != 1:
        raise SystemExit(
            f"v220 parent/output archive count differs: {old_matches}, {new_matches}"
        )
    with ZipFile(old_matches[0]) as archive:
        old = {item.filename: archive.read(item.filename) for item in archive.infolist()}
    with ZipFile(new_matches[0]) as archive:
        new = {item.filename: archive.read(item.filename) for item in archive.infolist()}
    changed = [name for name in old if old[name] != new[name]]
    if changed != [build.build.PSX]:
        raise SystemExit(f"v220 changed unexpected parent members: {changed}")
    before, after = old[build.build.PSX], new[build.build.PSX]
    if len(before) != len(after):
        raise SystemExit("v220 changed PSX.EXE size")
    offsets = [index for index, pair in enumerate(zip(before, after)) if pair[0] != pair[1]]
    frame_at = (
        build.old.file_at(build.build.v171.SOURCE_BASE)
        + build.FRAME - build.build.v171.RESIDENT_BASE
    )
    if len(offsets) != 26 or not all(
        frame_at <= offset < frame_at + build.FRAME_N for offset in offsets
    ):
        raise SystemExit(
            f"v220 parent delta differs: bytes={len(offsets)} "
            f"range=0x{min(offsets):X}..0x{max(offsets):X}"
        )
    print("PASS parent delta: PSX.EXE only, 26 bytes inside resident frame")


def main() -> None:
    build.OUT_STEM = v220.OUT_STEM
    build.STACK_SIZE = v220.STACK_SIZE
    build.failclosed_frame = v220.separated_frame
    parent_delta()
    verify.main()
    print("v220_separate_decode_scratch_regressions=PASS")


if __name__ == "__main__":
    main()
