#!/usr/bin/env python3
"""Build v220 TEST ONLY: separate decoded rows from expanded-cell scratch.

v219b stopped the BIOS false-marker crash, but its compact stack reused SP+0
for both the 24-byte Huffman result and the 72-byte expanded 4bpp cache cell.
Writing the first expanded row therefore destroyed decoded rows 1 and 2.

This successor changes only the temporary stack layout.  The paired marker,
owner range guard, A/B selection, one-DrawOT borrow/restore path, resident size,
heap boundary, RAM tables, VRAM destinations, DAT files and COMM.IMG remain
unchanged.
"""
from __future__ import annotations

import hashlib

import build_arc1_v219_failclosed_borrow_restore as base


OUT_STEM = "arc1_v220_separate_decode_scratch_TEST_ONLY"
STACK_SIZE = 0x280
DECODED_AT = 0x48
BACKUP_AT = 0x60
SAVED_A0 = 0x258
ORIGINAL_FRAME = base.failclosed_frame


def separated_frame(address: int, huffman_address: int,
                    layout: dict[str, tuple[int, int]]) -> bytes:
    return ORIGINAL_FRAME(
        address,
        huffman_address,
        layout,
        decoded_at=DECODED_AT,
        backup_at=BACKUP_AT,
        saved_a0=SAVED_A0,
        stack_size=STACK_SIZE,
        allow_decode_scratch_alias=False,
    )


def main() -> None:
    base.OUT_STEM = OUT_STEM
    base.STACK_SIZE = STACK_SIZE
    base.failclosed_frame = separated_frame
    base.main()

    report = base.build.REPORT
    text = report.read_text(encoding="utf-8")
    text = text.replace(
        "v219 TEST ONLY - fail-closed paired-marker borrow/restore",
        "v220 TEST ONLY - separate decode and expanded-cell scratch",
        1,
    )
    text = text.replace(
        "runtime=FAIL; user cold boot succeeded but all dynamic glyphs were corrupted",
        "runtime=PENDING; emulator_run=NO",
        1,
    )
    text += "\n".join([
        f"expanded_cell_scratch=SP+0x00..0x47 ({72} bytes)",
        f"decoded_rows=SP+0x{DECODED_AT:02X}..0x{DECODED_AT + 24 - 1:02X} (24 bytes)",
        f"VRAM_backup=SP+0x{BACKUP_AT:02X}..0x{SAVED_A0 - 1:03X} ({base.BACKUP_BYTES} bytes)",
        "decode_scratch_overlap=NO",
        "v219b_runtime=FAIL; all 28 synthetic glyph planes mismatched",
        "v220_runtime=PENDING; emulator_run=NO",
        "",
    ])
    report.write_text(text, encoding="utf-8")

    output = base.one_output()
    print(f"v220_output={output}")
    print(f"v220_sha256={hashlib.sha256(output.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
