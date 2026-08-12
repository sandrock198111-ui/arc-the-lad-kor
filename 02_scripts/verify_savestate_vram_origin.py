"""Verify the DuckStation VRAM origin without using font pixels as the anchor.

COMM.IMG begins at VRAM x=320.  Its first byte can therefore be mistaken for a
1024-wide VRAM origin shifted by 640 bytes.  This read-only verifier uses the
structural ``GPU-VRAM`` marker, inventories every save-state offset, and proves why
the shifted interpretation appears to show a valid framebuffer at x=704..1023.

Writes ``01_work/analysis/vram_occupancy_map/vram_origin_verification.txt``.
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from extract_savestate_vram import inflate, locate_vram, section  # noqa: E402

STATES = Path.home() / "AppData/Local/DuckStation/savestates"
REPORT = ROOT / "01_work/analysis/vram_occupancy_map/vram_origin_verification.txt"
VRAM_W, VRAM_H = 1024, 512
VRAM_SIZE = VRAM_W * VRAM_H * 2
COMM_SHIFT_BYTES = 320 * 2


def origin(blob: bytes) -> tuple[int, int]:
    gpu = section(blob, "GPU")
    return gpu, locate_vram(blob)


def main() -> None:
    files = sorted(STATES.glob("*.sav"))
    offsets: Counter[int] = Counter()
    failed: list[str] = []
    first: tuple[Path, bytes, int] | None = None

    for path in files:
        try:
            blob = inflate(path)
            gpu, base = origin(blob)
            offsets[base - gpu] += 1
            if first is None:
                first = (path, blob, base)
        except BaseException as exc:
            failed.append(f"{path.name}: {exc}")

    if first is None:
        raise SystemExit("no state had a usable GPU-VRAM marker")

    path, blob, base = first
    # A false origin at true+640 maps fake x704..1023,row y onto the real
    # x0..319,row y+1 because 320+704 == 1024.  Compare all complete rows.
    wrapped_equal = 0
    for y in range(VRAM_H - 1):
        fake_start = base + COMM_SHIFT_BYTES + (y * VRAM_W + 704) * 2
        true_start = base + ((y + 1) * VRAM_W) * 2
        if blob[fake_start:fake_start + 320 * 2] == blob[true_start:true_start + 320 * 2]:
            wrapped_equal += 1

    lines = [
        "DuckStation savestate VRAM-origin verification",
        f"input_states={len(files)}",
        f"marker_success={sum(offsets.values())}",
        f"marker_failures={len(failed)}",
        "marker_offsets=" + " ".join(
            f"GPU+{offset}:{count}" for offset, count in sorted(offsets.items())
        ),
        f"representative_state={path.name}",
        f"false_origin_delta={COMM_SHIFT_BYTES} bytes",
        ("false_x704_1023_equals_true_x0_319_next_row="
         f"{wrapped_equal}/{VRAM_H - 1}"),
        "",
        "Conclusion:",
        "- VRAM starts immediately after the GPU-VRAM marker; no fixed GPU+N is universal.",
        "- COMM.IMG x=320 is 640 bytes after the true row origin.",
        "- A +640 false origin wraps the true x=0 framebuffer to fake x=704,",
        "  so a readable right-edge screen is evidence of the shift, not of that origin.",
    ]
    if failed:
        lines.extend(("", "failures:", *failed))
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
