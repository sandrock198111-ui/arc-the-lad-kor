"""Pull RAM and VRAM out of a DuckStation save state without pixel heuristics.

DuckStation serializes the literal ``GPU-VRAM`` marker immediately before the raw
1024x512x16-bit VRAM array.  That structural marker is the only origin oracle used
here.  Font pixels and resident glyph strips may be checked afterwards, but they
must never choose the origin: either can be blank, patched, or shifted by the
COMM.IMG x=320 placement and still look plausible.
"""
from __future__ import annotations

import struct
import sys
from compression import zstd
from pathlib import Path

RAM_BASE, RAM_SIZE = 0x80000000, 2 * 1024 * 1024
VRAM_W, VRAM_H = 1024, 512
VRAM_SIZE = VRAM_W * VRAM_H * 2
GPU_VRAM_MARKER = struct.pack("<I", len("GPU-VRAM")) + b"GPU-VRAM"
BUS_RAM_PAYLOAD_SKIP = 64

STRIP_A_RAM, STRIP_B_RAM = 0x801FE4D8, 0x801FE880
STRIP_ROW_BYTES, STRIP_ROWS = 78, 12
STRIP_A_XY, STRIP_B_XY = (961, 480), (961, 500)


def inflate(path: Path) -> bytes:
    raw = path.read_bytes()
    if raw[:5] != b"DUCCT":
        raise SystemExit(f"{path.name}: not a DuckStation compressed save state")
    data_off = struct.unpack_from("<I", raw, 0xC4)[0]
    if raw[data_off:data_off + 4] != b"\x28\xB5\x2F\xFD":
        raise SystemExit(f"{path.name}: no zstd frame at the recorded data offset")
    # The frame is followed by the screenshot; the decoder stops at the end marker.
    return zstd.decompress(raw[data_off:])


def section(blob: bytes, name: str) -> int:
    tag = struct.pack("<I", len(name)) + name.encode()
    at = blob.find(tag)
    if at < 0:
        raise SystemExit(f"no {name} section")
    return at + len(tag)


def locate_vram(blob: bytes) -> int:
    """Return the raw VRAM array offset selected by DuckStation's marker.

    The search is deliberately bounded to the beginning of the GPU section and
    fails closed if zero or multiple complete arrays are found.
    """
    gpu = section(blob, "GPU")
    search_end = min(len(blob), gpu + (1 << 16))
    matches: list[int] = []
    cursor = gpu
    while True:
        marker = blob.find(GPU_VRAM_MARKER, cursor, search_end)
        if marker < 0:
            break
        base = marker + len(GPU_VRAM_MARKER)
        if base + VRAM_SIZE <= len(blob):
            matches.append(base)
        cursor = marker + 1
    if len(matches) != 1:
        raise ValueError(
            f"expected one complete GPU-VRAM array, found {len(matches)}"
        )
    return matches[0]


def locate_ram(blob: bytes) -> int:
    """Return the start of the 2 MiB PS1 RAM payload in the Bus section."""
    base = section(blob, "Bus") + BUS_RAM_PAYLOAD_SKIP
    if base + RAM_SIZE > len(blob):
        raise ValueError("Bus RAM payload is incomplete")
    return base


def locate(blob: bytes) -> tuple[bytes, int]:
    """Backward-compatible pair: RAM bytes and the structural VRAM offset."""
    ram_base = locate_ram(blob)
    return blob[ram_base:ram_base + RAM_SIZE], locate_vram(blob)


def verify(blob: bytes, ram: bytes, base: int) -> bool:
    for ram_at, (x, y) in ((STRIP_A_RAM, STRIP_A_XY), (STRIP_B_RAM, STRIP_B_XY)):
        for r in range(STRIP_ROWS):
            src = ram[ram_at - RAM_BASE + r * STRIP_ROW_BYTES:][:STRIP_ROW_BYTES]
            dst = blob[base + ((y + r) * VRAM_W + x) * 2:][:STRIP_ROW_BYTES]
            if src != dst:
                return False
    return True


def load(path: Path) -> tuple[bytes, bytes]:
    blob = inflate(path)
    ram, base = locate(blob)
    return ram, blob[base:base + VRAM_SIZE]


def main() -> None:
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    target = Path(sys.argv[1])
    files = sorted(target.glob("HASH-340476B50F5F94CD_*.sav")) if target.is_dir() else [target]
    if not files:
        raise SystemExit("no Arc the Lad save states found")
    for arg in files:
        blob = inflate(arg)
        ram, base = locate(blob)
        gpu = section(blob, "GPU")
        strip_check = "match" if verify(blob, ram, base) else "not-applicable/mismatch"
        print(f"{arg.name}  VRAM at GPU+{base - gpu}, GPU-VRAM marker; strips={strip_check}")
        if out:
            out.mkdir(parents=True, exist_ok=True)
            (out / f"{arg.stem}.vram.bin").write_bytes(blob[base:base + VRAM_SIZE])
            (out / f"{arg.stem}.ram.bin").write_bytes(ram)


if __name__ == "__main__":
    main()
