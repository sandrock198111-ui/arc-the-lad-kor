"""Pull RAM and VRAM out of a DuckStation .sav, and anchor VRAM by an exact match.

The .sav is a small header followed by a zstd frame at the offset stored at 0xC4.
Inside is the same sectioned blob the older .state.bin files hold: a u32 length, an
ASCII section name, then that section's data.

Finding VRAM inside the GPU section is the part worth care.  The section is about
700 bytes larger than VRAM and nothing says where the pixels start, and an even-byte
error is a pure horizontal shift of the whole image -- invisible to any test that
only looks at VRAM's internal structure.  Earlier attempts to score alignment by
pixel runs or texture-page edges narrowed it to six candidates exactly one texture
page apart and could not choose between them, which is precisely the ambiguity that
would put every later measurement on the wrong page.

So the anchor comes from outside: the resident glyph strips.  Strip A lives in
reserved RAM at a known address and is uploaded every frame to a known VRAM
rectangle, so its first row must appear at a computable byte offset.  One match
fixes the base with no ambiguity left, and the second strip then confirms it.
"""
from __future__ import annotations

import struct
import sys
from compression import zstd
from pathlib import Path

RAM_BASE, RAM_SIZE = 0x80000000, 2 * 1024 * 1024
VRAM_W, VRAM_H = 1024, 512
VRAM_SIZE = VRAM_W * VRAM_H * 2

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


def locate(blob: bytes) -> tuple[bytes, int]:
    """Fix the RAM and VRAM bases together, by the one thing that ties them.

    Neither section says where its payload begins, so both are searched at once and
    only the pair that reproduces the per-frame strip upload is accepted: strip A's
    bytes in reserved RAM must equal, row for row, the VRAM rectangle they are copied
    into, and strip B's must too.  That is 936 bytes matching at two computed
    addresses, which no wrong pair survives.
    """
    bus, gpu = section(blob, "Bus"), section(blob, "GPU")
    limit = gpu + VRAM_SIZE + 4096
    for skip in range(0, 256, 4):
        ram = blob[bus + skip:bus + skip + RAM_SIZE]
        if len(ram) != RAM_SIZE:
            continue
        row = ram[STRIP_A_RAM - RAM_BASE:][:STRIP_ROW_BYTES]
        if not any(row):
            continue
        want = (STRIP_A_XY[1] * VRAM_W + STRIP_A_XY[0]) * 2
        at = blob.find(row, gpu, limit)
        while at >= 0:
            base = at - want
            if base >= gpu and base + VRAM_SIZE <= len(blob) and verify(blob, ram, base):
                return ram, base
            at = blob.find(row, at + 1, limit)
    raise SystemExit("no RAM/VRAM pair reproduces the strip upload; "
                     "is this state from a build with resident strips?")


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
        print(f"{arg.name}  VRAM at GPU+{base - gpu}, anchored on both strips")
        if out:
            out.mkdir(parents=True, exist_ok=True)
            (out / f"{arg.stem}.vram.bin").write_bytes(blob[base:base + VRAM_SIZE])
            (out / f"{arg.stem}.ram.bin").write_bytes(ram)


if __name__ == "__main__":
    main()
