from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output" / "story_s1061_forest_dialogue_patch_only.zip"
SOURCE_ROOT = Path(r"E:\arc\out")
OUTPUT = ROOT / "03_output" / "story_reed_king_flashback_underground_patch_only.zip"
FILLER = 0x9C

# Slot-pair sources: 1-2 reed battle aftermath, 3-4 and 7-8 throne room,
# 5-6 flashback narration, 9-10 underground scene.
TARGETS = ("F/SF0D1.DAT", "22/S2053.DAT", "F/SF091.DAT", "23/S2081.DAT", "23/S2082.DAT")


def blocks(data: bytes) -> list[tuple[int, int]]:
    found: list[tuple[int, int]] = []
    for marker in range(0x47000, len(data) - 4):
        if data[marker:marker + 2] not in (b"\x17\x00", b"\x19\x00"):
            continue
        header = marker - 6
        if data[header:header + 2] != b"\x29\x00" or data[header + 4:header + 6] != b"\x7f\x00":
            continue
        start = marker + 2
        if data[start:start + 2] in (b"\x00\x00", b"\x01\x00", b"\x03\x00", b"\x04\x00"):
            start += 2
        end = data.find(b"\x00\x00", start, min(start + 0x100, len(data)))
        if end > start:
            found.append((start, end))
    return found


def text(capacity: int) -> bytes:
    if capacity >= 6:
        return bytes.fromhex("98 a0 e6 01 90 8c")
    if capacity >= 3:
        return bytes.fromhex("98 a0 3c")
    if capacity >= 2:
        return bytes.fromhex("98 a0")
    return bytes.fromhex("90")


def main() -> None:
    modified: dict[str, bytes] = {}
    count = 0
    for name in TARGETS:
        data = bytearray((SOURCE_ROOT / name).read_bytes())
        rows = blocks(data)
        if not rows:
            raise SystemExit(f"no bounded dialogue in {name}")
        for start, end in rows:
            payload = text(end - start)
            if data[end:end + 2] != b"\x00\x00" or len(payload) > end - start:
                raise SystemExit(f"invalid boundary or capacity: {name} 0x{start:X}")
            data[start:end] = bytes([FILLER]) * (end - start)
            data[start:start + len(payload)] = payload
            if data[end:end + 2] != b"\x00\x00":
                raise SystemExit(f"boundary changed: {name} 0x{start:X}")
            count += 1
        modified[name] = bytes(data)

    with zipfile.ZipFile(BASE) as base, zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as out:
        for info in base.infolist():
            if info.filename not in {"BUILD_REPORT.txt", *modified}:
                out.writestr(info, base.read(info.filename))
        for name, data in modified.items():
            out.writestr(name, data)

    with zipfile.ZipFile(OUTPUT) as out:
        names = out.namelist()
        if len(names) != 22 or len(names) != len(set(names)) or "BUILD_REPORT.txt" in names:
            raise SystemExit("unexpected ZIP structure")
        for name, data in modified.items():
            if names.count(name) != 1 or out.read(name) != data:
                raise SystemExit(f"ZIP verification failed: {name}")
    print(f"wrote {OUTPUT}")
    print(f"files=22 blocks={count} sha256={hashlib.sha256(OUTPUT.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
