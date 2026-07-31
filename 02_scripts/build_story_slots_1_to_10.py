from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output" / "story_s1061_forest_dialogue_patch_only.zip"
SOURCE_ROOT = Path(r"E:\arc\out")
OUTPUT = ROOT / "03_output" / "story_slots_1_to_10_dialogue_patch_only.zip"
FILLER = 0x9C

# Latest state-source coverage:
# guard: S2031/S2033; throne room: S2051/S2052/S2057;
# night forest: S2061; city: S2021.
TARGETS = (
    "21/S2031.DAT",
    "21/S2033.DAT",
    "22/S2051.DAT",
    "22/S2052.DAT",
    "22/S2057.DAT",
    "23/S2061.DAT",
    "21/S2021.DAT",
)


def scan_blocks(data: bytes) -> list[tuple[int, int]]:
    blocks: list[tuple[int, int]] = []
    for marker_offset in range(0x47000, len(data) - 4):
        if data[marker_offset : marker_offset + 2] not in (b"\x17\x00", b"\x19\x00"):
            continue
        header = marker_offset - 6
        if data[header : header + 2] != b"\x29\x00" or data[header + 4 : header + 6] != b"\x7F\x00":
            continue
        start = marker_offset + 2
        if data[start : start + 2] in (b"\x00\x00", b"\x01\x00", b"\x03\x00", b"\x04\x00"):
            start += 2
        end = data.find(b"\x00\x00", start, min(len(data), start + 0x100))
        if end > start:
            blocks.append((start, end))
    return blocks


def replacement(capacity: int) -> bytes:
    # Stable high-slot Korean: 아크 / 가자, with the known question glyph.
    if capacity >= 6:
        return bytes.fromhex("98 a0 e6 01 90 8c")
    if capacity >= 3:
        return bytes.fromhex("98 a0 3c")
    if capacity >= 2:
        return bytes.fromhex("98 a0")
    return bytes.fromhex("90")


def main() -> None:
    modified: dict[str, bytes] = {}
    report: list[str] = []
    for name in TARGETS:
        path = SOURCE_ROOT / name
        data = bytearray(path.read_bytes())
        blocks = scan_blocks(data)
        if not blocks:
            raise SystemExit(f"no bounded dialogue blocks found in {name}")
        for start, end in blocks:
            original = bytes(data[start:end])
            payload = replacement(end - start)
            if len(payload) > len(original):
                raise SystemExit(f"{name} 0x{start:X}: replacement exceeds capacity")
            if data[end : end + 2] != b"\x00\x00":
                raise SystemExit(f"{name} 0x{start:X}: boundary missing")
            data[start:end] = bytes([FILLER]) * len(original)
            data[start : start + len(payload)] = payload
            if data[end : end + 2] != b"\x00\x00":
                raise SystemExit(f"{name} 0x{start:X}: boundary changed")
            report.append(f"{name} 0x{start:X} {len(payload)}/{len(original)}")
        modified[name] = bytes(data)

    with zipfile.ZipFile(BASE) as base_zip, zipfile.ZipFile(
        OUTPUT, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as result:
        for info in base_zip.infolist():
            if info.filename not in {"BUILD_REPORT.txt", *modified}:
                result.writestr(info, base_zip.read(info.filename))
        for name, data in modified.items():
            result.writestr(name, data)

    with zipfile.ZipFile(OUTPUT) as result:
        names = result.namelist()
        if "BUILD_REPORT.txt" in names or len(names) != 24:
            raise SystemExit(f"unexpected ZIP contents: entries={len(names)}")
        for name, data in modified.items():
            if names.count(name) != 1 or result.read(name) != data:
                raise SystemExit(f"output verification failed for {name}")

    print("\n".join(report))
    print(f"wrote {OUTPUT}")
    print(f"files=24 blocks={len(report)} sha256={hashlib.sha256(OUTPUT.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
