from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output" / "story_house_sd011_live_slots_1_to_4_patch_only.zip"
OUTPUT = ROOT / "03_output" / "story_s1041_short_questions_patch_only.zip"
TARGET = "1/S1041.DAT"

PATCHES = (
    (0x47EA4, bytes.fromhex("98 A0 3C"), bytes.fromhex("DD D3 3C"), "아크?"),
    (0x480C0, bytes.fromhex("C8 3C 9C"), bytes.fromhex("1D A7 3C"), "예?"),
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def main() -> None:
    if not BASE.exists():
        raise SystemExit(f"base patch is missing: {BASE}")

    with zipfile.ZipFile(BASE) as base_zip:
        names = [info.filename for info in base_zip.infolist()]
        if TARGET not in names:
            raise SystemExit(f"{TARGET} is missing from the base patch")
        data = bytearray(base_zip.read(TARGET))

        for offset, replacement, expected, label in PATCHES:
            actual = bytes(data[offset : offset + len(expected)])
            if actual != expected:
                raise SystemExit(
                    f"{TARGET} 0x{offset:X}: expected {expected.hex(' ')}, "
                    f"found {actual.hex(' ')}"
                )
            boundary = offset + len(expected)
            if data[boundary : boundary + 2] != b"\x00\x00":
                raise SystemExit(f"{TARGET} 0x{offset:X}: 00 00 boundary is missing")
            data[offset : offset + len(replacement)] = replacement
            if data[boundary : boundary + 2] != b"\x00\x00":
                raise SystemExit(f"{TARGET} 0x{offset:X}: boundary was corrupted")
            print(f"patched {TARGET} 0x{offset:X}: {label}")

        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        if OUTPUT.exists():
            OUTPUT.unlink()
        with zipfile.ZipFile(
            OUTPUT, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as output_zip:
            for info in base_zip.infolist():
                if info.filename == "BUILD_REPORT.txt":
                    continue
                payload = bytes(data) if info.filename == TARGET else base_zip.read(info)
                output_zip.writestr(info, payload)

    with zipfile.ZipFile(OUTPUT) as result_zip:
        result_names = result_zip.namelist()
        if len(result_names) != 16 or "BUILD_REPORT.txt" in result_names:
            raise SystemExit(f"unexpected output contents: {result_names}")
        result_data = result_zip.read(TARGET)
        for offset, replacement, _, _ in PATCHES:
            if result_data[offset : offset + len(replacement)] != replacement:
                raise SystemExit(f"output verification failed at 0x{offset:X}")

    print(f"wrote {OUTPUT}")
    print(f"files=16")
    print(f"sha256={digest(OUTPUT.read_bytes())}")


if __name__ == "__main__":
    main()
