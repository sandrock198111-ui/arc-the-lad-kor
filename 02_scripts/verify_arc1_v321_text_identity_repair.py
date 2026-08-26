#!/usr/bin/env python3
"""Independent static verifier for the V321 16px text-identity repair."""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import build_arc1_v320c_hanme_official_beol as font  # noqa: E402
from build_arc1_v231_static_promotion_restored162 import text_regions  # noqa: E402


BASE = ROOT / "03_output/arc1_v320c_hanme_official_beol_TEST_ONLY_81D215E1.zip"
BASE_SHA256 = "81D215E1B1138E26707353D8982AE3139AE4F3900F6E832FEC83BB66A43AEA8D"
BUILD = ROOT / "03_output/arc1_v321_text_identity_repair_TEST_ONLY_1B04A832.zip"
BUILD_SHA256 = "1B04A832B33BF061A1AAC8BEE1186B53D6FE977ACA5295C6B5A019CD0759DDFF"
ASSIGNMENTS = ROOT / "01_work/analysis/arc1_v320_hanme_static_recovery/character_assignments.csv"
ATLAS_MAPPING = ROOT / "01_work/analysis/arc1_v319_pilgi16_integration/atlas_mapping.csv"
PIECES = ROOT / "01_work/analysis/hangul_johab_16px/pieces_1bpp.bin"
OUTPUT = ROOT / "01_work/analysis/arc1_v321_text_identity_repair"

SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
GWAL_INDEX = 170
GWAL_CODE = b"\xAB"
PUM_CODE = bytes.fromhex("DD 80")


class VerifyError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as handle:
        names = [info.filename for info in handle.infolist() if not info.is_dir()]
        return names, {name: handle.read(name) for name in names}


def token_width(value: int) -> int:
    return 1 if value < 0xDD else 2


def encode_direct_index(index: int) -> bytes | None:
    if 0 <= index < 0xDC:
        return bytes((index + 1,))
    lead_delta, trail = divmod(index - 0xDB, 255)
    if 0 <= lead_delta <= 3 and 1 <= trail <= 0xFE:
        return bytes((0xDD + lead_delta, trail))
    return None


def code_map() -> dict[bytes, str]:
    result: dict[bytes, str] = {}
    # Start with the physical atlas identity so legacy direct codes that did
    # not need a V320 assignment (for example 0x5A) are still decodable.
    with ATLAS_MAPPING.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            if not row["char"]:
                continue
            code = encode_direct_index(int(row["index"]))
            if code is not None:
                result.setdefault(code, row["char"])
    with ASSIGNMENTS.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            code = bytes.fromhex(row["code_hex"])
            char = row["char"]
            # V320 assignments are authoritative for reused codes; the atlas
            # identity above only fills codes that were left untouched.
            result[code] = char
    result[GWAL_CODE] = "괄"
    result[PUM_CODE] = "품"
    return result


def decode(data: bytes, mapping: dict[bytes, str]) -> str:
    output: list[str] = []
    offset = 0
    while offset < len(data):
        width = token_width(data[offset])
        token = data[offset : offset + width]
        if len(token) != width or token not in mapping:
            raise VerifyError(f"unmapped token at +0x{offset:X}: {token.hex(' ')}")
        output.append(mapping[token])
        offset += width
    return "".join(output)


def slot(data: bytes, index: int) -> bytes:
    start = SLOT_BASE + index * SLOT_SIZE
    end = data.index(0, start, start + SLOT_SIZE)
    return data[start:end]


def main() -> None:
    if sha256_file(BASE) != BASE_SHA256 or sha256_file(BUILD) != BUILD_SHA256:
        raise VerifyError("archive hash drift")
    base_names, base = archive(BASE)
    final_names, final = archive(BUILD)
    if base_names != final_names or len(final_names) != 164:
        raise VerifyError("ZIP topology drift")

    changed = [name for name in final_names if base[name] != final[name]]
    expected_changed = {
        "PSX.EXE", "COMM.IMG", "1/S1072.DAT", "1/S1021.DAT",
        "1/S1031.DAT", "D/SD011.DAT", "21/S2021.DAT",
    }
    if set(changed) != expected_changed:
        raise VerifyError(f"changed members differ: {changed}")

    mapping = code_map()
    phrases = {
        "state1": decode(final["1/S1072.DAT"][0x47932:0x47950], mapping),
        "state2": decode(slot(final["1/S1021.DAT"], 58), mapping),
        "state3": decode(slot(final["1/S1031.DAT"], 0), mapping),
        "state4": decode(slot(final["D/SD011.DAT"], 10), mapping)
        + "\n" + decode(slot(final["D/SD011.DAT"], 11), mapping),
        "state5": decode(slot(final["D/SD011.DAT"], 12), mapping)
        + "\n" + decode(slot(final["D/SD011.DAT"], 0), mapping),
    }
    expected_phrases = {
        "state1": "촌장: 이 말괄량이 덕분에 마침내 꺼지는구나.",
        "state2": "아버지의 유품인 갑옷과 검을 찾았다.",
        "state3": "엄마...",
        "state4": "그 불을 줘.\n내가 다시 붙이고 올게.",
        "state5": "걱정 마.\n불은 내가 다시 붙이고 올게.",
    }
    if phrases != expected_phrases:
        raise VerifyError(f"phrase readback differs: {phrases}")

    # Independently derive the 57 PSX text offsets and prove that each is the
    # pinned same-width AB->64 legacy 몬 repair, with no other PSX change.
    legacy_offsets: list[int] = []
    for name, start, end in text_regions(base):
        if name != "PSX.EXE":
            continue
        data = base[name]
        offset = start
        while offset < end:
            width = 2 if data[offset] == 0xE2 or 0xE3 <= data[offset] <= 0xE8 else token_width(data[offset])
            if width == 1 and data[offset] == 0xAB:
                legacy_offsets.append(offset)
            offset += width
    if len(legacy_offsets) != 57:
        raise VerifyError(f"legacy 몬 census differs: {len(legacy_offsets)}")
    psx_diff = {
        offset
        for offset, pair in enumerate(zip(base["PSX.EXE"], final["PSX.EXE"]))
        if pair[0] != pair[1]
    }
    if psx_diff != set(legacy_offsets):
        raise VerifyError("PSX Expected-Write set differs")
    if any(base["PSX.EXE"][offset] != 0xAB or final["PSX.EXE"][offset] != 0x64 for offset in legacy_offsets):
        raise VerifyError("legacy 몬 byte transition differs")

    # Recompose 괄 from the pinned 360 Hanme pieces, then prove no other plane
    # changed.  This implementation shares font primitives, but the exhaustive
    # plane comparison and archive/member diff above are independent of V321.
    pieces = font.load_pieces(PIECES.read_bytes())
    expected_gwal = font.compose(pieces, "괄", True)
    if font.read_plane(final["COMM.IMG"], GWAL_INDEX) != expected_gwal:
        raise VerifyError("괄 bitmap differs from official composition")
    changed_planes = []
    for index in range(font.MAX_PHYSICAL_INDEX):
        if font.read_plane(base["COMM.IMG"], index) != font.read_plane(final["COMM.IMG"], index):
            changed_planes.append(index)
    if changed_planes != [GWAL_INDEX]:
        raise VerifyError(f"COMM plane set differs: {changed_planes}")

    # The two mixed inline sites retain every E4/E6 timing byte.
    for name, start, end in (
        ("1/S1031.DAT", 0x4787A, 0x47883),
        ("D/SD011.DAT", 0x47B60, 0x47B7D),
        ("D/SD011.DAT", 0x47D58, 0x47D71),
    ):
        if base[name][start:end] != final[name][start:end]:
            raise VerifyError(f"inline wrapper changed: {name}:0x{start:X}")

    result = {
        "result": "PASS",
        "build_sha256": BUILD_SHA256,
        "changed_members": changed,
        "phrases": phrases,
        "legacy_mon_psx_bytes": len(legacy_offsets),
        "changed_COMM_planes": changed_planes,
        "geometry": "PSX geometry/code words inherited; no hook edits",
        "runtime": "PENDING",
    }
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "independent_verification.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V321 independent static verification: PASS",
        f"build_sha256={BUILD_SHA256}",
        f"changed_members={','.join(changed)}",
        "disk_readback=" + " | ".join(f"{key}:{value.replace(chr(10), ' / ')}" for key, value in phrases.items()),
        f"legacy_mon_psx_bytes={len(legacy_offsets)} (AB->64 only)",
        f"changed_COMM_planes={changed_planes}",
        "runtime=PENDING user cold boot",
    ]
    (OUTPUT / "independent_verification.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
