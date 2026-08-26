#!/usr/bin/env python3
"""Build V321: repair five V320C runtime-proven text identity failures.

V320C's 16px geometry and official Hanme beol selection are frozen.  This
builder changes only one new Hangul plane and the exact script bytes proven by
the six user save states.  It also removes the sole dead-slot 0xAB token before
assigning that one-byte code to 괄.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import pickle
import struct
import sys
from collections import defaultdict
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


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
BASE_MEMBER_SHA256 = {
    "COMM.IMG": "DB97B75C8D468715695CE40C4BFDC61F79F47CF8E08D114A30009B755AACC216",
    "PSX.EXE": "3D477AF6E97860485D89ADA92932FA90FA05B0834B583072E7A0946D2912D291",
    "1/S1072.DAT": "052EDD631CC7B56EA8C74A8DF1F5DCC269B06071D09916278B8DE7A144033366",
    "1/S1021.DAT": "B3909F4A49B32896962EAE1CBDE9B069C643CE0C6E0B3E67F6218846713D63C2",
    "1/S1031.DAT": "015C85210E91289D54B92277B6CCEACECA6DFB2D56596ABC1A64FA42D96E9008",
    "D/SD011.DAT": "6F3E3F1BA45D3ECA33B78F0F394372BF3477ACA01CA4708E336F91815183D018",
    "21/S2021.DAT": "574178EE461B7A1218B573C51F698642D2F60BD2F676EA169C4F688054150585",
}

PIECES = ROOT / "01_work/analysis/hangul_johab_16px/pieces_1bpp.bin"
PIECES_SHA256 = "409ABA72F4BA2282AA5C4E4982A9EEA16FBD14FB0413A40E151537A6653E2904"
ASSIGNMENTS = ROOT / "01_work/analysis/arc1_v320_hanme_static_recovery/character_assignments.csv"
ASSIGNMENTS_SHA256 = "933BDAC4BC4C39D33DB134D2FF836902B5053B93725C96E19DED714CB7DE98A4"
ATLAS_MAPPING = ROOT / "01_work/analysis/arc1_v319_pilgi16_integration/atlas_mapping.csv"
ATLAS_MAPPING_SHA256 = "9553E7643621CC80C23355067611EAE7650FEF7CB547DC9115B62157DB0C3122"
CELL_AUDIT = ROOT / "01_work/analysis/font_cell_audit_full/cell_consumers.csv"
CELL_AUDIT_SHA256 = "63EF327777CC8A4E072AF68B8A1FE2B2EF4DFD8570D6176980157B7BBF7D5A73"
VOTED_MAP = ROOT / "01_work/analysis/hangul_johab_16px/code_map_voted.pkl"
VOTED_MAP_SHA256 = "514ACCDB7329A0D18BB547F2C09E115A8A3E34DD412672BE85826BC54259866A"

OUTPUT_DIR = ROOT / "03_output"
ANALYSIS_DIR = ROOT / "01_work/analysis/arc1_v321_text_identity_repair"
OUTPUT_STEM = "arc1_v321_text_identity_repair_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v320c"

EXPECTED_MEMBERS = 164
COMM = "COMM.IMG"
PSX = "PSX.EXE"
SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
NEW_GWAL_INDEX = 170
NEW_GWAL_CODE = bytes((NEW_GWAL_INDEX + 1,))  # 0xAB
PUM_INDEX = 347
PUM_CODE = bytes.fromhex("DD 80")

REPAIRS = {
    ("1/S1031.DAT", 0): "엄마...",
    ("D/SD011.DAT", 10): "그 불을 줘.",
    ("D/SD011.DAT", 11): "내가 다시 붙이고 올게.",
    ("D/SD011.DAT", 12): "걱정 마.",
    ("D/SD011.DAT", 0): "불은 내가 다시 붙이고 올게.",
}


class BuildError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def clone_zipinfo(info: ZipInfo) -> ZipInfo:
    clone = ZipInfo(info.filename, info.date_time)
    for attribute in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(clone, attribute, getattr(info, attribute))
    return clone


def read_archive(path: Path) -> tuple[list[ZipInfo], dict[str, bytes]]:
    with ZipFile(path) as archive:
        infos = archive.infolist()
        members = {
            info.filename: archive.read(info.filename)
            for info in infos
            if not info.is_dir()
        }
    if len(members) != EXPECTED_MEMBERS or len(members) != len(set(members)):
        raise BuildError("base archive topology drift")
    return infos, members


def write_archive(
    stem: str,
    infos: list[ZipInfo],
    members: dict[str, bytes],
    selected: set[str] | None,
) -> tuple[Path, str]:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    temporary = OUTPUT_DIR / f".{stem}.{os.getpid()}.building.zip"
    if temporary.exists():
        raise BuildError(f"temporary output exists: {temporary}")
    try:
        with ZipFile(temporary, "w", ZIP_DEFLATED, compresslevel=1) as archive:
            for info in infos:
                if info.is_dir():
                    if selected is None:
                        archive.writestr(clone_zipinfo(info), b"")
                    continue
                if selected is None or info.filename in selected:
                    archive.writestr(clone_zipinfo(info), members[info.filename])
        digest = sha256_file(temporary)
        final = OUTPUT_DIR / f"{stem}_{digest[:8]}.zip"
        if final.exists():
            if sha256_file(final) != digest:
                raise BuildError(f"existing output differs: {final}")
            temporary.unlink()
        else:
            temporary.replace(final)
        return final, digest
    finally:
        if temporary.exists():
            temporary.unlink()


def token_width(value: int) -> int:
    return 1 if value < 0xDD else 2


def is_control(data: bytes | bytearray, offset: int) -> bool:
    return data[offset] == 0xE2 or 0xE3 <= data[offset] <= 0xE8


def load_codes() -> tuple[dict[str, bytes], dict[bytes, str]]:
    choices: dict[str, list[bytes]] = defaultdict(list)
    code_char: dict[bytes, str] = {}
    with ASSIGNMENTS.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            code = bytes.fromhex(row["code_hex"])
            char = row["char"]
            choices[char].append(code)
            previous = code_char.setdefault(code, char)
            if previous != char:
                raise BuildError(f"assignment code collision: {code.hex()}")
    preferred = {char: min(codes, key=lambda code: (len(code), code)) for char, codes in choices.items()}
    if NEW_GWAL_CODE in code_char or PUM_CODE in code_char:
        raise BuildError("new repair code unexpectedly owned by an assignment")
    return preferred, code_char


def encode_text(text: str, preferred: dict[str, bytes]) -> bytes:
    output = bytearray()
    for char in text:
        code = preferred.get(char)
        if code is None:
            raise BuildError(f"no V320 code for {char!r}")
        output.extend(code)
    if not output or len(output) >= SLOT_SIZE:
        raise BuildError(f"invalid E2 payload length for {text!r}: {len(output)}")
    return bytes(output)


def read_slot(data: bytes | bytearray, slot: int) -> bytes:
    start = SLOT_BASE + slot * SLOT_SIZE
    end = bytes(data).index(0, start, start + SLOT_SIZE)
    return bytes(data[start:end])


def write_slot(data: bytearray, slot: int, payload: bytes) -> None:
    if b"\0" in payload or len(payload) >= SLOT_SIZE:
        raise BuildError(f"invalid slot {slot} payload")
    start = SLOT_BASE + slot * SLOT_SIZE
    data[start : start + SLOT_SIZE] = payload + bytes(SLOT_SIZE - len(payload))


def count_external_code(members: dict[str, bytes], code: int) -> list[tuple[str, int, int]]:
    hits: list[tuple[str, int, int]] = []
    for name, data in members.items():
        if len(data) < 0x47800:
            continue
        for slot in range((0x47800 - SLOT_BASE) // SLOT_SIZE):
            start = SLOT_BASE + slot * SLOT_SIZE
            try:
                end = data.index(0, start, start + SLOT_SIZE)
            except ValueError:
                continue
            offset = start
            while offset < end:
                width = 2 if is_control(data, offset) else token_width(data[offset])
                if width == 1 and data[offset] == code:
                    hits.append((name, slot, offset))
                offset += width
    return hits


def count_region_code(members: dict[str, bytes], code: int) -> list[tuple[str, int]]:
    hits: list[tuple[str, int]] = []
    for name, start, end in text_regions(members):
        data = members[name]
        offset = start
        while offset < end:
            width = 2 if is_control(data, offset) else token_width(data[offset])
            if width == 1 and data[offset] == code:
                hits.append((name, offset))
            offset += width
    return hits


def safe_geometry(index: int) -> bool:
    audit: dict[tuple[int, int], int] = {}
    with CELL_AUDIT.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            audit[(int(row["row"]), int(row["col"]))] = int(row["nontext_reads"])
    cell = index // font.PLANES
    x0 = (cell % font.COLS) * font.CELL
    y0 = (cell // font.COLS) * font.CELL
    if x0 + font.CELL > 252 or y0 + font.CELL > 256:
        return False
    overlaps = {
        (y // 12, x // 12)
        for y in range(y0, y0 + font.CELL)
        for x in range(x0, x0 + font.CELL)
    }
    return all(audit.get(key, -1) == 0 for key in overlaps)


def main() -> None:
    fixed = (
        (BASE, BASE_SHA256, "V320C base"),
        (PIECES, PIECES_SHA256, "Hanme pieces"),
        (ASSIGNMENTS, ASSIGNMENTS_SHA256, "V320 assignments"),
        (ATLAS_MAPPING, ATLAS_MAPPING_SHA256, "atlas mapping"),
        (CELL_AUDIT, CELL_AUDIT_SHA256, "cell audit"),
        (VOTED_MAP, VOTED_MAP_SHA256, "V238 voted character map"),
    )
    for path, expected, label in fixed:
        if not path.is_file() or sha256_file(path) != expected:
            raise BuildError(f"{label} hash mismatch: {path}")

    infos, before = read_archive(BASE)
    for name, expected in BASE_MEMBER_SHA256.items():
        if sha256_bytes(before[name]) != expected:
            raise BuildError(f"base member hash drift: {name}")

    expected_dead_hit = [("21/S2021.DAT", 11, 0x4558E)]
    if count_external_code(before, NEW_GWAL_CODE[0]) != expected_dead_hit:
        raise BuildError("0xAB external-slot ownership drift")
    legacy_mon_hits = count_region_code(before, NEW_GWAL_CODE[0])
    if len(legacy_mon_hits) != 57 or {name for name, _offset in legacy_mon_hits} != {PSX}:
        raise BuildError("0xAB legacy PSX-text ownership drift")
    with VOTED_MAP.open("rb") as handle:
        voted_map = pickle.load(handle)
    if voted_map.get(b"\xAB") != "몬":
        raise BuildError("historical 0xAB semantic is no longer 몬")
    if bytes.fromhex("E2 8C") in before["21/S2021.DAT"][0x47800:]:
        raise BuildError("the 21/S2021 dead slot gained an inline caller")

    preferred, code_char = load_codes()
    pieces = font.load_pieces(PIECES.read_bytes())
    comm = bytearray(before[COMM])
    if any(font.read_plane(comm, NEW_GWAL_INDEX)) or not safe_geometry(NEW_GWAL_INDEX):
        raise BuildError("new 괄 plane is not blank and nontext-safe")
    gwal_rows = font.compose(pieces, "괄", True)
    comm_offsets = font.put_plane(comm, NEW_GWAL_INDEX, gwal_rows)
    if font.read_plane(comm, NEW_GWAL_INDEX) != gwal_rows:
        raise BuildError("괄 plane readback failed")
    if font.read_plane(comm, PUM_INDEX) != font.compose(pieces, "품", True):
        raise BuildError("existing 품 plane is not the official Hanme bitmap")
    for index in range(font.MAX_PHYSICAL_INDEX):
        if index != NEW_GWAL_INDEX and font.read_plane(comm, index) != font.read_plane(before[COMM], index):
            raise BuildError(f"neighbor COMM plane changed: {index}")

    members = {name: bytearray(data) for name, data in before.items()}
    allowed: dict[str, set[int]] = defaultdict(set)

    # V320B's pointer-pool restore exposed 57 V238 strings that V320 had not
    # re-encoded.  Their pinned historical 0xAB meaning is 몬; move all of them
    # to the current one-byte 몬 code (0x64) before giving plane 170 to 괄.
    if preferred.get("몬") != b"\x64":
        raise BuildError("current one-byte 몬 assignment drift")
    for name, offset in legacy_mon_hits:
        if members[name][offset] != 0xAB:
            raise BuildError(f"legacy 몬 byte drift: {name}:0x{offset:X}")
        members[name][offset] = 0x64
        allowed[name].add(offset)

    # 1: canonical 말괄량이.  0xAB is now an explicit one-byte 괄 code.
    s1072 = members["1/S1072.DAT"]
    if s1072[0x4793B] != 0xD1:
        raise BuildError("S1072 말괄량이 source byte drift")
    s1072[0x4793B] = NEW_GWAL_CODE[0]
    allowed["1/S1072.DAT"].add(0x4793B)

    # 2: canonical 유품인.  Physical index 347 already contains 품.
    s1021 = members["1/S1021.DAT"]
    if bytes(s1021[0x46D06:0x46D08]) != bytes.fromhex("E9 CD"):
        raise BuildError("S1021 유정인 source bytes drift")
    s1021[0x46D06:0x46D08] = PUM_CODE
    allowed["1/S1021.DAT"].update(range(0x46D06, 0x46D08))

    # 3-5: rewrite the runtime-proven external slots using current V320 codes.
    for (name, slot), text in REPAIRS.items():
        payload = encode_text(text, preferred)
        write_slot(members[name], slot, payload)
        start = SLOT_BASE + slot * SLOT_SIZE
        allowed[name].update(range(start, start + SLOT_SIZE))
        if read_slot(members[name], slot) != payload:
            raise BuildError(f"slot readback failed: {name} slot {slot}")

    # Remove the only latent 0xAB alias before assigning that code to 괄.
    s2021 = members["21/S2021.DAT"]
    if s2021[0x4558E] != 0xAB:
        raise BuildError("dead-slot 몬 collision guard failed")
    s2021[0x4558E] = 0x64
    allowed["21/S2021.DAT"].add(0x4558E)

    members[COMM] = comm
    allowed[COMM].update(comm_offsets)
    final_members = {name: bytes(data) for name, data in members.items()}

    if count_external_code(final_members, NEW_GWAL_CODE[0]):
        raise BuildError("0xAB remains in an external E2 slot")
    if count_region_code(final_members, NEW_GWAL_CODE[0]) != [("1/S1072.DAT", 0x4793B)]:
        raise BuildError("final 괄 code ownership is not unique")

    caller_guards = {
        ("1/S1031.DAT", bytes.fromhex("E2 81")): [0x4787A],
        ("D/SD011.DAT", bytes.fromhex("E2 8B")): [0x47B60],
        ("D/SD011.DAT", bytes.fromhex("E2 8C")): [0x47B70],
        ("D/SD011.DAT", bytes.fromhex("E2 8D")): [0x47D58],
        ("D/SD011.DAT", bytes.fromhex("E2 81")): [0x47D62],
    }
    for (name, command), expected_hits in caller_guards.items():
        data = final_members[name]
        hits = [
            offset
            for offset in range(0x47800, len(data) - 1)
            if data[offset : offset + 2] == command
        ]
        if hits != expected_hits:
            raise BuildError(f"E2 caller drift for {name} {command.hex()}: {hits}")

    # Every edit is size-preserving and confined to its declared ownership.
    if any(len(final_members[name]) != len(before[name]) for name in before):
        raise BuildError("member size changed")
    changed_members = [name for name in before if final_members[name] != before[name]]
    expected_changed = {
        COMM, PSX, "1/S1072.DAT", "1/S1021.DAT", "1/S1031.DAT",
        "D/SD011.DAT", "21/S2021.DAT",
    }
    if set(changed_members) != expected_changed:
        raise BuildError(f"changed member set drift: {changed_members}")
    for name in changed_members:
        actual = {
            offset
            for offset, (left, right) in enumerate(zip(before[name], final_members[name]))
            if left != right
        }
        if not actual or not actual <= allowed[name]:
            raise BuildError(f"Expected-Write failure in {name}")
    psx_actual = {
        offset
        for offset, (left, right) in enumerate(zip(before[PSX], final_members[PSX]))
        if left != right
    }
    if psx_actual != {offset for _name, offset in legacy_mon_hits}:
        raise BuildError("PSX change escaped the 57 catalogued legacy 몬 bytes")

    # Preserve the inline E4/E6 timing/control wrappers byte-for-byte.
    for name, start, end in (
        ("1/S1031.DAT", 0x4787A, 0x47883),
        ("D/SD011.DAT", 0x47B60, 0x47B7D),
        ("D/SD011.DAT", 0x47D58, 0x47D71),
    ):
        if final_members[name][start:end] != before[name][start:end]:
            raise BuildError(f"inline control wrapper changed: {name}:0x{start:X}")

    output_path, output_hash = write_archive(OUTPUT_STEM, infos, final_members, None)
    delta_path, delta_hash = write_archive(
        DELTA_STEM, infos, final_members, expected_changed
    )
    with ZipFile(output_path) as archive:
        if [info.filename for info in archive.infolist() if not info.is_dir()] != [
            info.filename for info in infos if not info.is_dir()
        ]:
            raise BuildError("output topology drift")
        for name in final_members:
            if archive.read(name) != final_members[name]:
                raise BuildError(f"output round-trip failed: {name}")
    with ZipFile(delta_path) as archive:
        if set(archive.namelist()) != expected_changed:
            raise BuildError("delta topology drift")

    ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
    repair_rows = [
        {"scene": 1, "member": "1/S1072.DAT", "location": "0x4793B", "before": "?", "after": "괄", "expected": "촌장: 이 말괄량이 덕분에 마침내 꺼지는구나."},
        {"scene": 2, "member": "1/S1021.DAT", "location": "slot58+0x06", "before": "정", "after": "품", "expected": "아버지의 유품인 갑옷과 검을 찾았다."},
        {"scene": 3, "member": "1/S1031.DAT", "location": "slot0", "before": "legacy", "after": "current", "expected": "엄마..."},
        {"scene": 4, "member": "D/SD011.DAT", "location": "slot10+slot11", "before": "legacy", "after": "current", "expected": "그 불을 줘. 내가 다시 붙이고 올게."},
        {"scene": 5, "member": "D/SD011.DAT", "location": "slot12+slot0", "before": "legacy", "after": "current", "expected": "걱정 마. 불은 내가 다시 붙이고 올게."},
    ]
    with (ANALYSIS_DIR / "repairs.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=repair_rows[0].keys())
        writer.writeheader()
        writer.writerows(repair_rows)

    manifest = {
        "build": "V321 TEST_ONLY 16px text identity repair",
        "base": {"path": str(BASE), "sha256": BASE_SHA256},
        "output": {"path": str(output_path), "sha256": output_hash},
        "delta": {"path": str(delta_path), "sha256": delta_hash},
        "changed_members": changed_members,
        "font": {
            "cell": 16,
            "new_char": "괄",
            "code_hex": NEW_GWAL_CODE.hex(" ").upper(),
            "physical_index": NEW_GWAL_INDEX,
            "official_beol": True,
            "pieces_sha256": PIECES_SHA256,
            "changed_COMM_bytes": len(comm_offsets),
        },
        "geometry": "V320C code words unchanged: packet16/advance14/line16/space6",
        "runtime": "PENDING user cold boot",
        "release_status": "DIAGNOSTIC; DO NOT DISTRIBUTE",
    }
    (ANALYSIS_DIR / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V321 TEST ONLY - 16px text identity repair",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output_path.name}",
        f"sha256={output_hash}",
        f"delta={delta_path.name}",
        f"delta_sha256={delta_hash}",
        f"changed_members={','.join(changed_members)}",
        "repairs=말괄량이; 유품인; 엄마...; two D/SD011 composite E2 return lines",
        "new_glyph=괄 code AB physical170 official Hanme beol; prior AB dead-slot token reencoded as 몬(64)",
        "PSX=57 catalogued legacy 몬 text bytes AB->64 only; executable code/geometry unchanged",
        "runtime=PENDING user cold boot; TEST_ONLY",
    ]
    (ANALYSIS_DIR / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
