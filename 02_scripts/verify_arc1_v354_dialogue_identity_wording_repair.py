#!/usr/bin/env python3
"""Independent static verifier for V354 dialogue/identity repairs."""

from __future__ import annotations

import csv
import hashlib
import json
import struct
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/arc1_v353_summon_skill_action_record_repair_TEST_ONLY_83AB9F25.zip"
BASE_SHA256 = "83AB9F2580478826D4B37F9B8147A6594646E3995C9B8211645C59AC7458AE91"
ANALYSIS = ROOT / "01_work/analysis/arc1_v354_dialogue_identity_wording_repair"
ASSIGNMENTS = ROOT / "01_work/analysis/arc1_v320_hanme_static_recovery/character_assignments.csv"
ASSIGNMENTS_SHA256 = "933BDAC4BC4C39D33DB134D2FF836902B5053B93725C96E19DED714CB7DE98A4"
ATLAS = ROOT / "01_work/analysis/arc1_v319_pilgi16_integration/atlas_mapping.csv"
ATLAS_SHA256 = "9553E7643621CC80C23355067611EAE7650FEF7CB547DC9115B62157DB0C3122"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
S4031 = "4/S4031.DAT"
S5041 = "5/S5041.DAT"
S8051 = "8/S8051.DAT"
SE05A = "E5/SE05A.DAT"
EXPECTED_MEMBERS = [S4031, S5041, S8051, SE05A]
SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT_META = 0x7F

BAD = bytes.fromhex("DD B4")
GOOD = bytes.fromhex("DE 52")
IDENTITY = (
    (S4031, 0x45916),
    (S5041, 0x45214),
    (S8051, 0x4548C),
    (SE05A, 0x48BFA),
    (SE05A, 0x4903A),
)

# member, E2 body, slot, metadata, exact old payload, exact final payload,
# exact approved final Korean
DIALOGUE = (
    (
        S5041, 0x47BEA, 8, 22,
        bytes.fromhex(
            "DD C4 0F A1 31 51 DD 02 A1 35 DD 1B 0A DD 01 A1 5F DD A8 "
            "0D A1 2B A1 DD 88 06 04 0E 21"
        ),
        bytes.fromhex(
            "DD C4 0F A1 31 51 DD 02 A1 35 DD 1B 0A 03 A1 5F DD A0 A1 "
            "DE 1C 0D A1 2B A1 DD 88 06 04 A1 1B 03 49 21"
        ),
        "빛의 정령: 인간들이 무슨 짓을 해 왔는지 말이야.",
    ),
    (
        S5041, 0x47E0C, 3, 35,
        bytes.fromhex(
            "15 DD 16 A1 6C 19 0F A1 DD 10 0D A1 28 24 A1 18 4E DD 04 "
            "A1 38 0A A1 50 A1 1F 01 06 A1 6A 0F A1 8B A1 09 DD DF 0C 21"
        ),
        bytes.fromhex(
            "15 DD 16 A1 3E 19 0F A1 DD 10 DD 09 0D A1 DE 13 DD A4 0D "
            "A1 50 A1 1F 06 A1 6A 0F A1 8B A1 09 DD DF 0C A9"
        ),
        "그건 신하의 공적을 빼앗을 수 있는 왕의 상 아닌가!",
    ),
)

V353_ACTION_RECORD = bytes.fromhex("58 38 12 80 6C 3B 12 80 26 00 00 00")
ACTION_RECORD_FILE = 0x78ADC


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as z:
        names = [item.filename for item in z.infolist() if not item.is_dir()]
        return names, {name: z.read(name) for name in names}


def slot_start(slot: int) -> int:
    return SLOT_BASE + slot * SLOT_SIZE


def disk_id(slot: int) -> int:
    return slot + (0x81 if slot < 40 else 0x82)


def slot_payload(data: bytes, slot: int) -> bytes:
    raw = data[slot_start(slot):slot_start(slot) + SLOT_META]
    end = raw.find(b"\0")
    if end < 0:
        raise AssertionError(f"unterminated slot {slot}")
    return raw[:end]


def all_hits(members: dict[str, bytes], needle: bytes) -> list[tuple[str, int]]:
    hits: list[tuple[str, int]] = []
    for name, data in members.items():
        offset = 0
        while True:
            offset = data.find(needle, offset)
            if offset < 0:
                break
            hits.append((name, offset))
            offset += 1
    return hits


def direct_index(token: bytes) -> int | None:
    if len(token) == 1:
        return token[0] - 1 if 1 <= token[0] <= 0xDC else None
    if len(token) != 2:
        return None
    lead, trail = token
    if lead in (0xE9, 0xEA) or not (0xDD <= lead <= 0xE0 and 1 <= trail <= 0xFE):
        return None
    return (lead - 0xDD) * 255 + trail + 0xDB


def encode_index(index: int) -> bytes | None:
    if 0 <= index < 0xDC:
        return bytes((index + 1,))
    lead_delta, trail = divmod(index - 0xDB, 255)
    if 0 <= lead_delta <= 3 and 1 <= trail <= 0xFE:
        return bytes((0xDD + lead_delta, trail))
    return None


def load_code_map() -> dict[bytes, str]:
    # Reconstruct all directly addressable codes from the physical atlas first.
    # The assignment table then overrides special encodings such as punctuation
    # and the half-width space.
    result: dict[bytes, str] = {}
    for index, row in atlas_rows().items():
        token = encode_index(index)
        char = row.get("char", "")
        if token is not None and char:
            result[token] = char
    with ASSIGNMENTS.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        code_hex = row.get("code_hex", "").strip()
        char = row.get("char", "")
        if code_hex and char:
            result[bytes.fromhex(code_hex)] = char
    result[GOOD] = "재"
    return result


def decode(payload: bytes, mapping: dict[bytes, str]) -> str:
    result: list[str] = []
    offset = 0
    while offset < len(payload):
        width = 2 if payload[offset] >= 0xDD else 1
        token = payload[offset:offset + width]
        if len(token) != width or token not in mapping:
            raise AssertionError(f"unmapped token at {offset}: {token.hex(' ').upper()}")
        result.append(mapping[token])
        offset += width
    return "".join(result)


def atlas_rows() -> dict[int, dict[str, str]]:
    with ATLAS.open(encoding="utf-8-sig", newline="") as handle:
        return {int(row["index"]): row for row in csv.DictReader(handle)}


def plane_rows(comm: bytes, index: int) -> tuple[int, ...]:
    cell, plane = divmod(index, 4)
    col, row = cell % 15, cell // 15
    bit = 1 << plane
    result: list[int] = []
    for y in range(16):
        value = 0
        base = (row * 16 + y) * 896 + col * 8
        for x in range(16):
            byte = comm[base + x // 2]
            nibble = (byte >> (0 if x % 2 == 0 else 4)) & 0x0F
            if nibble & bit:
                value |= 1 << (15 - x)
        result.append(value)
    return tuple(result)


def expected_diff(old: dict[str, bytes]) -> dict[str, set[int]]:
    expected = {name: set() for name in EXPECTED_MEMBERS}
    for member, offset in IDENTITY:
        expected[member].update((offset, offset + 1))
    for member, _body, slot, _metadata, old_payload, new_payload, _text in DIALOGUE:
        start = slot_start(slot)
        old_block = old_payload + bytes(SLOT_META - len(old_payload))
        new_block = new_payload + bytes(SLOT_META - len(new_payload))
        expected[member].update(
            start + index
            for index, (before, after) in enumerate(zip(old_block, new_block, strict=True))
            if before != after
        )
    return expected


def main() -> None:
    if sha(BASE.read_bytes()) != BASE_SHA256:
        raise AssertionError("V353 base hash drift")
    if sha(ASSIGNMENTS.read_bytes()) != ASSIGNMENTS_SHA256:
        raise AssertionError("character assignment hash drift")
    if sha(ATLAS.read_bytes()) != ATLAS_SHA256:
        raise AssertionError("atlas map hash drift")

    fulls = [
        path for path in (ROOT / "03_output").glob(
            "arc1_v354_dialogue_identity_wording_repair_TEST_ONLY_*.zip"
        ) if "delta_from" not in path.name
    ]
    deltas = list((ROOT / "03_output").glob(
        "arc1_v354_dialogue_identity_wording_repair_TEST_ONLY_delta_from_v353_*.zip"
    ))
    if len(fulls) != 1 or len(deltas) != 1:
        raise AssertionError(f"expected one V354 full/delta: {fulls} / {deltas}")
    output, delta = fulls[0], deltas[0]
    output_sha, delta_sha = sha(output.read_bytes()), sha(delta.read_bytes())
    if not output.stem.endswith(output_sha[:8]) or not delta.stem.endswith(delta_sha[:8]):
        raise AssertionError("archive digest suffix mismatch")

    old_names, old = archive(BASE)
    new_names, new = archive(output)
    if old_names != new_names or len(new_names) != 164:
        raise AssertionError("archive topology/order changed")
    changed = [name for name in old_names if old[name] != new[name]]
    if changed != EXPECTED_MEMBERS:
        raise AssertionError(f"changed-member drift: {changed}")
    if any(len(old[name]) != len(new[name]) for name in old_names):
        raise AssertionError("member size changed")

    expected = expected_diff(old)
    for member in EXPECTED_MEMBERS:
        actual = {
            index for index, (before, after) in enumerate(zip(old[member], new[member], strict=True))
            if before != after
        }
        if actual != expected[member]:
            raise AssertionError(f"Expected-Write mismatch {member}: {sorted(actual ^ expected[member])[:20]}")
    for member, offset in IDENTITY:
        if old[member][offset:offset + 2] != BAD or new[member][offset:offset + 2] != GOOD:
            raise AssertionError(f"identity repair mismatch: {member}:0x{offset:X}")

    rows = atlas_rows()
    if direct_index(BAD) != 399 or rows[399]["char"] != "개":
        raise AssertionError("DD B4/physical399 identity drift")
    if direct_index(GOOD) != 556 or rows[556]["char"] != "재":
        raise AssertionError("DE 52/physical556 identity drift")
    if not any(plane_rows(new[COMM], 556)):
        raise AssertionError("COMM.IMG physical556 is blank")

    mapping = load_code_map()
    for member, body, slot, metadata, old_payload, new_payload, text in DIALOGUE:
        if slot_payload(old[member], slot) != old_payload:
            raise AssertionError(f"old payload drift: {member} slot {slot}")
        if slot_payload(new[member], slot) != new_payload:
            raise AssertionError(f"new payload mismatch: {member} slot {slot}")
        if decode(new_payload, mapping) != text:
            raise AssertionError(f"decoded dialogue mismatch: {member} slot {slot}")
        token = bytes((0xE2, disk_id(slot)))
        if old[member][body:body + 2] != token or new[member][body:body + 2] != token:
            raise AssertionError(f"E2 caller changed: {member}:0x{body:X}")
        meta_offset = slot_start(slot) + SLOT_META
        if old[member][meta_offset] != metadata or new[member][meta_offset] != metadata:
            raise AssertionError(f"slot metadata changed: {member} slot {slot}")
        search_start = SLOT_BASE + 64 * SLOT_SIZE
        if new[member].find(token, search_start) != body or new[member].find(token, body + 1) >= 0:
            raise AssertionError(f"slot ownership changed: {member} slot {slot}")

    census = {
        "bad_exists": len(all_hits(new, bytes.fromhex("DE EB DD B4"))),
        "good_exists": len(all_hits(new, bytes.fromhex("DE EB DE 52"))),
        "bad_fun": len(all_hits(new, bytes.fromhex("DD B4 DD 2F"))),
        "good_fun": len(all_hits(new, bytes.fromhex("DE 52 DD 2F"))),
        "good_reorganize": len(all_hits(new, bytes.fromhex("DE 52 31 DD 06"))),
        "bad_reorganize": len(all_hits(new, bytes.fromhex("DD B4 31 DD 06"))),
    }
    if census != {
        "bad_exists": 0, "good_exists": 2, "bad_fun": 0,
        "good_fun": 3, "good_reorganize": 5, "bad_reorganize": 0,
    }:
        raise AssertionError(f"identity census mismatch: {census}")

    if new[PSX] != old[PSX] or new[COMM] != old[COMM]:
        raise AssertionError("PSX.EXE/COMM.IMG changed")
    if new[PSX][ACTION_RECORD_FILE:ACTION_RECORD_FILE + 12] != V353_ACTION_RECORD:
        raise AssertionError("V353 summon action record regressed")
    if new[PSX][:8] != b"PS-X EXE":
        raise AssertionError("PS-X EXE magic drift")
    if struct.unpack_from("<I", new[PSX], 0x18)[0] != 0x8011B000:
        raise AssertionError("PS-X EXE load address drift")

    delta_names, delta_members = archive(delta)
    if delta_names != EXPECTED_MEMBERS:
        raise AssertionError(f"delta topology drift: {delta_names}")
    if any(delta_members[name] != new[name] for name in EXPECTED_MEMBERS):
        raise AssertionError("delta member readback mismatch")

    with (ANALYSIS / "expected_writes.csv").open(encoding="utf-8-sig", newline="") as handle:
        csv_rows = list(csv.DictReader(handle))
    csv_triples = {
        (row["member"], int(row["offset"], 16), int(row["before"], 16), int(row["after"], 16))
        for row in csv_rows
    }
    actual_triples = {
        (member, offset, old[member][offset], new[member][offset])
        for member in EXPECTED_MEMBERS for offset in expected[member]
    }
    if csv_triples != actual_triples:
        raise AssertionError("expected_writes.csv mismatch")

    manifest = json.loads((ANALYSIS / "build_manifest.json").read_text(encoding="utf-8"))
    if manifest["output"]["sha256"] != output_sha or manifest["delta"]["sha256"] != delta_sha:
        raise AssertionError("manifest archive hash mismatch")
    verification = {
        "version": "V354",
        "result": "PASS_STATIC_RUNTIME_PENDING",
        "output": {"file": output.name, "sha256": output_sha},
        "delta": {"file": delta.name, "sha256": delta_sha},
        "checks": {
            "archive_topology_order": "PASS 164/164",
            "changed_members": changed,
            "expected_write": {member: len(expected[member]) for member in EXPECTED_MEMBERS},
            "glyph_identity": "DD B4=399=개; DE 52=556=재; COMM plane556 nonblank",
            "dialogue_decode": [item[-1] for item in DIALOGUE],
            "identity_census": census,
            "e2_callers_metadata": "PASS",
            "psx_comm_v353_action_record": "PASS byte exact",
            "delta_readback": "PASS",
        },
        "runtime": "PENDING user cold boot and scene review",
    }
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(verification, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"V354={output.name} sha256={output_sha}")
    print(f"delta={delta.name} sha256={delta_sha}")
    print(f"changed members/Expected-Write PASS: {verification['checks']['expected_write']}")
    print("glyph identity PASS: DD B4=개/399, DE 52=재/556, plane556 nonblank")
    print("2/2 approved dialogue payloads decode exactly; E2 callers/metadata preserved")
    print(f"identity census PASS: {census}")
    print("PSX.EXE/COMM.IMG/V353 summon action record/delta/topology/sizes PASS")
    print("RESULT: PASS (static only; V354 runtime pending)")


if __name__ == "__main__":
    main()
