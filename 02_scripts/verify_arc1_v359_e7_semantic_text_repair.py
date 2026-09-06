#!/usr/bin/env python3
"""Independent static verifier for V359.

This verifier deliberately does not import the V359 builder.  It re-declares
the eight sites, decodes every old/new slot, checks the newly allocated slot's
zero premise and caller ownership, compares the complete archive/delta diff,
and validates the Expected-Write ledger.
"""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from v354_dialogue_codec import SPACE_CODE, encode, load_v354, tokens  # noqa: E402


BASE = ROOT / "03_output/arc1_v358_dialogue_target_panel_fix_TEST_ONLY_D499D9D4.zip"
BASE_SHA256 = "D499D9D463A66B343A9D794A49753454788B3F18C6DC38B7CDE7A77304838061"
FULL = ROOT / "03_output/arc1_v359_e7_semantic_text_repair_TEST_ONLY_7D6B0F1B.zip"
FULL_SHA256 = "7D6B0F1B6A3C5A35B0EF61DF358278E46B261A496C57F1027D03D836AA9D6EC0"
DELTA = ROOT / "03_output/arc1_v359_e7_semantic_text_repair_TEST_ONLY_delta_from_v358_46F9CDB1.zip"
DELTA_SHA256 = "46F9CDB15F8C57C6F394F14BD67B41089C64156A7DFF72DD859F4C5C92DDFCD0"
ANALYSIS = ROOT / "01_work/analysis/arc1_v359_e7_semantic_text_repair"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
SLOT_SIZE = 0x80
SLOT_META = 0x7F
ROW_PIXELS = 228


@dataclass(frozen=True)
class Site:
    member: str
    source: int
    disk_id: int
    slot: int
    metadata: int
    old_text: str
    new_text: str


OLD_CHOPPIN = "초핀: 그때 커서와  로 링 안의 기술을 고르고 아이콘의 위치를 바꾸어 놓을 수 있습니다."
NEW_CHOPPIN = "초핀: 그때 커서와 결정 버튼으로 링 안의 기술을 골라 아이콘 위치를 변경할 수 있습니다."
SITES = (
    Site("21/S2045.DAT", 0x49292, 0x9D, 0x45E00, 53, OLD_CHOPPIN, NEW_CHOPPIN),
    Site("31/S3013.DAT", 0x4855E, 0x84, 0x45180, 40,
         "승무원: 또 자유롭게 돌아다닐 수 있는 곳에서는  를 여러 곳에서 눌러 보십시오.",
         "승무원: 또 자유롭게 돌아다닐 수 있는 곳에서는 여기저기서 결정 버튼을 눌러 보십시오."),
    Site("4/S4033.DAT", 0x48156, 0x8F, 0x45700, 24,
         "프리 커서일 때는  를 누르면 원래대로 돌아와.",
         "프리 커서일 때는 취소 버튼을 누르면 원래대로 돌아와."),
    Site("5/S5013.DAT", 0x4927E, 0x9E, 0x45E80, 53, OLD_CHOPPIN, NEW_CHOPPIN),
    Site("6/S6014.DAT", 0x4922A, 0x9C, 0x45D80, 53, OLD_CHOPPIN, NEW_CHOPPIN),
    Site("7/S7012.DAT", 0x48D22, 0x9C, 0x45D80, 53, OLD_CHOPPIN, NEW_CHOPPIN),
    Site("8/S8013.DAT", 0x47D10, 0x91, 0x45800, 53, OLD_CHOPPIN, NEW_CHOPPIN),
)

LR_MEMBER = "4/S4033.DAT"
LR_SOURCE = 0x48102
LR_BODY_LENGTH = 32
LR_DISK_ID = 0xA2
LR_SLOT = 0x46080
LR_METADATA = 30
LR_OLD = "전투 때는  를 함께 누르면 프리 커서가 돼."
LR_NEW = "전투 때는 L과 R을 함께 누르면 프리 커서가 돼."

EXPECTED_CHANGED = {
    "21/S2045.DAT": 44,
    "31/S3013.DAT": 24,
    "4/S4033.DAT": 87,
    "5/S5013.DAT": 44,
    "6/S6014.DAT": 44,
    "7/S7012.DAT": 44,
    "8/S8013.DAT": 44,
}


def sha(value: bytes | Path) -> str:
    raw = value.read_bytes() if isinstance(value, Path) else value
    return hashlib.sha256(raw).hexdigest().upper()


def archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as zf:
        names = [item.filename for item in zf.infolist() if not item.is_dir()]
        return names, {name: zf.read(name) for name in names}


def find_all(data: bytes, needle: bytes) -> list[int]:
    found: list[int] = []
    start = 0
    while True:
        at = data.find(needle, start)
        if at < 0:
            return found
        found.append(at)
        start = at + 1


def script_hits(data: bytes, needle: bytes) -> list[int]:
    return [offset for offset in find_all(data, needle) if offset >= 0x47000]


def payload(block: bytes) -> bytes:
    end = block[:SLOT_META].find(b"\0")
    if end < 0:
        raise AssertionError("slot has no terminator")
    if any(block[end + 1:SLOT_META]):
        raise AssertionError("slot padding is not zero")
    return block[:end]


def decode(raw: bytes, decoder: dict[bytes, str]) -> str:
    return "".join(decoder.get(token, f"<{token.hex().upper()}>") for token in tokens(raw))


def encode_checked(text: str, table: dict[str, bytes]) -> bytes:
    raw, missing = encode(text, table, keep_breaks=False)
    if missing or not raw or 0 in raw or len(raw) > 126:
        raise AssertionError(f"encoding failure: {text!r}; missing={missing}; len={len(raw)}")
    structural = [token for token in tokens(raw) if len(token) == 2 and 0xE2 <= token[0] <= 0xE8]
    if structural:
        raise AssertionError(f"control token leaked into prose: {structural}")
    return raw


def row_count(raw: bytes) -> int:
    rows, x = 1, 0
    for token in tokens(raw):
        advance = 6 if token == SPACE_CODE else 14
        if x + advance >= ROW_PIXELS:
            rows, x = rows + 1, 0
        x += advance
    return rows


def exact_block(raw: bytes, metadata: int) -> bytes:
    return raw + b"\0" + bytes(SLOT_META - len(raw) - 1) + bytes((metadata,))


def main() -> None:
    for path, expected, label in (
        (BASE, BASE_SHA256, "V358 base"),
        (FULL, FULL_SHA256, "V359 full"),
        (DELTA, DELTA_SHA256, "V359 delta"),
    ):
        if not path.is_file() or sha(path) != expected:
            raise AssertionError(f"{label} hash drift")

    old_names, old = archive(BASE)
    new_names, new = archive(FULL)
    if old_names != new_names or len(new_names) != 164 or len(set(new_names)) != 164:
        raise AssertionError("archive topology/order drift")
    changed = [name for name in old_names if old[name] != new[name]]
    if set(changed) != set(EXPECTED_CHANGED):
        raise AssertionError(f"changed-member drift: {changed}")
    if any(len(old[name]) != len(new[name]) for name in old_names):
        raise AssertionError("member size changed")
    if new[PSX] != old[PSX] or new[COMM] != old[COMM]:
        raise AssertionError("PSX.EXE/COMM.IMG changed")
    for name in old_names:
        if name not in EXPECTED_CHANGED and new[name] != old[name]:
            raise AssertionError(f"non-target member changed: {name}")

    _exe, _comm, table, decoder = load_v354()
    decoded_rows: list[dict[str, object]] = []
    allowed: dict[str, set[int]] = {name: set() for name in EXPECTED_CHANGED}
    for site in SITES:
        before = old[site.member]
        after = new[site.member]
        pair = bytes((0xE2, site.disk_id))
        if before[site.source:site.source + site.metadata + 2] != after[site.source:site.source + site.metadata + 2]:
            raise AssertionError(f"live body/control bytes changed: {site.member}:0x{site.source:X}")
        if script_hits(before, pair) != [site.source] or script_hits(after, pair) != [site.source]:
            raise AssertionError(f"E2 caller ownership drift: {site.member}:0x{site.source:X}")
        old_block = before[site.slot:site.slot + SLOT_SIZE]
        new_block = after[site.slot:site.slot + SLOT_SIZE]
        old_payload = payload(old_block)
        new_payload = payload(new_block)
        expected_new = encode_checked(site.new_text, table)
        if decode(old_payload, decoder) != site.old_text:
            raise AssertionError(f"old semantic decode drift: {site.member}")
        if new_block != exact_block(expected_new, site.metadata):
            raise AssertionError(f"new slot byte/readback drift: {site.member}")
        if decode(new_payload, decoder) != site.new_text or row_count(new_payload) > 4:
            raise AssertionError(f"new semantic/row decode drift: {site.member}")
        if old_block[SLOT_META] != site.metadata or new_block[SLOT_META] != site.metadata:
            raise AssertionError(f"slot metadata changed: {site.member}")
        allowed[site.member].update(range(site.slot, site.slot + SLOT_SIZE))
        decoded_rows.append({
            "member": site.member, "source": f"0x{site.source:X}",
            "disk_id": f"0x{site.disk_id:02X}", "slot": f"0x{site.slot:X}",
            "metadata": site.metadata, "text": site.new_text,
            "encoded_bytes": len(new_payload), "rows": row_count(new_payload),
        })

    old_lr = encode_checked(LR_OLD, table)
    new_lr = encode_checked(LR_NEW, table)
    if table.get("L") != bytes.fromhex("DD D8") or table.get("R") != bytes.fromhex("DE 88"):
        raise AssertionError("static L/R code mapping drift")
    if new_lr.count(bytes.fromhex("DD D8")) != 1 or new_lr.count(bytes.fromhex("DE 88")) != 1:
        raise AssertionError("LR payload does not contain exactly one L and R")
    if old[LR_MEMBER][LR_SOURCE:LR_SOURCE + LR_BODY_LENGTH] != old_lr:
        raise AssertionError("V358 inline LR bytes drift")
    if any(old[LR_MEMBER][LR_SLOT:LR_SLOT + SLOT_SIZE]):
        raise AssertionError("new-slot zero premise failed")
    expected_call = bytes((0xE2, LR_DISK_ID)) + bytes((SPACE_CODE[0],)) * LR_METADATA
    if new[LR_MEMBER][LR_SOURCE:LR_SOURCE + LR_BODY_LENGTH] != expected_call:
        raise AssertionError("new LR E2 caller/body readback failed")
    if script_hits(old[LR_MEMBER], bytes((0xE2, LR_DISK_ID))) or script_hits(
        new[LR_MEMBER], bytes((0xE2, LR_DISK_ID))
    ) != [LR_SOURCE]:
        raise AssertionError("new LR E2 ownership drift")
    lr_block = new[LR_MEMBER][LR_SLOT:LR_SLOT + SLOT_SIZE]
    if lr_block != exact_block(new_lr, LR_METADATA):
        raise AssertionError("new LR slot byte/readback drift")
    if decode(payload(lr_block), decoder) != LR_NEW or row_count(new_lr) > 4:
        raise AssertionError("new LR semantic/row decode drift")
    allowed[LR_MEMBER].update(range(LR_SOURCE, LR_SOURCE + LR_BODY_LENGTH))
    allowed[LR_MEMBER].update(range(LR_SLOT, LR_SLOT + SLOT_SIZE))
    decoded_rows.append({
        "member": LR_MEMBER, "source": f"0x{LR_SOURCE:X}",
        "disk_id": f"0x{LR_DISK_ID:02X}", "slot": f"0x{LR_SLOT:X}",
        "metadata": LR_METADATA, "text": LR_NEW,
        "encoded_bytes": len(new_lr), "rows": row_count(new_lr),
    })

    actual_diffs: dict[str, list[tuple[int, int, int]]] = {}
    for name in changed:
        diffs = [
            (offset, before, after)
            for offset, (before, after) in enumerate(zip(old[name], new[name], strict=True))
            if before != after
        ]
        actual_diffs[name] = diffs
        if len(diffs) != EXPECTED_CHANGED[name]:
            raise AssertionError(f"changed-byte count drift: {name} {len(diffs)}")
        outside = [offset for offset, _before, _after in diffs if offset not in allowed[name]]
        if outside:
            raise AssertionError(f"write outside approved ranges: {name}:{outside[:8]}")
    if sum(map(len, actual_diffs.values())) != 331:
        raise AssertionError("total Expected-Write count drift")

    delta_names, delta = archive(DELTA)
    if delta_names != changed or any(delta[name] != new[name] for name in changed):
        raise AssertionError("delta member order/readback drift")

    with (ANALYSIS / "expected_writes.csv").open(encoding="utf-8-sig", newline="") as handle:
        ledger = list(csv.DictReader(handle))
    ledger_set = {
        (row["member"], int(row["offset"], 16), int(row["before"], 16), int(row["after"], 16))
        for row in ledger
    }
    actual_set = {
        (name, offset, before, after)
        for name, diffs in actual_diffs.items()
        for offset, before, after in diffs
    }
    if ledger_set != actual_set or len(ledger) != 331:
        raise AssertionError("Expected-Write ledger differs from full archive diff")

    manifest = json.loads((ANALYSIS / "build_manifest.json").read_text(encoding="utf-8"))
    if manifest["output"]["sha256"] != FULL_SHA256 or manifest["delta"]["sha256"] != DELTA_SHA256:
        raise AssertionError("manifest artifact hashes disagree")

    result = {
        "version": "V359",
        "result": "PASS_STATIC_RUNTIME_PENDING",
        "full": {"file": FULL.name, "sha256": FULL_SHA256},
        "delta": {"file": DELTA.name, "sha256": DELTA_SHA256},
        "checks": {
            "archive_topology_order": "PASS 164/164",
            "changed_members": changed,
            "expected_writes": "PASS 331 bytes in seven DAT members",
            "semantic_decode": decoded_rows,
            "existing_slots": "PASS seven callers/bodies/metadata preserved",
            "new_slot": "PASS 4/S4033 Bank-A slot33 was zero/unreferenced; E2:A2 sole script caller",
            "lr_codes": "PASS L=DD D8 (physical 435), R=DE 88 (physical 610)",
            "psx_comm_non_targets": "PASS byte exact V358",
            "delta_readback": "PASS",
        },
        "runtime": "PENDING user cold boot and eight help-line review",
    }
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "Arc the Lad 1 V359 independent static verification",
        "STATIC PASS / RUNTIME PENDING / TEST_ONLY",
        "archive topology/order: PASS 164/164",
        f"changed members: {','.join(changed)}",
        "Expected-Write: PASS 331 bytes in seven DAT members",
        "semantic decode: PASS 8/8; glyph missing 0; every target <=3 rows",
        "existing slots: PASS 7/7 caller/body/metadata preserved",
        "new slot: PASS 4/S4033 Bank-A slot33 zero premise and sole E2:A2 script caller",
        "L/R map: PASS DD D8 / DE 88; no COMM.IMG allocation",
        "PSX.EXE/COMM.IMG/non-target members/delta: PASS",
        "runtime: PENDING user cold boot",
    ]
    (ANALYSIS / "independent_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
