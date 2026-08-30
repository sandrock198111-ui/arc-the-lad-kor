#!/usr/bin/env python3
"""Build V350: four runtime-reviewed Korean dialogue wording fixes.

The build is deliberately based on V349 and changes only four already-live E2
external-string slots in two DAT members.  PSX.EXE, COMM.IMG, the E2 callers,
slot metadata, member sizes, and every other archive member remain byte exact.
"""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import build_arc1_v345_story_timing_cursor_recovery as v345  # noqa: E402


BASE = ROOT / "03_output/arc1_v349_floor_resident_helper_reuse_TEST_ONLY_EC5724F9.zip"
BASE_SHA256 = "EC5724F91C6251C76D349AAB135BC411010CE7E4BBBDBCF0D4EFFEFE1488D481"
OUTPUT_STEM = "arc1_v350_dialogue_wording_fixes_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v349"
ANALYSIS = ROOT / "01_work/analysis/arc1_v350_dialogue_wording_fixes"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
S5024 = "5/S5024.DAT"
S5052 = "5/S5052.DAT"
SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT_META = 0x7F

BASE_MEMBER_SHA256 = {
    S5024: "C81501AC5CD8AF28FBC1CA24EDC04FD445DBAF4E61AC5EB8A6198EF570F5CE4D",
    S5052: "A3D96BE4B5E7CB73178096CBB9CC0CE58789473CD7291CD921C3E2304D622168",
    PSX: "0D540C1E71C4546708B7C6C1D7328D58E31137ED4453EBCEB5B7F645A4764E1F",
    COMM: "A6681F1355007725328372CC6143EF21EEE43A9FDE91FD3DC2EF3461C6805405",
}

# member, body offset, slot, expected +0x7F completion/skip metadata, final text
FIXES = (
    (S5024, 0x478E8, 0, 19, "뭔 소리야? 이래선 말이 안 되잖아."),
    (S5052, 0x47A90, 6, 19, "이야, 덕분에 살았군. 고맙다."),
    (S5052, 0x47ADA, 0, 25, "고맙다고는 해 주지. 하지만 보물은 나누지 않을 거야. 말이야 공짜니까."),
    (S5052, 0x47B28, 4, 27, "요슈아: 사람은 욕망만 따라 사는 게 아니다."),
)

EXPECTED_OLD_PAYLOAD = {
    (S5024, 0): bytes.fromhex(
        "5F DD A0 A1 1B 0D A1 19 06 A1 32 49 21 A1 DD 01 49 24 0C A1 "
        "DD 3F DD 31 73 04 A1 78 DD BC 09 21"
    ),
    (S5052, 0): bytes.fromhex(
        "1C DE CA 01 06 A1 1B 26 A1 19 54 04 38 A1 60 6D 26 A1 1E DD 55 "
        "04 A1 78 0D A1 32 49 21 A1 1B 38 A1 19 06 A1 DD 16 A1 DD 10 "
        "DE B9 07 3B 21"
    ),
    (S5052, 4): bytes.fromhex(
        "2C DD 86 09 DD 02 A1 34 DD 22 26 A1 DD E3 DD 6B 0D A1 8E 2B 25 "
        "38 A1 34 06 A1 18 DD 01 A1 09 07 01 21"
    ),
    (S5052, 6): bytes.fromhex(
        "09 07 B3 A1 DD A2 DD 2D 01 A1 DD A2 DD 2D 14 21 A1 1C 45 DD 68 "
        "19 54 14 21"
    ),
}


class BuildError(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def disk_id(slot: int) -> int:
    return slot + (0x81 if slot < 40 else 0x82)


def slot_start(slot: int) -> int:
    return SLOT_BASE + slot * SLOT_SIZE


def read_slot(data: bytes | bytearray, slot: int) -> bytes:
    start = slot_start(slot)
    block = bytes(data[start:start + SLOT_META])
    end = block.find(b"\0")
    if end < 0:
        raise BuildError(f"unterminated slot {slot}")
    return block[:end]


def slot_refs(data: bytes, slot: int) -> list[int]:
    token = bytes((0xE2, disk_id(slot)))
    result: list[int] = []
    offset = SLOT_BASE + 64 * SLOT_SIZE
    while True:
        offset = data.find(token, offset)
        if offset < 0:
            return result
        result.append(offset)
        offset += 2


def assert_base(names: list[str], base: dict[str, bytes]) -> None:
    if len(names) != 164 or len(base) != 164:
        raise BuildError("V349 archive topology drift")
    for member, expected in BASE_MEMBER_SHA256.items():
        if sha(base[member]) != expected:
            raise BuildError(f"V349 member hash drift: {member}")
    for member, body_offset, slot, metadata, _text in FIXES:
        data = base[member]
        if data[body_offset:body_offset + 2] != bytes((0xE2, disk_id(slot))):
            raise BuildError(f"E2 caller drift: {member}:0x{body_offset:X}")
        if slot_refs(data, slot) != [body_offset]:
            raise BuildError(f"slot ownership drift: {member} slot {slot}")
        if data[slot_start(slot) + SLOT_META] != metadata:
            raise BuildError(f"slot metadata drift: {member} slot {slot}")
        if read_slot(data, slot) != EXPECTED_OLD_PAYLOAD[(member, slot)]:
            raise BuildError(f"old payload drift: {member} slot {slot}")


def build_once(names: list[str], base: dict[str, bytes]) -> tuple[dict[str, bytes], list[dict[str, object]]]:
    assert_base(names, base)
    table = v345.character_codes()
    final = dict(base)
    mutable: dict[str, bytearray] = {S5024: bytearray(base[S5024]), S5052: bytearray(base[S5052])}
    report_rows: list[dict[str, object]] = []

    for member, body_offset, slot, metadata, text in FIXES:
        payload = v345.encode(text, table)
        if b"\0" in payload or not payload or len(payload) >= SLOT_META:
            raise BuildError(f"invalid encoded payload: {member}:0x{body_offset:X}")
        data = mutable[member]
        start = slot_start(slot)
        before_meta = data[start + SLOT_META]
        data[start:start + SLOT_META] = payload + bytes(SLOT_META - len(payload))
        if data[start + SLOT_META] != before_meta or before_meta != metadata:
            raise BuildError(f"slot metadata changed: {member} slot {slot}")
        if read_slot(data, slot) != payload:
            raise BuildError(f"slot readback failed: {member} slot {slot}")
        if data[body_offset:body_offset + 2] != bytes((0xE2, disk_id(slot))):
            raise BuildError(f"body caller changed: {member}:0x{body_offset:X}")
        report_rows.append({
            "member": member,
            "body_offset": f"0x{body_offset:X}",
            "slot": slot,
            "metadata": metadata,
            "old_bytes": len(EXPECTED_OLD_PAYLOAD[(member, slot)]),
            "new_bytes": len(payload),
            "new_hex": payload.hex(" ").upper(),
            "text": text,
        })

    final[S5024] = bytes(mutable[S5024])
    final[S5052] = bytes(mutable[S5052])

    for name in names:
        if name not in (S5024, S5052) and final[name] != base[name]:
            raise BuildError(f"unexpected member changed: {name}")
        if len(final[name]) != len(base[name]):
            raise BuildError(f"member size changed: {name}")
    if final[PSX] != base[PSX] or final[COMM] != base[COMM]:
        raise BuildError("PSX.EXE or COMM.IMG changed")
    return final, report_rows


def allowed_offsets() -> dict[str, set[int]]:
    result = {S5024: set(), S5052: set()}
    for member, _body, slot, _metadata, _text in FIXES:
        start = slot_start(slot)
        result[member].update(range(start, start + SLOT_META))
    return result


def main() -> None:
    if not BASE.is_file() or sha(BASE.read_bytes()) != BASE_SHA256:
        raise BuildError("V349 base archive hash drift")
    names, base = v345.read_archive(BASE)
    final, rows = build_once(names, base)
    second, rows2 = build_once(names, base)
    if final != second or rows != rows2:
        raise BuildError("in-memory deterministic rebuild mismatch")

    changed_members = [name for name in names if final[name] != base[name]]
    if changed_members != [S5024, S5052]:
        raise BuildError(f"changed-member drift: {changed_members}")
    allowed = allowed_offsets()
    changed_counts: dict[str, int] = {}
    for member in changed_members:
        actual = v345.changed_offsets(base[member], final[member])
        if not actual or not actual <= allowed[member]:
            raise BuildError(f"Expected-Write envelope violation: {member}")
        # The +0x7F metadata byte is specifically outside the allowed set.
        changed_counts[member] = len(actual)

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    output_temp = ROOT / "03_output" / f"{OUTPUT_STEM}.zip"
    delta_temp = ROOT / "03_output" / f"{DELTA_STEM}.zip"
    for path in (output_temp, delta_temp):
        if path.exists():
            path.unlink()
    v345.write_archive(output_temp, names, final)
    v345.write_archive(delta_temp, changed_members, final)
    output_hash = sha(output_temp.read_bytes())
    delta_hash = sha(delta_temp.read_bytes())
    output = output_temp.with_name(f"{OUTPUT_STEM}_{output_hash[:8]}.zip")
    delta = delta_temp.with_name(f"{DELTA_STEM}_{delta_hash[:8]}.zip")
    for source, target in ((output_temp, output), (delta_temp, delta)):
        if target.exists():
            if sha(target.read_bytes()) != sha(source.read_bytes()):
                raise BuildError(f"existing output differs: {target.name}")
            source.unlink()
        else:
            source.replace(target)

    with (ANALYSIS / "dialogue_fixes.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=tuple(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    manifest = {
        "version": "V350",
        "status": "STATIC_PASS_RUNTIME_PENDING",
        "base": {"file": BASE.name, "sha256": BASE_SHA256},
        "output": {"file": output.name, "sha256": output_hash},
        "delta": {"file": delta.name, "sha256": delta_hash},
        "changed_members_vs_v349": changed_members,
        "changed_bytes": changed_counts,
        "preserved": "PSX.EXE, COMM.IMG, E2 callers, slot +0x7F metadata, all other members byte exact",
        "runtime": "PENDING user cold boot/dialogue review; inherits V349 dungeon runtime gate",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V350 runtime-reviewed dialogue wording fixes",
        f"base={BASE.name} sha256={BASE_SHA256}",
        f"output={output.name} sha256={output_hash}",
        f"delta={delta.name} sha256={delta_hash}",
        f"changed_members={','.join(changed_members)}",
        f"changed_bytes={changed_counts}",
        "PSX.EXE/COMM.IMG/all other members=byte exact V349",
        "E2 callers and +0x7F slot metadata=byte exact V349",
        "runtime=PENDING user cold boot/dialogue review; TEST_ONLY",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    (ANALYSIS / "runtime_checklist.txt").write_text(
        "V350 cold-boot checklist\n"
        "1. V350.cue를 완전 콜드부팅하고 기존 메모리카드 저장을 불러온다.\n"
        "2. SAV 1 장면: '이야, 덕분에 살았군. 고맙다.'를 확인한다.\n"
        "3. SAV 2 장면: 보물/공짜 농담 문장을 확인한다.\n"
        "4. SAV 3 장면: 요슈아의 '욕망만 따라 사는 게 아니다.'를 확인한다.\n"
        "5. SAV 4 장면: '뭔 소리야? 이래선 말이 안 되잖아.'를 확인한다.\n"
        "6. V349의 던전 진입/지하 층수 표기 런타임 게이트도 그대로 확인한다.\n",
        encoding="utf-8",
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
