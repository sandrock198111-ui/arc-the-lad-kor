#!/usr/bin/env python3
"""Build V359: restore text equivalents for eight missing E7 button icons.

V358's current 16px atlas cannot safely restore the original multi-colour E7
icon cells without consuming additional VRAM planes.  The Korean prose had
therefore inherited visible double blanks at eight sites.  This incremental
build replaces those blanks with existing text glyphs (L/R, 결정 버튼, 취소
버튼).  Seven already-owned E2 slots are rewritten in place.  The one 32-byte
inline sentence uses pristine, unreferenced Bank-A slot 33 in 4/S4033.DAT.

No PSX.EXE, COMM.IMG, existing caller, live control byte, or existing slot
metadata is changed.  The new slot's skip value is exactly its 30-byte inline
replacement span.
"""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from v354_dialogue_codec import SPACE_CODE, encode, load_v354, tokens  # noqa: E402


VERSION = "V359"
BASE = ROOT / "03_output/arc1_v358_dialogue_target_panel_fix_TEST_ONLY_D499D9D4.zip"
BASE_SHA256 = "D499D9D463A66B343A9D794A49753454788B3F18C6DC38B7CDE7A77304838061"
CANONICAL = ROOT / "05_docs/script_translated_full.csv"
CANONICAL_SHA256 = "2AE70EB0C8A627686B714884469DD883683BE2B79FB5A5E7D793E0F73D911980"
EDITOR_LEDGER = ROOT / "05_docs/dialogue_all.csv"
EDITOR_LEDGER_SHA256 = "CEBB7E2C575F3669873693B2C6BC03AA239DAF801474DC3A326F31A58383EEC5"
OUTPUT_STEM = "arc1_v359_e7_semantic_text_repair_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v358"
ANALYSIS = ROOT / "01_work/analysis/arc1_v359_e7_semantic_text_repair"
OUT = ROOT / "03_output"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
SLOT_SIZE = 0x80
SLOT_TEXT_MAX = 0x7E
SLOT_META = 0x7F
ROW_PIXELS = 228
NORMAL_ADVANCE = 14
SPACE_ADVANCE = 6
FILL = SPACE_CODE[0]

BASE_MEMBER_SHA256 = {
    PSX: "00DD915FC981B20CDD762908DE9E650DB1CD8EA02F57C095474284E3D8C7C83F",
    COMM: "A6681F1355007725328372CC6143EF21EEE43A9FDE91FD3DC2EF3461C6805405",
    "21/S2045.DAT": "F2A4051BFFD4FC6BDA40BCE8923AD8E97346782C16F44535B66AB4E392B909E9",
    "31/S3013.DAT": "8D503A7A3A51664CF5E557AA772932944B633EDDD57E9C90F3AA83F614117B55",
    "4/S4033.DAT": "A6313977A86215758BED595D31041AB484B9B97F0F8B9F6EE49DBCCD513FEC4A",
    "5/S5013.DAT": "8E68A36BFFF3F4142FC7325383DBB3977A278F5867C7A50CF7CFCE744B1C0B97",
    "6/S6014.DAT": "136336623D15538D7B6ECA01CBA4B060E96B5B3431F5DF856C480412CD7AC2B3",
    "7/S7012.DAT": "5CF0A4C7624F31A16FAAE0245AC74EAA615854B8E2E78C47A3671693AAB8FF3E",
    "8/S8013.DAT": "D480D4725D6A336A38A4C0FBF5AB57D68ADF31B46D046C20BF66E549FE925D0C",
}

CHOPPIN_OLD = "초핀: 그때 커서와  로 링 안의 기술을 고르고 아이콘의 위치를 바꾸어 놓을 수 있습니다."
CHOPPIN_NEW = "초핀: 그때 커서와 결정 버튼으로 링 안의 기술을 골라 아이콘 위치를 변경할 수 있습니다."
CREW_OLD = "승무원: 또 자유롭게 돌아다닐 수 있는 곳에서는  를 여러 곳에서 눌러 보십시오."
CREW_NEW = "승무원: 또 자유롭게 돌아다닐 수 있는 곳에서는 여기저기서 결정 버튼을 눌러 보십시오."
LR_OLD = "전투 때는  를 함께 누르면 프리 커서가 돼."
LR_NEW = "전투 때는 L과 R을 함께 누르면 프리 커서가 돼."
CANCEL_OLD = "프리 커서일 때는  를 누르면 원래대로 돌아와."
CANCEL_NEW = "프리 커서일 때는 취소 버튼을 누르면 원래대로 돌아와."


@dataclass(frozen=True)
class ExistingSlotTarget:
    member: str
    source_offset: int
    disk_id: int
    slot_offset: int
    metadata: int
    old_text: str
    new_text: str
    original_icon: str


EXISTING = (
    ExistingSlotTarget("21/S2045.DAT", 0x49292, 0x9D, 0x45E00, 53, CHOPPIN_OLD, CHOPPIN_NEW, "E7:02"),
    ExistingSlotTarget("31/S3013.DAT", 0x4855E, 0x84, 0x45180, 40, CREW_OLD, CREW_NEW, "E7:02"),
    ExistingSlotTarget("4/S4033.DAT", 0x48156, 0x8F, 0x45700, 24, CANCEL_OLD, CANCEL_NEW, "E7:03"),
    ExistingSlotTarget("5/S5013.DAT", 0x4927E, 0x9E, 0x45E80, 53, CHOPPIN_OLD, CHOPPIN_NEW, "E7:02"),
    ExistingSlotTarget("6/S6014.DAT", 0x4922A, 0x9C, 0x45D80, 53, CHOPPIN_OLD, CHOPPIN_NEW, "E7:02"),
    ExistingSlotTarget("7/S7012.DAT", 0x48D22, 0x9C, 0x45D80, 53, CHOPPIN_OLD, CHOPPIN_NEW, "E7:02"),
    ExistingSlotTarget("8/S8013.DAT", 0x47D10, 0x91, 0x45800, 53, CHOPPIN_OLD, CHOPPIN_NEW, "E7:02"),
)

# The only target that was still inline in V358.
NEW_SLOT_MEMBER = "4/S4033.DAT"
NEW_SLOT_SOURCE = 0x48102
NEW_SLOT_BODY_LENGTH = 32
NEW_SLOT_DISK_ID = 0xA2
NEW_SLOT_INDEX = 33
NEW_SLOT_OFFSET = 0x45000 + NEW_SLOT_INDEX * SLOT_SIZE
NEW_SLOT_METADATA = NEW_SLOT_BODY_LENGTH - 2


class BuildError(RuntimeError):
    pass


def sha(value: bytes | Path) -> str:
    raw = value.read_bytes() if isinstance(value, Path) else value
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(text: str, table: dict[str, bytes]) -> bytes:
    payload, missing = encode(text, table, keep_breaks=False)
    if missing:
        raise BuildError(f"missing glyphs {sorted(set(missing))}: {text}")
    if not payload or 0 in payload or len(payload) > SLOT_TEXT_MAX:
        raise BuildError(f"invalid encoded payload length/content: {len(payload)}")
    structural = [token for token in tokens(payload) if len(token) == 2 and 0xE2 <= token[0] <= 0xE8]
    if structural:
        raise BuildError(f"ordinary prose contains structural tokens: {structural}")
    return payload


def wrapped_rows(payload: bytes) -> int:
    rows, x = 1, 0
    for token in tokens(payload):
        advance = SPACE_ADVANCE if token == SPACE_CODE else NORMAL_ADVANCE
        if x + advance >= ROW_PIXELS:
            rows, x = rows + 1, 0
        x += advance
    return rows


def slot_block(payload: bytes, metadata: int) -> bytes:
    if len(payload) > SLOT_TEXT_MAX or not 0 <= metadata <= 0x7F:
        raise BuildError("slot payload/metadata outside bounds")
    return payload + b"\0" + bytes(SLOT_META - len(payload) - 1) + bytes((metadata,))


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
    """Return E2-pair hits only in the DAT's live script/body region.

    Some DAT resource blocks below 0x47000 contain coincidental E2 xx byte
    pairs.  They are not token streams and must not be counted as E2 callers.
    """
    return [offset for offset in find_all(data, needle) if offset >= 0x47000]


def clone_info(source: ZipInfo) -> ZipInfo:
    clone = ZipInfo(source.filename, source.date_time)
    for attr in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(clone, attr, getattr(source, attr))
    return clone


def read_archive(path: Path) -> tuple[list[ZipInfo], list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        infos = [info for info in archive.infolist() if not info.is_dir()]
        names = [info.filename for info in infos]
        return infos, names, {name: archive.read(name) for name in names}


def write_archive(path: Path, infos: list[ZipInfo], names: list[str], members: dict[str, bytes]) -> None:
    by_name = {info.filename: info for info in infos}
    with ZipFile(path, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for name in names:
            archive.writestr(
                clone_info(by_name[name]), members[name],
                compress_type=ZIP_DEFLATED, compresslevel=9,
            )


def finalize_archive(temporary: Path, stem: str) -> tuple[Path, str]:
    digest = sha(temporary)
    output = temporary.with_name(f"{stem}_{digest[:8]}.zip")
    if output.exists():
        if sha(output) != digest:
            raise BuildError(f"refusing to replace different archive: {output}")
        temporary.unlink()
    else:
        temporary.replace(output)
    return output, digest


def read_canonical() -> dict[tuple[str, str], str]:
    with CANONICAL.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != 2878:
        raise BuildError("canonical dialogue census drift")
    return {(row["source file"], row["offset"]): row["korean"] for row in rows}


def assert_editor_ledger() -> None:
    with EDITOR_LEDGER.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.reader(handle))
    if len(rows) != 2879 or len(rows[0]) != 9:
        raise BuildError("dialogue_all.csv schema/census drift")
    indexed = {(row[1], row[2]): row for row in rows[1:]}
    for member, offset, expected in target_texts():
        row = indexed.get((member, f"0x{offset:X}"))
        if row is None or row[7] != expected or row[8] != expected:
            raise BuildError(f"editor ledger target drift: {member}:0x{offset:X}")


def target_texts() -> list[tuple[str, int, str]]:
    rows = [(target.member, target.source_offset, target.new_text) for target in EXISTING]
    rows.append((NEW_SLOT_MEMBER, NEW_SLOT_SOURCE, LR_NEW))
    return rows


def decode_payload(payload: bytes, decoder: dict[bytes, str]) -> str:
    return "".join(decoder.get(token, f"<{token.hex().upper()}>") for token in tokens(payload))


def assert_inputs(
    names: list[str], base: dict[str, bytes], table: dict[str, bytes],
    decoder: dict[bytes, str],
) -> None:
    if len(names) != 164 or len(set(names)) != 164 or set(names) != set(base):
        raise BuildError("V358 archive topology drift")
    for member, expected in BASE_MEMBER_SHA256.items():
        if member not in base or sha(base[member]) != expected:
            raise BuildError(f"V358 member hash drift: {member}")
    canonical = read_canonical()
    for member, offset, expected in target_texts():
        if canonical.get((member, f"0x{offset:X}")) != expected:
            raise BuildError(f"canonical target drift: {member}:0x{offset:X}")
    assert_editor_ledger()

    for target in EXISTING:
        data = base[target.member]
        pair = bytes((0xE2, target.disk_id))
        if data[target.source_offset:target.source_offset + 2] != pair:
            raise BuildError(f"E2 caller drift: {target.member}:0x{target.source_offset:X}")
        if script_hits(data, pair) != [target.source_offset]:
            raise BuildError(f"E2 ownership is not unique: {target.member}:{target.disk_id:02X}")
        block = data[target.slot_offset:target.slot_offset + SLOT_SIZE]
        end = block[:SLOT_META].find(b"\0")
        if end < 0 or decode_payload(block[:end], decoder) != target.old_text:
            raise BuildError(f"owned slot drift: {target.member}:0x{target.slot_offset:X}")
        if any(block[end + 1:SLOT_META]) or block[SLOT_META] != target.metadata:
            raise BuildError(f"owned slot padding/metadata drift: {target.member}:0x{target.slot_offset:X}")

    data = base[NEW_SLOT_MEMBER]
    old_inline = encoded(LR_OLD, table)
    if len(old_inline) != NEW_SLOT_BODY_LENGTH:
        raise BuildError("V358 inline LR sentence length drift")
    if data[NEW_SLOT_SOURCE:NEW_SLOT_SOURCE + NEW_SLOT_BODY_LENGTH] != old_inline:
        raise BuildError("V358 inline LR sentence bytes drift")
    if any(data[NEW_SLOT_OFFSET:NEW_SLOT_OFFSET + SLOT_SIZE]):
        raise BuildError("4/S4033 Bank-A slot33 is not zero")
    if script_hits(data, bytes((0xE2, NEW_SLOT_DISK_ID))):
        raise BuildError("4/S4033 E2:A2 already has a caller")


def build_once(
    names: list[str], base: dict[str, bytes], table: dict[str, bytes],
    decoder: dict[bytes, str],
) -> dict[str, bytes]:
    assert_inputs(names, base, table, decoder)
    output = dict(base)
    for target in EXISTING:
        data = bytearray(output[target.member])
        new_payload = encoded(target.new_text, table)
        if wrapped_rows(new_payload) > 4:
            raise BuildError(f"new prose exceeds four rows: {target.member}")
        data[target.slot_offset:target.slot_offset + SLOT_SIZE] = slot_block(new_payload, target.metadata)
        output[target.member] = bytes(data)

    data = bytearray(output[NEW_SLOT_MEMBER])
    payload = encoded(LR_NEW, table)
    if wrapped_rows(payload) > 4:
        raise BuildError("LR prose exceeds four rows")
    data[NEW_SLOT_OFFSET:NEW_SLOT_OFFSET + SLOT_SIZE] = slot_block(payload, NEW_SLOT_METADATA)
    data[NEW_SLOT_SOURCE:NEW_SLOT_SOURCE + NEW_SLOT_BODY_LENGTH] = (
        bytes((0xE2, NEW_SLOT_DISK_ID)) + bytes((FILL,)) * NEW_SLOT_METADATA
    )
    output[NEW_SLOT_MEMBER] = bytes(data)

    expected_members = {target.member for target in EXISTING} | {NEW_SLOT_MEMBER}
    changed = {name for name in names if output[name] != base[name]}
    if changed != expected_members:
        raise BuildError(f"changed-member drift: {sorted(changed ^ expected_members)}")
    for name in names:
        if len(output[name]) != len(base[name]):
            raise BuildError(f"member size changed: {name}")
        if name not in expected_members and output[name] != base[name]:
            raise BuildError(f"non-target member changed: {name}")
    if output[PSX] != base[PSX] or output[COMM] != base[COMM]:
        raise BuildError("PSX.EXE or COMM.IMG changed")

    for target in EXISTING:
        before = base[target.member]
        after = output[target.member]
        if after[target.source_offset:target.source_offset + target.metadata + 2] != before[
            target.source_offset:target.source_offset + target.metadata + 2
        ]:
            raise BuildError(f"existing caller/inline body changed: {target.member}")
        if after[target.slot_offset + SLOT_META] != target.metadata:
            raise BuildError(f"existing slot metadata changed: {target.member}")
    final_new = output[NEW_SLOT_MEMBER]
    if script_hits(final_new, bytes((0xE2, NEW_SLOT_DISK_ID))) != [NEW_SLOT_SOURCE]:
        raise BuildError("new E2:A2 ownership readback failed")
    if final_new[NEW_SLOT_OFFSET + SLOT_META] != NEW_SLOT_METADATA:
        raise BuildError("new slot metadata readback failed")
    return output


def changed_rows(names: list[str], base: dict[str, bytes], final: dict[str, bytes]) -> list[dict[str, str]]:
    slot_ranges = {
        target.member: (target.slot_offset, target.slot_offset + SLOT_SIZE) for target in EXISTING
    }
    rows: list[dict[str, str]] = []
    for name in names:
        for offset, (before, after) in enumerate(zip(base[name], final[name], strict=True)):
            if before == after:
                continue
            reason = "approved E7 semantic text in owned E2 slot"
            if name == NEW_SLOT_MEMBER and NEW_SLOT_SOURCE <= offset < NEW_SLOT_SOURCE + NEW_SLOT_BODY_LENGTH:
                reason = "externalize inline LR help to verified-free Bank-A slot33"
            elif name == NEW_SLOT_MEMBER and NEW_SLOT_OFFSET <= offset < NEW_SLOT_OFFSET + SLOT_SIZE:
                reason = "new LR text payload in verified-free Bank-A slot33"
            elif name in slot_ranges and not slot_ranges[name][0] <= offset < slot_ranges[name][1]:
                raise BuildError(f"unexpected DAT write: {name}:0x{offset:X}")
            rows.append({
                "member": name, "offset": f"0x{offset:X}",
                "before": f"{before:02X}", "after": f"{after:02X}", "reason": reason,
            })
    return rows


def main() -> None:
    for path, expected, label in (
        (BASE, BASE_SHA256, "V358 base"),
        (CANONICAL, CANONICAL_SHA256, "canonical dialogue"),
        (EDITOR_LEDGER, EDITOR_LEDGER_SHA256, "editor ledger"),
    ):
        if not path.is_file() or sha(path) != expected:
            raise BuildError(f"{label} hash drift: {path}")
    _exe, _comm, table, decoder = load_v354()
    infos, names, base = read_archive(BASE)
    final = build_once(names, base, table, decoder)
    if final != build_once(names, base, table, decoder):
        raise BuildError("deterministic in-memory rebuild mismatch")

    changed = [name for name in names if final[name] != base[name]]
    rows = changed_rows(names, base, final)
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    full_temp = OUT / f"{OUTPUT_STEM}.zip"
    delta_temp = OUT / f"{DELTA_STEM}.zip"
    for temporary in (full_temp, delta_temp):
        if temporary.exists():
            temporary.unlink()
    write_archive(full_temp, infos, names, final)
    write_archive(delta_temp, infos, changed, final)
    full_path, full_hash = finalize_archive(full_temp, OUTPUT_STEM)
    delta_path, delta_hash = finalize_archive(delta_temp, DELTA_STEM)

    with (ANALYSIS / "expected_writes.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=("member", "offset", "before", "after", "reason"))
        writer.writeheader()
        writer.writerows(rows)

    with (ANALYSIS / "translation_changes.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("member", "source_offset", "original_icon", "before", "after", "encoded_bytes", "rows"))
        for target in EXISTING:
            payload = encoded(target.new_text, table)
            writer.writerow((target.member, f"0x{target.source_offset:X}", target.original_icon,
                             target.old_text, target.new_text, len(payload), wrapped_rows(payload)))
        payload = encoded(LR_NEW, table)
        writer.writerow((NEW_SLOT_MEMBER, f"0x{NEW_SLOT_SOURCE:X}", "E7:07+E7:06",
                         LR_OLD, LR_NEW, len(payload), wrapped_rows(payload)))

    with (ANALYSIS / "slot_audit.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("member", "source_offset", "bank", "slot", "disk_id", "slot_offset",
                         "metadata", "allocation", "caller_count"))
        for target in EXISTING:
            writer.writerow((target.member, f"0x{target.source_offset:X}", "A",
                             (target.disk_id - 0x81 if target.disk_id <= 0xA8 else target.disk_id - 0x82),
                             f"0x{target.disk_id:02X}", f"0x{target.slot_offset:X}", target.metadata,
                             "existing-owned", 1))
        writer.writerow((NEW_SLOT_MEMBER, f"0x{NEW_SLOT_SOURCE:X}", "A", NEW_SLOT_INDEX,
                         f"0x{NEW_SLOT_DISK_ID:02X}", f"0x{NEW_SLOT_OFFSET:X}", NEW_SLOT_METADATA,
                         "new-pristine-zero-unreferenced", 1))

    changed_counts = {name: sum(row["member"] == name for row in rows) for name in changed}
    manifest = {
        "version": VERSION,
        "status": "STATIC_BUILD_COMPLETE_RUNTIME_PENDING_TEST_ONLY",
        "base": {"file": BASE.name, "sha256": BASE_SHA256},
        "output": {"file": full_path.name, "sha256": full_hash},
        "delta": {"file": delta_path.name, "sha256": delta_hash},
        "changed_members_vs_v358": changed,
        "changed_bytes": changed_counts,
        "targets": [
            {"member": member, "source_offset": f"0x{offset:X}", "text": text}
            for member, offset, text in target_texts()
        ],
        "slot_policy": {
            "existing_owned_slots_rewritten": len(EXISTING),
            "new_slots": [{"member": NEW_SLOT_MEMBER, "bank": "A", "slot": NEW_SLOT_INDEX,
                           "disk_id": f"0x{NEW_SLOT_DISK_ID:02X}", "metadata": NEW_SLOT_METADATA,
                           "premise": "V358 block all-zero and E2:A2 caller count zero"}],
        },
        "preserved": (
            "V358 PSX.EXE/COMM.IMG, archive topology/order/sizes, seven existing E2 callers, "
            "all currently live body control bytes, seven existing +0x7F metadata bytes, all non-target members"
        ),
        "runtime": "PENDING user cold boot and eight help-line review",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    report = [
        "Arc the Lad 1 V359 E7 semantic-text repair",
        "status=STATIC BUILD COMPLETE / RUNTIME PENDING / TEST_ONLY",
        f"base={BASE.name} sha256={BASE_SHA256}",
        f"full={full_path.name} sha256={full_hash}",
        f"delta={delta_path.name} sha256={delta_hash}",
        f"changed_members={','.join(changed)}",
        f"changed_bytes={changed_counts} total={len(rows)}",
        "targets=8 missing E7 meanings restored as text; 5 Choppin + 1 crew + LR + cancel",
        "slots=7 existing owned slots rewritten; 4/S4033 Bank-A slot33 newly allocated",
        "PSX.EXE/COMM.IMG/non-target members=byte exact V358",
        "runtime=PENDING user cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    (ANALYSIS / "runtime_checklist.txt").write_text(
        "V359 TEST_ONLY runtime checklist\n"
        "1. V359.cue를 완전 콜드부팅하고 이전 버전 savestate를 직접 불러오지 않는다.\n"
        "2. 4/S4033 도움말에서 'L과 R' 및 '취소 버튼'이 빈칸 없이 보이는지 확인한다.\n"
        "3. 초핀 도움말 5곳과 승무원 도움말 1곳에서 '결정 버튼'이 보이는지 확인한다.\n"
        "4. 각 문장이 4줄 이내로 표시되고 다음 대사/메뉴로 정상 진행하는지 확인한다.\n"
        "5. V358 대상 선택창, 대화, 전투, 아이템, 스킬, 커서가 그대로인지 표본 확인한다.\n",
        encoding="utf-8",
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
