#!/usr/bin/env python3
"""Build V358: wording repair and isolated two-line target-panel geometry fix.

This incremental build starts from the hash-pinned V357 full archive.  It
changes one E2 slot payload in F/SF0F1.DAT and three immediate bytes in the
dedicated two-line target-selection panel function.  V357's Bank-B handler,
all other dialogue, COMM.IMG, controls, archive topology, and member sizes are
preserved byte-for-byte.
"""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from v354_dialogue_codec import encode, load_v354, tokens  # noqa: E402


VERSION = "V358"
BASE = ROOT / "03_output/arc1_v357_user_reviewed_full_dialogue_bankb_TEST_ONLY_34854022.zip"
BASE_SHA256 = "34854022BB0CA1C17BF4D798B8405009F8CC04914253E1D48476B2A2DBC3397A"
OUTPUT_STEM = "arc1_v358_dialogue_target_panel_fix_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v357"
ANALYSIS = ROOT / "01_work/analysis/arc1_v358_dialogue_target_panel_fix"
OUT = ROOT / "03_output"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
DAT = "F/SF0F1.DAT"
BASE_MEMBER_SHA256 = {
    PSX: "18B6A3599A165A211AF9886213D2C62FE993CB96E531DAE1A6EAD6D8B28B588A",
    COMM: "A6681F1355007725328372CC6143EF21EEE43A9FDE91FD3DC2EF3461C6805405",
    DAT: "E863ECBB5B4290174D47C53BF3AC9C9B430B1C02B6D088CBD271D52008727CC1",
}

# F/SF0F1.DAT E2 slot ownership and approved wording.
SLOT_START = 0x45000
SLOT_SIZE = 0x80
SLOT_META = SLOT_SIZE - 1
CALLER = 0x47910
CALL = bytes.fromhex("E2 81")
METADATA = 0x2D
JAPANESE = "わかつたか、この我々に封印の技など必要ではない。\n山に帰るのは別の用じゃ。"
OLD_TEXT = "알겠느냐, 우리에게 봉인의 기술 따위는 필요 없다. 산으로 돌아가는 데에는 다른 용무가 있다."
NEW_TEXT = "알겠느냐? 우리에게 봉인의 기술 따위는 필요 없다. 산으로 돌아가는 건 다른 볼일이 있어서다."
OLD_PAYLOAD = bytes.fromhex(
    "DD 1E 54 DD 99 DD 51 B3 A1 3D 2E 0E 41 A1 DD B6 35 0F A1 24 DD E5 "
    "A1 DD B9 8E 06 A1 DE 4A 2C A1 71 01 21 A1 DD 45 4E DD 04 A1 72 09 "
    "0C 06 A1 81 0E 06 A1 01 DD BF A1 DD 1A 5F 0C A1 1F 01 21"
)
NEW_PAYLOAD = bytes.fromhex(
    "DD 1E 54 4D DD 51 D1 A1 3D 2E 0E 41 A1 DD B6 35 0F A1 24 DD E5 A1 "
    "DD B9 8E 06 A1 DE 4A 2C A1 71 01 21 A1 DD 45 4E D5 A1 72 09 0C 06 "
    "A1 DD 16 A1 01 DD BF A1 DD 50 6B 03 A1 1F 14 25 01 21"
)

# Dedicated two-line target-selection panel at RAM 0x80166AC4.
# The original 12px geometry was x=74,y=111,w=172,h=34 with text rows at
# y=115/129.  V358 preserves x/y and the first row, expands the panel for the
# 16px renderer, and moves only the second row down by 2px.
PANEL_FUNCTION_RAM = 0x80166AC4
PANEL_FUNCTION_FILE = 0x4C2C4
PANEL_CALLER_RAM = 0x80166898
PANEL_CALLER_FILE = 0x4C098
RAM_TO_FILE = 0x8011A800
PSX_PATCHES = (
    (0x4C2EC, 0x340600AC, 0x340600C6, "target panel width 172 -> 198"),
    (0x4C2F4, 0x34070022, 0x34070028, "target panel height 34 -> 40"),
    (0x4C334, 0x34050081, 0x34050083, "target panel second row y 129 -> 131"),
)


class BuildError(RuntimeError):
    pass


def sha(value: bytes | Path) -> str:
    raw = value.read_bytes() if isinstance(value, Path) else value
    return hashlib.sha256(raw).hexdigest().upper()


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


def write_archive(
    path: Path, infos: list[ZipInfo], names: list[str], members: dict[str, bytes]
) -> None:
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
            raise BuildError(f"refusing to replace a different archive: {output}")
        temporary.unlink()
    else:
        temporary.replace(output)
    return output, digest


def find_all(data: bytes, needle: bytes) -> list[int]:
    found: list[int] = []
    start = 0
    while True:
        at = data.find(needle, start)
        if at < 0:
            return found
        found.append(at)
        start = at + 1


def slot_payload(data: bytes) -> bytes:
    body = data[SLOT_START:SLOT_START + SLOT_META]
    end = body.find(b"\0")
    if end < 0:
        raise BuildError("F/SF0F1 slot0 is not terminated")
    return body[:end]


def jal_word(target: int) -> int:
    return 0x0C000000 | ((target >> 2) & 0x03FFFFFF)


def aligned_word_hits(data: bytes, word: int) -> list[int]:
    needle = struct.pack("<I", word)
    return [offset for offset in range(0x800, len(data) - 3, 4) if data[offset:offset + 4] == needle]


def control_tokens(payload: bytes) -> list[bytes]:
    return [token for token in tokens(payload) if len(token) == 2 and token[0] in range(0xE2, 0xE9)]


def assert_base(names: list[str], base: dict[str, bytes]) -> None:
    if len(names) != 164 or len(set(names)) != 164 or set(names) != set(base):
        raise BuildError("V357 archive topology drift")
    for member, expected in BASE_MEMBER_SHA256.items():
        if member not in base or sha(base[member]) != expected:
            raise BuildError(f"V357 member hash drift: {member}")

    dat = base[DAT]
    if slot_payload(dat) != OLD_PAYLOAD:
        raise BuildError("V357 F/SF0F1 slot0 payload drift")
    if dat[SLOT_START + SLOT_META] != METADATA:
        raise BuildError("V357 F/SF0F1 slot0 metadata drift")
    if find_all(dat, CALL) != [CALLER]:
        raise BuildError("F/SF0F1 slot0 E2 ownership drift")

    exe = base[PSX]
    if PANEL_FUNCTION_RAM - RAM_TO_FILE != PANEL_FUNCTION_FILE:
        raise BuildError("panel RAM/file conversion drift")
    if aligned_word_hits(exe, jal_word(PANEL_FUNCTION_RAM)) != [PANEL_CALLER_FILE]:
        raise BuildError("target-panel function caller census drift")
    for offset, before, _after, _reason in PSX_PATCHES:
        if struct.unpack_from("<I", exe, offset)[0] != before:
            raise BuildError(f"V357 PSX premise drift at 0x{offset:X}")
    if struct.unpack_from("<I", exe, 0x4C2F0)[0] != jal_word(0x8016C61C):
        raise BuildError("panel window call drift")
    if struct.unpack_from("<I", exe, 0x4C330)[0] != jal_word(0x8016B418):
        raise BuildError("second-row state initializer call drift")


def build_once(names: list[str], base: dict[str, bytes]) -> dict[str, bytes]:
    assert_base(names, base)
    _v354_exe, _comm, table, _decoder = load_v354()
    encoded, missing = encode(NEW_TEXT, table, keep_breaks=False)
    if missing or encoded != NEW_PAYLOAD:
        raise BuildError(f"approved text encoding drift: missing={missing}")
    if control_tokens(encoded):
        raise BuildError("approved ordinary prose unexpectedly contains a control token")
    if sum(token == b"\x21" for token in tokens(encoded)) != 2:
        raise BuildError("period encoding census drift")
    if sum(token == b"\xD1" for token in tokens(encoded)) != 1:
        raise BuildError("question-mark encoding census drift")
    if len(encoded) >= SLOT_META:
        raise BuildError("approved text does not fit F/SF0F1 slot0")

    final = dict(base)
    dat = bytearray(base[DAT])
    metadata_before = dat[SLOT_START + SLOT_META]
    dat[SLOT_START:SLOT_START + SLOT_META] = (
        encoded + b"\0" + bytes(SLOT_META - len(encoded) - 1)
    )
    if dat[SLOT_START + SLOT_META] != metadata_before:
        raise BuildError("slot metadata changed during payload rewrite")
    final[DAT] = bytes(dat)

    exe = bytearray(base[PSX])
    for offset, before, after, _reason in PSX_PATCHES:
        if struct.unpack_from("<I", exe, offset)[0] != before:
            raise BuildError(f"PSX write guard failed at 0x{offset:X}")
        struct.pack_into("<I", exe, offset, after)
    final[PSX] = bytes(exe)

    changed = [name for name in names if final[name] != base[name]]
    expected_changed = [name for name in names if name in {DAT, PSX}]
    if changed != expected_changed:
        raise BuildError(f"changed-member drift: {changed}")
    for name in names:
        if len(final[name]) != len(base[name]):
            raise BuildError(f"member size changed: {name}")
    if final[COMM] != base[COMM]:
        raise BuildError("COMM.IMG changed")
    if slot_payload(final[DAT]) != NEW_PAYLOAD:
        raise BuildError("new F/SF0F1 slot payload readback failed")
    if final[DAT][SLOT_START + SLOT_META] != METADATA:
        raise BuildError("slot metadata readback failed")
    if final[DAT][CALLER:CALLER + 2] != CALL or find_all(final[DAT], CALL) != [CALLER]:
        raise BuildError("E2 caller/ownership changed")

    psx_diff = {
        offset for offset, (before, after) in enumerate(zip(base[PSX], final[PSX], strict=True))
        if before != after
    }
    expected_psx_diff = {offset for offset, _before, _after, _reason in PSX_PATCHES}
    if psx_diff != expected_psx_diff:
        raise BuildError(f"PSX Expected-Write mismatch: {sorted(psx_diff ^ expected_psx_diff)}")
    dat_diff = {
        offset for offset, (before, after) in enumerate(zip(base[DAT], final[DAT], strict=True))
        if before != after
    }
    if not dat_diff or not dat_diff <= set(range(SLOT_START, SLOT_START + SLOT_META)):
        raise BuildError("DAT changed outside the owned slot0 payload")
    return final


def changed_rows(
    names: list[str], base: dict[str, bytes], final: dict[str, bytes]
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    psx_reasons = {offset: reason for offset, _before, _after, reason in PSX_PATCHES}
    for name in names:
        for offset, (before, after) in enumerate(zip(base[name], final[name], strict=True)):
            if before == after:
                continue
            reason = (
                psx_reasons[offset]
                if name == PSX
                else "approved F/SF0F1 slot0 wording; caller/control/metadata preserved"
            )
            rows.append({
                "member": name,
                "offset": f"0x{offset:X}",
                "before": f"{before:02X}",
                "after": f"{after:02X}",
                "reason": reason,
            })
    return rows


def main() -> None:
    if not BASE.is_file() or sha(BASE) != BASE_SHA256:
        raise BuildError("V357 base archive hash drift")
    infos, names, base = read_archive(BASE)
    final = build_once(names, base)
    if final != build_once(names, base):
        raise BuildError("in-memory deterministic rebuild mismatch")
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

    with (ANALYSIS / "expected_writes.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=("member", "offset", "before", "after", "reason"))
        writer.writeheader()
        writer.writerows(rows)

    with (ANALYSIS / "translation_change.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow((
            "member", "caller", "slot", "metadata", "japanese", "before_korean",
            "after_korean", "before_bytes", "after_bytes",
        ))
        writer.writerow((
            DAT, f"0x{CALLER:X}", 0, f"0x{METADATA:02X}", JAPANESE, OLD_TEXT,
            NEW_TEXT, len(OLD_PAYLOAD), len(NEW_PAYLOAD),
        ))

    with (ANALYSIS / "ui_geometry_audit.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow((
            "screen", "function_ram", "sole_caller_ram", "box_x", "box_y",
            "box_width_before", "box_width_after", "box_height_before",
            "box_height_after", "line1_y", "line2_y_before", "line2_y_after",
            "expected_margin",
        ))
        writer.writerow((
            "two-line target selection", f"0x{PANEL_FUNCTION_RAM:08X}",
            f"0x{PANEL_CALLER_RAM:08X}", 74, 111, 172, 198, 34, 40, 115,
            129, 131, "8px left/right; 4px top/bottom; no 16px row overlap",
        ))

    changed_counts = {
        name: sum(row["member"] == name for row in rows) for name in changed
    }
    manifest = {
        "version": VERSION,
        "status": "STATIC_BUILD_COMPLETE_RUNTIME_PENDING_TEST_ONLY",
        "base": {"file": BASE.name, "sha256": BASE_SHA256},
        "output": {"file": full_path.name, "sha256": full_hash},
        "delta": {"file": delta_path.name, "sha256": delta_hash},
        "changed_members_vs_v357": changed,
        "changed_bytes": changed_counts,
        "translation": {
            "member": DAT,
            "caller": f"0x{CALLER:X}",
            "slot": 0,
            "metadata": f"0x{METADATA:02X}",
            "japanese": JAPANESE,
            "before": OLD_TEXT,
            "after": NEW_TEXT,
            "encoded_bytes": len(NEW_PAYLOAD),
            "slot_capacity": SLOT_META,
        },
        "target_panel": {
            "function_ram": f"0x{PANEL_FUNCTION_RAM:08X}",
            "sole_caller_ram": f"0x{PANEL_CALLER_RAM:08X}",
            "box": {"before": [74, 111, 172, 34], "after": [74, 111, 198, 40]},
            "text_rows_y": {"before": [115, 129], "after": [115, 131]},
            "patches": [
                {
                    "file_offset": f"0x{offset:X}",
                    "before_word": f"0x{before:08X}",
                    "after_word": f"0x{after:08X}",
                    "reason": reason,
                }
                for offset, before, after, reason in PSX_PATCHES
            ],
        },
        "preserved": (
            "V357 Bank-B handler, COMM.IMG, all other dialogue/DAT, E2 caller, "
            "slot +0x7F metadata, E7 icons, cursors, bottom-help paths, member sizes/order"
        ),
        "runtime": "PENDING user cold boot and target-panel/dialogue regression review",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    report = [
        "Arc the Lad 1 V358 dialogue + target-panel fix",
        "status=STATIC BUILD COMPLETE / RUNTIME PENDING / TEST_ONLY",
        f"base={BASE.name} sha256={BASE_SHA256}",
        f"full={full_path.name} sha256={full_hash}",
        f"delta={delta_path.name} sha256={delta_hash}",
        f"changed_members={','.join(changed)}",
        f"changed_bytes={changed_counts} total={len(rows)}",
        f"dialogue={DAT} slot0 {len(OLD_PAYLOAD)}B -> {len(NEW_PAYLOAD)}B; caller 0x{CALLER:X}/metadata 0x{METADATA:02X} preserved",
        "panel=box 74,111,172,34 -> 74,111,198,40; rows 115/129 -> 115/131",
        "PSX.EXE=3 changed bytes only at 0x4C2EC,0x4C2F4,0x4C334",
        "COMM.IMG/all other DAT/E7/icons/cursors/bottom-help=byte exact V357",
        "runtime=PENDING user cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    (ANALYSIS / "runtime_checklist.txt").write_text(
        "V358 TEST_ONLY 콜드부팅 체크리스트\n"
        "1. V358.cue로 완전 콜드부팅한다. V357 RAM 상태를 직접 이어 불러오지 않는다.\n"
        "2. F/SF0F1 장면에서 '산으로 돌아가는 건 다른 볼일이 있어서다.'가 자연스럽게 표시되고 다음 대사로 진행되는지 확인한다.\n"
        "3. 2줄 대상 선택 안내창에서 두 줄이 겹치지 않고 오른쪽이 잘리지 않는지 확인한다.\n"
        "4. 안내창 좌우 약 8px, 상하 약 4px 여백과 둘째 줄 Y=131 배치를 확인한다.\n"
        "5. 전투 하단 도움말의 E7 버튼 아이콘과 글자 위치가 V357과 같은지 확인한다.\n"
        "6. 대상 커서, 선택 커서, 대화창, 아이템/스킬 UI가 V357처럼 동작하는지 회귀 확인한다.\n",
        encoding="utf-8",
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
