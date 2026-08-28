#!/usr/bin/env python3
"""Independent regression verification for V327's one-word $t1 restore."""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import verify_arc1_v326_compact_ui_recovery as v326  # noqa: E402


BASE = ROOT / "03_output/arc1_v326_compact_ui_recovery_TEST_ONLY_B1768404.zip"
FINAL = ROOT / "03_output/arc1_v327_compact_ui_t1_restore_TEST_ONLY_B93E1001.zip"
DELTA = ROOT / "03_output/arc1_v327_compact_ui_t1_restore_TEST_ONLY_delta_from_v326_F4FE1A1F.zip"
V324 = ROOT / "03_output/arc1_v324_static_ui_cursor_recovery_TEST_ONLY_06F7C289.zip"
UI_ROWS = ROOT / "01_work/analysis/arc1_v325_ui_reencode/ui_reencode.csv"
ANALYSIS = ROOT / "01_work/analysis/arc1_v327_compact_ui_t1_restore"

BASE_SHA256 = "B1768404E175886882D49AFD1C34255D532750E3927B8696CD53A1885039D4BE"
FINAL_SHA256 = "B93E100124AA69050DE6F181DB507E43042E20AF52EBEFC0857147D042B117EE"
DELTA_SHA256 = "F4FE1A1F3796233062B3B485F64DBFF2C269284E132E3A0EB88E9715F9DDA8EB"
V324_SHA256 = "06F7C289B593AB2767BA3D3ABC256ACCFD21781F60DF46A18F1D3FF58D67FD4B"

PSX = "PSX.EXE"
RAM_TO_FILE = 0x8011A800
UV_FILE = 0x80910
UV_RAM = 0x8019B110
UV_RETURN = 0x8016B5B0
RESTORE_RAM = 0x8019B140
RESTORE_FILE = RESTORE_RAM - RAM_TO_FILE
EXPECTED_WORD = 0x340900A0
EXPECTED_DIFF = {RESTORE_FILE, RESTORE_FILE + 2, RESTORE_FILE + 3}

STOCK_WORDS = {
    0x8016B524: 0x340900A0,  # ori t1,zero,160
    0x8016B640: 0x14890002,  # bne a0,t1,+2
    0x8016B648: 0x34030006,  # ori v1,zero,6
}
E7_TABLE_FILE = 0x80210
E7_TABLE = bytes.fromhex("62 0C C0 0C B4 0C 0C 0C CC 0C B2 0C C2 0C D8 14 EA 14")
E7_V_HOOK_FILE = 0x8019D000 - RAM_TO_FILE
E7_V_HOOK_WORDS = (
    0x2468FFFE, 0x1100000C, 0x00000000,
    0x2468FFFC, 0x11000009, 0x00000000,
    0x2468FFF8, 0x11000006, 0x00000000,
    0x2468FFF2, 0x11000003, 0x34020082,
    0x0806740F, 0x00000000, 0x340200E4,
    0xA2020029, 0x0805ADB4, 0x00000000,
)
E7_ICONS = (
    (1, 192, 12, 100), # E7 02 / circle
    (2, 180, 12, 112), # E7 03 / square
    (4, 204, 12, 112), # E7 05 / cross
    (7, 216, 20, 240), # E7 08 / START
)
ROW_BYTES = 896


class VerifyError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def read_zip(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        return names, {name: archive.read(name) for name in names}


def changed(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise VerifyError("member size changed")
    return {
        offset
        for offset, (old, new) in enumerate(zip(before, after, strict=True))
        if old != new
    }


def nibble(data: bytes, x: int, y: int) -> int:
    value = data[y * ROW_BYTES + x // 2]
    return (value >> (0 if x % 2 == 0 else 4)) & 0xF


def main() -> None:
    if sha256(BASE.read_bytes()) != BASE_SHA256:
        raise VerifyError("V326 base ZIP hash mismatch")
    if sha256(FINAL.read_bytes()) != FINAL_SHA256:
        raise VerifyError("V327 full ZIP hash mismatch")
    if sha256(DELTA.read_bytes()) != DELTA_SHA256:
        raise VerifyError("V327 delta ZIP hash mismatch")
    if sha256(V324.read_bytes()) != V324_SHA256:
        raise VerifyError("V324 E7 reference ZIP hash mismatch")

    base_names, base = read_zip(BASE)
    final_names, final = read_zip(FINAL)
    if base_names != final_names or len(final_names) != 164:
        raise VerifyError("archive topology mismatch")
    changed_members = [name for name in base_names if base[name] != final[name]]
    if changed_members != [PSX]:
        raise VerifyError(f"changed member set mismatch: {changed_members}")
    with ZipFile(DELTA) as archive:
        if archive.namelist() != [PSX] or archive.read(PSX) != final[PSX]:
            raise VerifyError("delta archive mismatch")

    exe0, exe1 = base[PSX], final[PSX]
    psx_diff = changed(exe0, exe1)
    if psx_diff != EXPECTED_DIFF:
        raise VerifyError(f"one-word Expected-Write mismatch: {sorted(psx_diff)}")
    if struct.unpack_from("<I", exe0, RESTORE_FILE)[0] != 0:
        raise VerifyError("V326 delay-slot premise drift")
    word = struct.unpack_from("<I", exe1, RESTORE_FILE)[0]
    if word != EXPECTED_WORD:
        raise VerifyError(f"restore word mismatch: 0x{word:08X}")
    op, rs, rt, imm = word >> 26, (word >> 21) & 31, (word >> 16) & 31, word & 0xFFFF
    if (op, rs, rt, imm) != (0x0D, 0, 9, 160):
        raise VerifyError("restore instruction does not decode as ori t1,zero,160")
    if struct.unpack_from("<I", exe1, RESTORE_FILE - 4)[0] != 0x0805AD6C:
        raise VerifyError("restore is not in the UV return-jump delay slot")

    for address, expected in STOCK_WORDS.items():
        actual = struct.unpack_from("<I", exe1, address - RAM_TO_FILE)[0]
        if actual != expected:
            raise VerifyError(f"stock t1 contract drift at 0x{address:08X}")

    # The four restored controls must lead to actual, preserved icon pixels,
    # not merely have the right E7 bytes in a string.  The builder doubles the
    # zero-based icon id before entering this V hook; 2/4/8/14 therefore mean
    # E7 02/03/05/08 and all route to V=228.
    if exe1[E7_TABLE_FILE:E7_TABLE_FILE + len(E7_TABLE)] != E7_TABLE:
        raise VerifyError("E7 U/width table drift")
    hook_words = struct.unpack_from(f"<{len(E7_V_HOOK_WORDS)}I", exe1, E7_V_HOOK_FILE)
    if hook_words != E7_V_HOOK_WORDS:
        raise VerifyError("E7 V=228 routing hook drift")
    _v324_names, v324_members = read_zip(V324)
    icon_results: dict[str, dict[str, int]] = {}
    for icon_id, u, width, expected_ink in E7_ICONS:
        old_pixels = [
            nibble(v324_members["COMM.IMG"], x, y)
            for y in range(228, 244) for x in range(u, u + width)
        ]
        new_pixels = [
            nibble(final["COMM.IMG"], x, y)
            for y in range(228, 244) for x in range(u, u + width)
        ]
        if new_pixels != old_pixels:
            raise VerifyError(f"E7 icon {icon_id} pixels differ from V324 accepted source")
        ink = sum(pixel != 0 for pixel in new_pixels)
        if ink != expected_ink:
            raise VerifyError(f"E7 icon {icon_id} ink census drift: {ink}")
        icon_results[str(icon_id)] = {"u": u, "v": 228, "width": width, "ink": ink}

    uv_words = struct.unpack_from(f"<{v326.UV_SIZE // 4}I", exe1, UV_FILE)
    expected_uv = (*v326.EXPECTED_UV_WORDS[:-1], EXPECTED_WORD)
    if uv_words != expected_uv:
        raise VerifyError("V327 UV helper word array mismatch")

    truth: dict[str, dict[str, int]] = {}
    for glyph in (0, 159, 160, 959, *range(960, 973), 973, 1238):
        stop, regs, memory = v326.run_helper(
            uv_words, UV_RAM, {UV_RETURN},
            {2: 0x66, 3: 6, 4: glyph, 5: 0x3000, 9: 160},
        )
        if stop != UV_RETURN or regs[9] != 160:
            raise VerifyError(f"t1 not restored on UV path for glyph {glyph}")
        if memory.get(0x3029) is None:
            raise VerifyError(f"overwritten V store not recreated for glyph {glyph}")
        if 960 <= glyph < 973:
            slot = glyph - 960
            if memory.get(0x3028) != 240 or memory.get(0x3029) != 176 + (slot >> 2) * 16:
                raise VerifyError(f"synthetic UV regression: {glyph}")
        elif memory.get(0x3028) is not None or memory.get(0x3029) != 0x66:
            raise VerifyError(f"stock UV regression: {glyph}")
        advance = 6 if glyph == regs[9] else 14
        if advance != (6 if glyph == 160 else 14):
            raise VerifyError(f"post-helper advance regression: {glyph}")
        truth[str(glyph)] = {"t1_after": regs[9], "advance": advance}

    # This is not a hypothetical edge case: V325's independently generated
    # resident UI set contains 697 encoded A1/physical-160 spaces.
    with UI_ROWS.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    space_count = sum(int(row["space_count"]) for row in rows)
    if len(rows) != 666 or space_count != 697:
        raise VerifyError(f"V325 UI space census drift: {len(rows)}/{space_count}")

    verification = {
        "result": "PASS",
        "hashes": {"base": BASE_SHA256, "final": FINAL_SHA256, "delta": DELTA_SHA256},
        "archive": {"members": len(final_names), "changed_members": changed_members},
        "changed_bytes": {PSX: len(psx_diff)},
        "instruction": {
            "ram": f"0x{RESTORE_RAM:08X}", "word": f"0x{word:08X}",
            "decoded": "ori t1,zero,160", "placement": "j 0x8016B5B0 delay slot",
        },
        "uv_truth_table": truth,
        "stock_blank_contract": "a0==160 -> advance 6; every other tested glyph -> advance 14",
        "affected_resident_UI_spaces_in_V325": space_count,
        "E7_icons": icon_results,
        "inheritance": (
            "V326 full hash anchored; V327 differs in exactly the three changed "
            "bytes of one UV-helper delay-slot word"
        ),
        "runtime": "PENDING user cold boot",
    }
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(verification, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "V327 independent verification: PASS",
        f"full_sha256={FINAL_SHA256}",
        f"delta_sha256={DELTA_SHA256}",
        "archive=164 members; changed=PSX.EXE only",
        "Expected-Write=3 changed bytes in one word at file 0x80940",
        "instruction=ori t1,zero,160 in UV return-jump delay slot",
        "UV paths=boundaries plus synthetic 960..972 all return with t1=160",
        "blank contract=physical160 advances 6px; nonblank samples advance 14px",
        f"impact census=V325 resident UI has {space_count} encoded physical160 spaces",
        "E7 routing=02/03/05/08 -> ids 1/2/4/7 at V228; four pixel rectangles match V324",
        "inheritance=V326 hash anchored; every byte except one delay-slot word preserved",
        "runtime=PENDING cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "independent_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
