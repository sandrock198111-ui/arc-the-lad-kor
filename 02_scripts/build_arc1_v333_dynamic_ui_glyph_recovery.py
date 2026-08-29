#!/usr/bin/env python3
"""Build V333: recover dynamic load/choice/battle UI glyphs on V332.

V332 already preserves the original six-pixel digit path in the synthetic
right-hand strip.  Runtime states show that four neighbouring UI classes still
reach repurposed 16px Hangul planes: load-slot numbers and L/time colon,
E5 choice indentation, and the battle HUD L/M/P labels.  This build extends
the proven strip by four planes and redirects only those exact producers.

No global character/lookup mapping is changed.  Ordinary Hangul, translated
UI strings, DAT members, the compact digit geometry and V332 alignment are
preserved byte-for-byte.
"""

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

import build_arc1_v324_static_ui_cursor_recovery as v324  # noqa: E402
import build_arc1_v320_hanme_static_recovery as v320  # noqa: E402
import build_arc1_v326_compact_ui_recovery as v326  # noqa: E402


BASE = ROOT / "03_output/arc1_v332_skill_config_bar_alignment_TEST_ONLY_D2951A33.zip"
BASE_SHA256 = "D2951A33C598C04BDDDCDC07678ADADCC18471CE98FE32B904527073445BB5AF"
BASE_PSX_SHA256 = "394CF9F98A4A4E95B3DD953EA8C72ADADE26B1A404382B8342794213F8178751"
BASE_COMM_SHA256 = "1D964EF01C21F83696F7292219D88EDE58B95CAF055474C02E2621B261ABAA21"

ORIGINAL = ROOT / "00_original/arc.zip"
ORIGINAL_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"
ORIGINAL_COMM_SHA256 = "6C7565B6C326A99A29266482868F17A144FF7D15B871D7D8F8B852EC41014A26"

OUTPUT_STEM = "arc1_v333_dynamic_ui_glyph_recovery_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v332"
ANALYSIS = ROOT / "01_work/analysis/arc1_v333_dynamic_ui_glyph_recovery"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
RAM_TO_FILE = 0x8011A800
ROW_BYTES = 896

# V326's synthetic strip.  Slots 0..12 are immutable.  V333 fills only the
# previously blank slots 13..16, so the final slot begins at V=240 and still
# satisfies V+16 <= 256.
SYNTH_BASE = 960
OLD_SYNTH_COUNT = 13
NEW_SYNTH_COUNT = 17
STRIP_X = 240
STRIP_Y = 176
STRIP_CELL = 16
SOURCE_CELL = 12

# slot, semantic, original 12px physical source
NEW_STRIP_GLYPHS = (
    (13, "compact_L", 825),
    (14, "hud_M", 553),
    (15, "hud_P", 363),
    (16, "time_colon", 36),
)

# Extend the inherited UV helper eligibility from slots 0..12 to 0..16.
UV_COUNT_FILE = 0x80918
UV_COUNT_OLD = 0x2D09000D  # sltiu t1,t0,13
UV_COUNT_NEW = 0x2D090011  # sltiu t1,t0,17

# E5 emits state+0x1D-1 direct glyph packets.  It must emit a synthetic blank,
# not physical 0 (now Hangul '다').
E5_PLACEHOLDER_FILE = 0x51604
E5_PLACEHOLDER_OLD = 0x00002021  # move a0,zero
E5_PLACEHOLDER_NEW = 0x340403C0  # ori a0,zero,960
E5_JAL_FILE = 0x51608
E5_JAL_WORD = 0x0C05AD46          # jal 0x8016B518
E5_DELAY_WORD = 0x02002821        # move a1,s0

# Programmatic load-list strings and pointer.
LOAD_SLOT_FILES = (0x78090, 0x78094, 0x78098)
LOAD_SLOT_OLD = (b"\x12\0\0\0", b"\x13\0\0\0", b"\x14\0\0\0")
LOAD_L_POINTER_FILE = 0x780FC
LOAD_L_POINTER_OLD = 0x8019C968
LOAD_COLON_FILE = 0x78240
LOAD_COLON_OLD = b"\x25\0\0\0"

# Five hardcoded battle-HUD strings.  The third auxiliary pointer is unrelated
# and remains byte exact.  Pointer two is the historically unused V tail and
# is restored to an explicit empty string.
HUD_POINTERS = (0x823AC, 0x823B0, 0x823B4, 0x823B8, 0x823BC)
HUD_POINTERS_OLD = (
    0x8019C954,
    0x8019C968,
    0x8019C95C,
    0x8019C960,
    0x8019C964,
)
HUD_AUX_PAYLOAD = b"\xDD\xB2\0\0"

# V332 leaves this verified pool tail entirely zero and with no pointer hits.
FREE_START = 0x809E0
FREE_END = 0x80A94
HUD_L_FILE = 0x809E0
HUD_M_FILE = 0x809E8
HUD_P_FILE = 0x809F0
LOAD_L_FILE = 0x809F4
EMPTY_FILE = 0x809F8


class BuildError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def changed_offsets(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise BuildError("member size changed")
    return {
        offset
        for offset, (old, new) in enumerate(zip(before, after, strict=True))
        if old != new
    }


def encode(index: int) -> bytes:
    token = v320.encode_index(index)
    if token is None or len(token) != 2:
        raise BuildError(f"synthetic index is not a safe two-byte token: {index}")
    return token


def pixel_nibble(comm: bytes | bytearray, x: int, y: int) -> int:
    at = y * ROW_BYTES + x // 2
    return (comm[at] >> (0 if x % 2 == 0 else 4)) & 0xF


def set_plane_pixel(
    comm: bytearray, x: int, y: int, plane: int, enabled: bool
) -> None:
    at = y * ROW_BYTES + x // 2
    shift = 0 if x % 2 == 0 else 4
    nibble = (comm[at] >> shift) & 0xF
    bit = 1 << plane
    nibble = (nibble | bit) if enabled else (nibble & (~bit & 0xF))
    if shift == 0:
        comm[at] = (comm[at] & 0xF0) | nibble
    else:
        comm[at] = (comm[at] & 0x0F) | (nibble << 4)


def read_strip_plane(comm: bytes | bytearray, slot: int) -> tuple[int, ...]:
    plane = slot & 3
    base_y = STRIP_Y + (slot >> 2) * STRIP_CELL
    rows: list[int] = []
    for y in range(STRIP_CELL):
        value = 0
        for x in range(STRIP_CELL):
            if pixel_nibble(comm, STRIP_X + x, base_y + y) & (1 << plane):
                value |= 1 << (STRIP_CELL - 1 - x)
        rows.append(value)
    return tuple(rows)


def padded_source(rows: tuple[int, ...]) -> tuple[int, ...]:
    if len(rows) != SOURCE_CELL:
        raise BuildError("source plane height drift")
    # The original reader stores bit 11 at x=0.  Shift into a 16px row while
    # retaining the exact left alignment used by V326.
    return tuple(value << (STRIP_CELL - SOURCE_CELL) for value in rows) + (0,) * 4


def write_extended_strip(
    base_comm: bytes, original_comm: bytes
) -> tuple[bytes, list[dict[str, object]]]:
    comm = bytearray(base_comm)

    # Existing V326 strip is an immutable canary.
    inherited = [read_strip_plane(base_comm, slot) for slot in range(OLD_SYNTH_COUNT)]

    rows: list[dict[str, object]] = []
    for slot, semantic, source_index in NEW_STRIP_GLYPHS:
        before_planes = {
            plane: read_strip_plane(comm, (slot & ~3) | plane)
            for plane in range(4)
        }
        if any(read_strip_plane(comm, slot)):
            raise BuildError(f"synthetic target plane {slot} is not blank")

        plane = slot & 3
        base_y = STRIP_Y + (slot >> 2) * STRIP_CELL
        source_rows = v326.read_original_plane(original_comm, source_index)
        for y in range(STRIP_CELL):
            for x in range(STRIP_CELL):
                enabled = (
                    y < SOURCE_CELL
                    and x < SOURCE_CELL
                    and bool(source_rows[y] & (1 << (SOURCE_CELL - 1 - x)))
                )
                set_plane_pixel(comm, STRIP_X + x, base_y + y, plane, enabled)

        expected = padded_source(source_rows)
        if read_strip_plane(comm, slot) != expected:
            raise BuildError(f"synthetic plane readback failed: {slot}/{semantic}")
        for neighbor in range(4):
            if neighbor == plane:
                continue
            if read_strip_plane(comm, (slot & ~3) | neighbor) != before_planes[neighbor]:
                raise BuildError(f"neighbor plane changed at slot {slot}, plane {neighbor}")

        rows.append(
            {
                "slot": slot,
                "synthetic_index": SYNTH_BASE + slot,
                "semantic": semantic,
                "source_original_index": source_index,
                "plane": plane,
                "texture_u_d14": STRIP_X,
                "texture_u_d6": STRIP_X + 4,
                "texture_v": base_y,
                "source_sha256": sha256_bytes(struct.pack(">12H", *source_rows)),
            }
        )

    if [read_strip_plane(comm, slot) for slot in range(OLD_SYNTH_COUNT)] != inherited:
        raise BuildError("inherited compact strip changed")
    return bytes(comm), rows


def pointer_hits(exe: bytes, start: int, end: int) -> list[tuple[int, int]]:
    hits: list[tuple[int, int]] = []
    for offset in range(0, len(exe) - 3, 4):
        value = struct.unpack_from("<I", exe, offset)[0]
        target = value - RAM_TO_FILE
        if start <= target < end:
            hits.append((offset, target))
    return hits


def assert_base(exe: bytes, comm: bytes) -> None:
    if sha256_bytes(exe) != BASE_PSX_SHA256 or sha256_bytes(comm) != BASE_COMM_SHA256:
        raise BuildError("V332 member hash drift")
    if struct.unpack_from("<I", exe, UV_COUNT_FILE)[0] != UV_COUNT_OLD:
        raise BuildError("UV helper count premise drift")
    if struct.unpack_from("<3I", exe, E5_PLACEHOLDER_FILE) != (
        E5_PLACEHOLDER_OLD,
        E5_JAL_WORD,
        E5_DELAY_WORD,
    ):
        raise BuildError("E5 placeholder/JAL context drift")
    for offset, expected in zip(LOAD_SLOT_FILES, LOAD_SLOT_OLD, strict=True):
        if exe[offset : offset + 4] != expected:
            raise BuildError(f"load slot source drift at 0x{offset:X}")
    if struct.unpack_from("<I", exe, LOAD_L_POINTER_FILE)[0] != LOAD_L_POINTER_OLD:
        raise BuildError("load L pointer premise drift")
    if exe[LOAD_COLON_FILE : LOAD_COLON_FILE + 4] != LOAD_COLON_OLD:
        raise BuildError("load colon source drift")
    if struct.unpack_from("<5I", exe, HUD_POINTERS[0]) != HUD_POINTERS_OLD:
        raise BuildError("battle HUD pointer premise drift")
    aux_file = HUD_POINTERS_OLD[2] - RAM_TO_FILE
    if exe[aux_file : aux_file + 4] != HUD_AUX_PAYLOAD:
        raise BuildError("battle HUD auxiliary payload drift")
    if any(exe[FREE_START:FREE_END]) or pointer_hits(exe, FREE_START, FREE_END):
        raise BuildError("verified V332 free pool tail is no longer free")

    # Slots 13..16 must be blank before the write.  Slot 16 is the final
    # addressable 16px row: U+16 and V+16 both equal 256.
    for slot, _semantic, _source in NEW_STRIP_GLYPHS:
        if any(read_strip_plane(comm, slot)):
            raise BuildError(f"base synthetic target {slot} is not blank")
        v = STRIP_Y + (slot >> 2) * STRIP_CELL
        if STRIP_X + STRIP_CELL > 256 or v + STRIP_CELL > 256:
            raise BuildError(f"synthetic target outside 8-bit UV page: {slot}")


def build_once(
    before: dict[str, bytes], original_comm: bytes
) -> tuple[dict[str, bytes], dict[str, object]]:
    exe = bytearray(before[PSX])
    assert_base(bytes(exe), before[COMM])

    comm, strip_rows = write_extended_strip(before[COMM], original_comm)

    struct.pack_into("<I", exe, UV_COUNT_FILE, UV_COUNT_NEW)
    struct.pack_into("<I", exe, E5_PLACEHOLDER_FILE, E5_PLACEHOLDER_NEW)

    # Load slot numbers reuse V326's digit planes 3/4/5 (= 1/2/3).
    for offset, synthetic in zip(LOAD_SLOT_FILES, (963, 964, 965), strict=True):
        payload = encode(synthetic) + b"\0\0"
        exe[offset : offset + 4] = payload

    hud_l = encode(960) + encode(973) + b"\0"
    hud_m = encode(960) + encode(974) + b"\0"
    hud_p = encode(975) + b"\0"
    load_l = encode(973) + b"\0"
    payloads = (
        (HUD_L_FILE, hud_l),
        (HUD_M_FILE, hud_m),
        (HUD_P_FILE, hud_p),
        (LOAD_L_FILE, load_l),
    )
    for offset, payload in payloads:
        exe[offset : offset + len(payload)] = payload

    # Explicit NUL target for the unused legacy V tail.
    exe[EMPTY_FILE] = 0

    struct.pack_into("<I", exe, LOAD_L_POINTER_FILE, RAM_TO_FILE + LOAD_L_FILE)
    exe[LOAD_COLON_FILE : LOAD_COLON_FILE + 4] = encode(976) + b"\0\0"

    hud_new = (
        RAM_TO_FILE + HUD_L_FILE,
        RAM_TO_FILE + EMPTY_FILE,
        HUD_POINTERS_OLD[2],
        RAM_TO_FILE + HUD_M_FILE,
        RAM_TO_FILE + HUD_P_FILE,
    )
    struct.pack_into("<5I", exe, HUD_POINTERS[0], *hud_new)

    # Readback every local route; the global E9/EA lookup remains immutable.
    if struct.unpack_from("<I", exe, UV_COUNT_FILE)[0] != UV_COUNT_NEW:
        raise BuildError("UV helper count writeback failed")
    if struct.unpack_from("<I", exe, E5_PLACEHOLDER_FILE)[0] != E5_PLACEHOLDER_NEW:
        raise BuildError("E5 placeholder writeback failed")
    if struct.unpack_from("<5I", exe, HUD_POINTERS[0]) != hud_new:
        raise BuildError("HUD pointer writeback failed")
    if struct.unpack_from("<I", exe, LOAD_L_POINTER_FILE)[0] != RAM_TO_FILE + LOAD_L_FILE:
        raise BuildError("load L pointer writeback failed")
    for offset, payload in payloads:
        if exe[offset : offset + len(payload)] != payload:
            raise BuildError(f"new payload readback failed at 0x{offset:X}")

    final = dict(before)
    final[PSX] = bytes(exe)
    final[COMM] = comm
    metadata = {
        "strip_rows": strip_rows,
        "hud_pointers": [f"0x{value:08X}" for value in hud_new],
        "load_slot_indices": [963, 964, 965],
        "load_l_index": 973,
        "load_colon_index": 976,
        "e5_placeholder_index": 960,
    }
    return final, metadata


def main() -> None:
    if not BASE.is_file() or v324.sha256_file(BASE) != BASE_SHA256:
        raise BuildError(f"V332 base hash mismatch: {BASE}")
    if not ORIGINAL.is_file() or v324.sha256_file(ORIGINAL) != ORIGINAL_SHA256:
        raise BuildError(f"original archive hash mismatch: {ORIGINAL}")

    infos, before = v324.read_archive(BASE)
    with ZipFile(ORIGINAL) as archive:
        original_comm = archive.read(COMM)
    if sha256_bytes(original_comm) != ORIGINAL_COMM_SHA256:
        raise BuildError("original COMM.IMG hash mismatch")
    if len(before) != 164:
        raise BuildError(f"V332 member count drift: {len(before)}")

    final, metadata = build_once(before, original_comm)
    rebuilt, rebuilt_metadata = build_once(before, original_comm)
    if final != rebuilt or metadata != rebuilt_metadata:
        raise BuildError("in-memory deterministic rebuild mismatch")

    changed_members = [name for name in before if before[name] != final[name]]
    if set(changed_members) != {PSX, COMM} or len(changed_members) != 2:
        raise BuildError(f"changed member set drift: {changed_members}")
    if any(len(before[name]) != len(final[name]) for name in before):
        raise BuildError("member size changed")

    psx_changed = changed_offsets(before[PSX], final[PSX])
    comm_changed = changed_offsets(before[COMM], final[COMM])

    psx_envelope = set(range(UV_COUNT_FILE, UV_COUNT_FILE + 4))
    psx_envelope |= set(range(E5_PLACEHOLDER_FILE, E5_PLACEHOLDER_FILE + 4))
    for offset in LOAD_SLOT_FILES:
        psx_envelope |= set(range(offset, offset + 4))
    psx_envelope |= set(range(LOAD_L_POINTER_FILE, LOAD_L_POINTER_FILE + 4))
    psx_envelope |= set(range(LOAD_COLON_FILE, LOAD_COLON_FILE + 4))
    psx_envelope |= set(range(HUD_POINTERS[0], HUD_POINTERS[-1] + 4))
    psx_envelope |= set(range(FREE_START, EMPTY_FILE + 1))
    if not psx_changed <= psx_envelope:
        raise BuildError(f"PSX Expected-Write escape: {sorted(psx_changed - psx_envelope)[:8]}")

    comm_envelope: set[int] = set()
    for slot, _semantic, _source in NEW_STRIP_GLYPHS:
        base_y = STRIP_Y + (slot >> 2) * STRIP_CELL
        for y in range(base_y, base_y + STRIP_CELL):
            comm_envelope.update(range(y * ROW_BYTES + STRIP_X // 2, y * ROW_BYTES + 128))
    if not comm_changed <= comm_envelope:
        raise BuildError(f"COMM Expected-Write escape: {sorted(comm_changed - comm_envelope)[:8]}")

    output_path, output_hash = v324.write_archive(OUTPUT_STEM, infos, final, None)
    delta_path, delta_hash = v324.write_archive(
        DELTA_STEM, infos, final, {PSX, COMM}
    )
    with ZipFile(output_path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        expected_names = [item.filename for item in infos if not item.is_dir()]
        if names != expected_names or any(archive.read(name) != final[name] for name in final):
            raise BuildError("full ZIP round-trip/topology mismatch")
    with ZipFile(delta_path) as archive:
        if archive.namelist() != [name for name in final if name in {PSX, COMM}]:
            raise BuildError("delta ZIP topology mismatch")
        if any(archive.read(name) != final[name] for name in archive.namelist()):
            raise BuildError("delta ZIP payload mismatch")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    with (ANALYSIS / "expected_writes.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow(("member", "offset", "before", "after", "region"))
        for member, offsets in ((PSX, psx_changed), (COMM, comm_changed)):
            for offset in sorted(offsets):
                if member == COMM:
                    region = "synthetic_strip_slots_13_to_16"
                elif FREE_START <= offset <= EMPTY_FILE:
                    region = "dynamic_ui_payload_pool"
                elif offset == E5_PLACEHOLDER_FILE:
                    region = "E5_placeholder_0_to_960"
                elif offset == UV_COUNT_FILE:
                    region = "UV_synthetic_count_13_to_17"
                else:
                    region = "dynamic_UI_local_route"
                writer.writerow(
                    (
                        member,
                        f"0x{offset:X}",
                        f"{before[member][offset]:02X}",
                        f"{final[member][offset]:02X}",
                        region,
                    )
                )

    with (ANALYSIS / "synthetic_glyphs.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(metadata["strip_rows"][0]))
        writer.writeheader()
        writer.writerows(metadata["strip_rows"])

    manifest = {
        "build": "V333 TEST_ONLY dynamic UI glyph recovery",
        "base": {"path": str(BASE), "sha256": BASE_SHA256},
        "output": {"path": str(output_path), "sha256": output_hash},
        "delta": {"path": str(delta_path), "sha256": delta_hash},
        "changed_members": changed_members,
        "changed_bytes": {PSX: len(psx_changed), COMM: len(comm_changed)},
        "routes": metadata,
        "expected_runtime": {
            "load": "slot 1/2/3, L, compact level/time digits and colon",
            "choice": "two invisible 14px placeholders; no visible 다다",
            "battle_hud": "compact L and digits, blank spacer, M/P, HP orb and counters",
        },
        "preserved": (
            "all DAT, V332 skill/config alignment, ordinary Hangul/E9-EA lookup, "
            "six-pixel compact digits, icons and every non-PSX/COMM member"
        ),
        "runtime": (
            "FAIL: V333 writes 0xF4DFE7DF at live delay slot 0x8019B1E0; "
            "user state 7A1C1499... captured Reserved Instruction with BD=1"
        ),
        "release_status": "DO NOT USE; superseded by V334 delay-slot repair",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V333 TEST ONLY - dynamic UI glyph recovery",
        f"base={BASE.name}",
        f"output={output_path.name}",
        f"sha256={output_hash}",
        f"delta={delta_path.name}",
        f"delta_sha256={delta_hash}",
        "changed_members=PSX.EXE, COMM.IMG",
        f"changed_bytes=PSX.EXE {len(psx_changed)} / COMM.IMG {len(comm_changed)}",
        "load=local slot-number/L/colon routes only; compact numeric formatting retained",
        "choice=E5 physical0 -> synthetic blank960; two-slot 28px indentation retained",
        "battle_hud=local blank/L/M/P payloads; compact digits and HP orb retained",
        "ordinary Hangul, global lookup, DAT and V332 alignment=unchanged",
        "runtime=FAIL; 0x8019B1E0 live delay-slot overwrite; DO NOT USE",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
