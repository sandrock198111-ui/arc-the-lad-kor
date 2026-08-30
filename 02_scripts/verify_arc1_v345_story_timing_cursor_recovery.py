#!/usr/bin/env python3
"""Independent byte-level verifier for V345.

This verifier deliberately does not import the V345 builder.  It reconstructs
the permitted writes and checks the story-control and cursor invariants from
pinned archives and literal byte specifications.
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
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = ROOT / "03_output/arc1_v344_location_name_vertical_center_TEST_ONLY_69B3EC07.zip"
V340 = ROOT / "03_output/arc1_v340_battle_choice_ui_geometry_TEST_ONLY_3F63BFD1.zip"
V341 = ROOT / "03_output/arc1_v341_runtime_ui_recovery_TEST_ONLY_FCAF5CFB.zip"
FINAL = ROOT / "03_output/arc1_v345_story_timing_cursor_recovery_TEST_ONLY_AB9A8E99.zip"
DELTA = ROOT / "03_output/arc1_v345_story_timing_cursor_recovery_TEST_ONLY_delta_from_v344_E0C7A923.zip"
PRISTINE = ROOT / "00_original/arc.zip"
ANALYSIS = ROOT / "01_work/analysis/arc1_v345_story_timing_cursor_recovery"

ARCHIVE_HASHES = {
    BASE: "69B3EC07D300C28EF6C7F42588E6B392025F0392AE1207A586562B0D23001886",
    V340: "3F63BFD149A100152DE8B1B3223136CC501AF5AC19E19F443D4519142F9C783E",
    V341: "FCAF5CFB8BAC230A041DC68E9B23B0F6916112D8F5406B2312DD19CE2A4E33D2",
    FINAL: "AB9A8E99707D4E11EF0878E65451AA0DAD441328C6EDE9277E6142A9164BC54D",
    DELTA: "E0C7A92394014ED2C53CE38CB8DDB25829716C5FC89A05A5F2FD0238C6EBBC7F",
}

PSX = "PSX.EXE"
COMM = "COMM.IMG"
S4031 = "4/S4031.DAT"
S4041 = "4/S4041.DAT"
SD031 = "D/SD031.DAT"
CHANGED = [S4031, S4041, PSX]
FINAL_MEMBER_HASHES = {
    PSX: "C4572A888018DC24325E30E6250B60513058C24D74DBF0E1CA95EA2DA1E82AD3",
    COMM: "A6681F1355007725328372CC6143EF21EEE43A9FDE91FD3DC2EF3461C6805405",
    S4031: "8A21D64DCF8955727D5FC96DFE661FB59A9C73568C3E66BC789E880725D2564A",
    S4041: "C770E19C2244F70CF9ECBFD11C776B1777FC4B4A0AB87A14BA415E6AAA32808D",
    SD031: "11DDDE33D07E3E26FDA993E753CFEEE5559679D0A902B1FF20065B9C6AE1B789",
    "4/S4021.DAT": "BB07EE131F48005359B38FDE8E4C8D10A2FF2DE09B6B5862FF1ED503A0C5DC2D",
    "4/S4022.DAT": "6474F028B069A147896E4D41F3301723B64AC8B817E8ADFAF85D3EE65662CB4B",
    "F/SF081.DAT": "7BEA54E4DB7EA72CEFBF1971A926215C45787FF1CE4A10C851646F9D92B93E1C",
}

SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT_COUNT = 64
PAD = 0xA1

S4031_A_AT = 0x47F7A
S4031_A = bytes.fromhex(
    "DD BA 4E D5 A1 7E A1 1A DD 31 0E A1 33 DD 70 03 A1 DD D9 A1 "
    "1C 37 0F A1 24 DD 72 26 A1 83 3D DD A7 A1 94 DD 69 0D A1 A1"
)
S4031_B_AT = 0x48516
S4031_B = bytes.fromhex(
    "DD 0D 09 02 A1 1C 37 0F A1 24 DD 72 0D A1 DD 56 28 0F A1"
)
S4031_SLOT = 34
S4031_TOKEN_AT = SLOT_BASE + S4031_SLOT * SLOT_SIZE + 0x10
S4031_BODY = 0x47FD4

S4041_BODY = 0x47AA4
S4041_SLOT = 4
S4041_SLOT_AT = SLOT_BASE + S4041_SLOT * SLOT_SIZE
S4041_VISIBLE = bytes.fromhex(
    "72 0E A1 DE 04 DD 26 A1 24 DD 52 0D A1 09 06 A1 28 1A B3 A1 "
    "15 A1 74 4E DD 04 A1 47 A1 DE 90 0E A1 DE 17 DE A0 19 DD 05 21"
)
S4041_STOCK = bytes.fromhex(
    "94 23 DD B9 39 1E DD F5 DE FA 2F DE 79 51 1E 7E E6 01 E6 01 "
    "41 1C 61 2F 38 29 21 BE 2A DD E2 23 2E 1F 46 3D 37 E4 79 E4 "
    "3D E4 3D"
)
S4041_NEW_BODY = bytes.fromhex("E2 85") + S4041_STOCK[2:]
S4041_CONTROLS = bytes.fromhex("E4 79 E4 3D E4 3D")

CURSOR_RANGES = (
    (0x2060, bytes.fromhex("64 3F 06 0C")),
    (0x3E14, bytes.fromhex("1F 80 11 3C BC 52 31 26")),
    (0x75590, bytes.fromhex(
        "1F 80 08 3C 58 E0 09 8D 24 E0 0A 95 1F 80 0B 3C BC 52 6B 25 "
        "05 00 2B 15 00 00 00 00 03 00 40 15 E8 FF A4 AF 22 FD 07 08 "
        "00 00 00 00 87 DB 05 08 00 00 00 00"
    )),
    (0x8F0D0, bytes.fromhex(
        "B8 01 A4 8F BC 01 B4 8F 87 DB 05 0C C0 01 B3 8F CC 01 BF 8F "
        "C4 01 B2 8F C8 01 B0 8F 08 00 E0 03 D0 01 BD 27"
    )),
)

V199 = (
    ("4/S4021.DAT", 0x47992, 32, False, ()),
    ("4/S4021.DAT", 0x47AFA, 25, False, ()),
    ("4/S4021.DAT", 0x47B8E, 30, True, ((8, 0xE6, 0x01), (21, 0xE6, 0x01))),
    ("4/S4022.DAT", 0x47A0C, 40, True, ((4, 0xE6, 0x01),)),
    ("4/S4022.DAT", 0x47AFA, 33, True, ((12, 0xE6, 0x01), (21, 0xE6, 0x01))),
    ("4/S4022.DAT", 0x47D34, 37, True, ((4, 0xE6, 0x01), (15, 0xE6, 0x01))),
    ("4/S4022.DAT", 0x47E1E, 26, False, ()),
    ("F/SF081.DAT", 0x479EC, 33, False, ()),
)


class VerifyError(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def word(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def read_archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        return names, {name: archive.read(name) for name in names}


def body(data: bytes, offset: int) -> bytes:
    end = data.find(b"\0", offset)
    if end < 0:
        raise VerifyError(f"unterminated body at 0x{offset:X}")
    return data[offset:end]


def changes(before: bytes, after: bytes) -> set[int]:
    if len(before) != len(after):
        raise VerifyError("member size changed")
    return {
        index for index, (old, new) in enumerate(zip(before, after, strict=True))
        if old != new
    }


def marker_topology(payload: bytes) -> tuple[tuple[int, int, int], ...]:
    return tuple(
        (index, payload[index], payload[index + 1])
        for index in range(len(payload) - 1)
        if payload[index] in (0xE4, 0xE5, 0xE6)
    )


def disk_id(slot: int) -> int:
    return slot + (0x81 if slot < 40 else 0x82)


def references(data: bytes, slot: int) -> list[int]:
    needle = bytes((0xE2, disk_id(slot)))
    cursor = SLOT_BASE + SLOT_COUNT * SLOT_SIZE
    found: list[int] = []
    while True:
        cursor = data.find(needle, cursor)
        if cursor < 0:
            return found
        found.append(cursor)
        cursor += 2


def verify_archives() -> tuple[dict[str, bytes], dict[str, bytes], bytes, bytes, dict[str, bytes]]:
    for path, expected in ARCHIVE_HASHES.items():
        if not path.is_file() or sha(path.read_bytes()) != expected:
            raise VerifyError(f"archive hash drift: {path.name}")
    base_names, base = read_archive(BASE)
    v340_names, v340 = read_archive(V340)
    v341_names, v341 = read_archive(V341)
    final_names, final = read_archive(FINAL)
    delta_names, delta = read_archive(DELTA)
    if len(base_names) != 164 or final_names != base_names:
        raise VerifyError("164-member topology drift")
    if set(v340_names) != set(base_names) or set(v341_names) != set(base_names):
        raise VerifyError("cursor-source archive topology drift")
    if [name for name in base_names if base[name] != final[name]] != CHANGED:
        raise VerifyError("changed-member set/order drift")
    if delta_names != CHANGED or any(delta[name] != final[name] for name in CHANGED):
        raise VerifyError("delta readback drift")
    for name, expected in FINAL_MEMBER_HASHES.items():
        if sha(final[name]) != expected:
            raise VerifyError(f"final member hash drift: {name}")
    if any(len(base[name]) != len(final[name]) for name in base_names):
        raise VerifyError("archive member size drift")
    with ZipFile(PRISTINE) as archive:
        pristine = {S4041: archive.read(S4041)}
    return base, final, v340[PSX], v341[PSX], pristine


def verify_expected_writes(base: dict[str, bytes], final: dict[str, bytes]) -> dict[str, set[int]]:
    actual = {name: changes(base[name], final[name]) for name in CHANGED}
    if {name: len(offsets) for name, offsets in actual.items()} != {
        S4031: 42, S4041: 85, PSX: 64
    }:
        raise VerifyError("changed-byte census drift")
    rows = list(csv.DictReader(
        (ANALYSIS / "expected_writes.csv").open(encoding="utf-8-sig", newline="")
    ))
    stated: dict[str, set[int]] = {name: set() for name in CHANGED}
    for row in rows:
        member = row["member"]
        offset = int(row["offset"], 16)
        if member not in stated:
            raise VerifyError("Expected-Write names an extra member")
        if row["before"] != f"{base[member][offset]:02X}" or row["after"] != f"{final[member][offset]:02X}":
            raise VerifyError(f"Expected-Write readback mismatch: {member} 0x{offset:X}")
        stated[member].add(offset)
    if len(rows) != 191 or stated != actual:
        raise VerifyError("Expected-Write set differs from complete binary diff")
    return actual


def verify_story(base: dict[str, bytes], final: dict[str, bytes], pristine: dict[str, bytes]) -> None:
    s31 = final[S4031]
    if body(s31, S4031_A_AT) != S4031_A or body(s31, S4031_B_AT) != S4031_B:
        raise VerifyError("S4031 in-place wording readback drift")
    if s31[S4031_TOKEN_AT:S4031_TOKEN_AT + 2] != bytes.fromhex("DE 01"):
        raise VerifyError("S4031 서클 token is not physical 475")
    if references(s31, S4031_SLOT) != [S4031_BODY]:
        raise VerifyError("S4031 slot34 owner drift")
    block34 = s31[SLOT_BASE + S4031_SLOT * SLOT_SIZE:SLOT_BASE + (S4031_SLOT + 1) * SLOT_SIZE]
    if block34[-1] != 24:
        raise VerifyError("S4031 slot34 completion drift")

    stock = body(pristine[S4041], S4041_BODY)
    if stock != S4041_STOCK:
        raise VerifyError("pristine S4041 control body drift")
    s41 = final[S4041]
    block4 = s41[S4041_SLOT_AT:S4041_SLOT_AT + SLOT_SIZE]
    if (
        block4[:41] != S4041_VISIBLE
        or block4[41] != 0
        or any(block4[42:127])
        or block4[127] != 35
    ):
        raise VerifyError("S4041 slot4 payload/completion drift")
    if references(s41, S4041_SLOT) != [S4041_BODY]:
        raise VerifyError("S4041 slot4 owner drift")
    if body(s41, S4041_BODY) != S4041_NEW_BODY:
        raise VerifyError("S4041 body is not E2 85 + pristine tail")
    if body(s41, S4041_BODY)[37:] != S4041_CONTROLS or 2 + block4[127] != 37:
        raise VerifyError("S4041 resume arithmetic/final controls drift")
    if body(base[S4041], S4041_BODY)[:41] != S4041_VISIBLE:
        raise VerifyError("S4041 Korean source premise drift")


def verify_cursor(base: dict[str, bytes], final: dict[str, bytes], v340: bytes, v341: bytes) -> None:
    exe = final[PSX]
    allowed: set[int] = set()
    for offset, expected in CURSOR_RANGES:
        size = len(expected)
        allowed.update(range(offset, offset + size))
        if v341[offset:offset + size] != expected or exe[offset:offset + size] != expected:
            raise VerifyError(f"V341 cursor range mismatch at 0x{offset:X}")
        if base[PSX][offset:offset + size] != v340[offset:offset + size]:
            raise VerifyError(f"V344 was not the V340 rollback at 0x{offset:X}")
    if not changes(base[PSX], exe) <= allowed:
        raise VerifyError("PSX diff escaped four cursor ranges")

    # Critical control-flow and owner constants, decoded independently.
    if word(exe, 0x2060) != 0x0C063F64 or word(exe, 0x2064) != 0x26040070:
        raise VerifyError("frame DrawOT gate or its delay slot drift")
    if (word(exe, 0x3E14), word(exe, 0x3E18)) != (0x3C11801F, 0x263152BC):
        raise VerifyError("range owner initializer does not form 0x801F52BC")
    gate_words = tuple(word(exe, 0x75590 + index * 4) for index in range(13))
    if gate_words[3:8] != (0x3C0B801F, 0x256B52BC, 0x152B0005, 0, 0x15400003):
        raise VerifyError("active-owner/active-flag gate drift")
    if gate_words[9:13] != (0x0807FD22, 0, 0x0805DB87, 0):
        raise VerifyError("cursor uploader/fallback tail jumps drift")
    if word(exe, 0x8F0D8) != 0x0C05DB87 or word(exe, 0x8F0F0) != 0x27BD01D0:
        raise VerifyError("uploader DrawOT epilogue drift")

    # Later working-build invariants must survive the V341 range transplant.
    preserved = {
        0x50DF4: 0x08067409,  # V343 RA-safe non-linking hook
        0x82840: 0x0805AD7F,  # V343 tail jump, not jr ra
        0x82844: 0xA4A2002E,  # helper delay slot
        0x51DE8: 0x34020004,  # V344 location-name Y centering
    }
    for offset, expected in preserved.items():
        if word(exe, offset) != expected or word(base[PSX], offset) != expected:
            raise VerifyError(f"post-V341 invariant drift at 0x{offset:X}")


def verify_historical_guards(base: dict[str, bytes], final: dict[str, bytes]) -> None:
    if final[COMM] != base[COMM] or final[SD031] != base[SD031]:
        raise VerifyError("COMM or V210 SD031 changed")
    for name in ("4/S4021.DAT", "4/S4022.DAT", "F/SF081.DAT"):
        if final[name] != base[name]:
            raise VerifyError(f"V199 protected member changed: {name}")
    for name, offset, length, starts_e2, markers in V199:
        payload = body(final[name], offset)
        observed = (len(payload), payload.startswith(b"\xE2"), marker_topology(payload))
        if observed != (length, starts_e2, markers):
            raise VerifyError(f"V199 body topology drift: {name} 0x{offset:X}")
    sd = final[SD031]
    for absolute, expected in (
        (0x45AB8, bytes.fromhex("E6 01")),
        (0x45B42, bytes.fromhex("E6 01")),
        (0x463DF, bytes.fromhex("E4 1F E6 01")),
        (0x463F1, bytes.fromhex("E4 3D")),
        (0x4640D, bytes.fromhex("E4 3D")),
    ):
        if sd[absolute:absolute + len(expected)] != expected:
            raise VerifyError(f"V210 SD031 control drift at 0x{absolute:X}")


def main() -> None:
    base, final, v340, v341, pristine = verify_archives()
    actual = verify_expected_writes(base, final)
    verify_story(base, final, pristine)
    verify_cursor(base, final, v340, v341)
    verify_historical_guards(base, final)

    result = {
        "result": "STATIC_PASS_RUNTIME_PENDING",
        "archives": {path.name: expected for path, expected in ARCHIVE_HASHES.items()},
        "changed_members": CHANGED,
        "changed_bytes": {name: len(actual[name]) for name in CHANGED},
        "S4031": "same-size wording + DE01 physical-475 서클; slot34/meta24 preserved",
        "S4041": "slot4/meta35; E2 85; resume rel37; E4 79/E4 3D/E4 3D restored",
        "range_cursor": "four V341 ranges exact; active owner 0x801F52BC; frame gate and DrawOT epilogue restored",
        "preserved": "V343 RA-safe jump, V344 location Y, V199 bodies, V210 SD031, COMM.IMG",
        "runtime": "PENDING user cold boot; TEST_ONLY",
    }
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "V345 independent static verification: PASS",
        f"full={FINAL.name} sha256={ARCHIVE_HASHES[FINAL]}",
        f"delta={DELTA.name} sha256={ARCHIVE_HASHES[DELTA]}",
        f"PSX.EXE sha256={FINAL_MEMBER_HASHES[PSX]}",
        "archive=164 members; changed=S4031,S4041,PSX only; sizes unchanged",
        "Expected-Write=191/191 exact (42+85+64)",
        "S4031=same-size terminology + physical-475 서클; owner/meta preserved",
        "S4041=slot4 completion35 -> resume rel37 -> E4 79/E4 3D/E4 3D",
        "cursor=V341 four ranges exact; V343 RA-safe hook and V344 location Y preserved",
        "regression=V199 body topology + V210 SD031 controls + COMM.IMG byte exact",
        "runtime=PENDING user cold boot; TEST_ONLY",
    ]
    (ANALYSIS / "independent_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
