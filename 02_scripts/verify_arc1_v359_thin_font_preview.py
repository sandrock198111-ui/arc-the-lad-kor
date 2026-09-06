#!/usr/bin/env python3
"""Independent static verifier for the V359 full Thin-font TEST_ONLY build."""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import sys
from collections import defaultdict
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v320_hanme_static_recovery as low  # noqa: E402
import build_arc1_v320c_hanme_official_beol as official  # noqa: E402


BASE = ROOT / "03_output/arc1_v359_e7_semantic_text_repair_TEST_ONLY_7D6B0F1B.zip"
FULL = ROOT / "03_output/arc1_v359_thin_font_all_TEST_ONLY_D38CAB43.zip"
DELTA = ROOT / "03_output/arc1_v359_thin_font_all_TEST_ONLY_COMM_delta_from_v359_40E86013.zip"
FONT_ARCHIVE = Path(
    r"C:\Users\Administrator\.paseo\uploads\upload_1a60438a-45e6-4b32-b9dc-d1cdec784af5"
    r"\8x4x4-fonts-all.zip"
)
ATLAS = ROOT / "01_work/analysis/arc1_v319_pilgi16_integration/atlas_mapping.csv"
ASSIGNMENTS = ROOT / "01_work/analysis/arc1_v320_hanme_static_recovery/character_assignments.csv"
ANALYSIS = ROOT / "01_work/analysis/arc1_v359_thin_font_all"

BASE_SHA = "7D6B0F1B6A3C5A35B0EF61DF358278E46B261A496C57F1027D03D836AA9D6EC0"
FULL_SHA = "D38CAB437797F649819E4D777C0C6344C67351D5EB5BFFAB812F22C4F71B821A"
DELTA_SHA = "40E860132A39D9FA24323B6345368C2CB30129B276CFC598AADC97952FEABAE5"
FONT_SHA = "31084434DC45D383B21A8A3BE10A47869BB31E92D7C2C5AEEF91BD439D956A78"
THIN_TTF_SHA = "0B8DEBDD6FDEFACCD68FE1BC077D113ABF04F22644B68A807BF50B4ECE813B8C"
HANME_TTF_SHA = "1E025C5F01A60C8A409D0814884A30F40EA210EB4636209ACBDBE2F0651EEF06"
THIN_PIECES_SHA = "F6CC99A24127C98D935DD73B32A20D1AF51CBD2485A6B9B0D4DE6335E258D956"
HANME_PIECES_SHA = "409ABA72F4BA2282AA5C4E4982A9EEA16FBD14FB0413A40E151537A6653E2904"
COMM = "COMM.IMG"

SPECIAL = {
    170: "\uad04",
    762: "\ubc40",
    819: "\uc13c",
    823: "\ucca9",
    865: "\ud0d1",
}


def sha(value: bytes | Path) -> str:
    data = value.read_bytes() if isinstance(value, Path) else value
    return hashlib.sha256(data).hexdigest().upper()


def is_hangul(value: str) -> bool:
    return len(value) == 1 and 0xAC00 <= ord(value) <= 0xD7A3


def raster(ttf: bytes) -> tuple[tuple[int, ...], ...]:
    font = ImageFont.truetype(BytesIO(ttf), 16)
    result = []
    for glyph in range(360):
        image = Image.new("L", (16, 16), 0)
        ImageDraw.Draw(image).text((0, 0), chr(0xF600 + glyph), font=font, fill=255)
        result.append(tuple(
            sum(1 << (15 - x) for x in range(16) if image.getpixel((x, y)) > 96)
            for y in range(16)
        ))
    return tuple(result)


def piece_sha(pieces: tuple[tuple[int, ...], ...]) -> str:
    return sha(b"".join(struct.pack(">16H", *rows) for rows in pieces))


def expected_thin_rows(
    pieces: tuple[tuple[int, ...], ...], ch: str
) -> tuple[int, ...]:
    """Independently reproduce the approved ㅇ+ㅔ separation correction."""
    rows = list(official.compose(pieces, ch, official=True))
    syllable = ord(ch) - 0xAC00
    cho = syllable // 588
    jung = (syllable % 588) // 28
    jong = syllable % 28
    if cho != 11 or jung != 5:
        return tuple(rows)

    old_edge = 8 if jong == 0 else 7
    new_edge = old_edge - 1
    last_side_row = 5 if jong == 0 else 4
    for y in range(2, last_side_row + 1):
        rows[y] &= ~(0x8000 >> old_edge)
        rows[y] |= 0x8000 >> new_edge
    rows[4] &= ~((0x8000 >> 7) | (0x8000 >> 8))
    rows[4] |= 0x8000 >> new_edge
    return tuple(rows)


def archives(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        names = [entry.filename for entry in archive.infolist() if not entry.is_dir()]
        return names, {name: archive.read(name) for name in names}


def runtime_target(index: int) -> int:
    if 168 <= index <= 170:
        return 741 + index - 168
    if 804 <= index < 820:
        return index - 643
    return index


def expected_targets() -> dict[int, str]:
    logical: dict[int, str] = {}

    def add(index: int, ch: str) -> None:
        if not is_hangul(ch):
            return
        previous = logical.setdefault(index, ch)
        if previous != ch:
            raise AssertionError(f"identity conflict: {index} {previous!r}/{ch!r}")

    with ATLAS.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != 728:
        raise AssertionError("atlas census drift")
    for ordinal, row in enumerate(rows):
        if int(row["index"]) != ordinal:
            raise AssertionError("atlas order drift")
        add(ordinal, row["char"])

    with ASSIGNMENTS.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != 750:
        raise AssertionError("assignment census drift")
    for row in rows:
        add(int(row["physical_index"]), row["char"])
    logical.update(SPECIAL)
    if len(logical) != 723 or len(set(logical.values())) != 690:
        raise AssertionError("logical target census drift")

    actual: dict[int, str] = {}
    for index, ch in logical.items():
        physical = runtime_target(index)
        previous = actual.setdefault(physical, ch)
        if previous != ch:
            raise AssertionError(f"runtime target conflict: {physical}")
    if len(actual) != 723:
        raise AssertionError("runtime target census drift")
    return actual


def collisions(pieces: tuple[tuple[int, ...], ...], chars: list[str]) -> int:
    seen: dict[tuple[int, ...], str] = {}
    duplicates = 0
    for ch in chars:
        rows = expected_thin_rows(pieces, ch)
        first = seen.setdefault(rows, ch)
        duplicates += first != ch
    return duplicates


def main() -> None:
    for path, expected in ((BASE, BASE_SHA), (FULL, FULL_SHA), (DELTA, DELTA_SHA),
                           (FONT_ARCHIVE, FONT_SHA)):
        if not path.is_file() or sha(path) != expected:
            raise AssertionError(f"artifact/input hash drift: {path}")

    old_names, old = archives(BASE)
    new_names, new = archives(FULL)
    delta_names, delta = archives(DELTA)
    if old_names != new_names or len(new_names) != 164 or len(set(new_names)) != 164:
        raise AssertionError("full archive topology/order drift")
    if delta_names != [COMM] or delta[COMM] != new[COMM]:
        raise AssertionError("COMM-only delta mismatch")
    changed_members = [name for name in old_names if old[name] != new[name]]
    if changed_members != [COMM]:
        raise AssertionError(f"changed-member scope drift: {changed_members}")
    if any(len(old[name]) != len(new[name]) for name in old_names):
        raise AssertionError("member size drift")

    with ZipFile(FONT_ARCHIVE) as archive:
        thin_ttf = archive.read("Thin_8x4x4.ttf")
        hanme_ttf = archive.read("Hanme_8x4x4.ttf")
    if sha(thin_ttf) != THIN_TTF_SHA or sha(hanme_ttf) != HANME_TTF_SHA:
        raise AssertionError("font member hash drift")
    thin = raster(thin_ttf)
    hanme = raster(hanme_ttf)
    if piece_sha(thin) != THIN_PIECES_SHA or piece_sha(hanme) != HANME_PIECES_SHA:
        raise AssertionError("font piece raster drift")

    targets = expected_targets()
    corrected = set()
    for physical in range(low.COLS * low.FULL_ROWS * low.PLANES):
        before = low.read_plane(old[COMM], physical)
        after = low.read_plane(new[COMM], physical)
        if physical in targets:
            ch = targets[physical]
            if before != official.compose(hanme, ch, official=True):
                raise AssertionError(f"base Hanme premise drift: {physical}")
            expected = expected_thin_rows(thin, ch)
            if expected != official.compose(thin, ch, official=True):
                corrected.add(ch)
            if after != expected:
                raise AssertionError(f"Thin readback drift: {physical}")
        elif after != before:
            raise AssertionError(f"non-target plane changed: {physical}")

    mapped_collision_count = collisions(thin, sorted(set(targets.values()), key=ord))
    full_collision_count = collisions(
        thin, [chr(codepoint) for codepoint in range(0xAC00, 0xD7A4)]
    )
    if corrected != {chr(cp) for cp in (0xC5D0, 0xC5D1, 0xC5D4, 0xC5D8)}:
        raise AssertionError(f"ㅇ+ㅔ correction scope drift: {sorted(corrected)!r}")
    if mapped_collision_count != 0 or full_collision_count != 19:
        raise AssertionError("Thin collision census drift")

    diffs = [
        (offset, before, after)
        for offset, (before, after) in enumerate(zip(old[COMM], new[COMM], strict=True))
        if before != after
    ]
    if len(diffs) != 9324:
        raise AssertionError(f"COMM changed-byte census drift: {len(diffs)}")
    with (ANALYSIS / "expected_writes.csv").open(encoding="utf-8-sig", newline="") as handle:
        ledger = list(csv.DictReader(handle))
    ledger_set = {
        (int(row["offset"], 16), int(row["before"], 16), int(row["after"], 16))
        for row in ledger
    }
    if len(ledger) != 9324 or ledger_set != set(diffs):
        raise AssertionError("Expected-Write ledger mismatch")

    # Explicit later-feature guards in addition to the all-plane comparison.
    protected = tuple(range(804, 820)) + (738, 774) + tuple(range(960, 1920))
    if any(low.read_plane(old[COMM], index) != low.read_plane(new[COMM], index) for index in protected):
        raise AssertionError("native damage/quotes/high-page compact assets changed")

    result = {
        "identity": "V359 full Thin font candidate (build number unchanged)",
        "result": "PASS_STATIC_RUNTIME_PENDING_TEST_ONLY",
        "full": {"file": FULL.name, "sha256": FULL_SHA},
        "delta": {"file": DELTA.name, "sha256": DELTA_SHA},
        "checks": {
            "archive_topology_order": "PASS 164/164",
            "changed_members": [COMM],
            "expected_writes": "PASS 9324 COMM bytes",
            "font_raster_control": "PASS exact Hanme and Thin component hashes",
            "target_planes": "PASS 723/723 Thin readback",
            "non_target_planes": "PASS 1197/1197 byte-semantic plane preservation",
            "mapped_collisions": 0,
            "full_hangul_collision_extras": 19,
            "ieung_e_correction": "PASS U+C5D0/U+C5D1/U+C5D4/U+C5D8 only",
            "protected_assets": "PASS native damage, quotes, compact digits/icons, E7/high page",
            "psx_dat": "PASS byte exact V359",
        },
        "runtime": "opening scene visually approved except corrected ㅇ+ㅔ join; global PENDING",
    }
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "Arc the Lad 1 V359 full Thin font independent verification",
        "STATIC PASS / RUNTIME PENDING / TEST_ONLY; build number unchanged",
        "archive topology/order: PASS 164/164",
        "changed members: COMM.IMG only; Expected-Write PASS 9324 bytes",
        "font render controls: PASS exact Hanme/Thin component hashes",
        "Thin readback: PASS 723/723 runtime Hangul planes",
        "non-target preservation: PASS 1197/1197 planes",
        "mapped collision: 0; full 11172 collision extras: 19",
        "ㅇ+ㅔ local separation: PASS U+C5D0/U+C5D1/U+C5D4/U+C5D8 only",
        "native damage/quotes/compact digits/icons/E7/high-page assets: PASS preserved",
        "PSX.EXE/all DAT: PASS byte exact V359",
        "runtime: opening scene visually approved except corrected ㅇ+ㅔ join; global PENDING",
    ]
    (ANALYSIS / "independent_verification.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    print("\n".join(lines))


if __name__ == "__main__":
    main()
