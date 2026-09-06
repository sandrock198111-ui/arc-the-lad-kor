#!/usr/bin/env python3
"""Build the V359-numbered TEST_ONLY full Thin 8x4x4 Hangul candidate.

This is deliberately not a new numbered release.  It keeps every V359 member
byte-exact except COMM.IMG and replaces every Hangul plane that the current
renderer can actually address.  The V336 logical-to-runtime relocations are
resolved before writing, so the native damage-number bank at logical physical
804..819 is never overwritten.

Thin's stock ㅇ+ㅔ composition joins the two components at one pixel.  The
mapped 에-family syllables receive a deterministic local separation correction;
the font size, baseline, cell, and game advance are not changed.

The supplied 8x4x4-fonts archive is external input.  Both the archive and the
contained TTF are hash-pinned.  Rasterisation is guarded by first regenerating
the historical Hanme component blob exactly; a Pillow/FreeType stack that
would produce different pixels therefore fails closed before touching output.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import struct
import sys
from collections import defaultdict
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from PIL import Image, ImageDraw, ImageFont, __version__ as PILLOW_VERSION


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v320_hanme_static_recovery as v320  # noqa: E402
import build_arc1_v320c_hanme_official_beol as v320c  # noqa: E402


BASE = ROOT / "03_output/arc1_v359_e7_semantic_text_repair_TEST_ONLY_7D6B0F1B.zip"
BASE_SHA256 = "7D6B0F1B6A3C5A35B0EF61DF358278E46B261A496C57F1027D03D836AA9D6EC0"
BASE_COMM_SHA256 = "A6681F1355007725328372CC6143EF21EEE43A9FDE91FD3DC2EF3461C6805405"
FONT_ARCHIVE_SHA256 = "31084434DC45D383B21A8A3BE10A47869BB31E92D7C2C5AEEF91BD439D956A78"
THIN_MEMBER = "Thin_8x4x4.ttf"
THIN_TTF_SHA256 = "0B8DEBDD6FDEFACCD68FE1BC077D113ABF04F22644B68A807BF50B4ECE813B8C"
HANME_MEMBER = "Hanme_8x4x4.ttf"
HANME_TTF_SHA256 = "1E025C5F01A60C8A409D0814884A30F40EA210EB4636209ACBDBE2F0651EEF06"
HANME_PIECES_SHA256 = "409ABA72F4BA2282AA5C4E4982A9EEA16FBD14FB0413A40E151537A6653E2904"
THIN_PIECES_SHA256 = "F6CC99A24127C98D935DD73B32A20D1AF51CBD2485A6B9B0D4DE6335E258D956"

ASSIGNMENTS = ROOT / "01_work/analysis/arc1_v320_hanme_static_recovery/character_assignments.csv"
ASSIGNMENTS_SHA256 = "933BDAC4BC4C39D33DB134D2FF836902B5053B93725C96E19DED714CB7DE98A4"
ATLAS = ROOT / "01_work/analysis/arc1_v319_pilgi16_integration/atlas_mapping.csv"
ATLAS_SHA256 = "9553E7643621CC80C23355067611EAE7650FEF7CB547DC9115B62157DB0C3122"

OUTPUT_STEM = "arc1_v359_thin_font_all_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_COMM_delta_from_v359"
ANALYSIS = ROOT / "01_work/analysis/arc1_v359_thin_font_all"
OUT = ROOT / "03_output"

COMM = "COMM.IMG"
PSX = "PSX.EXE"
EXPECTED_MEMBERS = 164
EXPECTED_LOGICAL_TARGETS = 723
EXPECTED_UNIQUE_CHARS = 690
EXPECTED_RUNTIME_TARGETS = 723
EXPECTED_TARGET_COLLISIONS = 0
EXPECTED_FULL_HANGUL_COLLISION_EXTRAS = 19
EXPECTED_IEUNG_E_CORRECTIONS = 4

# Later audited additions absent from the frozen V320 identity tables.
SPECIAL_LOGICAL = {
    "\uad04": 170,  # 괄
    "\ubc40": 762,  # 뱀
    "\uc13c": 819,  # 센
    "\ucca9": 823,  # 첩
    "\ud0d1": 865,  # 탑
}


class BuildError(RuntimeError):
    pass


def sha(value: bytes | Path) -> str:
    raw = value.read_bytes() if isinstance(value, Path) else value
    return hashlib.sha256(raw).hexdigest().upper()


def is_hangul(ch: str) -> bool:
    return len(ch) == 1 and 0xAC00 <= ord(ch) <= 0xD7A3


def bitmap_bytes(rows: tuple[int, ...]) -> bytes:
    return struct.pack(">16H", *rows)


def render_pieces(ttf: bytes) -> tuple[tuple[int, ...], ...]:
    """Render the 360 PUA component glyphs with the proven PoC recipe."""
    font = ImageFont.truetype(BytesIO(ttf), 16)
    pieces: list[tuple[int, ...]] = []
    for index in range(360):
        image = Image.new("L", (16, 16), 0)
        ImageDraw.Draw(image).text((0, 0), chr(0xF600 + index), font=font, fill=255)
        rows: list[int] = []
        for y in range(16):
            value = 0
            for x in range(16):
                if image.getpixel((x, y)) > 96:
                    value |= 1 << (15 - x)
            rows.append(value)
        pieces.append(tuple(rows))
    return tuple(pieces)


def pieces_blob(pieces: tuple[tuple[int, ...], ...]) -> bytes:
    return b"".join(bitmap_bytes(rows) for rows in pieces)


def thin_rows(pieces: tuple[tuple[int, ...], ...], ch: str) -> tuple[int, ...]:
    """Compose Thin and separate the stock joined ㅇ+ㅔ components.

    The source font joins the right edge of ㅇ to the left arm of ㅔ.  Narrowing
    that edge by one pixel and shortening the arm by two pixels creates one
    blank column while preserving the 16x16 cell and 14px game advance.
    """
    rows = list(v320c.compose(pieces, ch, official=True))
    value = ord(ch) - 0xAC00
    cho, remainder = divmod(value, 21 * 28)
    jung, jong = divmod(remainder, 28)
    if cho != 11 or jung != 5:  # ㅇ + ㅔ
        return tuple(rows)

    old_right = 8 if jong == 0 else 7
    new_right = old_right - 1
    side_rows = range(2, 6) if jong == 0 else range(2, 5)
    for y in side_rows:
        rows[y] &= ~(1 << (15 - old_right))
        rows[y] |= 1 << (15 - new_right)

    # Original ㅔ arm is x=7..10.  Keep x=9..10; x=8 is the visible gap.
    rows[4] &= ~((1 << (15 - 7)) | (1 << (15 - 8)))
    rows[4] |= 1 << (15 - new_right)
    return tuple(rows)


def runtime_physical(logical: int) -> tuple[int, str]:
    """Apply the current V337 common-gate relocation to a logical index."""
    if 168 <= logical <= 170:
        return 741 + logical - 168, "V336 displaced 168..170 backup"
    if 804 <= logical < 820:
        return logical - 643, "V337 damage-bank text remap 804..819 -> 161..176"
    return logical, "identity"


def load_targets() -> tuple[dict[int, str], dict[int, set[str]], dict[int, tuple[int, str]]]:
    logical: dict[int, str] = {}
    sources: dict[int, set[str]] = defaultdict(set)

    def register(index: int, ch: str, source: str, override: bool = False) -> None:
        if not is_hangul(ch):
            return
        if not 0 <= index < 960:
            raise BuildError(f"logical Hangul outside low page: {index} {ch!r}")
        previous = logical.get(index)
        if previous is not None and previous != ch and not override:
            raise BuildError(f"logical identity conflict at {index}: {previous!r}/{ch!r}")
        logical[index] = ch
        sources[index].add(source)

    with ATLAS.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != 728:
        raise BuildError(f"atlas row census drift: {len(rows)}")
    for expected, row in enumerate(rows):
        index = int(row["index"])
        if index != expected:
            raise BuildError("atlas index/order drift")
        register(index, row["char"], "V319 atlas")

    with ASSIGNMENTS.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != 750:
        raise BuildError(f"assignment row census drift: {len(rows)}")
    for row in rows:
        register(int(row["physical_index"]), row["char"], "V320 assignment")

    for ch, index in SPECIAL_LOGICAL.items():
        register(index, ch, "post-V320 audited addition", override=True)

    if len(logical) != EXPECTED_LOGICAL_TARGETS or len(set(logical.values())) != EXPECTED_UNIQUE_CHARS:
        raise BuildError(
            f"logical target census drift: {len(logical)}/{len(set(logical.values()))}"
        )

    actual: dict[int, tuple[int, str]] = {}
    for logical_index, ch in logical.items():
        physical, reason = runtime_physical(logical_index)
        previous = actual.setdefault(physical, (logical_index, ch))
        if previous != (logical_index, ch):
            raise BuildError(f"runtime physical collision at {physical}: {previous}/{(logical_index, ch)}")
        sources[logical_index].add(reason)
    if len(actual) != EXPECTED_RUNTIME_TARGETS:
        raise BuildError(f"runtime target census drift: {len(actual)}")
    return logical, sources, actual


def clone_info(source: ZipInfo) -> ZipInfo:
    clone = ZipInfo(source.filename, source.date_time)
    for attribute in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(clone, attribute, getattr(source, attribute))
    return clone


def read_archive(path: Path) -> tuple[list[ZipInfo], list[str], dict[str, bytes]]:
    with ZipFile(path) as archive:
        infos = [info for info in archive.infolist() if not info.is_dir()]
        names = [info.filename for info in infos]
        if len(names) != EXPECTED_MEMBERS or len(set(names)) != EXPECTED_MEMBERS:
            raise BuildError("V359 archive topology drift")
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


def finalize(temporary: Path, stem: str) -> tuple[Path, str]:
    digest = sha(temporary)
    output = temporary.with_name(f"{stem}_{digest[:8]}.zip")
    if output.exists():
        if sha(output) != digest:
            raise BuildError(f"refusing to replace a different archive: {output}")
        temporary.unlink()
    else:
        temporary.replace(output)
    return output, digest


def collision_rows(
    pieces: tuple[tuple[int, ...], ...], chars: list[str]
) -> list[tuple[str, str, str]]:
    owners: dict[tuple[int, ...], str] = {}
    collisions: list[tuple[str, str, str]] = []
    for ch in chars:
        rows = thin_rows(pieces, ch)
        first = owners.setdefault(rows, ch)
        if first != ch:
            collisions.append((first, ch, sha(bitmap_bytes(rows))))
    return collisions


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "font_archive", type=Path,
        help="uploaded 8x4x4-fonts-all.zip (hash-pinned by this builder)",
    )
    args = parser.parse_args()
    font_archive = args.font_archive.resolve()

    for path, expected, label in (
        (BASE, BASE_SHA256, "V359 base"),
        (ATLAS, ATLAS_SHA256, "atlas mapping"),
        (ASSIGNMENTS, ASSIGNMENTS_SHA256, "character assignments"),
        (font_archive, FONT_ARCHIVE_SHA256, "font archive"),
    ):
        if not path.is_file() or sha(path) != expected:
            raise BuildError(f"{label} hash drift: {path}")

    with ZipFile(font_archive) as archive:
        thin_ttf = archive.read(THIN_MEMBER)
        hanme_ttf = archive.read(HANME_MEMBER)
    if sha(thin_ttf) != THIN_TTF_SHA256 or sha(hanme_ttf) != HANME_TTF_SHA256:
        raise BuildError("font member hash drift")

    hanme_pieces = render_pieces(hanme_ttf)
    thin_pieces = render_pieces(thin_ttf)
    if sha(pieces_blob(hanme_pieces)) != HANME_PIECES_SHA256:
        raise BuildError("rasterizer differs from the proven Hanme piece extraction")
    if sha(pieces_blob(thin_pieces)) != THIN_PIECES_SHA256:
        raise BuildError("Thin component extraction drift")

    logical, sources, actual = load_targets()
    infos, names, base = read_archive(BASE)
    if sha(base[COMM]) != BASE_COMM_SHA256:
        raise BuildError("V359 COMM hash drift")

    # Fail closed if even one target is no longer the official Hanme bitmap.
    for physical, (_logical, ch) in sorted(actual.items()):
        if v320.read_plane(base[COMM], physical) != v320c.compose(hanme_pieces, ch, official=True):
            raise BuildError(f"current plane ownership drift: {physical} {ch!r}")

    target_collisions = collision_rows(thin_pieces, sorted(set(logical.values()), key=ord))
    if len(target_collisions) != EXPECTED_TARGET_COLLISIONS:
        raise BuildError(f"mapped Thin collision census drift: {len(target_collisions)}")
    all_collisions = collision_rows(
        thin_pieces, [chr(codepoint) for codepoint in range(0xAC00, 0xD7A4)]
    )
    if len(all_collisions) != EXPECTED_FULL_HANGUL_COLLISION_EXTRAS:
        raise BuildError(f"full Thin collision census drift: {len(all_collisions)}")

    comm = bytearray(base[COMM])
    target_rows: dict[int, tuple[int, ...]] = {}
    corrected_chars: set[str] = set()
    for physical, (_logical, ch) in sorted(actual.items()):
        rows = thin_rows(thin_pieces, ch)
        if rows != v320c.compose(thin_pieces, ch, official=True):
            corrected_chars.add(ch)
        v320.put_plane(comm, physical, rows)
        target_rows[physical] = rows
    if len(corrected_chars) != EXPECTED_IEUNG_E_CORRECTIONS:
        raise BuildError(f"ㅇ+ㅔ correction census drift: {sorted(corrected_chars)!r}")

    # All 1,920 planes are checked: target Thin, every non-target plane exact V359.
    for physical in range(v320.COLS * v320.FULL_ROWS * v320.PLANES):
        got = v320.read_plane(comm, physical)
        if physical in target_rows:
            if got != target_rows[physical]:
                raise BuildError(f"Thin readback mismatch: {physical}")
        elif got != v320.read_plane(base[COMM], physical):
            raise BuildError(f"non-target COMM plane changed: {physical}")

    final = dict(base)
    final[COMM] = bytes(comm)
    changed_members = [name for name in names if final[name] != base[name]]
    if changed_members != [COMM]:
        raise BuildError(f"changed-member scope drift: {changed_members}")
    for name in names:
        if len(final[name]) != len(base[name]):
            raise BuildError(f"member size changed: {name}")
        if name != COMM and final[name] != base[name]:
            raise BuildError(f"non-COMM member changed: {name}")
    if final[PSX] != base[PSX]:
        raise BuildError("PSX.EXE changed")

    # Deterministic second in-memory application.
    second = bytearray(base[COMM])
    for physical, rows in sorted(target_rows.items()):
        v320.put_plane(second, physical, rows)
    if bytes(second) != final[COMM]:
        raise BuildError("deterministic COMM rebuild mismatch")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    for path in (OUT / f"{OUTPUT_STEM}.zip", OUT / f"{DELTA_STEM}.zip"):
        if path.exists():
            path.unlink()
    full_temp = OUT / f"{OUTPUT_STEM}.zip"
    delta_temp = OUT / f"{DELTA_STEM}.zip"
    write_archive(full_temp, infos, names, final)
    write_archive(delta_temp, infos, [COMM], final)
    full_path, full_hash = finalize(full_temp, OUTPUT_STEM)
    delta_path, delta_hash = finalize(delta_temp, DELTA_STEM)

    changed_offsets = [
        (offset, before, after)
        for offset, (before, after) in enumerate(zip(base[COMM], final[COMM], strict=True))
        if before != after
    ]
    changed_planes = [
        physical for physical in sorted(target_rows)
        if v320.read_plane(base[COMM], physical) != v320.read_plane(final[COMM], physical)
    ]

    with (ANALYSIS / "glyph_targets.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow((
            "logical_physical", "runtime_physical", "char", "unicode", "sources",
            "hanme_ink", "thin_ink", "hanme_sha256", "thin_sha256", "changed",
        ))
        for physical, (logical_index, ch) in sorted(actual.items()):
            old_rows = v320.read_plane(base[COMM], physical)
            new_rows = target_rows[physical]
            writer.writerow((
                logical_index, physical, ch, f"U+{ord(ch):04X}",
                "; ".join(sorted(sources[logical_index])),
                sum(row.bit_count() for row in old_rows),
                sum(row.bit_count() for row in new_rows),
                sha(bitmap_bytes(old_rows)), sha(bitmap_bytes(new_rows)),
                int(old_rows != new_rows),
            ))

    with (ANALYSIS / "full_hangul_thin_collisions.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow(("first_char", "duplicate_char", "bitmap_sha256"))
        writer.writerows(all_collisions)

    with (ANALYSIS / "expected_writes.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("member", "offset", "before", "after", "reason"))
        for offset, before, after in changed_offsets:
            writer.writerow((COMM, f"0x{offset:X}", f"{before:02X}", f"{after:02X}",
                             "mapped Hangul Hanme -> Thin full candidate"))

    manifest = {
        "identity": "V359 full Thin font candidate (build number intentionally unchanged)",
        "status": "STATIC_BUILD_COMPLETE_RUNTIME_PENDING_TEST_ONLY",
        "base": {"file": BASE.name, "sha256": BASE_SHA256},
        "font_input": {
            "archive": font_archive.name, "archive_sha256": FONT_ARCHIVE_SHA256,
            "thin_member": THIN_MEMBER, "thin_ttf_sha256": THIN_TTF_SHA256,
            "thin_pieces_sha256": THIN_PIECES_SHA256,
            "hanme_control_member": HANME_MEMBER,
            "hanme_control_pieces_sha256": HANME_PIECES_SHA256,
            "pillow_version": PILLOW_VERSION, "size": 16, "threshold": 96,
        },
        "output": {"file": full_path.name, "sha256": full_hash},
        "delta": {"file": delta_path.name, "sha256": delta_hash},
        "changed_members_vs_v359": changed_members,
        "changed_bytes": {COMM: len(changed_offsets)},
        "glyph_scope": {
            "logical_physical_targets": len(logical),
            "runtime_physical_targets": len(actual),
            "unique_hangul": len(set(logical.values())),
            "changed_planes": len(changed_planes),
            "mapped_thin_collisions": len(target_collisions),
            "full_11172_collision_extras": len(all_collisions),
            "ieung_e_corrected_chars": sorted(corrected_chars, key=ord),
            "mean_ink_hanme": sum(
                sum(row.bit_count() for row in v320.read_plane(base[COMM], physical))
                for physical in actual
            ) / len(actual),
            "mean_ink_thin": sum(
                sum(row.bit_count() for row in target_rows[physical]) for physical in actual
            ) / len(actual),
        },
        "preserved": (
            "PSX.EXE, all 163 non-COMM members, all non-target COMM planes including "
            "native damage bank 804..819, quotes 738/774, compact digits/icons, E7 assets"
        ),
        "runtime": "opening scene visually approved except corrected ㅇ+ㅔ join; global runtime PENDING",
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "Arc the Lad 1 V359 full Thin font candidate",
        "build number intentionally unchanged; STATIC PASS / RUNTIME PENDING / TEST_ONLY",
        f"base={BASE.name} sha256={BASE_SHA256}",
        f"full={full_path.name} sha256={full_hash}",
        f"delta={delta_path.name} sha256={delta_hash}",
        f"font archive sha256={FONT_ARCHIVE_SHA256}",
        f"Thin TTF/pieces sha256={THIN_TTF_SHA256}/{THIN_PIECES_SHA256}",
        f"Hanme raster control={HANME_PIECES_SHA256} PASS",
        f"targets=logical {len(logical)}, runtime {len(actual)}, unique Hangul {len(set(logical.values()))}",
        f"changed COMM planes={len(changed_planes)}, changed bytes={len(changed_offsets)}",
        f"mean ink Hanme/Thin={manifest['glyph_scope']['mean_ink_hanme']:.3f}/"
        f"{manifest['glyph_scope']['mean_ink_thin']:.3f}",
        f"collisions=mapped {len(target_collisions)}, full 11172 extras {len(all_collisions)}",
        "local Thin correction=ㅇ+ㅔ family "
        + ",".join(f"U+{ord(ch):04X}" for ch in sorted(corrected_chars, key=ord)),
        "changed members=COMM.IMG only; PSX.EXE/DAT/UI logic/control bytes byte-exact V359",
        "runtime=opening scene visually approved except corrected ㅇ+ㅔ join; global runtime PENDING",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
