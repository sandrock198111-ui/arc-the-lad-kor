#!/usr/bin/env python3
"""Build the broad V319 Pilgi 16px integration test.

This is a deliberately broad TEST_ONLY bridge, not the final clean production
builder.  It keeps all 164 cumulative V318 patch members (translated DAT, E2,
speaker/UI work and the v240 15-column code rewrite), while applying two
independently guarded changes:

1. The historical v240 Hanme atlas is matched back to Unicode by exact 16x16
   bitmap identity.  The 554 identities retained by later analysis artifacts
   are cross-checked against an exhaustive reconstruction of all 11,172 Hangul
   syllables from the original 360-piece Hanme blob.  This recovers all 100
   otherwise unidentified physical slots without guessing, so all 654 inked
   atlas planes are redrawn with the same temporary Pilgi validation face.
2. The v241/v242 geometry is separated correctly: packet W/H stays 16x16,
   cursor and wrap advance are 14, line pitch is 16, and the half-width path
   remains 8.  Dynamic-cache upload and high-page paths stay disabled as in
   V318.

The input font archive and every historical/data input are hash pinned.  The
output remains TEST_ONLY until a cold-boot pass covers dialogue, UI, battle and
world-map transition paths.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import pickle
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "06_tools/python_packages"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import PIL  # noqa: E402
from PIL import Image, ImageDraw, ImageFont, features  # noqa: E402


BASE = ROOT / "03_output/arc1_v318_v241_nocache_recovery_TEST_ONLY_50B30D67.zip"
BASE_SHA256 = "50B30D67FC5856B548A986EB17470AF179EC0E3CFAF595F2291C225F1EF8DFBF"
V240 = ROOT / "03_output/arc1_v240_johab_font_TEST_ONLY_1A307BDE.zip"
V240_SHA256 = "1A307BDE5184763122522BEC3C5A57597C3458E8CC5017321E603550F9F43ED2"
V241 = ROOT / "03_output/arc1_v241_halfwidth_TEST_ONLY_CEC05368.zip"
V241_SHA256 = "CEC0536802239A2B54E383D3C53CF9D648703A25D70F633703FF3E1F900113E1"

ARTIFACT_DIR = ROOT / "01_work/analysis/hangul_johab_16px"
ARTIFACT_HASHES = {
    "composed_16px.pkl": "3B11711E434C1F66BD7E0ABD9E11065E711F22FB8A581ECD01DCDBAA4C479906",
    "ascii_16px.pkl": "36BBEF684D730517042E2174E5D6D12A639D9DDD60E40529E2AEE29C7AE141BB",
    "code_to_char.pkl": "D2FB3A64C3E2203A1012590BEE24A36EAB30D0B5A9691A86BAC518B97A158E23",
    "pieces_1bpp.bin": "409ABA72F4BA2282AA5C4E4982A9EEA16FBD14FB0413A40E151537A6653E2904",
}

FONT_ARCHIVE_SHA256 = "31084434DC45D383B21A8A3BE10A47869BB31E92D7C2C5AEEF91BD439D956A78"
FONT_NAME = "Pilgi_8x4x4.ttf"
FONT_SHA256 = "30EC39649ECBE2DC1E716F0FF7C8793AA364CFB7D5AB37C4401FE0936E1417A9"
FONT_SIZE = 16
THRESHOLD = 96
EXPECTED_PILLOW = "12.3.0"
EXPECTED_FREETYPE = "2.14.3"

OUTPUT_DIR = ROOT / "03_output"
ANALYSIS_DIR = ROOT / "01_work/analysis/arc1_v319_pilgi16_integration"
OUTPUT_STEM = "arc1_v319_pilgi16_integration_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v318"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
RAM_TO_FILE = 0x8011A800
ROW_BYTES = 896
CELL = 16
COLS = 15
PLANES = 4
ATLAS_CELLS = 182
ATLAS_INDICES = ATLAS_CELLS * PLANES
FULL_16PX_ROWS = 512 // CELL
EXPECTED_PATCH_MEMBERS = 164
EXPECTED_COMM_SHA256 = "D0A59E8315A7886A4A5E375D5DBF7E2ABD6B99D7F75A45EF1180E48CE8AE597B"
EXPECTED_ATLAS_INK = 654
EXPECTED_ATLAS_BLANK = 74
EXPECTED_ATLAS_MATCHED = 654
EXPECTED_ATLAS_UNMATCHED = 0
EXPECTED_LEGACY_IDENTIFIED = 554
EXPECTED_HANGUL_IDENTIFIED = 632
EXPECTED_LEGACY_HANGUL_AGREEMENT = 532
EXPECTED_PIECE_RECOVERED = 100
EXPECTED_UNIQUE_RENDERED_CHARS = 626
EXPECTED_HANGUL_SHAPES = 11_172
EXPECTED_SHAPE_AMBIGUITIES = 0

# Historical v240/v247 Hanme composition rule, independently reconstructed
# from pieces_1bpp.bin and checked against all 711 component triples recorded
# in hangul_map.csv (0 disagreements).  hangul_map.csv's new_index/old_index
# columns belong to a later generation and are intentionally not consumed.
# Vowel order: ㅏ ㅐ ㅑ ㅒ ㅓ ㅔ ㅕ ㅖ ㅗ ㅘ ㅙ ㅚ ㅛ ㅜ ㅝ ㅞ ㅟ ㅠ ㅡ ㅢ ㅣ
V240_JUNG_GROUP = (
    0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 3, 1, 2, 3, 3, 3, 2, 1, 3, 0,
)
PIECE_COUNT = 360
EXPECTED_BLANK_PIECES = 16

# Geometry sites in V318.  The main state uses D=14, E=16, F=2, +10=0.
# Packet W is D+F, packet H is E, cursor/wrap use D, and line pitch is E+10.
INIT_WORDS = {
    0x8016B150: (0xA620000A, 0xAE200008),  # sh ord=0 -> sw Y/ord=0
    0x8016B154: (0xA6200008, 0xA2200010),  # freed word -> line extra=0
    0x8016B15C: (0xA220000C, 0xAE20000C),  # clear style/D/E/F together
    0x8016B160: (0x34020010, 0x3402000E),  # D / cursor advance = 14
    0x8016B168: (0xA222000E, 0x34020010),  # load E / packet height = 16
    0x8016B16C: (0xA220000F, 0xA222000E),  # store E
    0x8016B174: (0xA2220010, 0xA222000F),  # F / packet-width correction = 2
}
RESET_WORDS = {
    0x8016B394: (0x34040010, 0x3404000E),  # D=14
    0x8016B39C: (0x00003021, 0x34060002),  # F=2
    0x8016B3A4: (0x34070002, 0x00003821),  # line extra=0
}
PACKET_WORDS = {
    0x8016B5CC: (0x90C2000D, 0x90C3000D),  # lbu v1,D
    0x8016B5D0: (0x00000000, 0x90C1000F),  # lbu at,F
    0x8016B5D4: (0xA0A2002A, 0x90C2000E),  # lbu v0,E
    0x8016B5D8: (0x90C2000E, 0x00611821),  # addu v1,v1,at
    0x8016B5DC: (0x00000000, 0xA0A3002A),  # sb v1,W
    # 0x8016B5E0 remains the original sb v0,H.  A dormant historical helper
    # has a direct edge to this exact address, so its re-entry semantic stays.
}
WRAP_WORDS = {
    0x8016BA24: (0x9205000F, 0x00002821),  # wrap uses D, not private F marker
}
ALL_WORD_EDITS = {**INIT_WORDS, **RESET_WORDS, **PACKET_WORDS, **WRAP_WORDS}

CACHE_UPLOAD_JAL = 0x0C07FD9A


class BuildError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def file_offset(address: int) -> int:
    return address - RAM_TO_FILE


def word(blob: bytes | bytearray, address: int) -> int:
    return struct.unpack_from("<I", blob, file_offset(address))[0]


def clone_zipinfo(info: ZipInfo) -> ZipInfo:
    clone = ZipInfo(info.filename, info.date_time)
    for attribute in (
        "compress_type",
        "comment",
        "extra",
        "create_system",
        "create_version",
        "extract_version",
        "flag_bits",
        "volume",
        "internal_attr",
        "external_attr",
    ):
        setattr(clone, attribute, getattr(info, attribute))
    return clone


def read_archive(path: Path) -> tuple[list[ZipInfo], dict[str, bytes]]:
    with ZipFile(path) as archive:
        infos = archive.infolist()
        if len({info.filename for info in infos}) != len(infos):
            raise BuildError(f"duplicate archive member names: {path}")
        members = {
            info.filename: archive.read(info.filename)
            for info in infos
            if not info.is_dir()
        }
    return infos, members


def write_archive(
    stem: str,
    infos: list[ZipInfo],
    members: dict[str, bytes],
    selected: set[str] | None,
) -> tuple[Path, str]:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    temporary = OUTPUT_DIR / f".{stem}.{os.getpid()}.building.zip"
    if temporary.exists():
        raise BuildError(f"temporary output already exists: {temporary}")
    try:
        with ZipFile(temporary, "w", ZIP_DEFLATED, compresslevel=1) as archive:
            for info in infos:
                if info.is_dir():
                    if selected is None:
                        archive.writestr(clone_zipinfo(info), b"")
                    continue
                if selected is None or info.filename in selected:
                    archive.writestr(clone_zipinfo(info), members[info.filename])
        digest = sha256_file(temporary)
        final = OUTPUT_DIR / f"{stem}_{digest[:8]}.zip"
        if final.exists():
            if sha256_file(final) != digest:
                raise BuildError(f"existing output differs: {final}")
            temporary.unlink()
        else:
            temporary.replace(final)
        return final, digest
    finally:
        if temporary.exists():
            temporary.unlink()


def validate_rows(rows: object, label: str) -> tuple[int, ...]:
    if not isinstance(rows, (tuple, list)) or len(rows) != CELL:
        raise BuildError(f"{label}: expected {CELL} bitmap rows")
    result = tuple(int(value) for value in rows)
    if any(value < 0 or value >= (1 << CELL) for value in result):
        raise BuildError(f"{label}: bitmap row outside 16-bit range")
    return result


def load_historical_pieces(raw: bytes) -> tuple[tuple[int, ...], ...]:
    expected_size = PIECE_COUNT * CELL * 2
    if len(raw) != expected_size:
        raise BuildError(
            f"historical piece blob size drift: {len(raw)} != {expected_size}"
        )
    pieces = tuple(
        tuple(struct.unpack_from(">16H", raw, index * CELL * 2))
        for index in range(PIECE_COUNT)
    )
    expected_blank = (
        {beol * 20 for beol in range(8)}
        | {160 + beol * 22 for beol in range(4)}
        | {248 + beol * 28 for beol in range(4)}
    )
    actual_blank = {index for index, rows in enumerate(pieces) if not any(rows)}
    if actual_blank != expected_blank or len(actual_blank) != EXPECTED_BLANK_PIECES:
        raise BuildError(
            "historical piece layout drift: "
            f"blank slots {sorted(actual_blank)} != {sorted(expected_blank)}"
        )
    return pieces


def synthesize_v240_hangul(
    pieces: tuple[tuple[int, ...], ...], codepoint: int
) -> tuple[int, ...]:
    if not 0xAC00 <= codepoint <= 0xD7A3:
        raise BuildError(f"not a precomposed Hangul syllable: U+{codepoint:04X}")
    value = codepoint - 0xAC00
    cho, remainder = divmod(value, 588)
    jung, jong = divmod(remainder, 28)
    group = V240_JUNG_GROUP[jung]
    cho_beol = group + (4 if jong else 0)
    jung_beol = (1 if cho in (0, 15) else 0) + (2 if jong else 0)
    piece_indices = [
        cho_beol * 20 + cho + 1,
        160 + jung_beol * 22 + jung + 1,
    ]
    if jong:
        piece_indices.append(248 + group * 28 + jong)
    rows = tuple(
        pieces[piece_indices[0]][y]
        | pieces[piece_indices[1]][y]
        | (pieces[piece_indices[2]][y] if jong else 0)
        for y in range(CELL)
    )
    if not any(rows):
        raise BuildError(f"historical synthesis produced blank U+{codepoint:04X}")
    return rows


def read_plane(buf: bytes | bytearray, index: int) -> tuple[int, ...]:
    if not 0 <= index < COLS * FULL_16PX_ROWS * PLANES:
        raise BuildError(f"physical 16px index outside COMM page: {index}")
    cell, plane = divmod(index, PLANES)
    col, row = cell % COLS, cell // COLS
    bit = 1 << plane
    rows: list[int] = []
    for y in range(CELL):
        value = 0
        base = (row * CELL + y) * ROW_BYTES + col * (CELL // 2)
        for x in range(CELL):
            at = base + x // 2
            shift = 0 if x % 2 == 0 else 4
            if ((buf[at] >> shift) & 0x0F) & bit:
                value |= 1 << (CELL - 1 - x)
        rows.append(value)
    return tuple(rows)


def put_plane(buf: bytearray, index: int, rows: tuple[int, ...]) -> None:
    validate_rows(rows, f"put index {index}")
    cell, plane = divmod(index, PLANES)
    col, row = cell % COLS, cell // COLS
    bit = 1 << plane
    for y, source in enumerate(rows):
        base = (row * CELL + y) * ROW_BYTES + col * (CELL // 2)
        for x in range(CELL):
            at = base + x // 2
            shift = 0 if x % 2 == 0 else 4
            nibble = (buf[at] >> shift) & 0x0F
            if (source >> (CELL - 1 - x)) & 1:
                nibble |= bit
            else:
                nibble &= ~bit & 0x0F
            keep = 0xF0 if shift == 0 else 0x0F
            buf[at] = (buf[at] & keep) | (nibble << shift)


def render(face: ImageFont.FreeTypeFont, ch: str) -> tuple[int, ...]:
    image = Image.new("L", (CELL, CELL), 0)
    ImageDraw.Draw(image).text((0, 0), ch, font=face, fill=255)
    pixels = image.load()
    return tuple(
        sum(
            1 << (CELL - 1 - x)
            for x in range(CELL)
            if pixels[x, y] > THRESHOLD
        )
        for y in range(CELL)
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    default_font = os.environ.get("ARC1_FONT_ZIP")
    parser.add_argument(
        "--font-zip",
        type=Path,
        default=Path(default_font) if default_font else None,
        help="8x4x4-fonts-all.zip (or set ARC1_FONT_ZIP)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.font_zip is None:
        raise BuildError("--font-zip is required (or set ARC1_FONT_ZIP)")
    font_zip = args.font_zip.resolve()

    fixed_inputs = (
        (BASE, BASE_SHA256, "V318 base"),
        (V240, V240_SHA256, "historical v240"),
        (V241, V241_SHA256, "historical v241"),
    )
    for path, expected, label in fixed_inputs:
        if not path.is_file() or sha256_file(path) != expected:
            raise BuildError(f"{label} hash mismatch: {path}")
    for name, expected in ARTIFACT_HASHES.items():
        path = ARTIFACT_DIR / name
        if not path.is_file() or sha256_file(path) != expected:
            raise BuildError(f"analysis artifact hash mismatch: {path}")
    if not font_zip.is_file() or sha256_file(font_zip) != FONT_ARCHIVE_SHA256:
        raise BuildError("font archive hash mismatch")
    freetype_version = features.version("freetype2")
    if PIL.__version__ != EXPECTED_PILLOW or freetype_version != EXPECTED_FREETYPE:
        raise BuildError(
            "font renderer version drift: "
            f"Pillow {PIL.__version__}/{EXPECTED_PILLOW}, "
            f"FreeType {freetype_version}/{EXPECTED_FREETYPE}"
        )

    infos, before = read_archive(BASE)
    _v240_infos, v240 = read_archive(V240)
    _v241_infos, v241 = read_archive(V241)
    if len(before) != EXPECTED_PATCH_MEMBERS:
        raise BuildError(f"V318 member count drift: {len(before)}")
    if set(before) != set(v240) or set(before) != set(v241):
        raise BuildError("historical patch archive topology drift")
    if not (before[COMM] == v240[COMM] == v241[COMM]):
        raise BuildError("v240/v241/V318 COMM.IMG is not byte-identical")
    if sha256_bytes(before[COMM]) != EXPECTED_COMM_SHA256:
        raise BuildError("historical 15-column COMM.IMG hash mismatch")

    with ZipFile(font_zip) as archive:
        names = [name for name in archive.namelist() if name.endswith(FONT_NAME)]
        if names != [FONT_NAME]:
            raise BuildError(f"expected exactly {FONT_NAME} at archive root: {names}")
        font_bytes = archive.read(FONT_NAME)
    if sha256_bytes(font_bytes) != FONT_SHA256:
        raise BuildError("Pilgi font hash mismatch")
    face = ImageFont.truetype(io.BytesIO(font_bytes), FONT_SIZE)

    with (ARTIFACT_DIR / "composed_16px.pkl").open("rb") as handle:
        composed = pickle.load(handle)
    with (ARTIFACT_DIR / "ascii_16px.pkl").open("rb") as handle:
        ascii_glyphs = pickle.load(handle)
    with (ARTIFACT_DIR / "code_to_char.pkl").open("rb") as handle:
        code_to_char = pickle.load(handle)

    historical_pieces = load_historical_pieces(
        (ARTIFACT_DIR / "pieces_1bpp.bin").read_bytes()
    )

    legacy_shape_to_chars: dict[tuple[int, ...], set[str]] = {}
    for old_index, rows_object in composed.items():
        ch = code_to_char.get(old_index)
        if isinstance(ch, str) and len(ch) == 1:
            rows = validate_rows(rows_object, f"composed old index {old_index}")
            legacy_shape_to_chars.setdefault(rows, set()).add(ch)
    for ch, rows_object in ascii_glyphs.items():
        if not isinstance(ch, str) or len(ch) != 1:
            raise BuildError(f"invalid ASCII artifact key: {ch!r}")
        rows = validate_rows(rows_object, f"ASCII {ord(ch):04X}")
        legacy_shape_to_chars.setdefault(rows, set()).add(ch)
    legacy_ambiguities = {
        rows: chars
        for rows, chars in legacy_shape_to_chars.items()
        if any(rows) and len(chars) > 1
    }
    if len(legacy_ambiguities) != EXPECTED_SHAPE_AMBIGUITIES:
        raise BuildError(
            f"nonblank legacy source-shape ambiguity: {len(legacy_ambiguities)}"
        )

    # Rebuild the exact dictionary that created the v240 Hanme atlas.  This is
    # a bitmap identity lookup, not a semantic guess: all 11,172 Unicode
    # syllables produce distinct nonblank shapes under the historical rule.
    hangul_shape_to_chars: dict[tuple[int, ...], set[str]] = {}
    for codepoint in range(0xAC00, 0xD7A4):
        ch = chr(codepoint)
        rows = synthesize_v240_hangul(historical_pieces, codepoint)
        hangul_shape_to_chars.setdefault(rows, set()).add(ch)
    hangul_ambiguities = {
        rows: chars
        for rows, chars in hangul_shape_to_chars.items()
        if len(chars) > 1
    }
    if len(hangul_shape_to_chars) != EXPECTED_HANGUL_SHAPES:
        raise BuildError(
            "historical Hangul shape count drift: "
            f"{len(hangul_shape_to_chars)} != {EXPECTED_HANGUL_SHAPES}"
        )
    if len(hangul_ambiguities) != EXPECTED_SHAPE_AMBIGUITIES:
        raise BuildError(
            f"historical Hangul shape ambiguity: {len(hangul_ambiguities)}"
        )

    shape_to_chars: dict[tuple[int, ...], set[str]] = {
        rows: set(chars) for rows, chars in legacy_shape_to_chars.items()
    }
    for rows, chars in hangul_shape_to_chars.items():
        shape_to_chars.setdefault(rows, set()).update(chars)
    combined_ambiguities = {
        rows: chars
        for rows, chars in shape_to_chars.items()
        if any(rows) and len(chars) > 1
    }
    if len(combined_ambiguities) != EXPECTED_SHAPE_AMBIGUITIES:
        raise BuildError(
            "legacy/piece reconstruction disagreement: "
            f"{len(combined_ambiguities)} nonblank shapes"
        )

    comm_before = before[COMM]
    comm = bytearray(comm_before)
    rendered: dict[str, tuple[int, ...]] = {}
    records: list[dict[str, object]] = []
    mapped_indices: set[int] = set()
    expected_rows: dict[int, tuple[int, ...]] = {}
    ink = blank = matched = unmatched = 0
    legacy_identified = hangul_identified = legacy_hangul_agreement = 0
    piece_recovered = 0
    for index in range(ATLAS_INDICES):
        old_rows = read_plane(comm_before, index)
        if not any(old_rows):
            blank += 1
            records.append(
                {"index": index, "status": "blank_preserved", "char": "", "unicode": ""}
            )
            continue
        ink += 1
        legacy_chars = legacy_shape_to_chars.get(old_rows, set())
        hangul_chars = hangul_shape_to_chars.get(old_rows, set())
        if len(legacy_chars) == 1:
            legacy_identified += 1
        if len(hangul_chars) == 1:
            hangul_identified += 1
        if legacy_chars and hangul_chars:
            if legacy_chars != hangul_chars:
                raise BuildError(
                    f"legacy/piece character conflict at atlas index {index}: "
                    f"{legacy_chars!r} != {hangul_chars!r}"
                )
            legacy_hangul_agreement += 1
        elif hangul_chars:
            piece_recovered += 1
        chars = legacy_chars | hangul_chars
        if len(chars) != 1:
            unmatched += 1
            records.append(
                {"index": index, "status": "unmatched_preserved", "char": "", "unicode": ""}
            )
            continue
        ch = next(iter(chars))
        rows = rendered.setdefault(ch, render(face, ch))
        if not any(rows):
            raise BuildError(f"Pilgi rendered mapped U+{ord(ch):04X} blank")
        put_plane(comm, index, rows)
        mapped_indices.add(index)
        expected_rows[index] = rows
        matched += 1
        if legacy_chars and hangul_chars:
            status = "pilgi_legacy_piece_agreement"
        elif hangul_chars:
            status = "pilgi_piece_recovered"
        else:
            status = "pilgi_legacy_nonhangul"
        records.append(
            {
                "index": index,
                "status": status,
                "char": ch,
                "unicode": f"U+{ord(ch):04X}",
            }
        )

    census = (ink, blank, matched, unmatched)
    expected_census = (
        EXPECTED_ATLAS_INK,
        EXPECTED_ATLAS_BLANK,
        EXPECTED_ATLAS_MATCHED,
        EXPECTED_ATLAS_UNMATCHED,
    )
    if census != expected_census:
        raise BuildError(f"historical atlas census drift: {census} != {expected_census}")
    provenance_census = (
        legacy_identified,
        hangul_identified,
        legacy_hangul_agreement,
        piece_recovered,
    )
    expected_provenance = (
        EXPECTED_LEGACY_IDENTIFIED,
        EXPECTED_HANGUL_IDENTIFIED,
        EXPECTED_LEGACY_HANGUL_AGREEMENT,
        EXPECTED_PIECE_RECOVERED,
    )
    if provenance_census != expected_provenance:
        raise BuildError(
            f"atlas provenance census drift: {provenance_census} != {expected_provenance}"
        )
    if len(rendered) != EXPECTED_UNIQUE_RENDERED_CHARS:
        raise BuildError(
            f"unique reconstructed character count drift: "
            f"{len(rendered)} != {EXPECTED_UNIQUE_RENDERED_CHARS}"
        )

    # Plane-level exhaustive guard.  Mapped planes must be exactly Pilgi and
    # every other 16px plane on the low page must remain byte-equivalent.
    for index in range(COLS * FULL_16PX_ROWS * PLANES):
        after_rows = read_plane(comm, index)
        if index in mapped_indices:
            if after_rows != expected_rows[index]:
                raise BuildError(f"Pilgi plane readback differs at index {index}")
        elif after_rows != read_plane(comm_before, index):
            raise BuildError(f"unselected COMM plane changed at index {index}")
    if bytes(comm[208 * ROW_BYTES :]) != comm_before[208 * ROW_BYTES :]:
        raise BuildError("COMM changed below the historical 13-row atlas")
    for y in range(208):
        start = y * ROW_BYTES + 120  # x=240 in packed 4bpp
        if bytes(comm[start : (y + 1) * ROW_BYTES]) != comm_before[start : (y + 1) * ROW_BYTES]:
            raise BuildError(f"COMM changed right of x=239 on row {y}")

    exe_before = before[PSX]
    exe = bytearray(exe_before)
    if len(exe) != 587_776:
        raise BuildError(f"unexpected V318 executable size: {len(exe)}")
    for address, (expected, replacement) in ALL_WORD_EDITS.items():
        actual = word(exe, address)
        if actual != expected:
            raise BuildError(
                f"geometry word drift at 0x{address:08X}: {actual:08X} != {expected:08X}"
            )
        struct.pack_into("<I", exe, file_offset(address), replacement)

    # Frozen companion geometry and recovery facts.
    frozen_words = {
        0x8016B348: 0x34050010,  # temporary half-width path height 16
        0x8016B398: 0x34050010,  # reset height 16
        0x8016B530: 0x3402003C,  # 15 columns * 4 planes
        0x8016B5E0: 0xA0A2002B,  # preserved dormant-helper re-entry semantic
        0x8016BEF4: 0x25080008,  # half-width step 8
        0x8016BEFC: 0x25290008,
        0x8011C860: 0x0C05DB87,  # stock DrawOT
        0x8016B764: 0x27BDFFD0,  # stock renderer prologue
    }
    for address, expected in frozen_words.items():
        actual = word(exe, address)
        if actual != expected:
            raise BuildError(
                f"frozen companion word drift at 0x{address:08X}: {actual:08X}"
            )
    if word(exe, 0x8016B5B4) != 0x14620005:
        raise BuildError("half-width branch no longer targets packet setup 0x8016B5CC")

    # Validate every direct call of the generic dimension setter.  These four
    # known callers are the reason F=2 is scoped to the main 16px state while
    # the explicit 6px/12px paths keep F=0.
    setter_calls = {
        0x801620EC: (0x34040006, 0x3405000C, 0x00003021, 0x00003821),
        0x80162114: (0x3404000C, 0x3405000C, 0x00003021, 0x34070002),
        0x8016B350: (0x34040006, 0x34050010, 0x00003021, 0x00003821),
        0x8016B3A0: (0x3404000E, 0x34050010, 0x34060002, 0x00003821),
    }
    setter_jal = 0x0C000000 | ((0x8016B4B0 >> 2) & 0x03FFFFFF)
    actual_call_sites = {
        RAM_TO_FILE + offset
        for offset in range(0x800, len(exe) - 3, 4)
        if struct.unpack_from("<I", exe, offset)[0] == setter_jal
    }
    if actual_call_sites != set(setter_calls):
        raise BuildError(f"dimension-setter call topology drift: {sorted(actual_call_sites)}")
    for call, expected_args in setter_calls.items():
        actual_args = (
            word(exe, call - 12),
            word(exe, call - 8),
            word(exe, call - 4),
            word(exe, call + 4),
        )
        if actual_args != expected_args:
            raise BuildError(
                f"dimension-setter arguments drift at 0x{call:08X}: {actual_args!r}"
            )

    text_size = struct.unpack_from("<I", exe, 0x1C)[0]
    text = bytes(exe[0x800 : 0x800 + text_size])
    if text.count(struct.pack("<I", CACHE_UPLOAD_JAL)):
        raise BuildError("dynamic-cache upload JAL returned")

    exe_diffs = {
        offset
        for offset, (left, right) in enumerate(zip(exe_before, exe))
        if left != right
    }
    allowed_exe = {
        offset
        for address in ALL_WORD_EDITS
        for offset in range(file_offset(address), file_offset(address) + 4)
    }
    if not exe_diffs or not exe_diffs <= allowed_exe:
        raise BuildError("PSX.EXE changed outside guarded geometry words")
    comm_diffs = {
        offset
        for offset, (left, right) in enumerate(zip(comm_before, comm))
        if left != right
    }
    if not comm_diffs:
        raise BuildError("Pilgi atlas produced no COMM changes")

    members = dict(before)
    members[PSX] = bytes(exe)
    members[COMM] = bytes(comm)
    if any(len(members[name]) != len(before[name]) for name in before):
        raise BuildError("a patch member changed size")
    changed_members = [name for name in before if members[name] != before[name]]
    if set(changed_members) != {PSX, COMM}:
        raise BuildError(f"unexpected V318-relative changed members: {changed_members}")

    output_path, output_hash = write_archive(OUTPUT_STEM, infos, members, None)
    delta_path, delta_hash = write_archive(DELTA_STEM, infos, members, {PSX, COMM})
    with ZipFile(output_path) as archive:
        if len(archive.infolist()) != len(infos):
            raise BuildError("cumulative archive topology changed")
        for name in before:
            if archive.read(name) != members[name]:
                raise BuildError(f"cumulative archive round-trip differs: {name}")
    with ZipFile(delta_path) as archive:
        if set(archive.namelist()) != {PSX, COMM}:
            raise BuildError("V318 delta contains an unexpected member")
        if any(archive.read(name) != members[name] for name in (PSX, COMM)):
            raise BuildError("V318 delta round-trip differs")

    ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
    with (ANALYSIS_DIR / "atlas_mapping.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=("index", "status", "char", "unicode"))
        writer.writeheader()
        writer.writerows(records)

    manifest = {
        "build": "V319 TEST_ONLY broad Pilgi16 integration",
        "base": {"path": str(BASE), "sha256": BASE_SHA256, "members": len(before)},
        "historical_atlas": {"v240_sha256": V240_SHA256, "v241_sha256": V241_SHA256},
        "font": {
            "status": "temporary structure-validation face; not final art direction",
            "archive": str(font_zip),
            "archive_sha256": FONT_ARCHIVE_SHA256,
            "member": FONT_NAME,
            "member_sha256": FONT_SHA256,
            "pillow": PIL.__version__,
            "freetype": freetype_version,
            "threshold": f">{THRESHOLD}",
        },
        "atlas": {
            "indices": ATLAS_INDICES,
            "ink": ink,
            "blank_preserved": blank,
            "pilgi_resolved": matched,
            "unresolved": unmatched,
            "legacy_identified": legacy_identified,
            "hangul_piece_identified": hangul_identified,
            "legacy_piece_agreement": legacy_hangul_agreement,
            "piece_recovered": piece_recovered,
            "exhaustive_hangul_shapes": len(hangul_shape_to_chars),
            "unique_pilgi_chars": len(rendered),
            "comm_changed_bytes": len(comm_diffs),
        },
        "geometry": {
            "packet": [16, 16],
            "cursor_advance": 14,
            "wrap_advance": 14,
            "line_pitch": 16,
            "half_width_step": 8,
            "main_state": {"D": 14, "E": 16, "F": 2, "plus_10": 0},
            "cache_upload_direct_calls": 0,
        },
        "output": {
            "path": str(output_path),
            "sha256": output_hash,
            "delta_path": str(delta_path),
            "delta_sha256": delta_hash,
            "changed_members_from_v318": changed_members,
            "psx_changed_bytes": len(exe_diffs),
        },
        "runtime": "PENDING user cold boot",
        "known_limits": [
            "Pilgi is a temporary structure-validation face, not the selected final 16px font",
            "14px advance overlaps adjacent 16px sprites by 2px and needs font-specific runtime acceptance",
            "automatic wrapping is not Korean word-boundary aware and can split an eojeol",
            "this bridge inherits v240's 773 unknown-code-to-blank rewrites",
            "the final production builder must reconstruct from pristine arc.zip",
        ],
    }
    (ANALYSIS_DIR / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "V319 TEST ONLY - broad V318 content with Pilgi 16px and separated geometry",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output_path.name}",
        f"sha256={output_hash}",
        f"delta_from_v318={delta_path.name}",
        f"delta_sha256={delta_hash}",
        f"preserved_members={len(before) - len(changed_members)}/{len(before)} byte-identical",
        f"changed_members={changed_members}",
        f"atlas=ink {ink}; Pilgi resolved {matched}; unresolved {unmatched}; blank {blank}",
        f"mapping=legacy {legacy_identified}; Hangul pieces {hangul_identified}; "
        f"agreement {legacy_hangul_agreement}; recovered {piece_recovered}",
        f"Hangul_exhaustive_shapes={len(hangul_shape_to_chars)}; ambiguities=0",
        f"unique_Pilgi_chars={len(rendered)}; COMM_changed_bytes={len(comm_diffs)}",
        "geometry=packet 16x16; cursor 14; wrap 14; line pitch 16; half-width 8",
        "state=main D14/E16/F2/+10=0; explicit 6px and 12px setter paths preserved",
        f"PSX_changed_bytes={len(exe_diffs)}; cache_upload_direct_calls=0",
        "runtime=PENDING user cold boot",
        "font_status=TEMPORARY structure-validation face; final 16px font is not selected",
        "primary_visual_gate=first village dialogue must use one consistent face and keep V318 breadth",
        "regression_gate=next dialogue/speaker/UI/battle/world-map transition",
        "known_limit=14px advance overlaps 16px sprites by 2px; inspect right/left edge collisions",
        "known_limit=automatic wrap can split Korean words; 16px reflow remains required",
        "known_limit=v240's 773 unknown-code blank rewrites are inherited, not repaired here",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
    ]
    (ANALYSIS_DIR / "build_report.txt").write_text(
        "\n".join(report) + "\n", encoding="utf-8"
    )
    print("\n".join(report))


if __name__ == "__main__":
    main()
