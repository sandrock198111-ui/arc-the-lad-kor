#!/usr/bin/env python3
"""Build V320C: replace V240's simplified Hanme beol rule with upstream rules.

V320B is the runtime-bootable Hanme 16px recovery.  Its text identity, E2/UI
content, geometry and executable are intentionally frozen here.  This build
changes only the already-identified Hangul planes in COMM.IMG.

The historical V240 atlas used one four-way vowel group for both choseong and
jongseong selection.  That is not the rule used by iolo/8x4x4-fonts.  In
particular, ㅗ/ㅛ/ㅡ plus a final consonant used choseong beol 5 and jongseong
beol 1 in V240, while the source generator selects beol 6 and 3.  This is the
systematic cause of the left-shifted 촌/들/는 family reported from V320B.

The three source arrays are copied verbatim from the hash-pinned upstream
``generate_hangul_syllables.py`` already recorded by the clean johab PoC.  The
360 BDF-derived Hanme component bitmaps remain byte-identical and hash pinned.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = ROOT / "03_output/arc1_v320b_hanme_exe_pointer_restore_TEST_ONLY_2366F366.zip"
BASE_SHA256 = "2366F366A12F81DCE689DA10355F04112BECEB24F4895D029896021F1F9FECE6"
BASE_COMM_SHA256 = "E73F668B7042E7A4FCD4DB83906B735C4385C2643A33AB0D3C3331E5BFB4219E"
BASE_PSX_SHA256 = "3D477AF6E97860485D89ADA92932FA90FA05B0834B583072E7A0946D2912D291"

ART = ROOT / "01_work/analysis/hangul_johab_16px"
PIECES = ART / "pieces_1bpp.bin"
PIECES_SHA256 = "409ABA72F4BA2282AA5C4E4982A9EEA16FBD14FB0413A40E151537A6653E2904"
ATLAS_MAPPING = ROOT / "01_work/analysis/arc1_v319_pilgi16_integration/atlas_mapping.csv"
ATLAS_MAPPING_SHA256 = "9553E7643621CC80C23355067611EAE7650FEF7CB547DC9115B62157DB0C3122"
CHAR_ASSIGNMENTS = ROOT / "01_work/analysis/arc1_v320_hanme_static_recovery/character_assignments.csv"
CHAR_ASSIGNMENTS_SHA256 = "933BDAC4BC4C39D33DB134D2FF836902B5053B93725C96E19DED714CB7DE98A4"

OUTPUT_DIR = ROOT / "03_output"
ANALYSIS_DIR = ROOT / "01_work/analysis/arc1_v320c_hanme_official_beol"
OUTPUT_STEM = "arc1_v320c_hanme_official_beol_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_COMM_delta_from_v320b"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
EXPECTED_MEMBERS = 164
ROW_BYTES = 896
CELL = 16
COLS = 15
PLANES = 4
MAX_PHYSICAL_INDEX = COLS * (256 // CELL) * PLANES

# Primary-source provenance pinned by build_arc1_johab_font_poc.py.
RULE_SOURCE_URL = (
    "https://raw.githubusercontent.com/iolo/8x4x4-fonts/"
    "main/generate_hangul_syllables.py"
)
RULE_SOURCE_SHA256 = "A498B4F7B7DC840AD637B093711ED6DB650EEEA96DAFA46728B4F30E730B3052"
RULE_SOURCE_SIZE = 3_201

# Vowel order: ㅏ ㅐ ㅑ ㅒ ㅓ ㅔ ㅕ ㅖ ㅗ ㅘ ㅙ ㅚ ㅛ ㅜ ㅝ ㅞ ㅟ ㅠ ㅡ ㅢ ㅣ
CHO_KIND_WITHOUT_JONG = (
    0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 3, 1, 2, 4, 4, 4, 2, 1, 3, 0,
)
CHO_KIND_WITH_JONG = (
    5, 5, 5, 5, 5, 5, 5, 5, 6, 7, 7, 7, 6, 6, 7, 7, 7, 6, 6, 7, 5,
)
JONG_KIND_BY_JUNG = (
    0, 2, 0, 2, 1, 2, 1, 2, 3, 0, 2, 1, 3, 3, 1, 2, 1, 3, 3, 1, 1,
)

# Historical V240 rule.  This is retained only as an exact input guard.
V240_JUNG_GROUP = (
    0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 3, 1, 2, 3, 3, 3, 2, 1, 3, 0,
)

PROBE_CHARS = ("촌", "들", "속", "롭", "론", "온", "는", "봉", "용", "꽃", "동")


class BuildError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def clone_zipinfo(info: ZipInfo) -> ZipInfo:
    clone = ZipInfo(info.filename, info.date_time)
    for attribute in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(clone, attribute, getattr(info, attribute))
    return clone


def read_archive(path: Path) -> tuple[list[ZipInfo], dict[str, bytes]]:
    with ZipFile(path) as archive:
        infos = archive.infolist()
        if len({info.filename for info in infos}) != len(infos):
            raise BuildError("duplicate archive member names")
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
        raise BuildError(f"temporary output exists: {temporary}")
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


def is_hangul(ch: str) -> bool:
    return len(ch) == 1 and 0xAC00 <= ord(ch) <= 0xD7A3


def load_pieces(raw: bytes) -> tuple[tuple[int, ...], ...]:
    if len(raw) != 360 * CELL * 2:
        raise BuildError(f"piece blob size drift: {len(raw)}")
    pieces = tuple(
        tuple(struct.unpack_from(">16H", raw, index * CELL * 2))
        for index in range(360)
    )
    expected_blank = (
        {beol * 20 for beol in range(8)}
        | {160 + beol * 22 for beol in range(4)}
        | {248 + beol * 28 for beol in range(4)}
    )
    actual_blank = {index for index, rows in enumerate(pieces) if not any(rows)}
    if actual_blank != expected_blank:
        raise BuildError("Hanme component layout drift")
    return pieces


def decompose(ch: str) -> tuple[int, int, int]:
    if not is_hangul(ch):
        raise BuildError(f"not Hangul: {ch!r}")
    value = ord(ch) - 0xAC00
    cho, remainder = divmod(value, 588)
    jung, jong = divmod(remainder, 28)
    return cho, jung, jong


def component_indices(ch: str, official: bool) -> tuple[int, int, int]:
    cho, jung, jong = decompose(ch)
    if official:
        cho_beol = (
            CHO_KIND_WITH_JONG[jung] if jong else CHO_KIND_WITHOUT_JONG[jung]
        )
        jong_beol = JONG_KIND_BY_JUNG[jung]
        # Upstream generator: 0/2 for ㄱ or ㅋ, otherwise 1/3.
        jung_beol = (0 if cho in (0, 15) else 1) + (2 if jong else 0)
    else:
        group = V240_JUNG_GROUP[jung]
        cho_beol = group + (4 if jong else 0)
        jong_beol = group
        # V240's historical artifact used the opposite jungseong selector.
        # hangul_map.csv records this exact choice, and the V320B bitmap guard
        # below independently proves it for every mapped physical plane.
        jung_beol = (1 if cho in (0, 15) else 0) + (2 if jong else 0)
    return (
        cho_beol * 20 + cho + 1,
        160 + jung_beol * 22 + jung + 1,
        248 + jong_beol * 28 + jong if jong else -1,
    )


def compose(
    pieces: tuple[tuple[int, ...], ...], ch: str, official: bool
) -> tuple[int, ...]:
    cho_piece, jung_piece, jong_piece = component_indices(ch, official)
    rows = tuple(
        pieces[cho_piece][y]
        | pieces[jung_piece][y]
        | (pieces[jong_piece][y] if jong_piece >= 0 else 0)
        for y in range(CELL)
    )
    if not any(rows):
        raise BuildError(f"blank composition: {ch}")
    return rows


def read_plane(buf: bytes | bytearray, index: int) -> tuple[int, ...]:
    if not 0 <= index < MAX_PHYSICAL_INDEX:
        raise BuildError(f"physical index outside 16px low page: {index}")
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


def put_plane(buf: bytearray, index: int, rows: tuple[int, ...]) -> set[int]:
    if len(rows) != CELL or any(value < 0 or value >= 1 << CELL for value in rows):
        raise BuildError(f"invalid bitmap for index {index}")
    cell, plane = divmod(index, PLANES)
    col, row = cell % COLS, cell // COLS
    bit = 1 << plane
    touched: set[int] = set()
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
            new_value = (buf[at] & keep) | (nibble << shift)
            if new_value != buf[at]:
                touched.add(at)
                buf[at] = new_value
    return touched


def hamming(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    return sum((a ^ b).bit_count() for a, b in zip(left, right, strict=True))


def bitmap_hash(rows: tuple[int, ...]) -> str:
    return sha256_bytes(b"".join(row.to_bytes(2, "big") for row in rows))


def main() -> None:
    fixed_inputs = (
        (BASE, BASE_SHA256, "V320B base"),
        (PIECES, PIECES_SHA256, "Hanme pieces"),
        (ATLAS_MAPPING, ATLAS_MAPPING_SHA256, "atlas mapping"),
        (CHAR_ASSIGNMENTS, CHAR_ASSIGNMENTS_SHA256, "character assignments"),
    )
    for path, expected, label in fixed_inputs:
        if not path.is_file() or sha256_file(path) != expected:
            raise BuildError(f"{label} hash mismatch: {path}")

    infos, before = read_archive(BASE)
    names = [info.filename for info in infos if not info.is_dir()]
    if len(before) != EXPECTED_MEMBERS or len(names) != EXPECTED_MEMBERS:
        raise BuildError("V320B member topology drift")
    if sha256_bytes(before[COMM]) != BASE_COMM_SHA256:
        raise BuildError("V320B COMM hash drift")
    if sha256_bytes(before[PSX]) != BASE_PSX_SHA256:
        raise BuildError("V320B PSX hash drift")

    pieces = load_pieces(PIECES.read_bytes())

    physical_char: dict[int, str] = {}
    physical_sources: dict[int, set[str]] = {}

    def register(index: int, ch: str, source: str) -> None:
        if not is_hangul(ch):
            return
        if not 0 <= index < MAX_PHYSICAL_INDEX:
            raise BuildError(f"mapped Hangul outside low page: {index} {ch}")
        previous = physical_char.setdefault(index, ch)
        if previous != ch:
            raise BuildError(f"physical identity conflict at {index}: {previous}/{ch}")
        physical_sources.setdefault(index, set()).add(source)

    atlas_rows = 0
    atlas_hangul = 0
    with ATLAS_MAPPING.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            index = int(row["index"])
            if index != atlas_rows:
                raise BuildError("atlas mapping order drift")
            atlas_rows += 1
            if is_hangul(row["char"]):
                atlas_hangul += 1
                register(index, row["char"], "V319 atlas identity")
    if atlas_rows != 728 or atlas_hangul != 632:
        raise BuildError(f"atlas mapping census drift: {atlas_rows}/{atlas_hangul}")

    assignment_rows = 0
    assignment_hangul_rows = 0
    with CHAR_ASSIGNMENTS.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            assignment_rows += 1
            if is_hangul(row["char"]):
                assignment_hangul_rows += 1
                register(int(row["physical_index"]), row["char"], "V320 assignment")
    if assignment_rows != 750 or assignment_hangul_rows != 727:
        raise BuildError(
            f"assignment mapping census drift: {assignment_rows}/{assignment_hangul_rows}"
        )
    if len(physical_char) != 718 or len(set(physical_char.values())) != 685:
        raise BuildError(
            f"final Hangul physical census drift: {len(physical_char)}/"
            f"{len(set(physical_char.values()))}"
        )

    # The V320B atlas must still be exactly the historical V240 composition.
    # If even one plane differs, this narrow builder is no longer the right tool.
    base_comm = before[COMM]
    for index, ch in sorted(physical_char.items()):
        expected = compose(pieces, ch, official=False)
        actual = read_plane(base_comm, index)
        if actual != expected:
            raise BuildError(
                f"V320B plane is not the guarded V240 composition: {index} {ch}"
            )

    all_rule_rows: list[dict[str, object]] = []
    all_changed = 0
    all_hamming = 0
    for codepoint in range(0xAC00, 0xD7A4):
        ch = chr(codepoint)
        old_indices = component_indices(ch, official=False)
        new_indices = component_indices(ch, official=True)
        old_rows = compose(pieces, ch, official=False)
        new_rows = compose(pieces, ch, official=True)
        distance = hamming(old_rows, new_rows)
        if distance:
            all_changed += 1
            all_hamming += distance
        cho, jung, jong = decompose(ch)
        all_rule_rows.append(
            {
                "char": ch,
                "unicode": f"U+{codepoint:04X}",
                "cho": cho,
                "jung": jung,
                "jong": jong,
                "v240_cho_piece": old_indices[0],
                "v240_jung_piece": old_indices[1],
                "v240_jong_piece": old_indices[2],
                "official_cho_piece": new_indices[0],
                "official_jung_piece": new_indices[1],
                "official_jong_piece": new_indices[2],
                "pixel_hamming": distance,
                "changed": int(bool(distance)),
            }
        )

    # Every reported sample is the same systematic family: ㅗ/ㅛ/ㅡ + jong.
    probe_rows: list[dict[str, object]] = []
    for ch in PROBE_CHARS:
        if ch not in physical_char.values():
            raise BuildError(f"reported probe character is not mapped: {ch}")
        cho, jung, jong = decompose(ch)
        old_indices = component_indices(ch, official=False)
        new_indices = component_indices(ch, official=True)
        if jung not in (8, 12, 18) or not jong:
            raise BuildError(f"probe family assumption drift: {ch}")
        old_cho_beol = old_indices[0] // 20
        new_cho_beol = new_indices[0] // 20
        old_jong_beol = (old_indices[2] - 248) // 28
        new_jong_beol = (new_indices[2] - 248) // 28
        if (old_cho_beol, new_cho_beol, old_jong_beol, new_jong_beol) != (5, 6, 1, 3):
            raise BuildError(f"probe beol transition drift: {ch}")
        probe_rows.append(
            {
                "char": ch,
                "unicode": f"U+{ord(ch):04X}",
                "cho": cho,
                "jung": jung,
                "jong": jong,
                "v240_cho_beol": old_cho_beol,
                "official_cho_beol": new_cho_beol,
                "v240_jong_beol": old_jong_beol,
                "official_jong_beol": new_jong_beol,
                "v240_piece_indices": "/".join(map(str, old_indices)),
                "official_piece_indices": "/".join(map(str, new_indices)),
                "pixel_hamming": hamming(
                    compose(pieces, ch, official=False),
                    compose(pieces, ch, official=True),
                ),
            }
        )

    comm = bytearray(base_comm)
    allowed_offsets: set[int] = set()
    mapped_rows: list[dict[str, object]] = []
    changed_planes = 0
    changed_chars: set[str] = set()
    for index, ch in sorted(physical_char.items()):
        old_rows = compose(pieces, ch, official=False)
        new_rows = compose(pieces, ch, official=True)
        distance = hamming(old_rows, new_rows)
        if distance:
            changed_planes += 1
            changed_chars.add(ch)
            allowed_offsets |= put_plane(comm, index, new_rows)
        mapped_rows.append(
            {
                "physical_index": index,
                "char": ch,
                "unicode": f"U+{ord(ch):04X}",
                "sources": "; ".join(sorted(physical_sources[index])),
                "v240_piece_indices": "/".join(
                    map(str, component_indices(ch, official=False))
                ),
                "official_piece_indices": "/".join(
                    map(str, component_indices(ch, official=True))
                ),
                "pixel_hamming": distance,
                "changed": int(bool(distance)),
                "before_bitmap_sha256": bitmap_hash(old_rows),
                "after_bitmap_sha256": bitmap_hash(new_rows),
            }
        )

    # Plane-level and byte-level Expected Write verification.
    for index in range(MAX_PHYSICAL_INDEX):
        actual = read_plane(comm, index)
        if index in physical_char:
            expected = compose(pieces, physical_char[index], official=True)
        else:
            expected = read_plane(base_comm, index)
        if actual != expected:
            raise BuildError(f"COMM plane readback mismatch at {index}")
    for y in range(512):
        if bytes(comm[y * ROW_BYTES + 120 : (y + 1) * ROW_BYTES]) != base_comm[
            y * ROW_BYTES + 120 : (y + 1) * ROW_BYTES
        ]:
            raise BuildError(f"COMM changed right of x=239 on row {y}")
    actual_offsets = {
        offset
        for offset, (left, right) in enumerate(zip(base_comm, comm))
        if left != right
    }
    if not actual_offsets or actual_offsets != allowed_offsets:
        raise BuildError(
            f"COMM Expected Write mismatch: actual={len(actual_offsets)} "
            f"allowed={len(allowed_offsets)}"
        )

    members = dict(before)
    members[COMM] = bytes(comm)
    changed_members = [name for name in names if members[name] != before[name]]
    if changed_members != [COMM]:
        raise BuildError(f"unexpected changed members: {changed_members}")
    if members[PSX] != before[PSX]:
        raise BuildError("V320B executable changed")
    if any(
        members[name] != before[name]
        for name in names
        if name not in (COMM,)
    ):
        raise BuildError("a non-COMM member changed")
    if any(len(members[name]) != len(before[name]) for name in names):
        raise BuildError("member size changed")

    output_path, output_hash = write_archive(OUTPUT_STEM, infos, members, None)
    delta_path, delta_hash = write_archive(DELTA_STEM, infos, members, {COMM})
    with ZipFile(output_path) as archive:
        if [info.filename for info in archive.infolist() if not info.is_dir()] != names:
            raise BuildError("output ZIP topology drift")
        for name in names:
            if archive.read(name) != members[name]:
                raise BuildError(f"output round-trip differs: {name}")
    with ZipFile(delta_path) as archive:
        if archive.namelist() != [COMM] or archive.read(COMM) != members[COMM]:
            raise BuildError("COMM-only delta round-trip differs")

    ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
    with (ANALYSIS_DIR / "mapped_glyph_changes.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=mapped_rows[0].keys())
        writer.writeheader()
        writer.writerows(mapped_rows)
    with (ANALYSIS_DIR / "reported_probe_changes.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=probe_rows[0].keys())
        writer.writeheader()
        writer.writerows(probe_rows)
    with (ANALYSIS_DIR / "all_hangul_rule_diff.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=all_rule_rows[0].keys())
        writer.writeheader()
        writer.writerows(all_rule_rows)

    manifest = {
        "build": "V320C TEST_ONLY Hanme official beol correction",
        "base": {"path": str(BASE), "sha256": BASE_SHA256},
        "rule": {
            "source_url": RULE_SOURCE_URL,
            "source_sha256": RULE_SOURCE_SHA256,
            "source_size": RULE_SOURCE_SIZE,
            "cho_without_jong": CHO_KIND_WITHOUT_JONG,
            "cho_with_jong": CHO_KIND_WITH_JONG,
            "jong_by_jung": JONG_KIND_BY_JUNG,
            "jung_rule": "0/2 for cho 0 or 15; otherwise 1/3",
        },
        "inputs": {
            "pieces_sha256": PIECES_SHA256,
            "atlas_mapping_sha256": ATLAS_MAPPING_SHA256,
            "character_assignments_sha256": CHAR_ASSIGNMENTS_SHA256,
        },
        "census": {
            "all_hangul": 11_172,
            "all_hangul_changed_vs_v240": all_changed,
            "all_hangul_pixel_hamming": all_hamming,
            "mapped_physical_planes": len(physical_char),
            "mapped_unique_characters": len(set(physical_char.values())),
            "mapped_changed_planes": changed_planes,
            "mapped_changed_unique_characters": len(changed_chars),
            "COMM_changed_bytes": len(actual_offsets),
        },
        "frozen": {
            "PSX_EXE_sha256": sha256_bytes(members[PSX]),
            "all_non_COMM_members_byte_identical": True,
            "geometry": "V320B packet16 advance14 line16 half-space6 unchanged",
        },
        "reported_probes": probe_rows,
        "output": {
            "path": str(output_path),
            "sha256": output_hash,
            "delta_path": str(delta_path),
            "delta_sha256": delta_hash,
            "changed_members": changed_members,
        },
        "runtime_status": "PENDING user cold boot and reported-glyph visual check",
    }
    (ANALYSIS_DIR / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    report = [
        "V320C TEST ONLY - Hanme official beol correction",
        f"base={BASE.name}",
        f"base_sha256={BASE_SHA256}",
        f"output={output_path.name}",
        f"sha256={output_hash}",
        f"delta={delta_path.name}",
        f"delta_sha256={delta_hash}",
        "changed_members=COMM.IMG only; PSX/DAT/E2/UI/geometry byte-identical to V320B",
        f"mapped_hangul={len(physical_char)} planes/{len(set(physical_char.values()))} unique chars",
        f"mapped_changed={changed_planes} planes/{len(changed_chars)} unique chars",
        f"all_11172_changed_vs_v240={all_changed}; pixel_hamming={all_hamming}",
        f"COMM_changed_bytes={len(actual_offsets)}",
        "reported_family=ㅗ/ㅛ/ㅡ+jong: cho beol 5->6; jong beol 1->3",
        "reported_probes=" + ",".join(PROBE_CHARS),
        f"rule_source_sha256={RULE_SOURCE_SHA256}",
        f"pieces_sha256={PIECES_SHA256}",
        f"PSX_EXE_sha256={sha256_bytes(members[PSX])} (unchanged)",
        "runtime=PENDING user cold boot and visual confirmation",
        "release_status=DIAGNOSTIC; DO NOT DISTRIBUTE",
    ]
    (ANALYSIS_DIR / "build_report.txt").write_text(
        "\n".join(report) + "\n", encoding="utf-8"
    )
    print("\n".join(report))


if __name__ == "__main__":
    try:
        main()
    except BuildError as error:
        raise SystemExit(f"GUARD FAILED: {error}") from error
