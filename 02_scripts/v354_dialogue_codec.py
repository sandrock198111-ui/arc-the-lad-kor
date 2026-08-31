"""Pinned V354 dialogue codec used by the human translation editor.

This module deliberately does not reuse ``plan_bulk_insertion.build_encoder``.
That routine describes the retired 12px renderer and crashes while reading the
current 16px archive.  V354 uses the static V320 assignment table, direct cells
from the V319 16px atlas, and a small number of later, explicitly audited glyph
additions.  Every external input is hash pinned and every E9/EA assignment is
checked against V354's live packed lookup table before it is exposed to the
editor.
"""
from __future__ import annotations

import csv
import hashlib
from collections import defaultdict
from pathlib import Path
from zipfile import ZipFile

import build_arc1_v320_hanme_static_recovery as v320


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "03_output/arc1_v354_dialogue_identity_wording_repair_TEST_ONLY_2AA6C42A.zip"
BUILD_SHA256 = "2AA6C42AC1F62B5D1C7121F27B77807610C9E05D423C548429CB38653DF9C194"
PSX_SHA256 = "7866E637A8CA5E641C6DA3518A5475BB736F0B4505F009917DC998FBBC06B7FD"
COMM_SHA256 = "A6681F1355007725328372CC6143EF21EEE43A9FDE91FD3DC2EF3461C6805405"

ASSIGNMENTS = ROOT / "01_work/analysis/arc1_v320_hanme_static_recovery/character_assignments.csv"
ASSIGNMENTS_SHA256 = "933BDAC4BC4C39D33DB134D2FF836902B5053B93725C96E19DED714CB7DE98A4"
ATLAS = ROOT / "01_work/analysis/arc1_v319_pilgi16_integration/atlas_mapping.csv"
ATLAS_SHA256 = "9553E7643621CC80C23355067611EAE7650FEF7CB547DC9115B62157DB0C3122"

SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
SLOT_COUNT = 79
SLOT_TEXT_MAX = SLOT_SIZE - 2
CHOICE = 0xE5
LINEBREAK = bytes((0xE6, 0x01))
SPACE_CODE = bytes((0xA1,))


class CodecError(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def tokens(data: bytes):
    """Walk a text stream with the runtime's 1/2-byte token-width rule."""
    offset = 0
    while offset < len(data):
        width = 1 if data[offset] < 0xDD else 2
        yield data[offset:offset + width]
        offset += width


def has_marker(raw: bytes, lead: int) -> bool:
    return any(len(token) == 2 and token[0] == lead for token in tokens(raw))


def encode(text: str, table: dict[str, bytes], keep_breaks: bool) -> tuple[bytes, list[str]]:
    """Encode editable prose; ``|`` is the editor's visible line/choice separator."""
    output = bytearray()
    missing: list[str] = []
    for char in text:
        if char == "|":
            output.extend(LINEBREAK if keep_breaks else SPACE_CODE)
        elif code := table.get(char):
            output.extend(code)
        else:
            missing.append(char)
    return bytes(output), missing


def direct_code(index: int) -> bytes | None:
    """Return the current stable direct code for a logical physical index."""
    return v320.encode_index(index)


# Later audited additions that are intentionally absent from the frozen V320
# assignment/atlas CSVs.  The logical index remains valid even where V336's
# common text gate relocates its pixels at runtime.
SPECIAL_LOGICAL = {
    "괄": (bytes((0xAB,)), 170),
    "%": (bytes.fromhex("DD B8"), 403),
    "뱀": (bytes.fromhex("DF 21"), 762),
    "센": (bytes.fromhex("DF 5A"), 819),
    "첩": (bytes.fromhex("DF 5E"), 823),
    "탑": (bytes.fromhex("DF 88"), 865),
    "」": (bytes.fromhex("DF 09"), 738),
    "「": (bytes.fromhex("DF 2D"), 774),
}

# U+FF62/U+FF63 are accepted aliases for the same two visible glyphs.  Decode
# always uses the full-width Korean/Japanese editorial form above.
ALIASES = {"｢": "「", "｣": "」"}

PUNCTUATION = {
    " ": bytes((0xA1,)),
    ",": bytes((0xB3,)),
    ".": bytes((0x21,)),
    "!": bytes((0xA9,)),
    "?": bytes((0xD1,)),
}

# Physical 403 used to hold ':' in the V319 atlas.  V325 deliberately replaced
# that audited plane with '%'; the old atlas name must not leak back into decode.
OVERWRITTEN_ATLAS_PLANES = {403}


def _resolve_index(exe: bytes, code: bytes) -> int | None:
    if len(code) == 1:
        return code[0] - 1 if 0x01 <= code[0] <= 0xDC else None
    if len(code) != 2:
        return None
    if code[0] in (0xE9, 0xEA):
        slot = (code[0] - 0xE9) * 254 + code[1] - 1
        if not 0 <= slot < v320.LOOKUP_SLOTS:
            return None
        return v320.lookup_get(exe, slot)
    return v320.direct_index(code)


def load_v354() -> tuple[bytes, bytes, dict[str, bytes], dict[bytes, str]]:
    """Load and validate V354, returning EXE, COMM, encoder and decoder maps."""
    if not BUILD.exists():
        raise CodecError(f"V354 full ZIP이 없습니다: {BUILD}")
    if sha(BUILD.read_bytes()) != BUILD_SHA256:
        raise CodecError("V354 full ZIP 해시가 달라졌습니다")
    if sha(ASSIGNMENTS.read_bytes()) != ASSIGNMENTS_SHA256:
        raise CodecError("V320 문자 할당표 해시가 달라졌습니다")
    if sha(ATLAS.read_bytes()) != ATLAS_SHA256:
        raise CodecError("V319 16px 아틀라스 표 해시가 달라졌습니다")

    with ZipFile(BUILD) as archive:
        exe = archive.read("PSX.EXE")
        comm = archive.read("COMM.IMG")
    if sha(exe) != PSX_SHA256 or sha(comm) != COMM_SHA256:
        raise CodecError("V354 PSX.EXE/COMM.IMG 기준이 달라졌습니다")

    candidates: dict[str, list[bytes]] = defaultdict(list)
    decoder: dict[bytes, str] = {}

    with ASSIGNMENTS.open(encoding="utf-8-sig", newline="") as handle:
        assignment_rows = list(csv.DictReader(handle))
    for row in assignment_rows:
        char = row.get("char", "")
        code_text = row.get("code_hex", "").replace(" ", "")
        if len(char) != 1 or not code_text:
            continue
        code = bytes.fromhex(code_text)
        expected = int(row["physical_index"])
        actual = _resolve_index(exe, code)
        if actual != expected:
            raise CodecError(
                f"V354 코드표 불일치: {char!r} {code.hex(' ').upper()} "
                f"physical {actual} != {expected}"
            )
        candidates[char].append(code)
        previous = decoder.setdefault(code, char)
        if previous != char:
            raise CodecError(f"문자 코드 충돌: {code.hex(' ').upper()} = {previous!r}/{char!r}")

    with ATLAS.open(encoding="utf-8-sig", newline="") as handle:
        atlas_rows = list(csv.DictReader(handle))
    for row in atlas_rows:
        char = row.get("char", "")
        index = int(row["index"])
        if index in OVERWRITTEN_ATLAS_PLANES:
            continue
        code = direct_code(index)
        if code is None:
            continue
        if len(char) == 1:
            candidates[char].append(code)
            decoder.setdefault(code, char)
        elif row.get("status") == "blank_preserved":
            # These codes draw nothing in V354.  Showing them as <05>/<22> made
            # harmless historical padding look like corrupt text in the editor.
            decoder.setdefault(code, " ")

    # The special additions are the newest source of truth and therefore win a
    # decoder collision with stale atlas metadata.
    for char, (code, logical_index) in SPECIAL_LOGICAL.items():
        if _resolve_index(exe, code) != logical_index:
            raise CodecError(f"후기 글리프 코드 불일치: {char!r}")
        if not any(v320.read_plane(comm, logical_index)):
            raise CodecError(f"후기 글리프 plane이 비었습니다: {char!r}/{logical_index}")
        candidates[char].append(code)
        decoder[code] = char

    selected = {
        char: min(set(codes), key=lambda value: (len(value), value))
        for char, codes in candidates.items()
    }
    for alias, canonical in ALIASES.items():
        selected[alias] = selected[canonical]
    for char, code in PUNCTUATION.items():
        selected[char] = code
        decoder[code] = char

    required = {
        " ": "A1", ",": "B3", ".": "21", "!": "A9", "?": "D1",
        "괄": "AB", "재": "DE52", "품": "DD80", "「": "DF2D", "」": "DF09",
    }
    for char, expected in required.items():
        actual = selected.get(char, b"").hex().upper()
        if actual != expected:
            raise CodecError(f"V354 필수 코드 불일치: {char!r} {actual} != {expected}")
    return exe, comm, selected, decoder


def self_test() -> None:
    _exe, _comm, table, decoder = load_v354()
    assert decoder[bytes((0x21,))] == "."
    assert encode("말괄량이, 존재!", table, False)[1] == []
    print(f"V354 codec PASS: {BUILD.name}, encodable characters={len(table)}")


if __name__ == "__main__":
    self_test()
