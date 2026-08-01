from __future__ import annotations

import csv
import unicodedata
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
DAT_ROOT = ROOT / "01_work"
COMM = DAT_ROOT / "COMM.IMG"
OUT_DIR = DAT_ROOT / "analysis" / "story_corpus"
OUT_CORPUS = OUT_DIR / "story_corpus.csv"
OUT_GLYPHS = OUT_DIR / "japanese_glyph_map.csv"
OUT_SUMMARY = OUT_DIR / "story_corpus_summary.md"
FONT_PATH = Path(r"C:\Windows\Fonts\msgothic.ttc")
MANUAL_CHARMAP = ROOT / "05_docs" / "japanese_charmap_manual.csv"

BASELINE_DIRS = (
    "1", "21", "22", "23", "31", "32", "4", "5", "6", "7", "8", "9",
    "B", "C1", "C2", "D", "E1", "E2", "E3", "E4", "E5", "F",
)

ROW_BYTES = 0x380
TEXT_MARKERS = {0x17, 0x19}
LINEBREAK = b"\xE6\x01"
PAGEBREAK = b"\xE4\x1F"
MAX_BODY = 0x180
SCRIPT_START = 0x45000


@dataclass(frozen=True)
class Dialogue:
    file: str
    marker_offset: int
    payload_start: int
    end_exclusive: int
    capacity: int
    marker: int
    prefix_kind: str
    confidence: str
    original_hex: str
    decoded_jp: str
    glyphs: int
    exact_glyphs: int
    ambiguous_glyphs: int
    unknown_glyphs: int


def get_pixel(data: bytes, x: int, y: int) -> int:
    value = data[y * ROW_BYTES + x // 2]
    return value & 0x0F if x % 2 == 0 else value >> 4


def bitmap_key_from_comm(data: bytes, index: int) -> bytes:
    row, remainder = divmod(index, 84)
    column, plane = divmod(remainder, 4)
    bit = 1 << plane
    return b"".join(
        sum(
            (1 if get_pixel(data, column * 12 + x, row * 12 + y) & bit else 0) << x
            for x in range(12)
        ).to_bytes(2, "little")
        for y in range(12)
    )


def bitmap_key_from_font(font: ImageFont.FreeTypeFont, char: str) -> bytes:
    canvas = Image.new("L", (24, 24), 0)
    draw = ImageDraw.Draw(canvas)
    bbox = draw.textbbox((0, 0), char, font=font)
    x_pos = (24 - (bbox[2] - bbox[0])) // 2 - bbox[0]
    y_pos = (24 - (bbox[3] - bbox[1])) // 2 - bbox[1]
    draw.text((x_pos, y_pos), char, fill=255, font=font)
    glyph = canvas.crop((6, 6, 18, 18)).point(
        lambda value: 255 if value >= 192 else 0, mode="1"
    )
    return b"".join(
        sum((1 if glyph.getpixel((x, y)) else 0) << x for x in range(12)).to_bytes(
            2, "little"
        )
        for y in range(12)
    )


def cp932_characters() -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in range(256):
        try:
            char = bytes((value,)).decode("cp932")
        except UnicodeDecodeError:
            continue
        if len(char) == 1 and char not in seen:
            seen.add(char)
            result.append(char)
    for first in range(256):
        for second in range(256):
            try:
                char = bytes((first, second)).decode("cp932")
            except UnicodeDecodeError:
                continue
            if len(char) == 1 and char not in seen:
                seen.add(char)
                result.append(char)
    return result


def candidate_priority(char: str) -> tuple[int, int, int]:
    code = ord(char)
    category = unicodedata.category(char)
    if 0x3040 <= code <= 0x30FF:
        script = 0
    elif 0x4E00 <= code <= 0x9FFF:
        script = 1
    elif category.startswith(("P", "S")):
        script = 2
    elif 0x20 <= code <= 0x7E:
        script = 3
    elif 0xFF61 <= code <= 0xFF9F:
        script = 5
    else:
        script = 4
    return script, code >= 0xE000, code


def code_for_index(index: int) -> bytes:
    if index < 0xDC:
        return bytes((index + 1,))
    value = index - 0xDB
    quotient = min(3, value // 255)
    second = value - quotient * 255
    first = 0xDD + quotient
    if first > 0xE0:
        raise ValueError(f"glyph index out of encoded range: {index}")
    return bytes((first, second))


def build_glyph_map() -> tuple[
    dict[int, str], dict[int, int], dict[int, tuple[str, int]], list[dict[str, str]]
]:
    comm = COMM.read_bytes()
    font = ImageFont.truetype(str(FONT_PATH), 12, index=0)
    templates: dict[bytes, list[str]] = defaultdict(list)
    for char in cp932_characters():
        templates[bitmap_key_from_font(font, char)].append(char)
    template_ints = [
        (int.from_bytes(bitmap, "little"), sorted(set(chars), key=candidate_priority))
        for bitmap, chars in templates.items()
    ]

    selected: dict[int, str] = {}
    ambiguity: dict[int, int] = {}
    nearest: dict[int, tuple[str, int]] = {}
    rows: list[dict[str, str]] = []
    for index in range(1240):
        game_bitmap = bitmap_key_from_comm(comm, index)
        candidates = sorted(
            set(templates.get(game_bitmap, [])),
            key=candidate_priority,
        )
        if candidates:
            selected[index] = candidates[0]
            ambiguity[index] = len(candidates)
        game_bits = int.from_bytes(game_bitmap, "little")
        best_distance = min((game_bits ^ bits).bit_count() for bits, _ in template_ints)
        near_candidates = sorted(
            {
                char
                for bits, chars in template_ints
                if (game_bits ^ bits).bit_count() == best_distance
                for char in chars
            },
            key=candidate_priority,
        )
        nearest[index] = (near_candidates[0], best_distance)
        rows.append(
            {
                "index": str(index),
                "code_hex": code_for_index(index).hex(" ").upper(),
                "selected": candidates[0] if candidates else "",
                "candidate_count": str(len(candidates)),
                "candidates": "|".join(candidates),
                "match": "exact" if candidates else "unknown",
                "nearest": near_candidates[0],
                "nearest_distance": str(best_distance),
            }
        )

    row_by_index = {int(row["index"]): row for row in rows}
    with MANUAL_CHARMAP.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            code = bytes.fromhex(row["code_hex"])
            if len(code) == 1 and 0x01 <= code[0] < 0xDD:
                index = code[0] - 1
            elif len(code) == 2 and 0xDD <= code[0] <= 0xE0:
                index = (code[0] - 0xDD) * 255 + code[1] + 0xDB
            else:
                raise SystemExit(f"invalid manual Japanese code: {row['code_hex']}")
            selected[index] = row["char"]
            ambiguity[index] = 1
            row_by_index[index]["selected"] = row["char"]
            row_by_index[index]["candidate_count"] = "1"
            row_by_index[index]["candidates"] = row["char"]
            row_by_index[index]["match"] = "manual"
    return selected, ambiguity, nearest, rows


def find_header29(data: bytes, marker_offset: int) -> int | None:
    for back in range(6, 18, 2):
        offset = marker_offset - back
        if offset < 0:
            continue
        if data[offset : offset + 2] == b"\x29\x00" and data[offset + 4 : offset + 6] == b"\x7F\x00":
            return offset
    return None


def token_end(data: bytes, start: int) -> int | None:
    """Find a terminator only at a measured runtime-token boundary."""
    offset = start
    limit = min(len(data) - 1, start + MAX_BODY)
    while offset < limit:
        first = data[offset]
        if first == 0:
            return offset if data[offset + 1] == 0 else None
        if first < 0xDD:
            offset += 1
        else:
            if offset + 1 >= limit:
                return None
            offset += 2
    return None


def payload_start(
    data: bytes, marker_offset: int, marker: int, header29: int | None
) -> tuple[int, str]:
    start = marker_offset + 2
    prefix = data[start : start + 2]
    if prefix in (
        b"\x01\x00",
        b"\x02\x00",
        b"\x03\x00",
        b"\x04\x00",
        b"\x05\x00",
        b"\x07\x00",
    ):
        return start + 2, f"control_{prefix.hex()}"
    if prefix == b"\x00\x00" and marker == 0x17 and header29 == marker_offset - 6:
        return start + 2, "control_0000"
    return start, "none"


def decode_body(
    body: bytes,
    glyph_map: dict[int, str],
    ambiguity: dict[int, int],
    nearest: dict[int, tuple[str, int]],
) -> tuple[str, int, int, int, int]:
    output: list[str] = []
    glyphs = exact = ambiguous = unknown = 0
    offset = 0
    while offset < len(body):
        if body[offset : offset + 2] == LINEBREAK:
            output.append("\n")
            offset += 2
            continue
        if body[offset : offset + 2] == PAGEBREAK:
            output.append("\f")
            offset += 2
            continue
        first = body[offset]
        if 0x01 <= first < 0xDD:
            index = first - 1
            raw = body[offset : offset + 1]
            offset += 1
        elif 0xDD <= first <= 0xE0 and offset + 1 < len(body):
            second = body[offset + 1]
            index = (first - 0xDD) * 255 + second + 0xDB
            raw = body[offset : offset + 2]
            offset += 2
        elif first >= 0xE1 and offset + 1 < len(body):
            second = body[offset + 1]
            output.append(f"<CTRL:{first:02X}:{second:02X}>")
            unknown += 1
            offset += 2
            continue
        else:
            raise ValueError(f"invalid token boundary at body offset {offset}: {first:02X}")
        glyphs += 1
        if index in glyph_map:
            output.append(glyph_map[index])
            exact += 1
            if ambiguity.get(index, 0) > 1:
                ambiguous += 1
        else:
            near_char, distance = nearest[index]
            if distance <= 20:
                output.append(f"<N:{near_char}:{distance}:{raw.hex().upper()}>")
            else:
                output.append(f"<G:{raw.hex().upper()}:{index}>")
            unknown += 1
    return "".join(output), glyphs, exact, ambiguous, unknown


def scan_file(
    path: Path,
    glyph_map: dict[int, str],
    ambiguity: dict[int, int],
    nearest: dict[int, tuple[str, int]],
) -> list[Dialogue]:
    data = path.read_bytes()
    result: list[Dialogue] = []
    seen: set[int] = set()
    for marker_offset in range(max(2, SCRIPT_START), len(data) - 8, 2):
        marker = int.from_bytes(data[marker_offset : marker_offset + 2], "little")
        if marker not in TEXT_MARKERS:
            continue
        header29 = find_header29(data, marker_offset)
        start, prefix_kind = payload_start(data, marker_offset, marker, header29)
        if start in seen:
            continue
        end = token_end(data, start)
        if end is None or not (3 <= end - start <= 0x100):
            continue
        body = data[start:end]
        decoded, glyphs, exact, ambiguous, unknown = decode_body(
            body, glyph_map, ambiguity, nearest
        )
        if glyphs == 0:
            continue
        ratio = exact / glyphs
        has_break = LINEBREAK in body or PAGEBREAK in body
        if ratio < 0.45 and header29 is None and not has_break:
            continue
        confidence = "high" if header29 is not None else "medium"
        if ratio >= 0.8 and has_break:
            confidence = "high"
        result.append(
            Dialogue(
                file=str(path.relative_to(DAT_ROOT)).replace("\\", "/"),
                marker_offset=marker_offset,
                payload_start=start,
                end_exclusive=end,
                capacity=end - start,
                marker=marker,
                prefix_kind=prefix_kind,
                confidence=confidence,
                original_hex=body.hex(" "),
                decoded_jp=decoded,
                glyphs=glyphs,
                exact_glyphs=exact,
                ambiguous_glyphs=ambiguous,
                unknown_glyphs=unknown,
            )
        )
        seen.add(start)
    return result


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    glyph_map, ambiguity, nearest, glyph_rows = build_glyph_map()
    with OUT_GLYPHS.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=glyph_rows[0].keys())
        writer.writeheader()
        writer.writerows(glyph_rows)

    dialogues: list[Dialogue] = []
    for directory in BASELINE_DIRS:
        for path in sorted((DAT_ROOT / directory).glob("*.DAT")):
            dialogues.extend(scan_file(path, glyph_map, ambiguity, nearest))

    fieldnames = list(asdict(dialogues[0]).keys()) if dialogues else []
    with OUT_CORPUS.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for item in dialogues:
            row = asdict(item)
            for key in ("marker_offset", "payload_start", "end_exclusive", "marker"):
                row[key] = f"0x{row[key]:X}"
            writer.writerow(row)

    by_file = Counter(item.file for item in dialogues)
    high = sum(item.confidence == "high" for item in dialogues)
    total_glyphs = sum(item.glyphs for item in dialogues)
    exact_glyphs = sum(item.exact_glyphs for item in dialogues)
    unknown_glyphs = sum(item.unknown_glyphs for item in dialogues)
    lines = [
        "# Story corpus extraction summary",
        "",
        f"- Dialogue candidates: {len(dialogues)}",
        f"- Files with candidates: {len(by_file)}",
        f"- High-confidence candidates: {high}",
        f"- Exact glyph-map entries: {len(glyph_map)} / 1240",
        f"- Decoded glyph occurrences: {exact_glyphs} / {total_glyphs}",
        f"- Unknown glyph/control occurrences: {unknown_glyphs}",
        "",
        "## Largest files",
        "",
        "| file | dialogues |",
        "|---|---:|",
    ]
    for file, count in by_file.most_common(80):
        lines.append(f"| `{file}` | {count} |")
    lines.extend(
        [
            "",
            "## Safety",
            "",
            "- This command only reads original DAT/COMM data and writes analysis files.",
            "- `<G:...>` marks a glyph without an exact bitmap match.",
            "- `<N:char:distance:code>` is a visual hint, not a confirmed character.",
            "- `<CTRL:XX:YY>` preserves an unclassified two-byte control pair.",
            "- Ambiguous exact matches are counted separately for later language-model review.",
        ]
    )
    OUT_SUMMARY.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"wrote {OUT_GLYPHS}")
    print(f"wrote {OUT_CORPUS}")
    print(f"wrote {OUT_SUMMARY}")
    print(
        f"dialogues={len(dialogues)} files={len(by_file)} high={high} "
        f"glyph_coverage={exact_glyphs}/{total_glyphs} unknown={unknown_glyphs}"
    )


if __name__ == "__main__":
    main()
