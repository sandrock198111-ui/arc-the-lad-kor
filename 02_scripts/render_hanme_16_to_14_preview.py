#!/usr/bin/env python3
"""Render a static Hanme 16px -> 14px comparison sheet.

This is deliberately not a game builder.  It reads the hash-pinned 16px Hanme
component blob used by V320C, composes syllables with the verified upstream
beol arrays, and compares four 14px conversions against the current 16px
bitmap.  No ARC member, disc image, executable, or save state is modified.
"""

from __future__ import annotations

import csv
import hashlib
import struct
from fractions import Fraction
from pathlib import Path

import PIL
from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
PIECES_PATH = ROOT / "01_work/analysis/hangul_johab_16px/pieces_1bpp.bin"
PIECES_SHA256 = "409ABA72F4BA2282AA5C4E4982A9EEA16FBD14FB0413A40E151537A6653E2904"
OUTPUT_PATH = ROOT / "04_screenshots/hanme_16_to_14_comparison.png"
ANALYSIS_DIR = ROOT / "01_work/analysis/hanme_16_to_14_preview"
METRICS_PATH = ANALYSIS_DIR / "metrics.csv"
REPORT_PATH = ANALYSIS_DIR / "report.txt"
LABEL_FONT_PATH = Path("C:/Windows/Fonts/malgun.ttf")

CELL = 16
TARGET = 14

# Vowel order:
# ㅏ ㅐ ㅑ ㅒ ㅓ ㅔ ㅕ ㅖ ㅗ ㅘ ㅙ ㅚ ㅛ ㅜ ㅝ ㅞ ㅟ ㅠ ㅡ ㅢ ㅣ
# These arrays match the hash-pinned upstream generate_hangul_syllables.py.
CHO_KIND_WITHOUT_JONG = (
    0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 3, 1, 2, 4, 4, 4, 2, 1, 3, 0,
)
CHO_KIND_WITH_JONG = (
    5, 5, 5, 5, 5, 5, 5, 5, 6, 7, 7, 7, 6, 6, 7, 7, 7, 6, 6, 7, 5,
)
JONG_KIND_BY_JUNG = (
    0, 2, 0, 2, 1, 2, 1, 2, 3, 0, 2, 1, 3, 3, 1, 2, 1, 3, 3, 1, 1,
)

FOCUS_CHARS = "괄유물인엄마촌들속롭론온는봉용꽃동"
DENSE_CHARS = "뛟쀎쀏쮊쮋"
SPARSE_CHARS = "그느스끄고"
METRIC_CHARS = FOCUS_CHARS + DENSE_CHARS + SPARSE_CHARS
SAMPLE_LINES = (
    "괄 유물인 엄마",
    "촌 들 속 롭 론 온",
    "는 봉 용 꽃 동",
    "약속대로 이 마을에서",
    "그런 걸 신경 쓰고",
)


class PreviewError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def load_pieces() -> tuple[tuple[int, ...], ...]:
    raw = PIECES_PATH.read_bytes()
    if sha256_bytes(raw) != PIECES_SHA256:
        raise PreviewError("pieces_1bpp.bin hash drift")
    if len(raw) != 360 * CELL * 2:
        raise PreviewError("pieces_1bpp.bin size drift")
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
        raise PreviewError("Hanme component layout drift")
    return pieces


def decompose(ch: str) -> tuple[int, int, int]:
    if len(ch) != 1 or not 0xAC00 <= ord(ch) <= 0xD7A3:
        raise PreviewError("not a modern Hangul syllable: {!r}".format(ch))
    value = ord(ch) - 0xAC00
    cho, remainder = divmod(value, 588)
    jung, jong = divmod(remainder, 28)
    return cho, jung, jong


def component_indices(ch: str) -> tuple[int, int, int]:
    cho, jung, jong = decompose(ch)
    cho_beol = CHO_KIND_WITH_JONG[jung] if jong else CHO_KIND_WITHOUT_JONG[jung]
    jung_beol = (0 if cho in (0, 15) else 1) + (2 if jong else 0)
    jong_beol = JONG_KIND_BY_JUNG[jung]
    return (
        cho_beol * 20 + cho + 1,
        160 + jung_beol * 22 + jung + 1,
        248 + jong_beol * 28 + jong if jong else -1,
    )


def compose(
    pieces: tuple[tuple[int, ...], ...], ch: str
) -> tuple[tuple[int, ...], ...]:
    cho_piece, jung_piece, jong_piece = component_indices(ch)
    rows = tuple(
        pieces[cho_piece][y]
        | pieces[jung_piece][y]
        | (pieces[jong_piece][y] if jong_piece >= 0 else 0)
        for y in range(CELL)
    )
    return tuple(
        tuple((row >> (CELL - 1 - x)) & 1 for x in range(CELL))
        for row in rows
    )


def center_crop(bitmap: tuple[tuple[int, ...], ...]) -> tuple[tuple[int, ...], ...]:
    return tuple(tuple(row[1:15]) for row in bitmap[1:15])


def nearest_14(bitmap: tuple[tuple[int, ...], ...]) -> tuple[tuple[int, ...], ...]:
    # Align-corners mapping used in the independent audit.
    mapping = tuple(round(i * (CELL - 1) / (TARGET - 1)) for i in range(TARGET))
    return tuple(
        tuple(bitmap[mapping[y]][mapping[x]] for x in range(TARGET))
        for y in range(TARGET)
    )


def overlap(a0: Fraction, a1: Fraction, b0: int, b1: int) -> Fraction:
    return max(Fraction(0), min(a1, Fraction(b1)) - max(a0, Fraction(b0)))


def area_14(
    bitmap: tuple[tuple[int, ...], ...], threshold_percent: int
) -> tuple[tuple[int, ...], ...]:
    scale = Fraction(CELL, TARGET)
    cell_area = scale * scale
    result: list[tuple[int, ...]] = []
    for dy in range(TARGET):
        y0 = Fraction(dy * CELL, TARGET)
        y1 = Fraction((dy + 1) * CELL, TARGET)
        row: list[int] = []
        for dx in range(TARGET):
            x0 = Fraction(dx * CELL, TARGET)
            x1 = Fraction((dx + 1) * CELL, TARGET)
            ink = Fraction(0)
            for sy in range(CELL):
                oy = overlap(y0, y1, sy, sy + 1)
                if not oy:
                    continue
                for sx in range(CELL):
                    if not bitmap[sy][sx]:
                        continue
                    ox = overlap(x0, x1, sx, sx + 1)
                    ink += ox * oy
            row.append(1 if ink * 100 >= cell_area * threshold_percent else 0)
        result.append(tuple(row))
    return tuple(result)


METHODS = (
    ("current16", "현재 16px", "16×16 / 전진 14 / 행 16", lambda bitmap: bitmap),
    ("crop14", "중앙 크롭 14px", "상하좌우 1px 제거", center_crop),
    ("nearest14", "최근접 14px", "경계 보존 / 획이 가늘어짐", nearest_14),
    ("area35", "면적 35% 14px", "조금 굵게 보존", lambda bitmap: area_14(bitmap, 35)),
    ("area50", "면적 50% 14px", "조금 가늘게 보존", lambda bitmap: area_14(bitmap, 50)),
)


def connected_components(bitmap: tuple[tuple[int, ...], ...]) -> int:
    height = len(bitmap)
    width = len(bitmap[0])
    seen: set[tuple[int, int]] = set()
    count = 0
    for y in range(height):
        for x in range(width):
            if not bitmap[y][x] or (x, y) in seen:
                continue
            count += 1
            stack = [(x, y)]
            seen.add((x, y))
            while stack:
                cx, cy = stack.pop()
                for oy in (-1, 0, 1):
                    for ox in (-1, 0, 1):
                        if not ox and not oy:
                            continue
                        nx, ny = cx + ox, cy + oy
                        if (
                            0 <= nx < width
                            and 0 <= ny < height
                            and bitmap[ny][nx]
                            and (nx, ny) not in seen
                        ):
                            seen.add((nx, ny))
                            stack.append((nx, ny))
    return count


def ink_count(bitmap: tuple[tuple[int, ...], ...]) -> int:
    return sum(sum(row) for row in bitmap)


def edge_ink(bitmap: tuple[tuple[int, ...], ...]) -> int:
    size = len(bitmap)
    cells = {(x, 0) for x in range(size)} | {(x, size - 1) for x in range(size)}
    cells |= {(0, y) for y in range(size)} | {(size - 1, y) for y in range(size)}
    return sum(bitmap[y][x] for x, y in cells)


def load_label_font(size: int) -> ImageFont.FreeTypeFont:
    if not LABEL_FONT_PATH.is_file():
        raise PreviewError("label font missing: {}".format(LABEL_FONT_PATH))
    return ImageFont.truetype(str(LABEL_FONT_PATH), size=size)


def centered_text(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    text: str,
    font: ImageFont.FreeTypeFont,
    fill: tuple[int, int, int],
) -> None:
    bounds = draw.textbbox((0, 0), text, font=font)
    width = bounds[2] - bounds[0]
    height = bounds[3] - bounds[1]
    x = box[0] + (box[2] - box[0] - width) // 2
    y = box[1] + (box[3] - box[1] - height) // 2 - bounds[1]
    draw.text((x, y), text, font=font, fill=fill)


def draw_bitmap(
    draw: ImageDraw.ImageDraw,
    bitmap: tuple[tuple[int, ...], ...],
    x0: int,
    y0: int,
    scale: int,
    fill: tuple[int, int, int],
) -> None:
    for y, row in enumerate(bitmap):
        for x, value in enumerate(row):
            if value:
                draw.rectangle(
                    (
                        x0 + x * scale,
                        y0 + y * scale,
                        x0 + (x + 1) * scale - 1,
                        y0 + (y + 1) * scale - 1,
                    ),
                    fill=fill,
                )


def draw_phrase(
    draw: ImageDraw.ImageDraw,
    pieces: tuple[tuple[int, ...], ...],
    transform,
    text: str,
    x0: int,
    y0: int,
    pixel_scale: int,
    advance: int,
) -> None:
    cursor = x0
    for ch in text:
        if ch == " ":
            cursor += 6 * pixel_scale
            continue
        bitmap = transform(compose(pieces, ch))
        draw_bitmap(draw, bitmap, cursor, y0, pixel_scale, (248, 248, 248))
        cursor += advance * pixel_scale


def wrapped_text(
    draw: ImageDraw.ImageDraw,
    text: str,
    box: tuple[int, int, int, int],
    font: ImageFont.FreeTypeFont,
    fill: tuple[int, int, int],
    line_gap: int = 4,
) -> None:
    words = text.split(" ")
    lines: list[str] = []
    current = ""
    max_width = box[2] - box[0]
    for word in words:
        candidate = word if not current else current + " " + word
        bounds = draw.textbbox((0, 0), candidate, font=font)
        if current and bounds[2] - bounds[0] > max_width:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    y = box[1]
    for line in lines:
        bounds = draw.textbbox((0, 0), line, font=font)
        draw.text((box[0], y - bounds[1]), line, font=font, fill=fill)
        y += bounds[3] - bounds[1] + line_gap


def build_metrics(
    pieces: tuple[tuple[int, ...], ...]
) -> tuple[list[dict[str, object]], dict[str, dict[str, float]]]:
    rows: list[dict[str, object]] = []
    summary: dict[str, dict[str, float]] = {}
    for key, _title, _note, transform in METHODS:
        density_ratios: list[float] = []
        component_changes = 0
        edge_sources = 0
        for ch in METRIC_CHARS:
            source = compose(pieces, ch)
            output = transform(source)
            source_ink = ink_count(source)
            output_ink = ink_count(output)
            source_density = source_ink / (len(source) * len(source[0]))
            output_density = output_ink / (len(output) * len(output[0]))
            density_ratio = output_density / source_density
            source_components = connected_components(source)
            output_components = connected_components(output)
            source_edge = edge_ink(source)
            edge_sources += int(source_edge > 0)
            component_changes += int(source_components != output_components)
            density_ratios.append(density_ratio)
            rows.append(
                {
                    "char": ch,
                    "unicode": "U+{:04X}".format(ord(ch)),
                    "method": key,
                    "source_ink": source_ink,
                    "output_ink": output_ink,
                    "density_ratio": "{:.4f}".format(density_ratio),
                    "source_components": source_components,
                    "output_components": output_components,
                    "source_edge_ink": source_edge,
                }
            )
        summary[key] = {
            "mean_density_ratio": sum(density_ratios) / len(density_ratios),
            "component_changes": float(component_changes),
            "edge_source_chars": float(edge_sources),
        }
    return rows, summary


def render_sheet(
    pieces: tuple[tuple[int, ...], ...],
    summary: dict[str, dict[str, float]],
) -> Image.Image:
    width, height = 2400, 1320
    margin, gap, panel_width = 40, 20, 448
    image = Image.new("RGB", (width, height), (18, 20, 26))
    draw = ImageDraw.Draw(image)
    title_font = load_label_font(34)
    subtitle_font = load_label_font(20)
    panel_font = load_label_font(24)
    small_font = load_label_font(16)
    tiny_font = load_label_font(14)

    draw.text((margin, 24), "Hanme 공식 벌 16px → 14px 정적 비교", font=title_font, fill=(255, 255, 255))
    draw.text(
        (margin, 72),
        "게임 데이터는 변경하지 않았습니다. 위쪽은 픽셀 4배 확대, 아래쪽 문장은 픽셀 2배 확대입니다.",
        font=subtitle_font,
        fill=(168, 178, 196),
    )

    source_chars = {
        ch for ch in set(METRIC_CHARS + "".join(SAMPLE_LINES)) if ch != " "
    }
    source_cache = {ch: compose(pieces, ch) for ch in source_chars}
    transformed: dict[str, dict[str, tuple[tuple[int, ...], ...]]] = {}
    for key, _title, _note, transform in METHODS:
        transformed[key] = {ch: transform(bitmap) for ch, bitmap in source_cache.items()}

    for method_index, (key, title, note, transform) in enumerate(METHODS):
        panel_x = margin + method_index * (panel_width + gap)
        panel_box = (panel_x, 116, panel_x + panel_width, 1260)
        draw.rounded_rectangle(panel_box, radius=16, fill=(33, 37, 46), outline=(66, 73, 88), width=2)
        centered_text(
            draw,
            (panel_x + 8, 128, panel_x + panel_width - 8, 164),
            title,
            panel_font,
            (255, 255, 255),
        )
        centered_text(
            draw,
            (panel_x + 8, 162, panel_x + panel_width - 8, 190),
            note,
            small_font,
            (158, 174, 202),
        )

        zoom = 4
        stride_x, stride_y = 82, 88
        glyph_top = 206
        for char_index, ch in enumerate(FOCUS_CHARS):
            column = char_index % 5
            row = char_index // 5
            cell_x = panel_x + 20 + column * stride_x
            cell_y = glyph_top + row * stride_y
            draw.rectangle(
                (cell_x, cell_y, cell_x + 63, cell_y + 63),
                fill=(20, 23, 30),
                outline=(82, 89, 105),
                width=1,
            )
            bitmap = transformed[key][ch]
            inset = (CELL - len(bitmap)) // 2
            if len(bitmap) == TARGET:
                draw.rectangle(
                    (
                        cell_x + inset * zoom,
                        cell_y + inset * zoom,
                        cell_x + (inset + TARGET) * zoom - 1,
                        cell_y + (inset + TARGET) * zoom - 1,
                    ),
                    outline=(127, 91, 44),
                    width=1,
                )
            draw_bitmap(
                draw,
                bitmap,
                cell_x + inset * zoom,
                cell_y + inset * zoom,
                zoom,
                (248, 248, 248),
            )
            centered_text(
                draw,
                (cell_x, cell_y + 65, cell_x + 64, cell_y + 84),
                ch,
                tiny_font,
                (197, 204, 218),
            )

        text_top = 584
        draw.text(
            (panel_x + 18, text_top),
            "문장 조판",
            font=small_font,
            fill=(221, 225, 234),
        )
        block = (panel_x + 18, text_top + 30, panel_x + panel_width - 18, text_top + 234)
        draw.rectangle(block, fill=(38, 31, 27), outline=(96, 80, 62), width=2)
        line_pitch = 16 if key == "current16" else 14
        for line_index, line in enumerate(SAMPLE_LINES):
            draw_phrase(
                draw,
                pieces,
                transform,
                line,
                block[0] + 14,
                block[1] + 14 + line_index * line_pitch * 2,
                2,
                14,
            )

        stats = summary[key]
        metric_text = (
            "27자 평균 밀도비 {:.3f} / 연결요소 변화 {}자".format(
                stats["mean_density_ratio"], int(stats["component_changes"])
            )
        )
        wrapped_text(
            draw,
            metric_text,
            (panel_x + 18, 862, panel_x + panel_width - 18, 930),
            small_font,
            (233, 205, 132),
        )
        descriptions = {
            "current16": "현재 V320C 모양입니다. 16px 그림을 14px씩 전진시켜 글자끼리 2px 겹칩니다.",
            "crop14": "획 굵기는 거의 그대로지만 셀 바깥 1px을 버립니다. 괄·마처럼 경계에 닿는 획이 잘립니다.",
            "nearest14": "가장자리 획은 남지만 16행·열 중 일부를 건너뛰어 전체적으로 가장 가늘게 보입니다.",
            "area35": "면적 리샘플 뒤 35% 이상을 켭니다. 얇은 획을 보존하면서 50%보다 조금 굵습니다.",
            "area50": "면적 리샘플 뒤 50% 이상을 켭니다. 35%보다 정돈되지만 얇은 획은 더 가늘어집니다.",
        }
        wrapped_text(
            draw,
            descriptions[key],
            (panel_x + 18, 928, panel_x + panel_width - 18, 1050),
            small_font,
            (184, 192, 207),
            line_gap=6,
        )
        if key in ("area35", "area50"):
            badge = "Claude 정량 안전 구간"
            draw.rounded_rectangle(
                (panel_x + 64, 1120, panel_x + panel_width - 64, 1160),
                radius=12,
                outline=(93, 182, 135),
                width=2,
            )
            centered_text(
                draw,
                (panel_x + 64, 1120, panel_x + panel_width - 64, 1160),
                badge,
                small_font,
                (131, 222, 172),
            )

    draw.text(
        (margin, 1280),
        "선택용 미리보기: 현재 16px / 중앙 크롭 / 최근접 / 면적 35% / 면적 50%",
        font=small_font,
        fill=(148, 158, 176),
    )
    return image


def main() -> None:
    pieces = load_pieces()
    metric_rows, summary = build_metrics(pieces)
    image = render_sheet(pieces, summary)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
    image.save(OUTPUT_PATH, format="PNG", optimize=False, compress_level=9)

    fieldnames = (
        "char",
        "unicode",
        "method",
        "source_ink",
        "output_ink",
        "density_ratio",
        "source_components",
        "output_components",
        "source_edge_ink",
    )
    with METRICS_PATH.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(metric_rows)

    report_lines = [
        "Hanme 16px -> 14px static preview",
        "game_data_modified=no",
        "pieces_sha256={}".format(PIECES_SHA256),
        "pillow_version={}".format(PIL.__version__),
        "label_font_sha256={}".format(sha256_file(LABEL_FONT_PATH)),
        "preview={}".format(OUTPUT_PATH.relative_to(ROOT).as_posix()),
        "preview_sha256={}".format(sha256_file(OUTPUT_PATH)),
        "metrics={}".format(METRICS_PATH.relative_to(ROOT).as_posix()),
    ]
    for key, _title, _note, _transform in METHODS:
        stats = summary[key]
        report_lines.append(
            "{} mean_density_ratio={:.4f} component_changes={}".format(
                key,
                stats["mean_density_ratio"],
                int(stats["component_changes"]),
            )
        )
    REPORT_PATH.write_text("\n".join(report_lines) + "\n", encoding="utf-8")

    print("preview={}".format(OUTPUT_PATH))
    print("preview_sha256={}".format(sha256_file(OUTPUT_PATH)))
    print("metrics={}".format(METRICS_PATH))
    print("report={}".format(REPORT_PATH))
    print("game data modified: no")


if __name__ == "__main__":
    main()
