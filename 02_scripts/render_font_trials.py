from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "01_work" / "font_trials" / "contact_sheet.png"
CHARS = "여기까지다이뒤는혼자가라아크조심하거돌올때리겠예"
FONTS = [
    ("Gulim", Path(r"C:\Windows\Fonts\gulim.ttc")),
    ("Malgun", Path(r"C:\Windows\Fonts\malgun.ttf")),
    ("HANDotum", Path(r"C:\Windows\Fonts\HANDotum.TTF")),
]
TRIALS = [(12, 128), (12, 192), (13, 128), (13, 192)]
SCALE = 6


def render_glyph(font_path: Path, size: int, threshold: int, char: str) -> Image.Image:
    font = ImageFont.truetype(str(font_path), size=size)
    canvas = Image.new("L", (24, 24), 0)
    draw = ImageDraw.Draw(canvas)
    bbox = draw.textbbox((0, 0), char, font=font)
    width = bbox[2] - bbox[0]
    height = bbox[3] - bbox[1]
    x = (24 - width) // 2 - bbox[0]
    y = (24 - height) // 2 - bbox[1]
    draw.text((x, y), char, fill=255, font=font)
    crop = canvas.crop((6, 6, 18, 18))
    return crop.point(lambda value: 255 if value >= threshold else 0, mode="1")


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    tile = 12 * SCALE
    label_height = 22
    row_height = tile + label_height
    sheet = Image.new("RGB", (len(CHARS) * tile, len(FONTS) * len(TRIALS) * row_height), "#202020")
    label_font = ImageFont.load_default()
    draw = ImageDraw.Draw(sheet)

    row = 0
    for font_name, font_path in FONTS:
        for size, threshold in TRIALS:
            label = f"{font_name} size={size} threshold={threshold}"
            draw.text((4, row * row_height + 3), label, fill="white", font=label_font)
            for column, char in enumerate(CHARS):
                glyph = render_glyph(font_path, size, threshold, char).resize((tile, tile), Image.Resampling.NEAREST)
                sheet.paste(glyph.convert("RGB"), (column * tile, row * row_height + label_height))
            row += 1

    sheet.save(OUTPUT)
    print(OUTPUT)


if __name__ == "__main__":
    main()
