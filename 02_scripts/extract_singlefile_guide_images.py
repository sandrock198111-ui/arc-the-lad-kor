#!/usr/bin/env python3
"""Extract large embedded raster images from locally saved SingleFile pages."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import re
import struct
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote_to_bytes


DATA_URI_RE = re.compile(
    r"data:(image/(?:jpeg|jpg|png|gif|webp));(?:(base64),)?([^\"'<>\s)]+)",
    re.IGNORECASE,
)
POST_NUMBER_RE = re.compile(r"입니다\.(\d+)")


class ImageSourceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.sources: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "img":
            return
        values = dict(attrs)
        for key in ("src", "data-src", "data-lazy-src"):
            value = values.get(key)
            if value and value.startswith("data:image/"):
                self.sources.append(value)


@dataclass(frozen=True)
class EmbeddedImage:
    mime: str
    data: bytes


def natural_post_key(path: Path) -> tuple[int, str]:
    match = POST_NUMBER_RE.search(path.name)
    return (int(match.group(1)) if match else 9999, path.name)


def decode_data_uri(mime: str, encoding: str | None, payload: str) -> EmbeddedImage | None:
    try:
        if encoding and encoding.lower() == "base64":
            data = base64.b64decode(payload, validate=False)
        else:
            data = unquote_to_bytes(payload)
    except (ValueError, base64.binascii.Error):
        return None
    return EmbeddedImage(mime=mime.lower(), data=data)


def dimensions(data: bytes) -> tuple[int | None, int | None]:
    if data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) >= 24:
        return struct.unpack(">II", data[16:24])
    if data.startswith((b"GIF87a", b"GIF89a")) and len(data) >= 10:
        return struct.unpack("<HH", data[6:10])
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP" and len(data) >= 30:
        chunk = data[12:16]
        if chunk == b"VP8X":
            return (
                1 + int.from_bytes(data[24:27], "little"),
                1 + int.from_bytes(data[27:30], "little"),
            )
        if chunk == b"VP8L" and data[20] == 0x2F:
            bits = int.from_bytes(data[21:25], "little")
            return (1 + (bits & 0x3FFF), 1 + ((bits >> 14) & 0x3FFF))
    if data.startswith(b"\xff\xd8"):
        pos = 2
        while pos + 9 < len(data):
            if data[pos] != 0xFF:
                pos += 1
                continue
            marker = data[pos + 1]
            pos += 2
            if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
                continue
            if pos + 2 > len(data):
                break
            length = int.from_bytes(data[pos : pos + 2], "big")
            if length < 2 or pos + length > len(data):
                break
            if marker in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}:
                height = int.from_bytes(data[pos + 3 : pos + 5], "big")
                width = int.from_bytes(data[pos + 5 : pos + 7], "big")
                return width, height
            pos += length
    return None, None


def extension(mime: str) -> str:
    return {"image/jpeg": ".jpg", "image/jpg": ".jpg"}.get(mime, "." + mime.split("/", 1)[1])


def collect_images(html: str) -> list[EmbeddedImage]:
    parser = ImageSourceParser()
    parser.feed(html)
    sources = list(parser.sources)
    sources.extend(match.group(0) for match in DATA_URI_RE.finditer(html))

    images: list[EmbeddedImage] = []
    seen: set[str] = set()
    for source in sources:
        match = DATA_URI_RE.match(source)
        if not match:
            continue
        image = decode_data_uri(match.group(1), match.group(2), match.group(3))
        if not image:
            continue
        digest = hashlib.sha256(image.data).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        images.append(image)
    return images


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path, help="Directory containing saved SingleFile HTML pages")
    parser.add_argument("output", type=Path, help="Directory for extracted candidate images")
    parser.add_argument("--min-bytes", type=int, default=100_000)
    parser.add_argument("--min-width", type=int, default=600)
    parser.add_argument("--min-height", type=int, default=400)
    args = parser.parse_args()

    files = sorted(args.source.glob("*.html"), key=natural_post_key)
    if not files:
        raise SystemExit(f"No HTML files found in {args.source}")
    args.output.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, str | int]] = []
    exported: dict[str, str] = {}
    for source_index, html_path in enumerate(files, 1):
        html = html_path.read_text(encoding="utf-8", errors="replace")
        candidates = collect_images(html)
        page_image_index = 0
        for image in candidates:
            width, height = dimensions(image.data)
            if len(image.data) < args.min_bytes:
                continue
            if width is not None and height is not None and (width < args.min_width or height < args.min_height):
                continue
            page_image_index += 1
            digest = hashlib.sha256(image.data).hexdigest()
            if digest not in exported:
                filename = f"post_{source_index:02d}_image_{page_image_index:02d}{extension(image.mime)}"
                (args.output / filename).write_bytes(image.data)
                exported[digest] = filename
            rows.append(
                {
                    "post": source_index,
                    "source_html": html_path.name,
                    "source_image": page_image_index,
                    "extracted_file": exported[digest],
                    "mime": image.mime,
                    "bytes": len(image.data),
                    "width": width or "",
                    "height": height or "",
                    "sha256": digest,
                }
            )

    index_path = args.output / "index.csv"
    with index_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]) if rows else ["post"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"HTML pages: {len(files)}")
    print(f"Candidate references: {len(rows)}")
    print(f"Unique extracted images: {len(exported)}")
    print(f"Index: {index_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
