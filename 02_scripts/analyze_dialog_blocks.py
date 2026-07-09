from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DAT_ROOT = ROOT / "01_work"
OUT_DIR = ROOT / "01_work" / "analysis"
OUT_CSV = OUT_DIR / "dialog_block_candidates.csv"
OUT_MD = OUT_DIR / "dialog_block_candidates_summary.md"

# Observed text/display markers immediately before body bytes.
# 0x17 and 0x19 are common for visible dialogue bodies in S1011/S1071/S1072.
TEXT_MARKERS = {0x17, 0x19}

# Bytes frequently seen in Japanese text bodies and control line breaks.
TEXTY_BYTES = set(range(0x1A, 0x62)) | {0x81, 0x8B, 0x8E, 0x8F, 0x92, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0xA1, 0xA6, 0xA9, 0xAD, 0xAF, 0xB3, 0xB5, 0xBD, 0xBF, 0xC4, 0xC5, 0xCA, 0xCB, 0xCD, 0xCF, 0xD4, 0xD9, 0xDA, 0xDD, 0xDE, 0xDF, 0xE4, 0xE6}


@dataclass(frozen=True)
class Candidate:
    file: str
    marker_offset: int
    body_start: int
    payload_start: int
    end_exclusive: int
    double_zero: int
    marker: int
    length: int
    payload_capacity: int
    linebreaks: int
    header29_offset: int | None
    confidence: str
    prefix_kind: str
    preserved_prefix_hex: str
    control_after_hex: str
    preview_hex: str


def first_double_zero(data: bytes, start: int, max_len: int = 0x180) -> int | None:
    limit = min(len(data) - 1, start + max_len)
    for i in range(start, limit):
        if data[i] == 0 and data[i + 1] == 0:
            return i
    return None


def has_text_shape(body: bytes) -> bool:
    if len(body) < 4:
        return False
    nonzero = [b for b in body if b != 0]
    if len(nonzero) < 4:
        return False
    texty = sum(1 for b in nonzero if b in TEXTY_BYTES)
    # Dialogue bodies often contain linebreak E6 01, but short one-line blocks may not.
    return texty / len(nonzero) >= 0.65


def find_header29(data: bytes, marker_offset: int) -> int | None:
    # Common pattern:
    #   29 00 xx 00 7F 00 17/19 00 <text body> 00 00
    for back in range(6, 18, 2):
        h = marker_offset - back
        if h < 0:
            continue
        if data[h:h + 2] == b"\x29\x00" and h + 7 < len(data) and data[h + 4:h + 6] == b"\x7F\x00":
            return h
    return None


def split_payload_start(body: bytes, body_start: int) -> tuple[int, str, str]:
    # Observed in S1011 and several one-line portrait blocks:
    #   17/19 00 01 00 <visible text> 00 00 ...
    # The 01 00 prefix behaves like an internal display/control prefix and was
    # not overwritten by the successful S1011 patches. Speaker-name bytes such
    # as DD 0B D4 25 are visible text and must stay inside the payload region.
    if body.startswith(b"\x01\x00"):
        return body_start + 2, "control_0100", body[:2].hex(" ")
    return body_start, "none", ""


def scan_file(path: Path) -> list[Candidate]:
    data = path.read_bytes()
    candidates: list[Candidate] = []
    seen_starts: set[int] = set()

    for marker_offset in range(2, len(data) - 8, 2):
        marker = data[marker_offset] | (data[marker_offset + 1] << 8)
        if marker not in TEXT_MARKERS:
            continue
        body_start = marker_offset + 2
        if body_start in seen_starts:
            continue
        double_zero = first_double_zero(data, body_start)
        if double_zero is None:
            continue
        length = double_zero - body_start
        if not (4 <= length <= 0x100):
            continue
        body = data[body_start:double_zero]
        if not has_text_shape(body):
            continue
        payload_start, prefix_kind, preserved_prefix_hex = split_payload_start(body, body_start)
        header29 = find_header29(data, marker_offset)
        linebreaks = body.count(b"\xE6\x01")
        confidence = "high" if header29 is not None else "medium"
        if linebreaks >= 1:
            confidence = "high" if confidence == "high" else "medium+"
        preview_hex = body[:48].hex(" ")
        candidates.append(
            Candidate(
                file=str(path.relative_to(DAT_ROOT)).replace("\\", "/"),
                marker_offset=marker_offset,
                body_start=body_start,
                payload_start=payload_start,
                end_exclusive=double_zero,
                double_zero=double_zero,
                marker=marker,
                length=length,
                payload_capacity=double_zero - payload_start,
                linebreaks=linebreaks,
                header29_offset=header29,
                confidence=confidence,
                prefix_kind=prefix_kind,
                preserved_prefix_hex=preserved_prefix_hex,
                control_after_hex=data[double_zero:double_zero + 16].hex(" "),
                preview_hex=preview_hex,
            )
        )
        seen_starts.add(body_start)

    # Remove candidates fully contained inside a previous candidate.
    filtered: list[Candidate] = []
    for cand in candidates:
        if any(other.file == cand.file and other.body_start < cand.body_start and cand.end_exclusive <= other.end_exclusive for other in candidates):
            continue
        filtered.append(cand)
    return filtered


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    all_candidates: list[Candidate] = []
    for path in sorted(DAT_ROOT.rglob("*.DAT")):
        # Skip generated test folders; analyze original extracted files only.
        rel = str(path.relative_to(DAT_ROOT)).replace("\\", "/")
        if rel.startswith("story_test_"):
            continue
        all_candidates.extend(scan_file(path))

    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "file", "marker_offset", "body_start", "payload_start", "end_exclusive", "double_zero", "marker",
                "length", "payload_capacity", "linebreaks", "header29_offset", "confidence",
                "prefix_kind", "preserved_prefix_hex", "control_after_hex", "preview_hex",
            ],
        )
        writer.writeheader()
        for c in all_candidates:
            writer.writerow({
                "file": c.file,
                "marker_offset": f"0x{c.marker_offset:X}",
                "body_start": f"0x{c.body_start:X}",
                "payload_start": f"0x{c.payload_start:X}",
                "end_exclusive": f"0x{c.end_exclusive:X}",
                "double_zero": f"0x{c.double_zero:X}",
                "marker": f"0x{c.marker:X}",
                "length": c.length,
                "payload_capacity": c.payload_capacity,
                "linebreaks": c.linebreaks,
                "header29_offset": "" if c.header29_offset is None else f"0x{c.header29_offset:X}",
                "confidence": c.confidence,
                "prefix_kind": c.prefix_kind,
                "preserved_prefix_hex": c.preserved_prefix_hex,
                "control_after_hex": c.control_after_hex,
                "preview_hex": c.preview_hex,
            })

    by_file: dict[str, int] = {}
    high_count = 0
    for c in all_candidates:
        by_file[c.file] = by_file.get(c.file, 0) + 1
        if c.confidence == "high":
            high_count += 1

    top = sorted(by_file.items(), key=lambda kv: (-kv[1], kv[0]))[:80]
    lines = [
        "# Dialogue block candidate summary",
        "",
        f"- Total candidates: {len(all_candidates)}",
        f"- High-confidence candidates: {high_count}",
        "",
        "## Top files",
        "",
        "| file | candidates |",
        "|---|---:|",
    ]
    for file, count in top:
        lines.append(f"| `{file}` | {count} |")
    lines.extend([
        "",
        "## Notes",
        "",
        "- `body_start` starts immediately after marker `17 00` or `19 00`.",
        "- `payload_start` is the first byte the patcher may overwrite. A leading `01 00` prefix is preserved.",
        "- Body ends at the first `00 00` boundary; bytes at and after that boundary are treated as control data.",
        "- `high` means a nearby `29 00 .. 7F 00` dialogue header was also found.",
        "- `medium+` means no nearby `29` header, but the body contains linebreaks and text-like bytes.",
    ])
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"wrote {OUT_CSV}")
    print(f"wrote {OUT_MD}")
    print(f"total={len(all_candidates)} high={high_count}")


if __name__ == "__main__":
    main()
