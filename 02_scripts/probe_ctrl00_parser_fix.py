"""Measure a token-width-aware replacement for the broad 17/19 scanner.

No files are written.  The proposed parser follows the measured runtime token
widths and rejects a candidate when a zero appears at a token boundary before
the established 00 00 record boundary.
"""
from __future__ import annotations

import csv
from collections import Counter

import measure_full_script_requirements as base


def token_end(data: bytes, begin: int) -> int | None:
    offset = begin
    limit = min(len(data) - 1, begin + base.MAX_BODY)
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


def decode(body: bytes, chars: dict[int, str]) -> tuple[str, int]:
    output: list[str] = []
    unknown = 0
    offset = 0
    while offset < len(body):
        first = body[offset]
        if first < 0xDD:
            index = first - 1
            offset += 1
            if index in chars:
                output.append(chars[index])
            else:
                output.append(f"<G:{index}>")
                unknown += 1
            continue
        if offset + 1 >= len(body):
            output.append(f"<TRUNC:{first:02X}>")
            unknown += 1
            break
        second = body[offset + 1]
        offset += 2
        if first <= 0xE0:
            index = (first - 0xDD) * 255 + second + 0xDB
            if index in chars:
                output.append(chars[index])
            else:
                output.append(f"<G:{index}>")
                unknown += 1
        elif (first, second) == (0xE6, 0x01):
            output.append("\n")
        elif (first, second) == (0xE4, 0x1F):
            output.append("\f")
        else:
            output.append(f"<CTRL:{first:02X}:{second:02X}>")
            unknown += 1
    return "".join(output), unknown


def records(name: str, data: bytes, chars: dict[int, str]) -> list[dict[str, str]]:
    output: list[dict[str, str]] = []
    seen: set[int] = set()
    for marker_offset in range(base.START, len(data) - 8, 2):
        marker = int.from_bytes(data[marker_offset : marker_offset + 2], "little")
        if marker not in (0x17, 0x19):
            continue
        header = base.find_header(data, marker_offset)
        begin = marker_offset + 2
        prefix = data[begin : begin + 2]
        if prefix in (b"\x01\0", b"\x02\0", b"\x03\0", b"\x04\0", b"\x05\0", b"\x07\0"):
            begin += 2
        elif prefix == b"\0\0" and marker == 0x17 and header == marker_offset - 6:
            begin += 2
        if begin in seen:
            continue
        end = token_end(data, begin)
        if end is None or not 3 <= end - begin <= 0x100:
            continue
        raw = data[begin:end]
        text, unknown = decode(raw, chars)
        glyphs = len(text) - text.count("\n") - text.count("\f")
        if glyphs == 0:
            continue
        if (
            (glyphs - unknown) / glyphs < 0.45
            and header is None
            and base.LINEBREAK not in raw
            and base.PAGEBREAK not in raw
        ):
            continue
        seen.add(begin)
        output.append(
            {
                "source file": name,
                "byte offset": f"0x{begin:X}",
                "length": str(len(raw)),
                "raw bytes as hex": raw.hex(" ").upper(),
                "decoded Japanese": text,
            }
        )
    return output


def key(row: dict[str, str]) -> tuple[str, str, str]:
    return row["source file"], row["byte offset"].upper(), row["raw bytes as hex"].upper()


def main() -> None:
    with base.SOURCE.open(encoding="utf-8-sig", newline="") if False else open(
        base.DOCS / "script_original_full.csv", encoding="utf-8-sig", newline=""
    ) as handle:
        before = list(csv.DictReader(handle))
    listing = base.iso_files(base.BIN)
    chars = base.glyph_map()
    targets = [name for name in sorted(listing) if name.upper().endswith(".DAT")]
    after = [
        row
        for name in targets
        for row in records(name, base.read_file(base.BIN, listing[name]), chars)
    ]
    before_map = {key(row): row for row in before}
    after_map = {key(row): row for row in after}
    removed = set(before_map) - set(after_map)
    added = set(after_map) - set(before_map)
    retained = set(before_map) & set(after_map)
    changed_text = sum(
        before_map[item]["decoded Japanese"] != after_map[item]["decoded Japanese"]
        for item in retained
    )
    ctrl00_before = sum("<CTRL:00>" in row["decoded Japanese"] for row in before)
    ctrl00_after = sum("<CTRL:00>" in row["decoded Japanese"] for row in after)
    complete_before = sum(
        "<G:" not in row["decoded Japanese"] and "<CTRL:" not in row["decoded Japanese"]
        for row in before
    )
    complete_after = sum(
        "<G:" not in row["decoded Japanese"] and "<CTRL:" not in row["decoded Japanese"]
        for row in after
    )
    removed_by_file = Counter(item[0] for item in removed)

    print(f"before_rows={len(before)}")
    print(f"after_rows={len(after)}")
    print(f"removed_rows={len(removed)}")
    print(f"added_rows={len(added)}")
    print(f"retained_rows={len(retained)}")
    print(f"retained_rows_with_corrected_control_tokens={changed_text}")
    print(f"ctrl00_before={ctrl00_before}")
    print(f"ctrl00_after={ctrl00_after}")
    print(f"complete_before={complete_before}")
    print(f"complete_after={complete_after}")
    print("removed_by_file:")
    for name, count in removed_by_file.most_common():
        print(f"  {name},{count}")


if __name__ == "__main__":
    main()
