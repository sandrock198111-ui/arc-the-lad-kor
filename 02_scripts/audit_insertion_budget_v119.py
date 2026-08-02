"""Does the finished translation fit, now that the glyph store is done?

The glyph work answered which syllables can be drawn.  It did not answer how much
text fits, and those are different questions.  Insertion is an in-place overwrite:
`build_story_*.py` refuses any line whose encoding is longer than the original
Japanese bytes it replaces.  So every translated line has its own byte budget, set
by the sentence it is replacing, and a line can be perfectly renderable and still
not fit.

This measures that, for all 2,650 translated lines at once.

The character-to-code map is read out of the built archive rather than any CSV.
Three separate maps in this project have drifted from the executable, and the rule
the project settled on is to count from the artifact.  So every code the decoder can
produce is resolved to a physical index, that index's 12x12 bitplane is read out of
the strips or the font page, and the shape is named against the rendered-glyph table.
Whatever is not named that way cannot be encoded, and is reported as missing rather
than guessed at.
"""
from __future__ import annotations

import csv
import pickle
import struct
import sys
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from build_story_sf0b1_return_full import get_pixel  # noqa: E402

BUILD = ROOT / "03_output/ui_hud_e7_v119_strip_c_patch_only.zip"
ORIGINAL = ROOT / "05_docs/script_original_full.csv"
TRANSLATED = ROOT / "05_docs/script_translated_full.csv"
REPORT = ROOT / "01_work/analysis/insertion_budget_v119.txt"
OVERFLOW_CSV = ROOT / "01_work/analysis/insertion_overflow_v119.csv"
CACHE = Path(
    r"C:\Users\ADMINI~1\AppData\Local\Temp\claude\E--korean"
    r"\328ae25b-6478-4de1-a913-c780c9b01e72\scratchpad\hangul_bitmaps.pkl"
)

RAM_TO_FILE = 0x8011A800
LOOKUP_SRC, LOOKUP_N = 0x801A8FD4, 508
IPR, PLANES, CELL = 84, 4, 12
STRIP_ROW_BYTES, STRIP_BYTES = 78, 936
STRIPS = {40: 0x801A8800, 63: 0x801A8BA8, 53: 0x801A93CC}

SPACE = b"\x9C"                 # one byte
LINEBREAK = b"\xE6\x01"         # the `|` in the translation tables


def bitmap(exe: bytes, font: bytes, index: int) -> tuple[int, ...] | None:
    row = index // IPR
    if row in STRIPS and index - row * IPR < 52:
        strip = exe[STRIPS[row] - RAM_TO_FILE:][:STRIP_BYTES]
        column, plane = divmod(index - row * IPR, PLANES)
        bit = 1 << plane
        out = []
        for y in range(CELL):
            for x in range(CELL):
                px = column * CELL + x
                byte = strip[y * STRIP_ROW_BYTES + px // 2]
                out.append(1 if (byte & 0x0F if px % 2 == 0 else byte >> 4) & bit else 0)
        return tuple(out)
    if row >= 512 // CELL:
        return None
    column, plane = divmod(index - row * IPR, PLANES)
    bit = 1 << plane
    return tuple(1 if get_pixel(font, column * CELL + x, row * CELL + y) & bit else 0
                 for y in range(CELL) for x in range(CELL))


def build_encoder() -> dict[str, bytes]:
    """char -> the shortest code that draws it, read out of the built archive."""
    with zipfile.ZipFile(BUILD) as archive:
        exe, font = archive.read("PSX.EXE"), archive.read("COMM.IMG")
    lut = struct.unpack_from(f"<{LOOKUP_N}H", exe, LOOKUP_SRC - RAM_TO_FILE)
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())

    codes: dict[int, bytes] = {}
    for lead in range(0xDD, 0xE9):                      # two-byte physical codes
        for trail in range(0x01, 0xFF):
            codes.setdefault((lead - 0xDD) * 255 + trail + 0xDB, bytes((lead, trail)))
    for slot, index in enumerate(lut):                  # two-byte virtual codes
        codes.setdefault(index, bytes((0xE9 + slot // 254, slot % 254 + 1)))

    table: dict[str, bytes] = {}
    # The one-byte ASCII rule, verified for indices 0..25 only (space through "9").
    # Outside that range the atlas holds Japanese shapes, so it must not be extended.
    for index in range(26):
        table[chr(index + 32)] = bytes((index + 1,))
    for index, code in sorted(codes.items()):
        bits = bitmap(exe, font, index)
        if not bits or not any(bits):
            continue
        char = shapes.get(bits)
        if char is not None:
            table.setdefault(char, code)
    return table


def encode(text: str, table: dict[str, bytes]) -> tuple[int, list[str]]:
    """Byte length of the line, and any character that has no code."""
    total, missing = 0, []
    for ch in text:
        if ch == " ":
            total += len(SPACE)
        elif ch == "|":
            total += len(LINEBREAK)
        elif ch in table:
            total += len(table[ch])
        else:
            total += 2
            missing.append(ch)
    return total, missing


def main() -> None:
    table = build_encoder()
    original = {}
    with ORIGINAL.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            original[(row["source file"], row["byte offset"])] = int(row["length"])
    with TRANSLATED.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))

    fits = over = 0
    overflow: list[tuple[int, str, str, int, int, str]] = []
    missing_chars: Counter = Counter()
    no_budget = 0
    slack_total = 0
    for row in rows:
        text = (row.get("korean") or "").strip()
        if not any("\uac00" <= c <= "\ud7a3" for c in text):
            continue
        budget = original.get((row["source file"], row["offset"]))
        if budget is None:
            no_budget += 1
            continue
        need, missing = encode(text, table)
        missing_chars.update(missing)
        if need <= budget:
            fits += 1
            slack_total += budget - need
        else:
            over += 1
            overflow.append((need - budget, row["source file"], row["offset"],
                             need, budget, text))

    overflow.sort(reverse=True)
    translated = fits + over
    lines = [
        "does the finished translation fit? measured against v119",
        "",
        "Insertion overwrites the original bytes in place and refuses anything longer,",
        "so each line's budget is the Japanese sentence it replaces. Encoding uses the",
        "character-to-code table read out of the built archive, not any CSV.",
        "",
        f"encodable characters in the build   {len(table)}",
        f"translated lines measured          {translated}",
        f"  fit in their original bytes      {fits}   ({100 * fits / translated:.1f}%)",
        f"  too long                         {over}   ({100 * over / translated:.1f}%)",
        f"lines with no budget row           {no_budget}",
        "",
        f"total slack on the lines that fit  {slack_total} bytes",
        f"total overflow to absorb           {sum(d for d, *_ in overflow)} bytes",
        "",
    ]
    if missing_chars:
        lines += [
            f"characters with no code in the build: {len(missing_chars)} distinct,"
            f" {sum(missing_chars.values())} occurrences",
            "  " + " ".join(f"{c}x{n}" for c, n in missing_chars.most_common(40)),
            "",
        ]
    else:
        lines += ["every character in the translation has a code in this build", ""]

    per_file: Counter = Counter()
    for delta, src, *_ in overflow:
        per_file[src] += delta
    ESCAPE = 16 * 0x80          # sixteen E2 external slots of 128 bytes, per file
    absorbable = sum(1 for f, n in per_file.items() if n <= ESCAPE)
    lines += [
        "the escape hatch, and whether it is enough",
        "",
        "A line that does not fit can be moved into an E2 external slot instead of being",
        f"written in place. There are 16 such slots of {0x80} bytes in a file, {ESCAPE} bytes,",
        "and the v120 probe used three of them, so the mechanism is proven.",
        "",
        f"  files with overflow              {len(per_file)}",
        f"  within one file's slot capacity  {absorbable}",
        f"  beyond it                        {len(per_file) - absorbable}",
        "",
        "worst files, by total bytes that must go somewhere:",
        *(f"  {n:>6}  {f}" for f, n in per_file.most_common(12)),
        "",
        "worst overflows, by how many bytes they exceed:",
    ]
    for delta, src, off, need, budget, text in overflow[:30]:
        lines.append(f"  +{delta:>3}  {src} {off}  {need}/{budget}  {text[:46]}")

    buckets = Counter(min((d - 1) // 8, 7) for d, *_ in overflow)
    lines += ["", "overflow size distribution:"]
    for k in range(8):
        label = f"{k * 8 + 1}-{k * 8 + 8}" if k < 7 else "57+"
        lines.append(f"  {label:>6} bytes over : {buckets.get(k, 0)}")

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with OVERFLOW_CSV.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["over_by", "source file", "byte offset", "needs", "budget", "korean"])
        writer.writerows(overflow)
    print("\n".join(lines[:26]))
    print(f"\n-> {REPORT}\n-> {OVERFLOW_CSV}")


if __name__ == "__main__":
    main()
