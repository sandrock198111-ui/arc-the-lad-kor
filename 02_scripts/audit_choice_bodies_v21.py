from __future__ import annotations

import csv
import hashlib
import zipfile
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "01_work"
CORPUS = WORK / "analysis/story_corpus/story_corpus.csv"
PATCH = ROOT / "03_output/story_choice_layout_v20_cumulative_patch_only.zip"
PATCH_HASH = "213717051809418251E5765D3BC72983990ADEE7A147F004FE4E7F2276C14AF4"
OUTPUT = WORK / "analysis/all_choices_v21"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def marker_positions(body: bytes) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for position in range(len(body) - 1):
        if body[position] == 0xE5:
            found.append((position, f"E5_{body[position + 1]:02X}"))
    return found


def segment_lengths(body: bytes, markers: list[tuple[int, str]]) -> list[int]:
    starts = [position for position, _ in markers]
    lengths: list[int] = []
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(body)
        lengths.append(end - (start + 2))
    return lengths


def main() -> None:
    if digest(PATCH.read_bytes()) != PATCH_HASH:
        raise SystemExit("v0.20 patch hash differs")
    OUTPUT.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(PATCH) as archive:
        patched = {name: archive.read(name) for name in archive.namelist()}

    audit: list[dict[str, object]] = []
    marker_types: Counter[str] = Counter()
    files: Counter[str] = Counter()
    for row in rows(CORPUS):
        if row["confidence"] != "high" or "<CTRL:E5>" not in row["decoded_jp"]:
            continue
        name = row["file"].replace("\\", "/")
        offset = int(row["payload_start"], 0)
        capacity = int(row["capacity"])
        original_file = (WORK / name).read_bytes()
        current_file = patched.get(name, original_file)
        original = original_file[offset:offset + capacity]
        current = current_file[offset:offset + capacity]
        original_markers = marker_positions(original)
        current_markers = marker_positions(current)
        for _, marker in original_markers:
            marker_types[marker] += 1
        files[name] += 1
        audit.append(
            {
                "file": name,
                "offset": f"0x{offset:X}",
                "capacity": capacity,
                "in_patch_zip": int(name in patched),
                "current_changed": int(current != original),
                "original_marker_count": len(original_markers),
                "current_marker_count": len(current_markers),
                "original_marker_types": "|".join(marker for _, marker in original_markers),
                "current_marker_types": "|".join(marker for _, marker in current_markers),
                "original_linebreaks": original.count(b"\xE6\x01"),
                "current_linebreaks": current.count(b"\xE6\x01"),
                "prompt_bytes": original_markers[0][0] if original_markers else "",
                "option_segment_bytes": "|".join(
                    str(value) for value in segment_lengths(original, original_markers)
                ),
                "decoded_jp": " / ".join(
                    line.rstrip()
                    for line in row["decoded_jp"].replace("\r", "").strip().split("\n")
                ),
            }
        )

    fields = [
        "file", "offset", "capacity", "in_patch_zip", "current_changed",
        "original_marker_count", "current_marker_count", "original_marker_types",
        "current_marker_types", "original_linebreaks", "current_linebreaks",
        "prompt_bytes", "option_segment_bytes", "decoded_jp",
    ]
    with (OUTPUT / "choice_body_audit.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(audit)

    summary = [
        "All choice body audit v0.21",
        f"patch={PATCH.relative_to(ROOT).as_posix()}",
        f"patch_sha256={digest(PATCH.read_bytes())}",
        f"choice_bodies={len(audit)}",
        f"choice_files={len(files)}",
        f"currently_changed={sum(int(row['current_changed']) for row in audit)}",
        f"currently_original={sum(not int(row['current_changed']) for row in audit)}",
        f"marker_mismatch={sum(row['original_marker_types'] != row['current_marker_types'] for row in audit)}",
        f"marker_types={dict(sorted(marker_types.items()))}",
    ]
    (OUTPUT / "summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")
    print("\n".join(summary))
    print(OUTPUT)


if __name__ == "__main__":
    main()
