from __future__ import annotations

import argparse
import csv
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from extract_duckstation_savestate import decompress


PS1_RAM_SIZE = 0x200000
DEFAULT_STATE_RAM_OFFSET = 0x1262
DEFAULT_RAM_SCRIPT_OFFSET = 0x117000
DEFAULT_FILE_SCRIPT_OFFSET = 0x47800
DEFAULT_COMPARE_SIZE = 0x700
TEXT_MARKERS = {0x17, 0x19}
TEXTY_BYTES = set(range(0x1A, 0x62)) | {
    0x81,
    0x8B,
    0x8E,
    0x8F,
    0x92,
    0x97,
    0x98,
    0x99,
    0x9A,
    0x9B,
    0x9C,
    0xA1,
    0xA6,
    0xA9,
    0xAD,
    0xAF,
    0xB3,
    0xB5,
    0xBD,
    0xBF,
    0xC4,
    0xC5,
    0xCA,
    0xCB,
    0xCD,
    0xCF,
    0xD4,
    0xD9,
    0xDA,
    0xDD,
    0xDE,
    0xDF,
    0xE4,
    0xE6,
}


@dataclass(frozen=True)
class Match:
    file: str
    equal_bytes: int
    compared_bytes: int
    ratio: float


@dataclass(frozen=True)
class Dialogue:
    marker: str
    ram_marker_offset: str
    ram_payload_start: str
    file_payload_start: str
    end_exclusive: str
    length: int
    prefix_kind: str
    payload_hex: str


def load_ram(path: Path, state_ram_offset: int) -> bytes:
    if path.suffix.lower() == ".sav":
        state = decompress(path, "last")
    else:
        state = path.read_bytes()

    if len(state) == PS1_RAM_SIZE:
        return state
    ram = state[state_ram_offset : state_ram_offset + PS1_RAM_SIZE]
    if len(ram) != PS1_RAM_SIZE:
        raise ValueError(f"{path} does not contain a complete 2 MiB PS1 RAM image")
    return ram


def rank_files(
    ram: bytes,
    dat_root: Path,
    ram_script_offset: int,
    file_script_offset: int,
    compare_size: int,
) -> list[Match]:
    ram_window = ram[ram_script_offset : ram_script_offset + compare_size]
    if len(ram_window) != compare_size:
        raise ValueError("RAM comparison window is outside the 2 MiB image")

    matches: list[Match] = []
    for path in sorted(dat_root.rglob("*.DAT")):
        data = path.read_bytes()
        file_window = data[file_script_offset : file_script_offset + compare_size]
        if len(file_window) != compare_size:
            continue
        equal = sum(a == b for a, b in zip(ram_window, file_window))
        matches.append(
            Match(
                file=str(path.relative_to(dat_root)).replace("\\", "/"),
                equal_bytes=equal,
                compared_bytes=compare_size,
                ratio=equal / compare_size,
            )
        )
    return sorted(matches, key=lambda item: (-item.equal_bytes, item.file))


def find_double_zero(data: bytes, start: int, limit: int) -> int | None:
    for offset in range(start, min(len(data) - 1, limit)):
        if data[offset : offset + 2] == b"\x00\x00":
            return offset
    return None


def has_text_shape(payload: bytes) -> bool:
    if len(payload) < 3 or 0 in payload:
        return False
    return sum(byte in TEXTY_BYTES for byte in payload) / len(payload) >= 0.65


def parse_dialogues(
    ram: bytes,
    ram_script_offset: int,
    file_script_offset: int,
    compare_size: int,
) -> list[Dialogue]:
    end = ram_script_offset + compare_size
    results: list[Dialogue] = []
    seen_payloads: set[int] = set()

    for marker_offset in range(ram_script_offset, end - 6, 2):
        marker = int.from_bytes(ram[marker_offset : marker_offset + 2], "little")
        if marker not in TEXT_MARKERS:
            continue

        body_start = marker_offset + 2
        payload_start = body_start
        prefix_kind = "none"
        prefix = ram[body_start : body_start + 2]
        if prefix == b"\x01\x00":
            payload_start += 2
            prefix_kind = "control_0100"
        elif prefix == b"\x00\x00" and marker == 0x17:
            payload_start += 2
            prefix_kind = "control_0000"

        if payload_start in seen_payloads:
            continue
        payload_end = find_double_zero(ram, payload_start, min(end, payload_start + 0x180))
        if payload_end is None or payload_end <= payload_start:
            continue

        payload = ram[payload_start:payload_end]
        if len(payload) > 0x100 or not has_text_shape(payload):
            continue
        file_payload = file_script_offset + payload_start - ram_script_offset
        results.append(
            Dialogue(
                marker=f"0x{marker:02X}",
                ram_marker_offset=f"0x{marker_offset:X}",
                ram_payload_start=f"0x{payload_start:X}",
                file_payload_start=f"0x{file_payload:X}",
                end_exclusive=f"0x{file_payload + len(payload):X}",
                length=len(payload),
                prefix_kind=prefix_kind,
                payload_hex=payload.hex(" "),
            )
        )
        seen_payloads.add(payload_start)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Map DuckStation save states to the DAT script block loaded in PS1 RAM."
    )
    parser.add_argument("states", nargs="+", type=Path)
    parser.add_argument("--dat-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--state-ram-offset", default=DEFAULT_STATE_RAM_OFFSET, type=lambda v: int(v, 0))
    parser.add_argument("--ram-script-offset", default=DEFAULT_RAM_SCRIPT_OFFSET, type=lambda v: int(v, 0))
    parser.add_argument("--file-script-offset", default=DEFAULT_FILE_SCRIPT_OFFSET, type=lambda v: int(v, 0))
    parser.add_argument("--compare-size", default=DEFAULT_COMPARE_SIZE, type=lambda v: int(v, 0))
    parser.add_argument("--top", default=5, type=int)
    args = parser.parse_args()

    args.output.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, object]] = []
    dialogue_rows: list[dict[str, object]] = []

    for state_path in args.states:
        ram = load_ram(state_path, args.state_ram_offset)
        matches = rank_files(
            ram,
            args.dat_root,
            args.ram_script_offset,
            args.file_script_offset,
            args.compare_size,
        )
        top_matches = matches[: args.top]
        dialogues = parse_dialogues(
            ram,
            args.ram_script_offset,
            args.file_script_offset,
            args.compare_size,
        )
        best = top_matches[0] if top_matches else None
        record = {
            "state": str(state_path),
            "best_match": None if best is None else asdict(best),
            "top_matches": [asdict(item) for item in top_matches],
            "dialogues": [asdict(item) for item in dialogues],
        }
        records.append(record)
        for dialogue in dialogues:
            row = {
                "state": state_path.name,
                "source_file": "" if best is None else best.file,
                "match_ratio": "" if best is None else f"{best.ratio:.6f}",
                **asdict(dialogue),
            }
            dialogue_rows.append(row)

        if best is None:
            print(f"{state_path.name}: no DAT candidates")
        else:
            print(
                f"{state_path.name}: {best.file} "
                f"{best.equal_bytes}/{best.compared_bytes} ({best.ratio:.2%})"
            )

    (args.output / "savestate_script_map.json").write_text(
        json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    csv_path = args.output / "savestate_dialogues.csv"
    fields = [
        "state",
        "source_file",
        "match_ratio",
        "marker",
        "ram_marker_offset",
        "ram_payload_start",
        "file_payload_start",
        "end_exclusive",
        "length",
        "prefix_kind",
        "payload_hex",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(dialogue_rows)

    print(f"wrote {args.output / 'savestate_script_map.json'}")
    print(f"wrote {csv_path}")


if __name__ == "__main__":
    main()
