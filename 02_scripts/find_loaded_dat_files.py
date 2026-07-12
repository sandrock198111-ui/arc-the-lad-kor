from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Find extracted DAT files whose byte windows are loaded in PS1 RAM."
    )
    parser.add_argument("state", type=Path)
    parser.add_argument("dat_root", type=Path)
    parser.add_argument("--state-ram-offset", default=0x1262, type=lambda v: int(v, 0))
    parser.add_argument("--chunk-size", default=0x80, type=lambda v: int(v, 0))
    parser.add_argument("--step", default=0x800, type=lambda v: int(v, 0))
    parser.add_argument("--minimum-matches", default=3, type=int)
    args = parser.parse_args()

    state = args.state.read_bytes()
    ram = state[args.state_ram_offset : args.state_ram_offset + 0x200000]
    if len(ram) != 0x200000:
        raise ValueError("state does not contain a complete 2 MiB PS1 RAM image")

    results: list[tuple[int, int, Path, int]] = []
    for path in sorted(args.dat_root.rglob("*.DAT")):
        data = path.read_bytes()
        deltas: Counter[int] = Counter()
        for file_offset in range(0, len(data) - args.chunk_size + 1, args.step):
            chunk = data[file_offset : file_offset + args.chunk_size]
            if len(set(chunk)) < 8 or chunk.count(0) > len(chunk) * 3 // 4:
                continue
            ram_offset = ram.find(chunk)
            if ram_offset >= 0:
                deltas[ram_offset - file_offset] += 1
        if not deltas:
            continue
        delta, matches = deltas.most_common(1)[0]
        if matches >= args.minimum_matches:
            results.append((matches, sum(deltas.values()), path, delta))

    for matches, total, path, delta in sorted(results, reverse=True):
        print(
            f"matches={matches:3d} total={total:3d} "
            f"delta=0x{delta:X} file={path}"
        )


if __name__ == "__main__":
    main()
