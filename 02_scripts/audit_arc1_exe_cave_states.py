#!/usr/bin/env python3
"""Audit candidate PSX.EXE caves across DuckStation save states.

This is a read-only ownership audit.  A zero run in the pristine executable is
not considered free merely because it is zero on disk.  The report separates:

* states whose live D941 signature matches the reference build;
* states from other/unknown builds;
* unreadable save-state formats;
* each region's exact bytes, zero/nonzero state and reference comparison.

The script never writes a game archive, executable or save state.  It writes a
CSV and a short report under ``01_work/analysis/johab16_integration``.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import re
import sys
import zipfile
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from build_arc1_johab_font_poc import file_offset  # noqa: E402
from extract_duckstation_savestate import decompress  # noqa: E402
from extract_savestate_vram import RAM_BASE, RAM_SIZE, locate_ram  # noqa: E402


DEFAULT_STATE_DIR = Path.home() / "AppData/Local/DuckStation/savestates"
DEFAULT_REFERENCE = (
    ROOT
    / "03_output/arc1_johab_font_16px_poc_pilgi_TEST_ONLY_D941D1BE.zip"
)
DEFAULT_OUT = ROOT / "01_work/analysis/johab16_integration"
DEFAULT_BUILD_DIR = ROOT / "03_output"

REGIONS = (
    ("e2_or_wrapper", 0x8018FCD0, 0x8018FDC5),
    ("bank_helper", 0x80193B44, 0x80193BC4),
    ("wrapper_candidate", 0x801A2074, 0x801A2304),
    ("ui_or_coord_table", 0x801A7460, 0x801A7860),
)

# These probes bind a state to the final D941 build without relying on a media
# path string.  They cover both patched call sites, the wrapper image and the
# complete coordinate table.  A state must match all four to be classified as
# the reference build.
REFERENCE_PROBES = (
    ("dialogue_hook_1", 0x8016BB8C, 8),
    ("dialogue_hook_2", 0x8016BDA0, 8),
    ("wrapper", 0x8018FCD0, 196),
    ("coord_table", 0x801A7460, 62),
)

MEDIA_RE = re.compile(
    rb"(?:[A-Za-z]:\\|/)[^\x00\r\n]{1,240}?\.(?:cue|bin|chd)", re.IGNORECASE
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def ram_slice(ram: bytes, address: int, size: int) -> bytes:
    offset = address - RAM_BASE
    if offset < 0 or offset + size > len(ram):
        raise ValueError(f"RAM range 0x{address:08X}+{size} is outside 2 MiB")
    return ram[offset : offset + size]


def exe_slice(exe: bytes, address: int, size: int) -> bytes:
    offset = file_offset(exe, address)
    return exe[offset : offset + size]


def load_reference(path: Path) -> bytes:
    if not path.is_file():
        raise SystemExit(f"reference ZIP does not exist: {path}")
    with zipfile.ZipFile(path) as archive:
        return archive.read("PSX.EXE")


def media_hint(blob: bytes) -> str:
    matches = []
    for raw in MEDIA_RE.findall(blob):
        text = raw.decode("utf-8", errors="replace")
        if text not in matches:
            matches.append(text)
    return " | ".join(matches[:3])


def expand_inputs(state_dir: Path, extras: list[Path]) -> list[Path]:
    paths = list(state_dir.glob("*.sav")) if state_dir.is_dir() else []
    for extra in extras:
        if extra.is_dir():
            paths.extend(extra.glob("*.sav"))
        elif extra.is_file():
            paths.append(extra)
    unique = {path.resolve(): path.resolve() for path in paths}
    return sorted(unique.values(), key=lambda path: str(path).lower())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    parser.add_argument("--extra", type=Path, action="append", default=[])
    parser.add_argument("--reference-zip", type=Path, default=DEFAULT_REFERENCE)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--build-dir", type=Path, default=DEFAULT_BUILD_DIR)
    parser.add_argument("--skip-build-scan", action="store_true")
    parser.add_argument("--limit", type=int)
    return parser.parse_args()


def scan_build_regions(build_dir: Path) -> tuple[
    dict[str, dict[str, list[str]]], list[tuple[str, str]]
]:
    """Index exact PSX region hashes from known build ZIPs.

    A save-state region matching a disk image is evidence of deliberate build
    content, not a runtime mutation.  A missing match remains unknown because
    not every historical build must still be present.
    """
    index: dict[str, dict[str, list[str]]] = {
        name: {} for name, _start, _end in REGIONS
    }
    failures: list[tuple[str, str]] = []
    for path in sorted(build_dir.glob("*.zip")):
        try:
            with zipfile.ZipFile(path) as archive:
                if "PSX.EXE" not in archive.namelist():
                    continue
                exe = archive.read("PSX.EXE")
            for name, start, end in REGIONS:
                sha = digest(exe_slice(exe, start, end - start))
                index[name].setdefault(sha, []).append(path.name)
        except BaseException as exc:
            failures.append((str(path), f"{type(exc).__name__}: {exc}"))
    return index, failures


def main() -> None:
    args = parse_args()
    reference = load_reference(args.reference_zip)
    paths = expand_inputs(args.state_dir, args.extra)
    if args.limit is not None:
        paths = paths[: args.limit]
    if not paths:
        raise SystemExit("no save states found")

    reference_probes = {
        name: exe_slice(reference, address, size)
        for name, address, size in REFERENCE_PROBES
    }
    reference_regions = {
        name: exe_slice(reference, start, end - start)
        for name, start, end in REGIONS
    }

    rows: list[dict[str, object]] = []
    failures: list[tuple[str, str]] = []
    classifications: Counter[str] = Counter()
    region_zero: Counter[str] = Counter()
    region_reference: Counter[str] = Counter()
    region_nonzero_hashes: dict[str, Counter[str]] = {
        name: Counter() for name, _start, _end in REGIONS
    }

    for number, path in enumerate(paths, 1):
        try:
            blob = decompress(path, "last")
            ram_at = locate_ram(blob)
            ram = blob[ram_at : ram_at + RAM_SIZE]
            if len(ram) != RAM_SIZE:
                raise ValueError("incomplete Bus RAM payload")
        except BaseException as exc:  # keep an exact unreadable population
            failures.append((str(path), f"{type(exc).__name__}: {exc}"))
            continue

        probe_matches = {
            name: ram_slice(ram, address, size) == reference_probes[name]
            for name, address, size in REFERENCE_PROBES
        }
        classification = (
            "reference_D941" if all(probe_matches.values()) else "other_or_unknown"
        )
        classifications[classification] += 1
        hint = media_hint(blob)

        for name, start, end in REGIONS:
            payload = ram_slice(ram, start, end - start)
            is_zero = not any(payload)
            matches_reference = payload == reference_regions[name]
            region_zero[name] += int(is_zero)
            region_reference[name] += int(matches_reference)
            if not is_zero:
                region_nonzero_hashes[name][digest(payload)] += 1
            rows.append(
                {
                    "state": str(path),
                    "classification": classification,
                    "media_hint": hint,
                    "probe_matches": sum(probe_matches.values()),
                    "probe_total": len(probe_matches),
                    "region": name,
                    "start": f"0x{start:08X}",
                    "end_exclusive": f"0x{end:08X}",
                    "bytes": len(payload),
                    "all_zero": int(is_zero),
                    "matches_reference": int(matches_reference),
                    "sha256": digest(payload),
                    "nonzero_bytes": sum(byte != 0 for byte in payload),
                }
            )
        if number % 50 == 0:
            print(f"states {number}/{len(paths)}", flush=True)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = args.out_dir / "exe_cave_state_audit.csv"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
        fieldnames = list(rows[0]) if rows else [
            "state", "classification", "media_hint", "probe_matches",
            "probe_total", "region", "start", "end_exclusive", "bytes",
            "all_zero", "matches_reference", "sha256", "nonzero_bytes",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    report = [
        "Arc the Lad 1 EXE cave save-state audit",
        f"reference_zip={args.reference_zip}",
        f"reference_psx_sha256={digest(reference)}",
        f"states_discovered={len(paths)}",
        f"states_read={sum(classifications.values())}",
        f"states_unreadable={len(failures)}",
        "classifications=" + ", ".join(
            f"{name}:{count}" for name, count in sorted(classifications.items())
        ),
        "",
    ]
    read = sum(classifications.values())
    for name, start, end in REGIONS:
        report.extend(
            [
                f"[{name}] 0x{start:08X}..0x{end:08X} ({end-start}B)",
                f"all_zero={region_zero[name]}/{read}",
                f"matches_reference={region_reference[name]}/{read}",
                f"distinct_nonzero_hashes={len(region_nonzero_hashes[name])}",
            ]
        )
        for sha, count in region_nonzero_hashes[name].most_common(5):
            report.append(f"  nonzero_sha256={sha} states={count}")
        report.append("")
    if failures:
        report.append("[unreadable]")
        report.extend(f"{path}: {error}" for path, error in failures)

    report_path = args.out_dir / "exe_cave_state_audit.txt"
    build_failures: list[tuple[str, str]] = []
    if args.skip_build_scan:
        build_index = {name: {} for name, _start, _end in REGIONS}
        report.append("build_scan=SKIPPED")
    else:
        build_index, build_failures = scan_build_regions(args.build_dir)
        report.extend(
            [
                "[known build image matching]",
                f"build_dir={args.build_dir}",
                f"build_scan_failures={len(build_failures)}",
            ]
        )
        for name, _start, _end in REGIONS:
            state_hashes = region_nonzero_hashes[name]
            matched = [sha for sha in state_hashes if sha in build_index[name]]
            report.append(
                f"{name}: matched_hashes={len(matched)}/{len(state_hashes)} "
                f"matched_states={sum(state_hashes[sha] for sha in matched)}/"
                f"{sum(state_hashes.values())}"
            )
        report.append("")

    build_rows = []
    for name, _start, _end in REGIONS:
        for sha, state_count in region_nonzero_hashes[name].most_common():
            builds = build_index[name].get(sha, [])
            build_rows.append(
                {
                    "region": name,
                    "sha256": sha,
                    "state_count": state_count,
                    "known_build_match": int(bool(builds)),
                    "build_count": len(builds),
                    "builds": " | ".join(builds),
                }
            )
    build_csv = args.out_dir / "exe_cave_build_hashes.csv"
    with build_csv.open("w", encoding="utf-8-sig", newline="") as handle:
        fields = [
            "region", "sha256", "state_count", "known_build_match",
            "build_count", "builds",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(build_rows)

    if build_failures:
        report.append("[build scan failures]")
        report.extend(f"{path}: {error}" for path, error in build_failures)
    report_path.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report[:18]))
    print(f"csv={csv_path}")
    print(f"build_csv={build_csv}")
    print(f"report={report_path}")


if __name__ == "__main__":
    main()
