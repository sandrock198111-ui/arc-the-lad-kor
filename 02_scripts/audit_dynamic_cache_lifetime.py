"""Trace the current high-page cache from upload to ordering-table consumption.

This is a fail-closed audit, not a proof-by-screenshot.  It verifies the static
frame call order in v163 and inventories active GPU consumers in every available
save state.  Unknown indirect transfer paths remain an explicit release blocker.
"""
from __future__ import annotations

import csv
import hashlib
import struct
import sys
import zipfile
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from analyze_arc1_v163_runtime import (  # noqa: E402
    CACHE_X, CACHE_Y, CACHE_U, CACHE_U_END, CACHE_V, CACHE_V_END,
    FONT_CLUT_MAX, FONT_CLUT_MIN, RAM_SIZE, is_page15, ram_at,
    trace_active_text_ot,
)
from extract_savestate_vram import inflate, locate_ram  # noqa: E402


BUILD = ROOT / "03_output/arc1_v163_text_clut_classifier_773E3B82.zip"
BUILD_SHA256 = "773E3B82B58FBE9C836C96F34EA03C122847EC8BBD691AE4FDCFBA00D778FE63"
V162_BUILD = ROOT / "03_output/arc1_v162_strip_a_dynamic_cache_1759E571.zip"
STATES = Path.home() / "AppData/Local/DuckStation/savestates"
OUT = ROOT / "01_work/analysis/dynamic_cache_lifetime"
CSV_OUT = OUT / "state_consumers.csv"
REPORT = OUT / "report.txt"

RAM_TO_FILE = 0x8011A800
SOURCE_BASE = 0x801A86EC
RESIDENT_BASE = 0x801FE3C4
FRAME_SYNC_CALL = 0x8011C49C
GPU_SYNC = 0x80176BA8
FRAME_HOOK = 0x8011C4AC
FRAME_ROUTINE = 0x801FF1A0
CLASSIFIER = 0x801FF410
CLASSIFIER_N = 36
STOCK_FRAME = 0x8011C814
LOADIMAGE = 0x80177E4C
DRAWOT = 0x80176E1C
STOCK_FRAME_HOOK = 0x0C047205
VRAM_W, VRAM_H = 1024, 512
CACHE_RECT = (CACHE_X, CACHE_Y, 15, CACHE_V_END - CACHE_V)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def u32(data: bytes, at: int) -> int:
    return struct.unpack_from("<I", data, at)[0]


def jal(target: int) -> int:
    return 0x0C000000 | ((target >> 2) & 0x03FFFFFF)


def jal_target(word: int, pc: int) -> int | None:
    if word >> 26 != 3:
        return None
    return ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)


def file_at(address: int) -> int:
    return address - RAM_TO_FILE


def resident_source_at(address: int) -> int:
    return SOURCE_BASE - RAM_TO_FILE + address - RESIDENT_BASE


def archive_member(path: Path, name: str) -> bytes:
    with zipfile.ZipFile(path) as archive:
        return archive.read(name)


def calls(exe: bytes, start: int, end: int, resident: bool = False) -> list[tuple[int, int]]:
    base = resident_source_at(start) if resident else file_at(start)
    result: list[tuple[int, int]] = []
    for offset, pc in zip(range(base, base + end - start, 4), range(start, end, 4)):
        target = jal_target(u32(exe, offset), pc)
        if target is not None:
            result.append((pc, target))
    return result


def rect_overlap(left: tuple[int, int, int, int], right: tuple[int, int, int, int]) -> bool:
    ax, ay, aw, ah = left
    bx, by, bw, bh = right
    return ax < bx + bw and ax + aw > bx and ay < by + bh and ay + ah > by


def gpu_write(packet: bytes, command: int) -> tuple[str, tuple[int, int, int, int]] | None:
    """Decode GP0 fill/copy/upload destinations if such a packet is in the OT."""
    if command == 0x02 and len(packet) >= 16:
        xy, wh = u32(packet, 8), u32(packet, 12)
        return "FillRect", (xy & 0x3FF, (xy >> 16) & 0x1FF,
                            wh & 0x3FF, (wh >> 16) & 0x1FF)
    if command == 0x80 and len(packet) >= 20:
        xy, wh = u32(packet, 12), u32(packet, 16)
        return "MoveImage", (xy & 0x3FF, (xy >> 16) & 0x1FF,
                             wh & 0x3FF, (wh >> 16) & 0x1FF)
    if command == 0xA0 and len(packet) >= 16:
        xy, wh = u32(packet, 8), u32(packet, 12)
        return "LoadImagePacket", (xy & 0x3FF, (xy >> 16) & 0x1FF,
                                   wh & 0x3FF, (wh >> 16) & 0x1FF)
    return None


def main() -> None:
    if sha256(BUILD) != BUILD_SHA256:
        raise SystemExit("v163 archive differs from the recorded build")
    with zipfile.ZipFile(BUILD) as archive:
        exe = archive.read("PSX.EXE")
    v163_classifier = exe[
        resident_source_at(CLASSIFIER):resident_source_at(CLASSIFIER) + CLASSIFIER_N
    ]
    v162_exe = archive_member(V162_BUILD, "PSX.EXE")
    v162_classifier = v162_exe[
        resident_source_at(CLASSIFIER):resident_source_at(CLASSIFIER) + CLASSIFIER_N
    ]

    sync_word = u32(exe, file_at(FRAME_SYNC_CALL))
    hook_word = u32(exe, file_at(FRAME_HOOK))
    frame_calls = calls(exe, FRAME_ROUTINE, CLASSIFIER, resident=True)
    stock_calls = calls(exe, STOCK_FRAME, STOCK_FRAME + 0x80)
    frame_targets = [target for _pc, target in frame_calls]
    stock_targets = [target for _pc, target in stock_calls]
    call_order_ok = (
        sync_word == jal(GPU_SYNC)
        and hook_word == jal(FRAME_ROUTINE)
        and LOADIMAGE in frame_targets
        and STOCK_FRAME in frame_targets
        and frame_targets.index(LOADIMAGE) < frame_targets.index(STOCK_FRAME)
        and DRAWOT in stock_targets
    )

    records: list[dict[str, object]] = []
    read = 0
    failures: list[str] = []
    total_text_reads = total_nontext_reads = total_write_conflicts = 0
    historical_nontext_reads = 0
    for number, path in enumerate(sorted(STATES.glob("*.sav")), 1):
        try:
            blob = inflate(path)
            ram_base = locate_ram(blob)
            ram = blob[ram_base:ram_base + RAM_SIZE]
            context, parity, packets = trace_active_text_ot(ram)
        except BaseException as exc:
            failures.append(f"{path.name}: {exc}")
            continue
        read += 1
        live_hook = u32(ram, ram_at(FRAME_HOOK))
        live_classifier = ram[ram_at(CLASSIFIER):ram_at(CLASSIFIER) + CLASSIFIER_N]
        if live_hook == STOCK_FRAME_HOOK:
            lineage = "stock"
        elif live_hook == jal(FRAME_ROUTINE) and live_classifier == v163_classifier:
            lineage = "v163"
        elif live_hook == jal(FRAME_ROUTINE) and live_classifier == v162_classifier:
            lineage = "v162_superseded"
        else:
            lineage = "other_or_unknown"
        release_relevant = lineage in ("stock", "v163")
        text_reads = nontext_reads = write_conflicts = 0
        write_details: list[str] = []
        read_details: list[str] = []
        for packet in packets:
            if packet.get("overlap"):
                if packet.get("text_cache"):
                    text_reads += 1
                else:
                    nontext_reads += 1
                read_details.append(
                    f"{packet.get('kind')}@0x{int(packet['address']):08X}:"
                    f"T{packet.get('tpage')}:U{packet.get('u')}:V{packet.get('v')}:"
                    f"W{packet.get('width')}:H{packet.get('height')}:C{packet.get('clut')}"
                )
            address = packet.get("address")
            command = packet.get("command")
            dma_words = packet.get("dma_words")
            if not isinstance(address, int) or not isinstance(command, int) or not isinstance(dma_words, int):
                continue
            at = ram_at(address)
            size = min(RAM_SIZE - at, 4 + dma_words * 4)
            decoded = gpu_write(ram[at:at + size], command)
            if decoded and rect_overlap(decoded[1], CACHE_RECT):
                write_conflicts += 1
                write_details.append(f"{decoded[0]}@0x{address:08X}:{decoded[1]}")
        if release_relevant:
            total_text_reads += text_reads
            total_nontext_reads += nontext_reads
            total_write_conflicts += write_conflicts
        else:
            historical_nontext_reads += nontext_reads
        records.append({
            "state": path.name,
            "lineage": lineage,
            "release_relevant": int(release_relevant),
            "frame_hook": f"0x{live_hook:08X}",
            "gpu_context": f"0x{context:08X}",
            "parity": parity,
            "active_ot_packets": len(packets),
            "cache_text_reads": text_reads,
            "cache_nontext_reads": nontext_reads,
            "cache_write_conflicts": write_conflicts,
            "read_details": " | ".join(read_details),
            "write_details": " | ".join(write_details),
        })
        if number % 40 == 0:
            print(f"  lifetime scan {number}", flush=True)

    OUT.mkdir(parents=True, exist_ok=True)
    with CSV_OUT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)
    lineage_counts = Counter(str(record["lineage"]) for record in records)

    # The ordering-table scan can reject a location, but it cannot enumerate every
    # asynchronous or indirect transfer the executable might perform after upload.
    # Until those paths are bounded, the agreed rule requires HOLD even at zero hits.
    unresolved = [
        "game update 0x801299F8 runs after upload and before DrawOT; descendants are unbounded",
        "MoveImage symbol/call graph is not independently resolved for this executable",
        "280 snapshots are regression coverage, not full-game ownership proof",
    ]
    verdict = "HOLD"
    lines = [
        "Dynamic cache lifetime audit",
        f"build={BUILD.name}",
        f"build_sha256={BUILD_SHA256}",
        f"cache_rect_16bit=x{CACHE_RECT[0]}..{CACHE_RECT[0]+CACHE_RECT[2]-1},"
        f"y{CACHE_RECT[1]}..{CACHE_RECT[1]+CACHE_RECT[3]-1}",
        f"frame_sync_word=0x{sync_word:08X}",
        f"frame_hook_word=0x{hook_word:08X}",
        f"frame_call_order={'PASS' if call_order_ok else 'FAIL'}",
        "frame_calls=" + " ".join(f"0x{pc:08X}->0x{target:08X}" for pc, target in frame_calls),
        "stock_frame_calls=" + " ".join(f"0x{pc:08X}->0x{target:08X}" for pc, target in stock_calls),
        f"savestates_read={read}",
        f"savestates_failed={len(failures)}",
        "lineages=" + " ".join(
            f"{name}:{count}" for name, count in sorted(lineage_counts.items())
        ),
        f"active_cache_text_reads={total_text_reads}",
        f"active_cache_nontext_reads={total_nontext_reads}",
        f"active_cache_write_conflicts={total_write_conflicts}",
        f"superseded_or_unknown_nontext_reads={historical_nontext_reads}",
        f"release_verdict={verdict}",
        "",
        "Unresolved:",
        *(f"- {item}" for item in unresolved),
        "",
        "A non-zero conflict rejects the rectangle. Zero sampled conflicts do not",
        "certify it while the unresolved transfer paths remain.",
        "Recommended next isolation: hook 0x8011C860 and upload immediately before",
        "DrawOT, after game update and display-environment setup. Runtime safety of",
        "LoadImage at that later boundary still requires a dedicated cold-boot probe.",
        f"details={CSV_OUT}",
    ]
    if failures:
        lines.extend(("", "state_failures:", *failures))
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    if not call_order_ok or failures or total_nontext_reads or total_write_conflicts:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
