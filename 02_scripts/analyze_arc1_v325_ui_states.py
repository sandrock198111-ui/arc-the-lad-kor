#!/usr/bin/env python3
"""Read-only V32x UI save-state audit for text objects and stale packets."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import pickle
import struct
import sys
from collections import defaultdict
from pathlib import Path
from zipfile import ZipFile

from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import analyze_arc1_v320c_savestates as legacy  # noqa: E402
import build_arc1_v320_hanme_static_recovery as v320  # noqa: E402
import build_arc1_v320c_hanme_official_beol as v320c  # noqa: E402


BUILD = ROOT / "03_output/arc1_v325_ui_reencode_TEST_ONLY_7828AA04.zip"
BUILD_SHA256 = "7828AA04F6A0684981332924C30B4139ABFCA5065138FA899C4D429E87C74CD1"
UI_AUDIT = ROOT / "01_work/analysis/arc1_v325_ui_reencode/ui_reencode.csv"
PIECES = ROOT / "01_work/analysis/hangul_johab_16px/pieces_1bpp.bin"
ASCII = ROOT / "01_work/analysis/hangul_johab_16px/ascii_16px.pkl"
OUTPUT = ROOT / "01_work/analysis/arc1_v325_runtime_states_10"

DEFAULT_STATES = (
    Path(r"C:\Users\Administrator\.paseo\uploads\upload_1641eaa6-e416-45d1-9ad8-ca7e7385c2d1\HASH-70F162DE5529DC72_1.sav"),
    Path(r"C:\Users\Administrator\.paseo\uploads\upload_ea06c466-fcb1-491e-91d3-ddc49a7750b3\HASH-70F162DE5529DC72_2.sav"),
    Path(r"C:\Users\Administrator\.paseo\uploads\upload_202771ff-b2ba-429d-a3f6-4184c86dd985\HASH-70F162DE5529DC72_3.sav"),
    Path(r"C:\Users\Administrator\.paseo\uploads\upload_36f3d0ce-b717-4fa3-8276-ed32e014b0a5\HASH-70F162DE5529DC72_4.sav"),
    Path(r"C:\Users\Administrator\.paseo\uploads\upload_9523cf74-f25c-48ef-9d87-e45bca43715a\HASH-70F162DE5529DC72_5.sav"),
    Path(r"C:\Users\Administrator\.paseo\uploads\upload_4d11aca0-6118-4e7e-8906-141c7109475e\HASH-70F162DE5529DC72_6.sav"),
    Path(r"C:\Users\Administrator\.paseo\uploads\upload_903d47e2-3517-4bf6-85f7-c7321ca6ed71\HASH-70F162DE5529DC72_7.sav"),
    Path(r"C:\Users\Administrator\.paseo\uploads\upload_a0e29dc0-6637-45ee-82a2-746f22c47d47\HASH-70F162DE5529DC72_8.sav"),
    Path(r"C:\Users\Administrator\.paseo\uploads\upload_8d766198-218f-4331-8c44-adb7a84576e5\HASH-70F162DE5529DC72_9.sav"),
    Path(r"C:\Users\Administrator\.paseo\uploads\upload_0c57d06b-e14e-42de-9d82-384af8aa720d\HASH-70F162DE5529DC72_10.sav"),
)

PACKET_STRIDE = 52
RAM_SIZE = 2 * 1024 * 1024
FIXED_UI_HEADERS = (0x801F9D44, 0x801F9D88)
COMPACT_STRIP_U = 244
COMPACT_STRIP_V = 176
COMPACT_STRIP_LABELS = (
    " ",
    "/",
    *tuple(str(value) for value in range(10)),
    "<aux127>",
    "L",
    "M",
    "P",
    ":",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def bitmap_key(rows: object) -> tuple[int, ...]:
    return v320.validate_rows(rows, "runtime identity")


def semantic_mapping(
    comm: bytes, exe: bytes, ui_audit: Path = UI_AUDIT
) -> dict[str, object]:
    """Map physical planes by their actual V325 bitmap, not legacy code names."""
    pieces = v320c.load_pieces(PIECES.read_bytes())
    ascii_rows = pickle.loads(ASCII.read_bytes())
    identities: dict[tuple[int, ...], set[str]] = defaultdict(set)
    for char, rows in ascii_rows.items():
        identities[bitmap_key(rows)].add(char)
    for cp in range(0xAC00, 0xD7A4):
        char = chr(cp)
        identities[v320c.compose(pieces, char, official=True)].add(char)

    physical_chars: dict[int, set[str]] = defaultdict(set)
    for physical in range(960):
        physical_chars[physical].update(identities.get(v320.read_plane(comm, physical), set()))

    # The exact character/token pairing used by V325 resolves ambiguous Hanme
    # bitmaps and gives priority to what the live UI encoder selected.
    for row in csv_rows(ui_audit):
        text = row["korean"]
        payload = bytes.fromhex(row["encoded_hex"]) if row["encoded_hex"] else b""
        text_at = byte_at = 0
        while text_at < len(text):
            marker = next(
                (item for item in ("{결정버튼}", "{취소버튼}") if text.startswith(item, text_at)),
                None,
            )
            if marker:
                text_at += len(marker)
                byte_at += 2
                continue
            width = 1 if payload[byte_at] < 0xDD else 2
            token = payload[byte_at : byte_at + width]
            slot = v320.virtual_slot(token)
            physical = (
                v320.lookup_get(exe, slot)
                if slot is not None and slot < v320.LOOKUP_SLOTS
                else v320.direct_index(token)
            )
            if physical is not None:
                physical_chars[physical].add(text[text_at])
            text_at += 1
            byte_at += width
    return {"physical_chars": physical_chars}


def visible_text(packets: list[dict[str, object]]) -> str:
    if not packets:
        return ""
    rows: dict[int, list[dict[str, object]]] = defaultdict(list)
    for packet in packets:
        rows[int(packet["y"])].append(packet)
    lines = []
    for y in sorted(rows):
        ordered = sorted(rows[y], key=lambda item: (int(item["x"]), int(item["ordinal"])))
        lines.append("".join(str(item["char"]) for item in ordered))
    # Keep internal spacing evidence, but strip padding after the final visible
    # glyph so generated CSV rows stay diff/check friendly and deterministic.
    return " / ".join(lines).rstrip()


def annotate_halfwidth_packets(
    packets: list[dict[str, object]], mapping: dict[str, object]
) -> None:
    """Decode the stock 6-pixel path used by digits and compact HUD labels.

    The common packet builder biases U by four pixels when state D is 6.  The
    underlying physical plane is therefore based on ``U - 4`` rather than U.
    The legacy 16px-only auditor intentionally rejected those packets because
    their U coordinate is not 16-aligned.
    """
    physical_chars = mapping["physical_chars"]
    assert isinstance(physical_chars, dict)
    for packet in packets:
        if int(packet["w"]) != 6:
            continue
        u, v = int(packet["u"]), int(packet["v"])
        clut = int(str(packet["clut"]), 16)
        if (
            u == COMPACT_STRIP_U
            and COMPACT_STRIP_V <= v <= COMPACT_STRIP_V + 48
            and (v - COMPACT_STRIP_V) % 16 == 0
            and 0x7FC0 <= clut <= 0x7FC3
        ):
            slot = ((v - COMPACT_STRIP_V) // 16) * 4 + (clut - 0x7FC0)
            if slot < len(COMPACT_STRIP_LABELS):
                packet["physical_index"] = 960 + slot
                packet["char"] = COMPACT_STRIP_LABELS[slot]
                packet["coordinate_mode"] = "compact_strip_u_plus_4"
                continue
        if u < 4 or (u - 4) % 16 or v % 16 or not 0x7FC0 <= clut <= 0x7FCF:
            continue
        physical = (
            (v // 16) * 60
            + ((u - 4) // 16) * 4
            + ((clut - 0x7FC0) & 3)
        )
        candidates = sorted(physical_chars.get(physical, set()))
        packet["physical_index"] = physical
        packet["char"] = (
            candidates[0]
            if len(candidates) == 1
            else "/".join(candidates)
            if candidates
            else f"<{physical}>"
        )
        packet["coordinate_mode"] = "halfwidth_u_plus_4"


def tail_packets(
    ram: bytes,
    base_address: int,
    count: int,
    limit: int,
    mapping: dict[str, object],
) -> list[dict[str, object]]:
    base = legacy.ram_offset(base_address)
    number = min(16, max(0, limit - count))
    rows = legacy.packets_at(ram, base + count * PACKET_STRIDE, number, mapping)
    annotate_halfwidth_packets(rows, mapping)
    output = []
    for row in rows:
        ordinal = int(row["ordinal"]) + count
        row["ordinal"] = ordinal
        at = base + ordinal * PACKET_STRIDE
        row["command_word"] = f"0x{legacy.u32(ram, at):08X}"
        row["nonzero_packet"] = int(any(ram[at : at + PACKET_STRIDE]))
        output.append(row)
    return output


def fixed_ui_objects(
    ram: bytes, mapping: dict[str, object]
) -> list[dict[str, object]]:
    """Return the non-adjacent 64/128-packet UI objects.

    These two headers point into the shared 0x801BE9BC packet arena, so they
    intentionally do not satisfy ``find_text_objects``' adjacency rule.
    """
    result: list[dict[str, object]] = []
    for address in FIXED_UI_HEADERS:
        header = legacy.ram_offset(address)
        base = legacy.u32(ram, header)
        limit = legacy.u16(ram, header + 4)
        count = legacy.u16(ram, header + 0x0A)
        if not base or not 1 <= limit <= 128 or count > limit:
            continue
        if not 0 <= legacy.ram_offset(base) < RAM_SIZE:
            continue
        state, packets = legacy.object_at(ram, header, mapping)
        annotate_halfwidth_packets(packets, mapping)
        result.append({"state": state, "packets": packets})
    return result


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("states", nargs="*", type=Path)
    parser.add_argument("--build", type=Path, default=BUILD)
    parser.add_argument("--build-sha256", default=BUILD_SHA256)
    parser.add_argument("--ui-audit", type=Path, default=UI_AUDIT)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--expected-states", type=int, default=10)
    parser.add_argument("--expected-game-id", default="V325")
    args = parser.parse_args()
    states = tuple(args.states) or DEFAULT_STATES
    if len(states) != args.expected_states:
        raise SystemExit(f"expected {args.expected_states} states, got {len(states)}")
    actual_build_sha256 = sha256_file(args.build)
    if actual_build_sha256 != args.build_sha256.upper():
        raise SystemExit(f"build hash drift: {actual_build_sha256}")
    args.output.mkdir(parents=True, exist_ok=True)

    summary_rows: list[dict[str, object]] = []
    object_rows: list[dict[str, object]] = []
    packet_rows: list[dict[str, object]] = []
    tail_rows: list[dict[str, object]] = []
    thumbnails: list[Image.Image] = []
    with ZipFile(args.build) as archive:
        exe = archive.read("PSX.EXE")
        comm = archive.read("COMM.IMG")
        mapping = semantic_mapping(comm, exe, args.ui_audit)
        for state_number, path in enumerate(states, 1):
            parsed = legacy.parse_state(path)
            if args.expected_game_id and parsed["game_id"] != args.expected_game_id:
                raise SystemExit(
                    f"{path.name}: expected game id {args.expected_game_id}, got {parsed['game_id']}"
                )
            ram = parsed["ram"]
            vram = parsed["vram"]
            thumbnail = legacy.save_thumbnail(
                parsed["thumbnail"], args.output / f"state{state_number}.png"
            )
            thumbnails.append(thumbnail)
            live_comm = legacy.runtime_comm(vram)
            objects = legacy.find_text_objects(ram, mapping)
            for item in objects:
                annotate_halfwidth_packets(item["packets"], mapping)
            known_headers = {
                str(item["state"]["header_address"]) for item in objects
            }
            objects.extend(
                item
                for item in fixed_ui_objects(ram, mapping)
                if str(item["state"]["header_address"]) not in known_headers
            )
            visible_count = 0
            for obj in objects:
                state = obj["state"]
                packets = obj["packets"]
                score = legacy.vram_text_score(vram, comm, packets)
                visible = int(float(score["best_ratio"]) >= 0.75 and int(score["expected_ink"]) > 0)
                visible_count += visible
                header = str(state["header_address"])
                record = {
                    "state": state_number,
                    "header": header,
                    "base": state["base_address"],
                    "limit": state["limit"],
                    "count": state["count"],
                    "x": state["x"],
                    "y": state["y"],
                    "D": state["D"],
                    "E": state["E"],
                    "F": state["F"],
                    "line_extra": state["line_extra"],
                    "source_pointer": state["source_pointer"],
                    "visible": visible,
                    "framebuffer_ratio": f"{float(score['best_ratio']):.6f}",
                    "expected_ink": score["expected_ink"],
                    "text": visible_text(packets),
                }
                object_rows.append(record)
                for packet in packets:
                    packet_rows.append({"state": state_number, "header": header, **packet})
                base_address = int(str(state["base_address"]), 16)
                for packet in tail_packets(
                    ram, base_address, int(state["count"]), int(state["limit"]), mapping
                ):
                    tail_rows.append({"state": state_number, "header": header, **packet})

            runtime_exe = ram[
                legacy.ram_offset(legacy.EXE_LOAD_ADDRESS) :
                legacy.ram_offset(legacy.EXE_LOAD_ADDRESS) + legacy.EXE_TEXT_SIZE
            ]
            disk_exe = exe[legacy.EXE_TEXT_FILE_OFFSET : legacy.EXE_TEXT_FILE_OFFSET + legacy.EXE_TEXT_SIZE]
            exe_word_diff = sum(
                runtime_exe[offset : offset + 4] != disk_exe[offset : offset + 4]
                for offset in range(0, len(disk_exe), 4)
            )
            summary_rows.append(
                {
                    "state": state_number,
                    "savestate": path.name,
                    "sha256": parsed["file_sha256"],
                    "game_id": parsed["game_id"],
                    "file_size": parsed["file_size"],
                    "ram_base": f"0x{int(parsed['ram_base']):X}",
                    "vram_base": f"0x{int(parsed['vram_base']):X}",
                    "runtime_COMM_exact": int(live_comm == comm),
                    "exe_different_words": exe_word_diff,
                    "text_objects": len(objects),
                    "framebuffer_visible_objects": visible_count,
                    "media_paths": " | ".join(parsed["media_paths"]),
                }
            )

    montage_rows = (len(thumbnails) + 1) // 2
    montage = Image.new("RGBA", (256 * 2, 192 * montage_rows), (0, 0, 0, 255))
    for index, image in enumerate(thumbnails):
        montage.paste(image, ((index % 2) * 256, (index // 2) * 192))
    montage.save(args.output / "states_montage.png")
    write_csv(args.output / "states.csv", summary_rows)
    write_csv(args.output / "objects.csv", object_rows)
    write_csv(args.output / "packets.csv", packet_rows)
    write_csv(args.output / "tail_packets.csv", tail_rows)
    report = {
        "build": args.build.name,
        "build_sha256": actual_build_sha256,
        "states": summary_rows,
        "objects": len(object_rows),
        "packets": len(packet_rows),
        "tail_packets": len(tail_rows),
        "note": "read-only DUCCU audit; visual/root-cause interpretation remains separate",
    }
    (args.output / "summary.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"wrote {args.output}")
    print(f"states={len(summary_rows)} objects={len(object_rows)} packets={len(packet_rows)} tails={len(tail_rows)}")
    for row in summary_rows:
        print(
            f"state{row['state']}: id={row['game_id']} COMM={row['runtime_COMM_exact']} "
            f"objects={row['text_objects']} visible={row['framebuffer_visible_objects']}"
        )


if __name__ == "__main__":
    main()
