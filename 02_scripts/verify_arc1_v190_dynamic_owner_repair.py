#!/usr/bin/env python3
"""Independently verify a v190 dynamic-owner repair archive."""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v190_dynamic_owner_repair as build  # noqa: E402
import plan_arc1_v190_dynamic_owner_repair as plan  # noqa: E402


EXPECTED = ROOT / "03_output/arc1_v190_dynamic_owner_repair_4AC51D4F.zip"
EXPECTED_SHA256 = "4AC51D4F38F38B65782DBD5AAE5A7DA03369A57D6E7DBF3F437E4EDB29556619"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def main() -> None:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else EXPECTED
    if digest(target) != EXPECTED_SHA256:
        raise SystemExit("v190 archive hash differs")
    with ZipFile(plan.BASE) as archive:
        base_names = archive.namelist()
        base = {name: archive.read(name) for name in base_names}
    with ZipFile(target) as archive:
        if archive.namelist() != base_names:
            raise SystemExit("archive member order differs")
        made = {name: archive.read(name) for name in archive.namelist()}

    if made[build.COMM] != base[build.COMM]:
        raise SystemExit("COMM.IMG differs from v189")
    if any(len(made[name]) != len(base[name]) for name in base):
        raise SystemExit("archive member length differs")

    layout, blobs, code_base = build.resident_layout()
    decoder = code_base
    decoder_blob = build.build_decoder(decoder, layout)
    huffman_address = build.align(decoder + len(decoder_blob))
    huffman_blob = build.build_huffman(huffman_address, layout)
    frame = build.align(huffman_address + len(huffman_blob))
    frame_blob = build.build_frame(frame, huffman_address, layout)
    used_end = frame + len(frame_blob)
    if used_end != build.HEAP_BASE:
        raise SystemExit("reconstructed resident does not end at the frozen heap")

    expected_resident = bytearray(build.COPY_N)
    for name, blob in blobs.items():
        at = layout[name][0] - build.RESIDENT_BASE
        expected_resident[at:at + len(blob)] = blob
    struct.pack_into(
        f"<{build.CACHE_N}H", expected_resident,
        layout["owners"][0] - build.RESIDENT_BASE,
        *([0xFFFF] * build.CACHE_N),
    )
    struct.pack_into(
        "<4H", expected_resident,
        layout["upload_rect"][0] - build.RESIDENT_BASE,
        build.v171.CACHE_X, build.v171.CACHE_Y, 3, build.old.CELL,
    )
    for address, blob in (
        (decoder, decoder_blob), (huffman_address, huffman_blob), (frame, frame_blob)
    ):
        at = address - build.RESIDENT_BASE
        expected_resident[at:at + len(blob)] = blob
    source_at = build.old.file_at(build.SOURCE_BASE)
    actual_resident = made[build.PSX][source_at:source_at + build.COPY_N]
    if actual_resident != bytes(expected_resident):
        raise SystemExit("built resident bytes differ from reconstruction")

    # Persistent lookup/checkpoints and their complete runtime readback.
    lookup_at = build.old.file_at(build.v171.PACKED_LOOKUP_RAM)
    lookup_blob = made[build.PSX][lookup_at:lookup_at + 568]
    if lookup_blob != plan.LOOKUP_TABLE.read_bytes():
        raise SystemExit("persistent 413-entry lookup differs")
    lookup = plan.old_plan.unpack_fixed(lookup_blob, plan.LOOKUP_N, plan.LOOKUP_BITS)
    with ZipFile(plan.BASE) as archive:
        base_exe = archive.read(build.PSX)
    old_lookup = plan.old_plan.unpack_fixed(
        base_exe[lookup_at:lookup_at + build.v171.PACKED_LOOKUP_BYTES],
        plan.OLD_LOOKUP_N, plan.LOOKUP_BITS,
    )
    if lookup[:plan.OLD_LOOKUP_N] != old_lookup:
        raise SystemExit("an original lookup entry changed")
    if lookup[-4:] != [plan.DYNAMIC_TAG + source for source in range(462, 466)]:
        raise SystemExit("EA 9C..EA 9F source mapping differs")

    checkpoint_at = build.old.file_at(build.v171.HUFFMAN_CHECKPOINTS_RAM)
    checkpoints_blob = made[build.PSX][checkpoint_at:checkpoint_at + 60]
    if checkpoints_blob != plan.SOURCE_CHECKPOINTS.read_bytes():
        raise SystemExit("persistent source checkpoints differ")
    checkpoints = tuple(struct.unpack("<30H", checkpoints_blob))
    rows_blob = blobs["huffman_rows"]
    rows = tuple(struct.unpack(f"<{len(rows_blob) // 2}H", rows_blob))
    counts = blobs["huffman_counts"]
    stream = blobs["source_bitstream"]
    decoded = [
        plan.old_plan.decode_huffman_source(source, rows, counts, checkpoints, stream)
        for source in range(plan.SOURCE_N)
    ]
    for ordinal, (_source, char, _code, _index, _where) in enumerate(plan.TARGETS):
        if decoded[462 + ordinal] != plan.EXPECTED_ROWS[char]:
            raise SystemExit(f"target runtime source differs: {char}")

    # Exact owner writes, including seven unchanged EA 9E references for 페.
    repairs = build.read_csv(plan.OWNER_REPAIRS)
    for row in repairs:
        data = made[row["member"]]
        offset = int(row["offset"], 0)
        expected = bytes.fromhex(row["new_hex"])
        if data[offset:offset + len(expected)] != expected:
            raise SystemExit(f"owner repair differs: {row['member']} 0x{offset:X}")
    changed = sorted(name for name in made if made[name] != base[name])
    expected_changed = sorted({build.PSX} | {row["member"] for row in repairs
                                            if row["old_hex"] != row["new_hex"]})
    if changed != expected_changed:
        raise SystemExit(f"changed member set differs: {changed}")

    # Hook topology and decoder immediates.
    if build.old.word(made[build.PSX], build.old.DECODER_ENTRY) != build.old.j(decoder):
        raise SystemExit("decoder hook target differs")
    if build.old.word(made[build.PSX], build.old.LATE_HOOK) != build.old.jal(frame):
        raise SystemExit("frame hook target differs")
    words = struct.unpack(f"<{len(decoder_blob) // 4}I", decoder_blob)
    if words.count(build.old.i_type(0x0B, build.T2, build.T3, plan.LOOKUP_N)) != 1:
        raise SystemExit("decoder 413-entry bound is missing or duplicated")
    if words[3] != build.old.i_type(0x0D, build.ZERO, build.T9, 2):
        raise SystemExit("decoder E9/EA two-byte advance fix is missing")

    print("v190 independent verification PASS")
    print(f"archive={target.name}")
    print(f"sha256={EXPECTED_SHA256}")
    print("COMM.IMG=v189 byte-identical")
    print("lookup=413/413; old 409 preserved")
    print("Huffman=466/466 runtime readback")
    print(f"resident={used_end - build.RESIDENT_BASE}/{build.COPY_N}")
    print(f"owners={len(repairs)}; changed_members={len(changed)}")
    print("emulator_run=NO")


if __name__ == "__main__":
    main()
