#!/usr/bin/env python3
"""Prove the V321 ')' regression from DUCCU states and E2 disk bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
import analyze_arc1_v320c_savestates as common  # noqa: E402


V320C = ROOT / "03_output/arc1_v320c_hanme_official_beol_TEST_ONLY_81D215E1.zip"
V321 = ROOT / "03_output/arc1_v321_text_identity_repair_TEST_ONLY_1B04A832.zip"
V321_SHA256 = "1B04A832B33BF061A1AAC8BEE1186B53D6FE977ACA5295C6B5A019CD0759DDFF"
OUTPUT = ROOT / "01_work/analysis/arc1_v322_e2_skip_restore"
SLOT_BASE = 0x45000
SLOT_SIZE = 0x80

STATE_EXPECTATIONS = (
    {
        "pointer": 0x80116883,
        "file_offset": 0x47883,
        "member": "1/S1031.DAT",
        "text": "엄마...\n조안)))",
        "parentheses": 3,
    },
    {
        "pointer": 0x80116B7D,
        "file_offset": 0x47B7D,
        "member": "D/SD011.DAT",
        "text": "그 불을 줘.)))))))\n)))\n내가 다시 붙이고 올게.)\n))))))))",
        "parentheses": 19,
    },
    {
        "pointer": 0x80116D71,
        "file_offset": 0x47D71,
        "member": "D/SD011.DAT",
        "text": "걱정 마.))))\n불은 내가 다시 붙이고 올게\n.)))))))))))",
        "parentheses": 15,
    },
)

CALLERS = (
    ("1/S1031.DAT", 0, 0x4787A, 7),
    ("D/SD011.DAT", 10, 0x47B60, 10),
    ("D/SD011.DAT", 11, 0x47B70, 9),
    ("D/SD011.DAT", 12, 0x47D58, 4),
    ("D/SD011.DAT", 0, 0x47D62, 11),
)


class AnalysisError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("saves", nargs=3, type=Path)
    args = parser.parse_args()
    if sha256_file(V321) != V321_SHA256:
        raise AnalysisError("V321 build hash drift")

    mapping = common.load_mappings()
    physical_chars = mapping["physical_chars"]
    assert isinstance(physical_chars, dict)
    if physical_chars.get(155) != {")"}:
        raise AnalysisError(f"physical 155 identity drift: {physical_chars.get(155)}")

    with ZipFile(V320C) as old_zip, ZipFile(V321) as bad_zip:
        old = {name: old_zip.read(name) for name in {row[0] for row in CALLERS}}
        bad = {name: bad_zip.read(name) for name in {row[0] for row in CALLERS}}
        comm = bad_zip.read("COMM.IMG")

    caller_rows = []
    for member, slot, site, skip in CALLERS:
        metadata = SLOT_BASE + slot * SLOT_SIZE + 0x7F
        if old[member][metadata] != skip or bad[member][metadata] != 0:
            raise AnalysisError(f"metadata premise differs: {member} slot {slot}")
        exposed = bad[member][site + 2 : site + 2 + skip]
        caller_rows.append(
            {
                "member": member,
                "slot": slot,
                "caller": f"0x{site:X}",
                "v320c_skip": old[member][metadata],
                "v321_skip": bad[member][metadata],
                "exposed_hex": exposed.hex(" ").upper(),
                "exposed_9c": exposed.count(0x9C),
                "resume": f"0x{site + 2 + skip:X}",
            }
        )

    states = []
    for index, (path, expected) in enumerate(zip(args.saves, STATE_EXPECTATIONS, strict=True), 1):
        parsed = common.parse_state(path.resolve())
        if parsed["game_id"] != "V321":
            raise AnalysisError(f"state {index} is not V321: {parsed['game_id']}")
        ram = parsed["ram"]
        vram = parsed["vram"]
        assert isinstance(ram, bytes) and isinstance(vram, bytes)
        state, packets = common.fixed_text_object(
            ram, mapping, common.TEXT_HEADER, common.EXPECTED_PACKET_BASE
        )
        text = common.packet_text(packets)
        pointer = int(str(state["source_pointer"]), 16)
        if text != expected["text"] or pointer != expected["pointer"]:
            raise AnalysisError(
                f"state {index} text/pointer drift: {text!r} {state['source_pointer']}"
            )
        right_parens = [packet for packet in packets if packet["physical_index"] == 155]
        if len(right_parens) != expected["parentheses"]:
            raise AnalysisError(f"state {index} physical155 count drift")
        for packet in right_parens:
            if (
                packet["u"], packet["v"], packet["clut"], packet["w"], packet["h"],
                packet["char"],
            ) != (128, 32, "0x7FC3", 16, 16, ")"):
                raise AnalysisError(f"state {index} ')' packet geometry drift")
        score = common.vram_text_score(vram, common.runtime_comm(vram), packets)
        if float(score["best_ratio"]) < 0.999:
            raise AnalysisError(f"state {index} framebuffer packet score drift: {score}")
        file_offset = pointer - 0x800CF000
        if file_offset != expected["file_offset"]:
            raise AnalysisError(f"state {index} cursor/file offset drift")
        states.append(
            {
                "state": index,
                "path": str(path.resolve()),
                "sha256": parsed["file_sha256"],
                "game_id": parsed["game_id"],
                "text": text,
                "packet_count": state["count"],
                "physical155_count": len(right_parens),
                "source_pointer": state["source_pointer"],
                "source_file_offset": f"0x{file_offset:X}",
                "framebuffer_best_ratio": score["best_ratio"],
            }
        )

    if [row["physical155_count"] for row in states] != [3, 19, 15]:
        raise AnalysisError("visible ')' census drift")
    if sum(int(row["exposed_9c"]) for row in caller_rows) != 37:
        raise AnalysisError("inline 0x9C census drift")

    result = {
        "result": "PASS",
        "conclusion": (
            "V321 zeroed E2 slot[0x7F], so completion did not skip preserved inline "
            "tails; exposed 0x9C renders as ')' at physical index 155."
        ),
        "states": states,
        "callers": caller_rows,
        "visible_parentheses": 37,
        "exposed_inline_9c": 37,
        "rejected_hypothesis": "PSX padding/fill loop; disk inline tails fully explain every packet",
    }
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "v321_runtime_regression.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "V321 E2 skip regression runtime analysis: PASS",
        "visible_parentheses=3,19,15 (total 37)",
        "inline_exposed_9c=3,19,15 (total 37)",
        "source_pointer_ends=0x47883,0x47B7D,0x47D71",
        "physical155=U128,V32,CLUT7FC3,W16,H16,')'",
        "cause=slot[0x7F] values 7,10,9,4,11 were zeroed by V321",
        "fix=restore metadata only; do not edit PSX.EXE, COMM.IMG, or inline wrappers",
    ]
    (OUTPUT / "v321_runtime_regression.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    print("\n".join(lines))


if __name__ == "__main__":
    main()
