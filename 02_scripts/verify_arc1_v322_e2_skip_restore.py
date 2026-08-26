#!/usr/bin/env python3
"""Independent static verifier for V322's five E2 skip bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/arc1_v321_text_identity_repair_TEST_ONLY_1B04A832.zip"
BASE_SHA256 = "1B04A832B33BF061A1AAC8BEE1186B53D6FE977ACA5295C6B5A019CD0759DDFF"
OUTPUT = ROOT / "01_work/analysis/arc1_v322_e2_skip_restore"
SLOT_BASE = 0x45000
SLOT_SIZE = 0x80

# Independent specification: member, slot, command offset, skip span, next bytes.
CASES = (
    ("1/S1031.DAT", 0, 0x4787A, "E2 81", "E6 01 90 94 9C 9C 9C", "00 00"),
    ("D/SD011.DAT", 10, 0x47B60, "E2 8B", "9C 9C 9C 9C 9C 9C 9C 9C 9C 9C", "E4 1F"),
    ("D/SD011.DAT", 11, 0x47B70, "E2 8C", "9C 9C 9C 9C 9C 9C 9C 9C 9C", "E4 33"),
    ("D/SD011.DAT", 12, 0x47D58, "E2 8D", "9C 9C 9C 9C", "E6 01"),
    ("D/SD011.DAT", 0, 0x47D62, "E2 81", "9C 9C 9C 9C 9C 9C 9C 9C 9C 9C 9C", "E4 79"),
)


class VerifyError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with ZipFile(path) as handle:
        names = [info.filename for info in handle.infolist() if not info.is_dir()]
        return names, {name: handle.read(name) for name in names}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("build", type=Path)
    args = parser.parse_args()
    build = args.build.resolve()
    if sha256_file(BASE) != BASE_SHA256:
        raise VerifyError("V321 base hash drift")
    if not build.is_file():
        raise VerifyError(f"missing build: {build}")

    base_names, base = archive(BASE)
    final_names, final = archive(build)
    if base_names != final_names or len(final_names) != 164:
        raise VerifyError("ZIP topology drift")
    changed = [name for name in final_names if base[name] != final[name]]
    if set(changed) != {"1/S1031.DAT", "D/SD011.DAT"}:
        raise VerifyError(f"changed members differ: {changed}")

    expected_offsets: dict[str, set[int]] = {}
    rows = []
    for member, slot, site, command_hex, skipped_hex, next_hex in CASES:
        command = bytes.fromhex(command_hex)
        skipped = bytes.fromhex(skipped_hex)
        next_bytes = bytes.fromhex(next_hex)
        metadata = SLOT_BASE + slot * SLOT_SIZE + 0x7F
        resume = site + len(command) + len(skipped)
        expected_offsets.setdefault(member, set()).add(metadata)

        if base[member][metadata] != 0 or final[member][metadata] != len(skipped):
            raise VerifyError(f"metadata transition differs: {member} slot {slot}")
        for data, label in ((base[member], "base"), (final[member], "final")):
            if data[site : site + 2] != command:
                raise VerifyError(f"{label} command differs: {member}:0x{site:X}")
            if data[site + 2 : resume] != skipped:
                raise VerifyError(f"{label} skip span differs: {member}:0x{site:X}")
            if data[resume : resume + len(next_bytes)] != next_bytes:
                raise VerifyError(f"{label} resume bytes differ: {member}:0x{resume:X}")
        rows.append(
            {
                "member": member,
                "slot": slot,
                "skip": len(skipped),
                "metadata_offset": f"0x{metadata:X}",
                "caller": f"0x{site:X}",
                "resume": f"0x{resume:X}",
                "exposed_9c": skipped.count(0x9C),
            }
        )

    for name in final_names:
        actual = {
            offset
            for offset, (old, new) in enumerate(zip(base[name], final[name], strict=True))
            if old != new
        }
        if actual != expected_offsets.get(name, set()):
            raise VerifyError(f"archive Expected-Write mismatch: {name}")
    if any(len(base[name]) != len(final[name]) for name in final_names):
        raise VerifyError("member size changed")

    result = {
        "result": "PASS",
        "build": str(build),
        "build_sha256": sha256_file(build),
        "changed_members": changed,
        "changed_bytes": sum(len(value) for value in expected_offsets.values()),
        "cases": rows,
        "v321_visible_9c_total": sum(int(row["exposed_9c"]) for row in rows),
        "runtime": "PENDING user cold boot",
    }
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "independent_verification.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "V322 independent static verification: PASS",
        f"build_sha256={result['build_sha256']}",
        f"changed_members={','.join(changed)}",
        "changed_bytes=5 (slot +0x7F only)",
        "skip_values=" + ",".join(str(row["skip"]) for row in rows),
        "resume_offsets=" + ",".join(str(row["resume"]) for row in rows),
        "runtime=PENDING user cold boot",
    ]
    (OUTPUT / "independent_verification.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    print("\n".join(lines))


if __name__ == "__main__":
    main()
