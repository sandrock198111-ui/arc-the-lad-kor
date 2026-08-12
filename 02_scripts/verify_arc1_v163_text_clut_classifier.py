"""Independent static and six-state control verification for v163."""
from __future__ import annotations

import hashlib
import struct
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v163_text_clut_classifier as build  # noqa: E402


REPORT = build.ANALYSIS / "independent_verification.txt"
STATE_DIR = ROOT / "01_work/analysis/v162_runtime_states"
RAM_DUMP_OFFSET = 0x1A62
RAM_SIZE = 2 * 1024 * 1024
FONT_CLUT_TABLE = 0x801F2FFE


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def read_archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with zipfile.ZipFile(path) as archive:
        names = [info.filename for info in archive.infolist()]
        return names, {name: archive.read(name) for name in names}


def selected(v: int, clut: int) -> bool:
    return v == build.base.CACHE_V and 0x7FC0 <= clut < 0x7FD0


def main() -> None:
    outputs = sorted(build.OUT_DIR.glob(f"{build.OUT_STEM}_????????.zip"))
    if len(outputs) != 1:
        raise SystemExit(f"expected exactly one v163 archive, found {len(outputs)}")
    output = outputs[0]
    base_names, old = read_archive(build.BASE_ZIP)
    names, current = read_archive(output)
    if names != base_names:
        raise SystemExit("archive member order or names changed")
    if any(current[name] != old[name] for name in names if name != build.PSX):
        raise SystemExit("a non-PSX member differs from v162")

    exe, old_exe = current[build.PSX], old[build.PSX]
    if len(exe) != len(old_exe):
        raise SystemExit("PSX.EXE size changed")
    classifier = build.build_classifier()
    expected_words = (
        0x90620029,  # lbu   v0,0x29(v1)
        0x94780030,  # lhu   t8,0x30(v1)
        0x2442FF20,  # addiu v0,v0,-224
        0x2C420001,  # sltiu v0,v0,1
        0x27188040,  # addiu t8,t8,-0x7FC0
        0x2F180010,  # sltiu t8,t8,16
        0x00581024,  # and   v0,v0,t8
        0x03E00008,  # jr    ra
        0x00000000,  # nop
    )
    if struct.unpack("<9I", classifier) != expected_words:
        raise SystemExit("classifier instruction words differ from the independent oracle")
    at = build.base.source_at(build.CLASSIFIER)
    if exe[at:at + len(classifier)] != classifier:
        raise SystemExit("classifier bytes differ")
    changed = {i for i, (left, right) in enumerate(zip(old_exe, exe)) if left != right}
    if not changed or not changed <= set(range(at, at + len(classifier))):
        raise SystemExit("an EXE byte outside the classifier changed")

    # Boundary controls for both halves of the predicate.
    accepted_cases = [(224, value) for value in range(0x7FC0, 0x7FD0)]
    rejected_cases = (
        [(223, value) for value in range(0x7FC0, 0x7FD0)]
        + [(225, value) for value in range(0x7FC0, 0x7FD0)]
        + [(224, 0x7FBF), (224, 0x7FD0), (224, 0x0010)]
    )
    if not all(selected(*case) for case in accepted_cases):
        raise SystemExit("a valid text boundary case was rejected")
    if any(selected(*case) for case in rejected_cases):
        raise SystemExit("an invalid boundary case was accepted")

    states = sorted(STATE_DIR.glob("slot*.state.bin"))
    if len(states) != 6:
        raise SystemExit(f"expected six v162 control states, found {len(states)}")
    linked = []
    state_clut_tables = []
    for state_path in states:
        state = state_path.read_bytes()
        ram = state[RAM_DUMP_OFFSET:RAM_DUMP_OFFSET + RAM_SIZE]
        table_at = FONT_CLUT_TABLE & 0x1FFFFF
        state_clut_tables.append(struct.unpack_from("<16H", ram, table_at))
        for offset in range(0, RAM_SIZE - 20, 4):
            if struct.unpack_from("<I", ram, offset + 4)[0] != 0xE100001F:
                continue
            target = struct.unpack_from("<I", ram, offset)[0] & 0x00FFFFFF
            if target in (0, 0x00FFFFFF) or target >= RAM_SIZE - 20:
                continue
            if ram[target + 7] != 0x65:
                continue
            u, v = ram[target + 12], ram[target + 13]
            clut = struct.unpack_from("<H", ram, target + 14)[0]
            linked.append((state_path.stem, 0x80000000 + offset,
                           0x80000000 + target, u, v, clut))

    if any(table != build.FONT_CLUTS for table in state_clut_tables):
        raise SystemExit("one or more live font CLUT tables differ")

    old_selected = [row for row in linked if row[4] == build.base.CACHE_V]
    new_selected = [row for row in linked if selected(row[4], row[5])]
    rejected_false = [row for row in old_selected if not selected(row[4], row[5])]
    if len(old_selected) != 10 or len(new_selected) != 8 or len(rejected_false) != 2:
        raise SystemExit(
            f"six-state control count differs: old={len(old_selected)} "
            f"new={len(new_selected)} rejected={len(rejected_false)}"
        )
    if {row[5] for row in rejected_false} != {0x0010}:
        raise SystemExit("rejected six-state packet is not the proven CLUT 0x0010 sprite")
    if not all(row[5] in build.FONT_CLUTS for row in new_selected):
        raise SystemExit("a newly accepted packet is outside the font CLUT table")

    stamp = digest(output.read_bytes())
    lines = [
        "v163 independent static/control verification: PASS",
        f"archive={output.name}",
        f"archive_sha256={stamp}",
        f"archive_members={len(names)}",
        f"changed_EXE_bytes={len(changed)}",
        "changed_non_EXE_members=0",
        f"classifier_bytes={len(classifier)}",
        "font_CLUT_table=" + " ".join(f"{value:04X}" for value in build.FONT_CLUTS),
        "font_CLUT_table_matching_states=6/6",
        f"predicate_accept_boundaries={len(accepted_cases)}/{len(accepted_cases)}",
        f"predicate_reject_boundaries={len(rejected_cases)}/{len(rejected_cases)}",
        f"v162_live_high_page_packets_old_rule={len(old_selected)}",
        f"v162_live_high_page_packets_new_rule={len(new_selected)}",
        f"proven_false_sprite_packets_rejected={len(rejected_false)}",
        "rejected_false_CLUTs=" + " ".join(f"{row[5]:04X}" for row in rejected_false),
        "all_v162_bytes_outside_classifier=byte_identical",
        "runtime_verification=PENDING user cold boot",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
