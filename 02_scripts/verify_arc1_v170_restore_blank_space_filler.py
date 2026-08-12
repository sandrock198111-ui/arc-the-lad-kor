"""Independent static verification for v170's one-plane space restoration."""
from __future__ import annotations

import hashlib
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "03_output/arc1_v169_e1_control_glyph_dispatch_218D38D2.zip"
BASE_SHA256 = "218D38D21FED1D20E79483D657ED2E31D86425DA644F88322461F18BC3C9D4B0"
PATCH = ROOT / "03_output/arc1_v170_restore_blank_space_filler_F8A67A67.zip"
PATCH_SHA256 = "F8A67A674A8E17F18C50DB7408FB3DCFD494FD9760C665D429CC11D36D9EF81B"
CONTROL = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
CONTROL_SHA256 = "A4358FEE5FEA4964C9DD376B630894EB5EC133EFEEDD9E5E85BBC5FDD8CA1A46"
ORIGINAL = ROOT / "00_original/arc.zip"
ORIGINAL_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"

OUT = ROOT / "01_work/analysis/arc1_v170_restore_blank_space_filler_verification"
REPORT = OUT / "verification_report.txt"
COMM = "COMM.IMG"
ROW_BYTES, CELL, IPR, PLANES = 896, 12, 84, 4
INDEX = 0x9C - 1


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def load(path: Path, expected: str):
    if digest(path) != expected:
        raise SystemExit(f"archive hash differs: {path.name}")
    with ZipFile(path) as archive:
        infos = archive.infolist()
        return infos, {info.filename: archive.read(info.filename) for info in infos}


def bitmap(font: bytes, index: int) -> tuple[int, ...]:
    row, within = divmod(index, IPR)
    column, plane = divmod(within, PLANES)
    result = []
    for y in range(CELL):
        for x in range(CELL):
            byte = font[(row * CELL + y) * ROW_BYTES + column * 6 + x // 2]
            nibble = (byte >> (4 * (x & 1))) & 0xF
            result.append((nibble >> plane) & 1)
    return tuple(result)


def main() -> None:
    base_infos, base = load(BASE, BASE_SHA256)
    patch_infos, patch = load(PATCH, PATCH_SHA256)
    _control_infos, control = load(CONTROL, CONTROL_SHA256)
    _original_infos, original = load(ORIGINAL, ORIGINAL_SHA256)

    if [info.filename for info in patch_infos] != [info.filename for info in base_infos]:
        raise SystemExit("archive member order changed")
    if any(len(patch[name]) != len(base[name]) for name in base):
        raise SystemExit("archive member length changed")
    changed_members = [name for name in base if base[name] != patch[name]]
    if changed_members != [COMM]:
        raise SystemExit(f"unexpected changed members: {changed_members}")

    before, after = base[COMM], patch[COMM]
    changed = [index for index, pair in enumerate(zip(before, after)) if pair[0] != pair[1]]
    if len(changed) != 26:
        raise SystemExit(f"expected 26 changed COMM bytes, found {len(changed)}")
    row, within = divmod(INDEX, IPR)
    column, plane = divmod(within, PLANES)
    allowed = {
        (row * CELL + y) * ROW_BYTES + column * 6 + x // 2
        for y in range(CELL) for x in range(CELL)
    }
    if not set(changed) <= allowed:
        raise SystemExit("COMM diff escaped index 155's physical cell")
    for at in changed:
        xor = before[at] ^ after[at]
        if xor & ~0x88 or after[at] & xor:
            raise SystemExit(f"non-plane-3 or set-bit write at COMM+0x{at:X}")

    original_bits = bitmap(original[COMM], INDEX)
    base_bits = bitmap(before, INDEX)
    control_bits = bitmap(control[COMM], INDEX)
    final_bits = bitmap(after, INDEX)
    if original_bits != base_bits or sum(base_bits) != 29:
        raise SystemExit("v169 does not carry the untouched 29-pixel glyph")
    if any(control_bits) or final_bits != control_bits:
        raise SystemExit("v170 blank plane does not reproduce v151")

    OUT.mkdir(parents=True, exist_ok=True)
    lines = [
        "v170 blank-space-filler independent verification",
        "",
        f"patch={PATCH.name}",
        f"sha256={PATCH_SHA256}",
        f"changed_members={COMM}",
        f"changed_COMM_bytes={len(changed)}",
        f"physical_index={INDEX}",
        f"row={row} column={column} plane={plane}",
        "untouched_pixels=29",
        "v169_pixels=29",
        "v151_pixels=0",
        "v170_pixels=0",
        "",
        "member_order=PASS",
        "member_lengths=PASS",
        "PSX_and_all_DAT_byte_identical=PASS",
        "diff_confined_to_one_plane=PASS",
        "only_set_bits_cleared=PASS",
        "v151_control_reproduced=PASS",
        "result=PASS_STATIC",
        "runtime=PENDING user cold boot",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(REPORT)


if __name__ == "__main__":
    main()
