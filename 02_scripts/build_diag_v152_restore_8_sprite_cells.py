"""v152 diagnostic: restore the eight COMM.IMG cells sampled by the bad monster.

This is deliberately not a release build.  It recreates the already-tested isolation
condition from v151:

* restore the 140 changed cells that were blank on the pristine disc;
* clear resident strips A, B and C in PSX.EXE;
* additionally restore the eight non-blank cells sampled by the 12x12 sprite packet
  grid at the corrupt monster's screen position.

Rows 0-7 and 8-13 both failed separately because the monster samples cells in both
halves.  Restoring exactly this cross-half set is the smallest discriminating test.
Text that used these cells will be missing or wrong in this diagnostic build.
"""
from __future__ import annotations

import hashlib
import sys
import zipfile
from pathlib import Path
from zipfile import ZipFile, ZipInfo

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = Path(__file__).resolve().parents[1]
BASE_ZIP = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
BASE_SHA256 = "A4358FEE5FEA4964C9DD376B630894EB5EC133EFEEDD9E5E85BBC5FDD8CA1A46"
PRISTINE = ROOT / "00_original/arc.zip"
PRISTINE_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"
OUT_DIR = ROOT / "03_output"
ANALYSIS = ROOT / "01_work/analysis/diag_v152_restore_8_sprite_cells"

CELL = 12
COLS = 21
ROW_BYTES = 896
RAM_TO_FILE = 0x8011A800
STRIP_BYTES = 936
STRIPS = {
    "A": 0x801A8800,
    "B": 0x801A8BA8,
    "C": 0x801A93CC,
}
CLASSIFIER = 0x801A8F50

# Exact intersection of the monster's 12x12 sprite packets and the 137 changed,
# originally non-blank physical cells.  The set intentionally crosses the old A/B
# bisection boundary.
TARGET_CELLS = (
    (0, 19),
    (1, 17),
    (5, 11),
    (8, 17),
    (9, 11),
    (11, 9),
    (11, 13),
    (11, 17),
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(out, attr, getattr(info, attr))
    return out


def cell_bytes(data: bytes, row: int, col: int) -> bytes:
    out = bytearray()
    for dy in range(CELL):
        at = (row * CELL + dy) * ROW_BYTES + (col * CELL) // 2
        out += data[at:at + CELL // 2]
    return bytes(out)


def restore_cell(dst: bytearray, src: bytes, row: int, col: int) -> None:
    for dy in range(CELL):
        at = (row * CELL + dy) * ROW_BYTES + (col * CELL) // 2
        dst[at:at + CELL // 2] = src[at:at + CELL // 2]


def changed_cells(a: bytes, b: bytes) -> set[tuple[int, int]]:
    rows = min(len(a), len(b)) // ROW_BYTES // CELL
    return {
        (row, col)
        for row in range(rows)
        for col in range(COLS)
        if cell_bytes(a, row, col) != cell_bytes(b, row, col)
    }


def main() -> None:
    if digest(BASE_ZIP.read_bytes()) != BASE_SHA256:
        raise SystemExit("base archive is not the frozen v151 build")
    if digest(PRISTINE.read_bytes()) != PRISTINE_SHA256:
        raise SystemExit("pristine archive hash mismatch")

    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}
        original_sizes = {name: len(data) for name, data in members.items()}
    with ZipFile(PRISTINE) as archive:
        pristine_font = archive.read("COMM.IMG")

    v151_font = members["COMM.IMG"]
    if len(v151_font) != len(pristine_font):
        raise SystemExit("COMM.IMG size mismatch")

    font = bytearray(v151_font)
    all_changed = changed_cells(v151_font, pristine_font)

    # Recreate DIAG_fontBLANK140: only cells that changed despite being physically
    # empty on the pristine disc are restored here.
    blank_changed = {
        cell for cell in all_changed if not any(cell_bytes(pristine_font, *cell))
    }
    if len(blank_changed) != 140:
        raise SystemExit(f"expected 140 changed pristine-blank cells, got {len(blank_changed)}")
    for cell in blank_changed:
        restore_cell(font, pristine_font, *cell)

    after_blank = changed_cells(bytes(font), pristine_font)
    if len(after_blank) != 137:
        raise SystemExit(f"expected 137 remaining changed cells, got {len(after_blank)}")

    target = set(TARGET_CELLS)
    if len(target) != len(TARGET_CELLS):
        raise SystemExit("duplicate target cell")
    missing = target - after_blank
    if missing:
        raise SystemExit(f"target cells are not all changed in v151: {sorted(missing)}")
    if any(not any(cell_bytes(pristine_font, *cell)) for cell in target):
        raise SystemExit("a target cell is pristine-blank; the two candidate classes mixed")

    for cell in target:
        restore_cell(font, pristine_font, *cell)
    after_target = changed_cells(bytes(font), pristine_font)
    if after_target != after_blank - target:
        raise SystemExit("restoring the target cells changed an unexpected physical cell")
    for cell in target:
        if cell_bytes(bytes(font), *cell) != cell_bytes(pristine_font, *cell):
            raise SystemExit(f"cell {cell} did not restore byte-for-byte")
    members["COMM.IMG"] = bytes(font)

    # Recreate the all-strips-zero control condition without touching classifier code.
    exe = bytearray(members["PSX.EXE"])
    strip_nonzero: dict[str, int] = {}
    for name, ram in STRIPS.items():
        at = ram - RAM_TO_FILE
        strip_nonzero[name] = sum(1 for byte in exe[at:at + STRIP_BYTES] if byte)
        exe[at:at + STRIP_BYTES] = bytes(STRIP_BYTES)
    guard = CLASSIFIER - RAM_TO_FILE
    if not any(exe[guard:guard + 64]):
        raise SystemExit("classifier code was erased")
    for name, ram in STRIPS.items():
        at = ram - RAM_TO_FILE
        if any(exe[at:at + STRIP_BYTES]):
            raise SystemExit(f"strip {name} was not cleared")
    members["PSX.EXE"] = bytes(exe)

    for name, data in members.items():
        if len(data) != original_sizes[name]:
            raise SystemExit(f"{name} changed size")
    # Compare against a fresh v151 read so the archive-level change set is proven exactly.
    with ZipFile(BASE_ZIP) as archive:
        base_members = {info.filename: archive.read(info.filename) for info in infos}
    changed_members = {name for name in members if members[name] != base_members[name]}
    if changed_members != {"COMM.IMG", "PSX.EXE"}:
        raise SystemExit(f"unexpected changed archive members: {sorted(changed_members)}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    temp = OUT_DIR / "DIAG_v152_restore_8_sprite_cells_building.zip"
    with ZipFile(temp, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    stamp = digest(temp.read_bytes())
    final = OUT_DIR / f"DIAG_v152_restore_8_sprite_cells_{stamp[:8]}.zip"
    if final.exists():
        raise SystemExit(f"refusing to overwrite existing output: {final.name}")
    temp.replace(final)

    report = [
        "v152 몬스터 스프라이트 교차 8칸 원본 복구 진단판",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {final.name}",
        f"sha256  {stamp}",
        "",
        f"원본이 비어 있던 변경 칸 복구  {len(blank_changed)}",
        f"추가 표적 칸 복구             {len(target)}",
        f"남은 원본 대비 변경 칸        {len(after_target)}",
        "표적 칸  " + ", ".join(f"({r},{c})" for r, c in TARGET_CELLS),
        "스트립 비움  " + ", ".join(
            f"{name}({strip_nonzero[name]} nonzero bytes)" for name in STRIPS
        ),
        "변경 멤버  COMM.IMG, PSX.EXE",
        "",
        "판정 기준",
        "  같은 몬스터가 움직일 때 블록이 사라지면 8칸 교차 가설 통과.",
        "  그대로면 8칸 밖의 셀 또는 별도 소비 경로가 남아 있으므로 가설 기각.",
        "",
        "주의",
        "  진단판이며 배포 금지. 복구한 칸을 쓰던 한글은 빈칸/오문자로 보일 수 있다.",
        "  strip A/B/C도 비웠으므로 해당 확장 글리프 역시 정상 표시 대상이 아니다.",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()
