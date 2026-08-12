"""v163: exclude non-text sprites from the strip-A high-page pass.

The six v162 runtime states prove that the cache bitmap, RAM shadow and VRAM
upload are exact.  They also expose one live false positive: an ordinary 12x12
sprite has U=4/V=224/CLUT=0x0010 and is linked immediately after a high-page
DR_TPAGE because v162 classifies only by V.

The stock glyph builder at 0x8016B5FC..0x8016B638 writes CLUT metadata from the
sixteen-entry table at 0x801F2FFE.  The table is exactly 0x7FC0..0x7FCF.  Keep
every v162 byte except the resident classifier, and require both V=224 and a
CLUT in that proven text range.
"""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v162_strip_a_dynamic_cache as base  # noqa: E402


BASE_ZIP = ROOT / "03_output/arc1_v162_strip_a_dynamic_cache_1759E571.zip"
BASE_SHA256 = "1759E57185F8EF16D8A5421EE122FB14F158939736D2C70AC728A1D8B2EEC056"
OUT_DIR = ROOT / "03_output"
OUT_STEM = "arc1_v163_text_clut_classifier"
ANALYSIS = ROOT / "01_work/analysis/arc1_v163_text_clut_classifier"
REPORT = ANALYSIS / "build_report.txt"
DISASSEMBLY = ANALYSIS / "classifier_words.txt"

PSX = base.PSX
CLASSIFIER = base.CLASSIFIER
OLD_CLASSIFIER_N = base.CLASSIFIER_N
CLASSIFIER_N = 36
FONT_CLUTS = tuple(range(0x7FC0, 0x7FD0))

ZERO, V0, V1, T8, RA = 0, 2, 3, 24, 31
JR_RA = base.r_type(RA, ZERO, ZERO, 0, 0x08)
NOP = 0


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def build_classifier() -> bytes:
    """Return v0=1 only for row-40 V and the stock text CLUT family.

    The independent lbu/lhu pair also serves as the R3000 load-delay spacing:
    neither loaded register is consumed by the immediately following load.
    """
    words = (
        base.i_type(0x24, V1, V0, 0x29),       # lbu   v0,0x29(v1)  (V)
        base.i_type(0x25, V1, T8, 0x30),       # lhu   t8,0x30(v1)  (CLUT)
        base.i_type(0x09, V0, V0, -base.CACHE_V),
        base.i_type(0x0B, V0, V0, 1),          # V == 224
        base.i_type(0x09, T8, T8, -0x7FC0),
        base.i_type(0x0B, T8, T8, 16),         # 0x7FC0 <= CLUT <= 0x7FCF
        base.r_type(V0, T8, V0, 0, 0x24),      # and   v0,v0,t8
        JR_RA,
        NOP,
    )
    return struct.pack(f"<{len(words)}I", *words)


def main() -> None:
    if digest(BASE_ZIP.read_bytes()) != BASE_SHA256:
        raise SystemExit("base archive is not the frozen v162 build")
    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {info.filename: archive.read(info.filename) for info in infos}
    original_members = dict(members)
    exe = bytearray(members[PSX])
    before = bytes(exe)

    old = base.build_classifier()
    old_at = base.source_at(CLASSIFIER)
    new = build_classifier()
    if len(old) != OLD_CLASSIFIER_N or len(new) != CLASSIFIER_N:
        raise SystemExit("classifier size invariant differs")
    if exe[old_at:old_at + len(old)] != old:
        raise SystemExit("v162 classifier bytes differ")
    if any(exe[old_at + len(old):old_at + len(new)]):
        raise SystemExit("classifier expansion area is not zero")
    if CLASSIFIER + len(new) > base.HEAP_BASE:
        raise SystemExit("classifier crosses the frozen heap boundary")

    exe[old_at:old_at + len(new)] = new
    if exe[old_at:old_at + len(new)] != new:
        raise SystemExit("classifier readback differs")
    members[PSX] = bytes(exe)

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    temporary = OUT_DIR / f"{OUT_STEM}_building.zip"
    if temporary.exists():
        raise SystemExit(f"refusing to reuse temporary output: {temporary.name}")
    with ZipFile(temporary, "w", ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(base.clone(info), members[info.filename])
    with ZipFile(temporary) as archive:
        if [i.filename for i in archive.infolist()] != [i.filename for i in infos]:
            raise SystemExit("archive member order changed")
        for name, expected in members.items():
            if archive.read(name) != expected:
                raise SystemExit(f"archive readback differs: {name}")

    stamp = digest(temporary.read_bytes())
    output = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {output.name}")
    temporary.replace(output)

    changed = {i for i, (left, right) in enumerate(zip(before, exe)) if left != right}
    allowed = set(range(old_at, old_at + len(new)))
    if not changed or not changed <= allowed:
        raise SystemExit("PSX.EXE changed outside the classifier")
    if any(name != PSX and members[name] != original_members[name] for name in members):
        raise SystemExit("a non-PSX member changed")

    words = struct.unpack(f"<{len(new) // 4}I", new)
    DISASSEMBLY.write_text(
        "\n".join(
            f"0x{CLASSIFIER + i * 4:08X}  {value:08X}"
            for i, value in enumerate(words)
        ) + "\n",
        encoding="utf-8",
    )
    lines = [
        "v163 text-CLUT high-page classifier",
        "",
        f"base={BASE_ZIP.name}",
        f"output={output.name}",
        f"sha256={stamp}",
        f"changed_EXE_bytes={len(changed)}",
        "changed_non_EXE_members=0",
        f"classifier_runtime=0x{CLASSIFIER:08X}",
        f"classifier_bytes={len(new)}",
        "old_rule=V == 224",
        "new_rule=V == 224 and 0x7FC0 <= CLUT <= 0x7FCF",
        "font_CLUT_table_runtime_evidence=" + " ".join(f"{x:04X}" for x in FONT_CLUTS),
        "font_CLUT_evidence=all six supplied v162 states; table is runtime data, not EXE data",
        "",
        "v162 cache decoder, bitmap writer, RAM shadow, upload and geometry unchanged",
        "runtime_verification=PENDING user cold boot",
        "rollback=v162",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
