"""Diagnostic, not a release: the unpatched disc, rebuilt and burned the same way.

Every axis of the patch has now been reverted on its own and the block above the
magenta slime survived all three.

    COMM.IMG original   -> block stays
    PSX.EXE  original   -> block stays
    all 161 .DAT original -> block stays

Those three axes are every byte the project changes.  If reverting each one alone
does not clear the block, then either two independent causes exist, or the cause is
not in the files at all -- and nobody has ever looked at the unpatched disc.  The
note that says the cell "was empty in the original so nothing showed" is an
inference drawn from the COMM.IMG theory, not something anyone saw on screen.

So this build carries no patch whatsoever.  00_original/arc.zip straight back into
an ISO, laid out by the original 01_work/arc1_original_layout.xml -- PSX.EXE at the
front of the root directory, no 284-sector dummy, no executable moved to the tail.
It is the control that the last four builds were missing.

    slime clean  -> the block is ours after all, and the untested axis is the disc
                    layout, since every DIAG so far shipped the v104 layout
    slime dirty  -> the block is not ours.  It is in the game or in the rebuild,
                    and a day of chasing font cells was chasing a ghost

Do not ship this.  It is the Japanese original with no translation in it.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ORIGINAL_ZIP = ROOT / "00_original/arc.zip"
REF_XML = ROOT / "01_work/arc1_original_layout.xml"
MKPSXISO = ROOT / "06_tools/mkpsxiso/mkpsxiso-2.30-win64/mkpsxiso.exe"
WORK = ROOT / "01_work/package_pristine"
FILES = WORK / "files"
NAME = "DIAG_pristine_original_disc"
BIN = ROOT / "03_output" / f"{NAME}.bin"
CUE = ROOT / "03_output" / f"{NAME}.cue"


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            sha.update(chunk)
    return sha.hexdigest().upper()


def extract() -> int:
    if FILES.exists():
        shutil.rmtree(FILES)
    FILES.mkdir(parents=True)
    count = 0
    with zipfile.ZipFile(ORIGINAL_ZIP) as archive:
        for entry in archive.infolist():
            if entry.is_dir():
                continue
            target = FILES / entry.filename.replace("\\", "/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(entry.filename))
            count += 1
    return count


def write_xml(xml_path: Path) -> None:
    """The reference layout with every source repointed at the pristine tree."""
    text = REF_XML.read_text(encoding="utf-8")
    base = FILES.as_posix()
    text = re.sub(r'source="out/([^"]*)"', lambda m: f'source="{base}/{m.group(1)}"', text)
    text = re.sub(r'file="out/([^"]*)"', lambda m: f'file="{base}/{m.group(1)}"', text)
    text = text.replace('image_name="mkpsxiso.bin"', f'image_name="{BIN.as_posix()}"')
    text = text.replace('cue_sheet="mkpsxiso.cue"', f'cue_sheet="{CUE.as_posix()}"')
    if "out/" in text:
        raise SystemExit("a source path was left pointing at out/")
    xml_path.write_text(text, encoding="utf-8")


def main() -> None:
    if not MKPSXISO.exists():
        raise SystemExit(f"mkpsxiso not found: {MKPSXISO}")
    count = extract()
    xml_path = WORK / f"{NAME}.xml"
    lba_path = WORK / f"{NAME}_lba.txt"
    write_xml(xml_path)
    for stale in (BIN, CUE):
        if stale.exists():
            stale.unlink()

    subprocess.run(
        [str(MKPSXISO), "-y", "-lba", str(lba_path), str(xml_path)],
        cwd=ROOT,
        check=True,
    )

    print()
    print("진단용 대조 빌드 (배포 금지 -- 번역이 하나도 안 들어 있다)")
    print(f"  원본 파일  {count}개, 패치 0개")
    print(f"  배치       {REF_XML.name} (원판 그대로. dummy 284 없음, PSX.EXE 맨 앞)")
    print(f"  bin        {BIN}")
    print(f"  sha256     {digest(BIN)}")
    print(f"  cue        {CUE}")
    print(f"  lba        {lba_path}")
    print()
    print("  확인할 것은 자홍 슬라임 위 블록 하나뿐이다. 글자는 전부 일본어가 맞다.")


if __name__ == "__main__":
    main()
