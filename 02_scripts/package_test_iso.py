"""Burn any patch zip to one fixed disc image, so a test costs one click.

The slime block was chased for a day through builds that had to be staged into
E:/arc/out by hand and burned in the GUI.  Two of those diagnostics were never
actually run -- there was not enough time between the zip being written and the
next one -- and the results were reported as if they had been.  A test that takes
five manual steps does not get run five times.

So this takes a patch zip and produces 03_output/TEST.bin + TEST.cue, always the
same two names.  DuckStation names its per-game memory card after the disc file,
so a fixed name means one card, `TEST_1.mcd`, and the saves stay put no matter
which build is inside.  Testing another build is: run this, reload the same cue.

The layout is the shipping one (01_work/arc1_v104_layout.xml): 284 dummy sectors
where PSX.EXE used to be, the executable moved to the tail.  Measured against the
original layout, that moves exactly one file -- PSX.EXE -- and leaves the other 506
on their original sectors, XA and STR included.  Keeping it constant across tests
means the only thing that varies is the patch.

    python 02_scripts/package_test_iso.py 03_output/DIAG3_original_exe.zip
"""
from __future__ import annotations

import argparse
import hashlib
import json
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
REF_XML = ROOT / "01_work/arc1_v104_layout.xml"
MKPSXISO = ROOT / "06_tools/mkpsxiso/mkpsxiso-2.30-win64/mkpsxiso.exe"
WORK = ROOT / "01_work/package_test"
FILES = WORK / "files"
STATE = WORK / "applied.json"
BIN = ROOT / "03_output/TEST.bin"
CUE = ROOT / "03_output/TEST.cue"
MEMCARDS = Path.home() / "AppData/Local/DuckStation/memcards"


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            sha.update(chunk)
    return sha.hexdigest().upper()


def ensure_tree() -> None:
    """Extract the untouched disc once; later runs reuse it."""
    if FILES.exists() and (FILES / "PSX.EXE").exists():
        return
    if FILES.exists():
        shutil.rmtree(FILES)
    FILES.mkdir(parents=True)
    print("원본 트리를 처음 한 번 푼다 (606MB, 다음부터는 건너뛴다)...")
    with zipfile.ZipFile(ORIGINAL_ZIP) as archive:
        for entry in archive.infolist():
            if entry.is_dir():
                continue
            target = FILES / entry.filename.replace("\\", "/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(entry.filename))


def restore_and_apply(patch_zip: Path) -> tuple[int, int]:
    """Undo whatever the last patch wrote, then write this one.

    Without the undo, a build that reverts one member would silently keep the
    previous build's version of it, and the test would measure nothing.
    """
    previous = set(json.loads(STATE.read_text(encoding="utf-8"))) if STATE.exists() else set()
    with zipfile.ZipFile(patch_zip) as archive:
        current = {
            i.filename.replace("\\", "/")
            for i in archive.infolist()
            if not i.is_dir() and i.filename.upper() != "TEST_INFO.TXT"
        }
        with zipfile.ZipFile(ORIGINAL_ZIP) as pristine:
            names = set(pristine.namelist())
            restored = 0
            for name in sorted(previous | current):
                if name not in names:
                    raise SystemExit(f"{name} is not on the original disc")
                (FILES / name).write_bytes(pristine.read(name))
                restored += 1
        for name in sorted(current):
            (FILES / name).write_bytes(archive.read(name))
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(sorted(current), indent=1), encoding="utf-8")
    return restored, len(current)


def write_xml(xml_path: Path, binary: Path, cue: Path) -> None:
    text = REF_XML.read_text(encoding="utf-8")
    base = FILES.as_posix()
    text = re.sub(r'source="out/([^"]*)"', lambda m: f'source="{base}/{m.group(1)}"', text)
    text = re.sub(r'file="out/([^"]*)"', lambda m: f'file="{base}/{m.group(1)}"', text)
    text = text.replace('image_name="mkpsxiso.bin"', f'image_name="{binary.as_posix()}"')
    text = text.replace('cue_sheet="mkpsxiso.cue"', f'cue_sheet="{cue.as_posix()}"')
    if "out/" in text:
        raise SystemExit("a source path was left pointing at out/")
    xml_path.write_text(text, encoding="utf-8")


def free_name() -> tuple[Path, Path, str]:
    """TEST.bin, unless DuckStation still has it open -- then TEST2, TEST3, ...

    Overwriting is blocked while the emulator holds the image, and waiting for the
    user to close it costs a round trip.  The memory card follows the disc name, so
    each new name gets a copy of the card and the saves stay put.
    """
    stem = "TEST"
    for suffix in ("", *(str(n) for n in range(2, 60))):
        binary, cue = BIN.with_name(f"TEST{suffix}.bin"), CUE.with_name(f"TEST{suffix}.cue")
        if not binary.exists():
            return binary, cue, f"TEST{suffix}"
        try:
            binary.unlink()
            if cue.exists():
                cue.unlink()
            return binary, cue, f"TEST{suffix}"
        except PermissionError:
            stem = f"TEST{suffix}"
            continue
    raise SystemExit(f"no free name after {stem}")


def carry_memory_card(stem: str) -> str | None:
    """The per-game card is named after the disc, so a new name starts empty."""
    target = MEMCARDS / f"{stem}_1.mcd"
    if target.exists() or not MEMCARDS.is_dir():
        return None
    sources = sorted(MEMCARDS.glob("*_1.mcd"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not sources:
        return None
    shutil.copyfile(sources[0], target)
    return f"{sources[0].name} -> {target.name}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("patch_zip", type=Path)
    args = parser.parse_args()
    patch_zip = args.patch_zip.resolve()
    if not patch_zip.exists():
        raise SystemExit(f"patch zip not found: {patch_zip}")
    if not MKPSXISO.exists():
        raise SystemExit(f"mkpsxiso not found: {MKPSXISO}")

    ensure_tree()
    restored, applied = restore_and_apply(patch_zip)
    binary, cue, stem = free_name()
    xml_path = WORK / f"{stem}.xml"
    lba_path = WORK / f"{stem}_lba.txt"
    write_xml(xml_path, binary, cue)
    card = carry_memory_card(stem)

    subprocess.run(
        [str(MKPSXISO), "-y", "-q", "-lba", str(lba_path), str(xml_path)],
        cwd=ROOT,
        check=True,
    )

    print()
    print("시험용 디스크를 새로 구웠다")
    print(f"  들어간 것  {patch_zip.name}")
    print(f"             원본으로 되돌린 파일 {restored}개, 패치 파일 {applied}개")
    print(f"  cue        {cue}")
    print(f"  sha256     {digest(binary)}")
    if card:
        print(f"  메모리카드 {card}")
    print()
    print(f"  DuckStation에서 03_output/{cue.name} 를 열면 된다. 세이브는 그대로 있다.")


if __name__ == "__main__":
    main()
