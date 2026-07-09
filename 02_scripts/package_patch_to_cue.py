from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape


ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_ZIP = ROOT / "00_original" / "arc.zip"
MKPSXISO = ROOT / "06_tools" / "mkpsxiso" / "mkpsxiso-2.30-win64" / "mkpsxiso.exe"
DEFAULT_LICENSE = ROOT / "01_work" / "license_data.dat"
OUTPUT_DIR = ROOT / "03_output"
WORK_ROOT = ROOT / "01_work"
SYSTEM_CNF = "BOOT = cdrom:\\PSX.EXE;1\r\nTCB = 4\r\nEVENT = 16\r\nSTACK = 801FFFF0\r\n"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)


def extract_zip(path: Path, dest: Path) -> list[str]:
    names: list[str] = []
    with zipfile.ZipFile(path) as archive:
        for entry in archive.infolist():
            if entry.is_dir():
                continue
            target = dest / entry.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(entry.filename))
            names.append(entry.filename.replace("\\", "/"))
    return names


def apply_patch_zip(path: Path, dest: Path) -> list[str]:
    changed: list[str] = []
    with zipfile.ZipFile(path) as archive:
        for entry in archive.infolist():
            if entry.is_dir() or entry.filename.upper() == "TEST_INFO.TXT":
                continue
            target = dest / entry.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(entry.filename))
            changed.append(entry.filename.replace("\\", "/"))
    return changed


def iso_name(path: str) -> str:
    return Path(path).name.upper()


def file_type(path: str, source: Path) -> str:
    suffix = source.suffix.upper()
    if suffix == ".XA":
        return "xa"
    if suffix == ".STR" and source.stat().st_size % 2336 == 0:
        return "str"
    return "data"


def add_file_xml(lines: list[str], indent: int, name: str, source: Path) -> None:
    typ = file_type(name, source)
    lines.append(
        f'{" " * indent}<file name="{escape(iso_name(name))}" type="{typ}" '
        f'source="{escape(source.as_posix())}"/>'
    )


def write_dir_xml(lines: list[str], base: Path, rel_dir: Path, files_by_dir: dict[str, list[str]]) -> None:
    key = rel_dir.as_posix() if rel_dir.as_posix() != "." else ""
    indent = 3 + len(rel_dir.parts) if key else 3
    for name in files_by_dir.get(key, []):
        if name.lower() == "license_data.dat":
            continue
        add_file_xml(lines, indent, name, base / name)

    child_dirs = sorted(
        [p for p in files_by_dir if p and Path(p).parent.as_posix() == (key or ".")],
        key=lambda p: Path(p).name.upper(),
    )
    for child in child_dirs:
        child_path = Path(child)
        child_indent = indent
        lines.append(f'{" " * child_indent}<dir name="{escape(child_path.name.upper())}">')
        write_dir_xml(lines, base, child_path, files_by_dir)
        lines.append(f'{" " * child_indent}</dir>')


def write_project_xml(files_dir: Path, xml_path: Path, bin_path: Path, cue_path: Path, file_order: list[str]) -> None:
    files_by_dir: dict[str, list[str]] = {}
    for name in file_order:
        if name.lower() == "license_data.dat":
            continue
        parent = Path(name).parent.as_posix()
        files_by_dir.setdefault("" if parent == "." else parent, []).append(name)

    if "SYSTEM.CNF" not in {Path(name).name.upper() for name in files_by_dir.get("", [])}:
        files_by_dir.setdefault("", []).insert(0, "SYSTEM.CNF")
    if "PSX.EXE" in {Path(name).name.upper() for name in files_by_dir.get("", [])}:
        root_files = files_by_dir[""]
        root_files.sort(key=lambda name: 0 if Path(name).name.upper() == "SYSTEM.CNF" else 1 if Path(name).name.upper() == "PSX.EXE" else 2)

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<iso_project image_name="{escape(bin_path.as_posix())}" cue_sheet="{escape(cue_path.as_posix())}">',
        ' <track type="data" cdvd_style="false">',
        '  <identifiers system="PLAYSTATION" application="PLAYSTATION" volume="ARC_THE_LAD" volume_set="ARC_THE_LAD" publisher="SCEI" data_preparer="MKPSXISO"/>',
        f'  <license file="{escape(DEFAULT_LICENSE.as_posix())}"/>',
        '  <directory_tree>',
    ]
    write_dir_xml(lines, files_dir, Path("."), files_by_dir)
    lines.extend(["  </directory_tree>", " </track>", "</iso_project>"])
    xml_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("patch_zip", type=Path)
    parser.add_argument("--name", default=None)
    args = parser.parse_args()

    patch_zip = args.patch_zip.resolve()
    if not patch_zip.exists():
        raise SystemExit(f"Patch zip not found: {patch_zip}")
    if not MKPSXISO.exists():
        raise SystemExit(f"mkpsxiso not found: {MKPSXISO}")
    if not DEFAULT_LICENSE.exists():
        raise SystemExit(f"license data not found: {DEFAULT_LICENSE}")

    name = args.name or patch_zip.stem.replace("_patch_only", "")
    work = WORK_ROOT / f"package_{name}"
    files_dir = work / "files"
    clean_dir(files_dir)
    (OUTPUT_DIR).mkdir(exist_ok=True)

    order = extract_zip(ORIGINAL_ZIP, files_dir)
    changed = apply_patch_zip(patch_zip, files_dir)
    (files_dir / "SYSTEM.CNF").write_text(SYSTEM_CNF, encoding="ascii", newline="")
    if "SYSTEM.CNF" not in order:
        order.insert(0, "SYSTEM.CNF")

    xml_path = work / f"{name}.xml"
    bin_path = OUTPUT_DIR / f"{name}.bin"
    cue_path = OUTPUT_DIR / f"{name}.cue"
    lba_path = work / f"{name}_lba.txt"
    write_project_xml(files_dir, xml_path, bin_path, cue_path, order)

    for output in (bin_path, cue_path):
        if output.exists():
            output.unlink()

    subprocess.run(
        [str(MKPSXISO), "-y", "-lba", str(lba_path), str(xml_path)],
        cwd=ROOT,
        check=True,
    )

    report = work / "PACKAGE_REPORT.txt"
    report.write_text(
        "\n".join(
            [
                f"patch_zip={patch_zip}",
                f"patch_sha256={digest(patch_zip)}",
                f"changed_files={len(changed)}",
                *[f"changed={item}" for item in changed],
                f"bin={bin_path}",
                f"bin_sha256={digest(bin_path)}",
                f"cue={cue_path}",
                f"cue_sha256={digest(cue_path)}",
                f"xml={xml_path}",
                f"lba={lba_path}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    print(report.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
