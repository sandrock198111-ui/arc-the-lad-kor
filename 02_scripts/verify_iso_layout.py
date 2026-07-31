"""Check a built image before running it: did every file keep its sector number?

The game reads its data by sector, so a layout change is silent until the game reads
something. Comparing the new image against the untouched original catches it in a few
seconds instead of costing a play session.

    python 02_scripts/verify_iso_layout.py E:\\arc\\arc1.bin
"""
from __future__ import annotations

import hashlib
import struct
import sys
import zipfile
from pathlib import Path

ORIGINAL = Path(r"E:\arc\원본\arc1.bin")
PATCH = Path(r"E:\korean\03_output/ui_hud_e7_v103_heap_reserved_glyphs_patch_only.zip")
RAW = 2352


def read_iso(path: Path) -> dict[str, tuple[int, int]]:
    raw = path.open("rb")

    def sector(lba: int) -> bytes:
        raw.seek(lba * RAW)
        b = raw.read(RAW)
        if len(b) < RAW:
            raise SystemExit(f"{path.name}: cannot read sector {lba}")
        return b[24:24 + 2048] if b[15] == 2 else b[16:16 + 2048]

    pvd = sector(16)
    if pvd[1:6] != b"CD001":
        raise SystemExit(f"{path.name}: no ISO9660 descriptor at sector 16")
    root_lba = struct.unpack_from("<I", pvd, 158)[0]
    root_len = struct.unpack_from("<I", pvd, 166)[0]

    def readdir(lba: int, length: int):
        data = b"".join(sector(lba + i) for i in range((length + 2047) // 2048))
        out, o = [], 0
        while o < len(data):
            n = data[o]
            if n == 0:
                o = (o // 2048 + 1) * 2048
                continue
            rec = data[o:o + n]
            nl = rec[32]
            out.append((rec[33:33 + nl].split(b";")[0].decode("ascii", "replace"),
                        struct.unpack_from("<I", rec, 2)[0],
                        struct.unpack_from("<I", rec, 10)[0], rec[25] & 2))
            o += n
        return out

    files, stack, seen = {}, [("", root_lba, root_len)], set()
    while stack:
        pre, l, n = stack.pop()
        if (l, n) in seen:
            continue
        seen.add((l, n))
        for name, lba, size, isdir in readdir(l, n):
            if name in ("\x00", "\x01"):
                continue
            if isdir:
                stack.append((pre + name + "/", lba, size))
            else:
                files[pre + name] = (lba, size)
    raw.close()
    return files


def extract(path: Path, lba: int, size: int) -> bytes:
    raw = path.open("rb")
    out = bytearray()
    for i in range((size + 2047) // 2048):
        raw.seek((lba + i) * RAW)
        b = raw.read(RAW)
        out += b[24:24 + 2048] if b[15] == 2 else b[16:16 + 2048]
    raw.close()
    return bytes(out[:size])


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    built = Path(sys.argv[1])
    if not built.exists():
        raise SystemExit(f"no such image: {built}")

    old = read_iso(ORIGINAL)
    new = read_iso(built)
    print(f"original {ORIGINAL}   {len(old)} files")
    print(f"built    {built}   {len(new)} files\n")

    ok = True

    missing = sorted(set(old) - set(new))
    added = sorted(set(new) - set(old))
    if missing:
        ok = False
        print(f"FAIL  {len(missing)} files missing from the built image: {missing[:5]}")
    if added:
        print(f"note  {len(added)} files not in the original: {added[:5]}")

    moved = [(n, old[n][0], new[n][0]) for n in sorted(set(old) & set(new))
             if old[n][0] != new[n][0] and n != "PSX.EXE"]
    if moved:
        ok = False
        print(f"FAIL  {len(moved)} data files changed sector number. The game reads "
              f"these by sector, so it will load the wrong data:")
        for n, a, b in moved[:10]:
            print(f"        {n:<24} {a} -> {b}")
    else:
        print(f"pass  all {len(set(old) & set(new)) - 1} data files kept their sector "
              f"number")

    for name in ("COMM.DAT", "COMM.IMG", "COMM.SND"):
        if name in new:
            same = new[name][0] == old[name][0]
            print(f"{'pass' if same else 'FAIL'}  {name:<10} LBA {new[name][0]}"
                  f"  (executable expects {old[name][0]})")
            ok &= same

    if "PSX.EXE" in new:
        lba, size = new["PSX.EXE"]
        print(f"\n  PSX.EXE at LBA {lba} (was {old['PSX.EXE'][0]}), {size} bytes")
        with zipfile.ZipFile(PATCH) as z:
            want = z.read("PSX.EXE")
        got = extract(built, lba, size)
        match = got == want
        print(f"{'pass' if match else 'FAIL'}  PSX.EXE content matches "
              f"{PATCH.name}")
        if not match:
            print(f"        built  sha256 {hashlib.sha256(got).hexdigest().upper()}")
            print(f"        wanted sha256 {hashlib.sha256(want).hexdigest().upper()}")
            print(f"        built {size} bytes, wanted {len(want)}")
        ok &= match
    else:
        ok = False
        print("FAIL  no PSX.EXE in the built image")

    print("\nRESULT:", "PASS - safe to run" if ok else "FAIL - do not run this image")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
