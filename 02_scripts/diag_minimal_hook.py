"""Strip the v159 payload down to nothing, one hook at a time.

v157 through v160 do not boot, and reburning v159 through a pipeline that booted
five other builds today does not change that, so the fault is inside PSX.EXE.  The
static checks pass: hooks are encoded correctly, the displaced instructions are
reproduced, registers are saved and restored, branches stay inside the routines and
every constant address lands in the copied block.

So the payload is removed instead of inspected.

    N1  both hooks back to what v151 had.  Nothing of the new code runs.
    N2  the frame hook stays but its routine is two instructions: j 0x8011C814, nop.
        The hook's own jal already set ra to 0x8011C4B4, so the stock function
        returns straight to the caller and no prologue is needed.

    N1 fails   the fault is not in the payload -- look at the hooks, the copy, or
               the data the build changed outside the executable
    N1 boots, N2 fails   the hook site or the code cave entry is wrong
    both boot  the fault is in the routine bodies, and they can be halved

    python 02_scripts/diag_minimal_hook.py N1
    python 02_scripts/diag_minimal_hook.py N2
"""
from __future__ import annotations

import hashlib
import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = ROOT / "03_output/arc1_v159_dynamic_cache_4E3F2466.zip"
R2F = 0x8011A800

FRAME_HOOK = 0x8011C4AC          # v159: jal 0x801FF080, stock: jal 0x8011C814
DECODER_HOOK = 0x801A74B8        # v159: j 0x801FEF40 + nop, v151: addiu + sltiu
FRAME_BODY = 0x801A93A8          # tail source of the routine that runs at 0x801FF080

STOCK_FRAME_CALL = 0x0C047205    # jal 0x8011C814
V151_DECODER = (0x2468FF17, 0x2D090002)   # addiu t0,v1,-233 / sltiu t1,t0,2
TRAMPOLINE = (0x08047205, 0x00000000)     # j 0x8011C814 / nop


def main() -> None:
    which = (sys.argv[1] if len(sys.argv) > 1 else "").upper()
    if which not in ("N1", "N2"):
        raise SystemExit(__doc__)

    with zipfile.ZipFile(BASE) as z:
        info = z.getinfo("PSX.EXE")
        exe = bytearray(z.read("PSX.EXE"))

    def put(ram: int, word: int) -> str:
        at = ram - R2F
        was = struct.unpack_from("<I", exe, at)[0]
        struct.pack_into("<I", exe, at, word)
        return f"  0x{ram:08X}  {was:08X} -> {word:08X}"

    lines = [put(DECODER_HOOK, V151_DECODER[0]), put(DECODER_HOOK + 4, V151_DECODER[1])]
    if which == "N1":
        lines.append(put(FRAME_HOOK, STOCK_FRAME_CALL))
    else:
        lines.append(put(FRAME_BODY, TRAMPOLINE[0]))
        lines.append(put(FRAME_BODY + 4, TRAMPOLINE[1]))

    out = ROOT / "03_output" / f"DIAG_{which}_minimal_hook.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as w:
        ni = zipfile.ZipInfo("PSX.EXE", info.date_time)
        for attr in ("compress_type", "external_attr", "create_system"):
            setattr(ni, attr, getattr(info, attr))
        w.writestr(ni, bytes(exe))

    print(f"{which} 진단 빌드 (배포 금지)")
    print("\n".join(lines))
    print(f"  프레임 훅   {'원본 jal 0x8011C814' if which == 'N1' else 'jal 0x801FF080 유지, 본문은 2명령'}")
    print(f"  디코더 훅   v151 원래 두 명령으로 복구")
    print(f"  output      {out.name}")
    print(f"  sha256      {hashlib.sha256(out.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
