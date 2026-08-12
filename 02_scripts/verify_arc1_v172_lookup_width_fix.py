"""Run the complete v171 verifier against v172's one-word decoder repair."""
from __future__ import annotations

import struct

import build_arc1_v172_lookup_width_fix as fix
import verify_arc1_v171_ui_asset_recovery as verify


PATCH_SHA256 = "109252A0BB30A7A262AA7D713521F94C21BB7C25B582A85658E2F7F4D87CF695"


def main() -> None:
    original_build_decoder = verify.build.build_decoder

    def corrected_build_decoder(address: int, layout: dict[str, int]) -> bytes:
        blob = bytearray(original_build_decoder(address, layout))
        offset = fix.FIX_RUNTIME - address
        if struct.unpack_from("<I", blob, offset)[0] != fix.BEFORE:
            raise SystemExit("assembled v171 decoder delay word differs")
        struct.pack_into("<I", blob, offset, fix.AFTER)
        return bytes(blob)

    verify.build.build_decoder = corrected_build_decoder
    verify.build.REPORT = fix.REPORT
    verify.PATCH = fix.OUT_DIR / "arc1_v172_lookup_width_fix_109252A0.zip"
    verify.PATCH_SHA256 = PATCH_SHA256
    verify.OUT = fix.ANALYSIS / "verification"
    verify.REPORT = verify.OUT / "verification_report.txt"
    verify.main()


if __name__ == "__main__":
    main()
