"""Independent structural and exact-pixel verification for v162."""
from __future__ import annotations

import csv
import hashlib
import struct
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v162_strip_a_dynamic_cache as build  # noqa: E402
from extract_savestate_vram import locate_vram  # noqa: E402


REPORT = build.ANALYSIS / "independent_verification.txt"
ASSIGNMENTS = build.PLAN / "glyph_assignments.csv"
ROW_DICTIONARY = build.PLAN / "row_dictionary.bin"
GLYPH_ROWS = build.PLAN / "dynamic_glyph_rows.bin"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def archive(path: Path) -> tuple[list[str], dict[str, bytes]]:
    with zipfile.ZipFile(path) as handle:
        names = [info.filename for info in handle.infolist()]
        return names, {name: handle.read(name) for name in names}


def plane(cell: bytes | bytearray, selected: int) -> tuple[int, ...]:
    return tuple(
        (((cell[y * 6 + x // 2] >> (4 * (x & 1))) & 0xF) >> selected) & 1
        for y in range(build.CELL) for x in range(build.CELL)
    )


def write_plane_like_fixed_loop(cell: bytearray, selected: int,
                                bits: tuple[int, ...]) -> None:
    """Semantic model of the exact v162 pair-order loop, not the old ideal helper."""
    bit = 1 << selected
    clear_both = ~(bit | (bit << 4)) & 0xFF
    for y in range(build.CELL):
        row_at = y * 6
        for x in range(build.CELL):
            at = row_at + x // 2
            value = cell[at]
            if x % 2 == 0:
                value &= clear_both
            if bits[y * build.CELL + x]:
                value |= bit << (4 if x & 1 else 0)
            cell[at] = value


def main() -> None:
    outputs = sorted(build.OUT_DIR.glob(f"{build.OUT_STEM}_????????.zip"))
    if len(outputs) != 1:
        raise SystemExit(f"expected exactly one v162 archive, found {len(outputs)}")
    output = outputs[0]
    base_names, base = archive(build.BASE_ZIP)
    names, current = archive(output)
    if names != base_names:
        raise SystemExit("archive member order or names changed")
    if any(current[name] != base[name] for name in names if name != build.PSX):
        raise SystemExit("a non-PSX member differs from v161")
    exe, base_exe = current[build.PSX], base[build.PSX]
    if len(exe) != len(base_exe):
        raise SystemExit("PSX.EXE size changed")

    table = struct.unpack_from(f"<{build.CACHE_N}H", exe,
                               build.source_at(build.CACHE_INDEX_RAM))
    if table != build.CACHE_INDICES:
        raise SystemExit("cache index table differs")
    if any(exe[build.source_at(build.SHADOW):
               build.source_at(build.SHADOW) + build.SHADOW_N]):
        raise SystemExit("dedicated cache shadow is not zero")
    if tuple(build.resident_word(exe, build.PIXEL_LOOP + i * 4) for i in range(13)) != \
            build.fixed_pixel_loop():
        raise SystemExit("pixel loop differs")
    if build.word(exe, build.GLYPH_PACKET_HOOK) != build.j(build.HELPER) or \
            build.word(exe, build.RENDER_HOOK) != build.j(build.STATELESS_DRIVER) or \
            build.word(exe, build.RENDER_HOOK + 4) != build.NOP or \
            build.word(exe, build.CLASSIFIER_CALL) != build.jal(build.CLASSIFIER):
        raise SystemExit("renderer hooks differ")

    # Exact glyph source rows.
    dictionary_blob = ROW_DICTIONARY.read_bytes()
    glyph_blob = GLYPH_ROWS.read_bytes()
    dictionary = struct.unpack(f"<{len(dictionary_blob) // 2}H", dictionary_blob)
    source_count = len(glyph_blob) // build.CELL

    def source_shape(source: int) -> tuple[int, ...]:
        rows = glyph_blob[source * build.CELL:(source + 1) * build.CELL]
        return tuple(
            1 if dictionary[rows[y]] & (1 << (build.CELL - 1 - x)) else 0
            for y in range(build.CELL) for x in range(build.CELL)
        )

    # Use a deliberately nonzero four-plane background.  The selected plane must
    # become exact and all three neighbors must remain byte-for-byte unchanged.
    checks = 0
    for slot in range(build.CACHE_N):
        selected = slot % build.PLANES
        for source in range(source_count):
            initial = bytearray((0xA5 ^ ((i * 37 + slot * 11) & 0xFF)) for i in range(72))
            before_other = {p: plane(initial, p) for p in range(build.PLANES) if p != selected}
            write_plane_like_fixed_loop(initial, selected, source_shape(source))
            if plane(initial, selected) != source_shape(source):
                raise SystemExit(f"selected plane mismatch: slot {slot}, source {source}")
            if any(plane(initial, p) != bits for p, bits in before_other.items()):
                raise SystemExit(f"neighbor plane changed: slot {slot}, source {source}")
            checks += 1

    # The old defect is reproduced as a control: at least one source loses an even
    # pixel when both nibbles are cleared on every x visit.
    control_failures = 0
    for source in range(source_count):
        bits = source_shape(source)
        cell = bytearray(72)
        bit = 1
        clear_both = ~(bit | (bit << 4)) & 0xFF
        for y in range(build.CELL):
            for x in range(build.CELL):
                at = y * 6 + x // 2
                cell[at] &= clear_both
                if bits[y * build.CELL + x]:
                    cell[at] |= bit << (4 if x & 1 else 0)
        control_failures += plane(cell, 0) != bits
    if not control_failures:
        raise SystemExit("old writer control did not reproduce the diagnosed defect")

    # Text/lookup data and every non-approved EXE byte stay at v161 semantics.
    lookup_at = build.file_at(0x801A7520)
    if exe[lookup_at:lookup_at + 409 * 2] != base_exe[lookup_at:lookup_at + 409 * 2]:
        raise SystemExit("lookup table changed")
    with ASSIGNMENTS.open(encoding="utf-8-sig", newline="") as handle:
        dynamic_sources = {int(row["source_id"]) for row in csv.DictReader(handle)
                           if row["source_id"]}
    if dynamic_sources != set(range(source_count)):
        raise SystemExit("dynamic source ids are not contiguous")

    changed = {i for i, (left, right) in enumerate(zip(base_exe, exe)) if left != right}
    allowed = set()
    for address, size, resident in (
        (build.CACHE_INDEX_RAM, build.CACHE_N * 2, True),
        (build.SHADOW, build.SHADOW_N, True),
        (build.FRAME_X_ADD, 4, True),
        (build.PIXEL_LOOP, 13 * 4, True),
        (build.HELPER, build.HELPER_N, True),
        (build.CLASSIFIER, build.CLASSIFIER_N, True),
        (build.GLYPH_PACKET_HOOK, 4, False),
        (build.RENDER_HOOK, 8, False),
        (build.CLASSIFIER_CALL, 4, False),
    ):
        start = build.source_at(address) if resident else build.file_at(address)
        allowed.update(range(start, start + size))
    if not changed <= allowed:
        raise SystemExit("changed byte outside the approved v162 regions")

    # Six v161 control states show the chosen high-page rectangle was empty while
    # the old low-page cell held the live cache.  This is evidence, not whole-game proof.
    state_dir = ROOT / "01_work/analysis/v161_runtime_states"
    state_rows = []
    for state in sorted(state_dir.glob("slot*.state.bin")):
        blob = state.read_bytes()
        vram_base = locate_vram(blob)
        values = [
            blob[vram_base + ((build.CACHE_Y + y) * 1024 + build.CACHE_X + x) * 2:
                 vram_base + ((build.CACHE_Y + y) * 1024 + build.CACHE_X + x) * 2 + 2]
            for y in range(build.CELL)
            for x in range((build.CACHE_N // build.PLANES) * 3)
        ]
        nonzero = sum(value != b"\0\0" for value in values)
        state_rows.append((state.stem, nonzero, len(values)))
    if len(state_rows) != 6 or any(nonzero for _, nonzero, _ in state_rows):
        raise SystemExit("v161 control states do not show the strip-A prefix empty")

    stamp = digest(output.read_bytes())
    lines = [
        "v162 independent static verification: PASS",
        f"archive={output.name}",
        f"archive_sha256={stamp}",
        f"archive_members={len(current)}",
        f"changed_EXE_bytes={len(changed)}",
        "changed_non_EXE_members=0",
        f"dynamic_sources={source_count}",
        f"cache_slots={build.CACHE_N}",
        f"exact_source_slot_pairs={checks}",
        f"old_writer_control_failures={control_failures}/{source_count}",
        "lookup_table=byte_identical_to_v161",
        "bounded_text_and_all_DAT=byte_identical_to_v161",
        "v151_stateless_renderer=byte_identical",
        "strip_A_prefix_geometry=x961..975,y480..491,tpage_0x1F,U4..63,V224",
        "v161_control_states_strip_A_nonzero=0/1080_halfwords",
        "runtime_verification=PENDING user cold boot",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
