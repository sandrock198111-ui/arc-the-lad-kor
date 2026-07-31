"""v93: repair the S3032 Yagun-office dialogue separators.

Runtime screenshots showed a garbled glyph at every `E6 01` inside the four
S3032 E2 dialogue blocks. The working reference is `21/S2021.DAT` at 0x45E00:

    E0 9C E0 9D  DF 80  9C  E0 68 ...
    아     크      :   (sp)  우 ...

That proven payload contains no `E6 01` at all. It writes the colon directly as
`DF 80` and relies on the game's automatic word wrap for line breaks. The earlier
note that `E6 01` is a required line break in these payloads is wrong; the code was
copied from the original Japanese script region into the Korean payloads, where it
resolves to no valid glyph.

v93 replaces only the `E6 01` occurrences:
  - the one following a speaker name becomes `DF 80 9C`  (colon + space)
  - every other one becomes `9C`                          (space)

Block 4 is a speakerless dialogue window, so both of its separators become spaces.

No character is re-encoded. Every other byte in the block, including its trailing
capacity byte, is preserved exactly.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
V92 = ROOT / "03_output/ui_hud_e7_v92_stateless_p6_pass_classifier_patch_only.zip"
OUTPUT = ROOT / "03_output/ui_hud_e7_v93_s3032_speaker_separator_patch_only.zip"
REPORT = ROOT / "01_work/analysis/ui_hud_e7_v93_s3032_speaker_separator/build_report.txt"

V92_SHA256 = "19768F72D6EC84016787909BA982C2D5E3014AD14770B0771BEB7446D9F0040D"

S3032 = "31/S3032.DAT"
S2021 = "21/S2021.DAT"

BLOCK_BASE = 0x45000
BLOCK_SIZE = 0x80

SEP = b"\xE6\x01"
SPACE = b"\x9C"
COLON = b"\xDF\x80"

# Proven reference: the working "아크: 우리가 ..." payload.
REF_OFFSET = 0x45E00
REF_PREFIX = bytes.fromhex("E09CE09DDF809CE068")  # 아 크 : <sp> 우

# (block index, has speaker name)
BLOCKS = [(0, True), (1, True), (2, True), (3, False)]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone_info(source: ZipInfo) -> ZipInfo:
    target = ZipInfo(source.filename, source.date_time)
    for attr in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(target, attr, getattr(source, attr))
    return target


def repair(block: bytes, has_speaker: bool) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise SystemExit("bad block size")
    tail = block[-1]
    body = block[:-1].rstrip(b"\x00")
    if body.count(SEP) != 2:
        raise SystemExit(f"expected exactly two {SEP.hex()} separators, found {body.count(SEP)}")

    first, rest = body.split(SEP, 1)
    second, third = rest.split(SEP, 1)
    new_body = first + (COLON + SPACE if has_speaker else SPACE) + second + SPACE + third

    if len(new_body) > BLOCK_SIZE - 1:
        raise SystemExit(f"payload overflow: {len(new_body)} bytes")
    out = bytearray(BLOCK_SIZE)
    out[: len(new_body)] = new_body
    out[-1] = tail
    return bytes(out)


def main() -> None:
    if sha256(V92.read_bytes()) != V92_SHA256:
        raise SystemExit("v92 archive hash differs")

    with ZipFile(V92, "r") as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}

    # Confirm the reference convention is present and unmodified in this build.
    ref = members[S2021][REF_OFFSET : REF_OFFSET + len(REF_PREFIX)]
    if ref != REF_PREFIX:
        raise SystemExit(f"S2021 reference payload changed: {ref.hex(' ').upper()}")
    ref_block = members[S2021][REF_OFFSET : REF_OFFSET + BLOCK_SIZE]
    if SEP in ref_block.split(b"\x00", 1)[0]:
        raise SystemExit("reference payload unexpectedly contains E6 01")

    original = members[S3032]
    patched = bytearray(original)
    changes = []
    for index, has_speaker in BLOCKS:
        off = BLOCK_BASE + index * BLOCK_SIZE
        old = bytes(original[off : off + BLOCK_SIZE])
        new = repair(old, has_speaker)
        patched[off : off + BLOCK_SIZE] = new
        changes.append((index, off, old, new, has_speaker))

    patched = bytes(patched)

    # scope: nothing outside the four blocks may move
    lo, hi = BLOCK_BASE, BLOCK_BASE + len(BLOCKS) * BLOCK_SIZE
    if patched[:lo] != original[:lo] or patched[hi:] != original[hi:]:
        raise SystemExit("S3032 changed outside the four dialogue blocks")
    if len(patched) != len(original):
        raise SystemExit("S3032 size changed")

    # no separator may survive, and no other member may change
    for index, off, _, new, _ in changes:
        if SEP in new[:-1].rstrip(b"\x00"):
            raise SystemExit(f"block {index} still contains E6 01")
        if new[-1] != original[off + BLOCK_SIZE - 1]:
            raise SystemExit(f"block {index} trailing byte changed")

    members[S3032] = patched

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as target:
        for info in infos:
            target.writestr(clone_info(info), members[info.filename])

    with ZipFile(OUTPUT, "r") as archive:
        if [i.filename for i in archive.infolist()] != [i.filename for i in infos]:
            raise SystemExit("output member order differs")
        with ZipFile(V92, "r") as src:
            for info in infos:
                out = archive.read(info.filename)
                if out != members[info.filename]:
                    raise SystemExit(f"output member differs: {info.filename}")
                if info.filename != S3032 and out != src.read(info.filename):
                    raise SystemExit(f"unexpected change in {info.filename}")

    diff = [i for i, (a, b) in enumerate(zip(original, patched)) if a != b]

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "Arc the Lad Korean patch v93 build report",
        "",
        f"base_v92={V92.name}",
        f"base_v92_sha256={V92_SHA256}",
        f"output={OUTPUT.name}",
        f"output_sha256={sha256(OUTPUT.read_bytes())}",
        f"s3032_sha256={sha256(patched)}",
        "",
        f"changed_members: {S3032} only",
        f"changed_bytes: {len(diff)}",
        "",
        f"reference convention: {S2021} @0x{REF_OFFSET:X} = {REF_PREFIX.hex(' ').upper()}  (아크 : 우...)",
        "",
        "blocks:",
    ]
    for index, off, old, new, has_speaker in changes:
        kind = "named speaker -> colon" if has_speaker else "speakerless -> space only"
        lines.append(f"- block {index + 1} @0x{off:X} ({kind})")
        lines.append(f"    before: {old[:-1].rstrip(bytes(1)).hex(' ').upper()}")
        lines.append(f"    after : {new[:-1].rstrip(bytes(1)).hex(' ').upper()}")
    lines += ["", "static_verification=PASS", "runtime_verification=PENDING"]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(OUTPUT)
    print(f"SHA256={sha256(OUTPUT.read_bytes())}")
    print(f"changed_bytes={len(diff)}")
    print(REPORT)


if __name__ == "__main__":
    main()
