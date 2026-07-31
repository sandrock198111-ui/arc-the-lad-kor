from __future__ import annotations

import csv
import hashlib
from pathlib import Path
from zipfile import ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
V89 = ROOT / "03_output/ui_hud_e7_v89_story_safe_book_glyph_patch_only.zip"
V90 = ROOT / "03_output/ui_hud_e7_v90_e2_control_p6_lifetime_fix_patch_only.zip"
OUTPUT = (
    ROOT
    / "03_output/ui_hud_e7_v91_v89_lifetime_yagun_slot_fix_patch_only.zip"
)
REPORT = (
    ROOT
    / "01_work/analysis/ui_hud_e7_v91_v89_lifetime_yagun_slot_fix/build_report.txt"
)

V89_SHA256 = "4A379BF0AA02D60E89C30E1BD26E9E884DF60AD0F9EF6FBB33537A9B396C9678"
V90_SHA256 = "496A5F8FB72F342B656D6CDA13819C196D64D27C23BCE35EB511BCECB67C0739"

PSX_MEMBER = "PSX.EXE"
S3032_MEMBER = "31/S3032.DAT"
SLOT_BASE = 0x45000
SLOT_SIZE = 0x80
TARGET_SLOT = 2
TARGET_OFFSET = SLOT_BASE + TARGET_SLOT * SLOT_SIZE
TARGET_MARKER = 0x20
NEWLINE = b"\xE6\x01"
SPACE = b"\x9C"

# "We cannot be held responsible" without reusing the collided old code for "책".
TARGET_TEXT = (
    "\uc57c\uad70\n"
    "\ub9cc\uc77c \ubb34\uc2a8 \uc77c\uc774 \uc0dd\uaca8\ub3c4\n"
    "\uadf8\ub54c\ub294 \uc800\ud76c\ub3c4 \uad00\uc5ec\ud560 \uc218 "
    "\uc5c6\uc2b5\ub2c8\ub2e4."
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone_info(source: ZipInfo) -> ZipInfo:
    target = ZipInfo(source.filename, source.date_time)
    target.compress_type = source.compress_type
    target.comment = source.comment
    target.extra = source.extra
    target.create_system = source.create_system
    target.create_version = source.create_version
    target.extract_version = source.extract_version
    target.flag_bits = source.flag_bits
    target.volume = source.volume
    target.internal_attr = source.internal_attr
    target.external_attr = source.external_attr
    return target


def load_mapping() -> dict[str, bytes]:
    mapping: dict[str, bytes] = {}
    for path in (
        ROOT / "05_docs/korean_charmap.csv",
        ROOT / "05_docs/korean_charmap_extended.csv",
    ):
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                char = row["char"]
                code_hex = row["code_hex"].strip()
                if char and code_hex:
                    mapping[char] = bytes.fromhex(code_hex)
    return mapping


def encode_text(text: str, mapping: dict[str, bytes]) -> bytes:
    result = bytearray()
    for char in text:
        if char == "\n":
            result.extend(NEWLINE)
        elif char == " ":
            result.extend(SPACE)
        else:
            if char not in mapping:
                raise SystemExit(f"missing Korean mapping for {char!r}")
            result.extend(mapping[char])
    if len(result) > SLOT_SIZE - 1:
        raise SystemExit(f"slot payload overflow: {len(result)} bytes")
    return bytes(result)


def main() -> None:
    if sha256(V89.read_bytes()) != V89_SHA256:
        raise SystemExit("v89 archive hash differs")
    if sha256(V90.read_bytes()) != V90_SHA256:
        raise SystemExit("v90 archive hash differs")

    with ZipFile(V89, "r") as archive:
        v89_members = {
            info.filename: archive.read(info.filename) for info in archive.infolist()
        }
    with ZipFile(V90, "r") as archive:
        infos = archive.infolist()
        v90_members = {
            info.filename: archive.read(info.filename) for info in infos
        }

    if list(v89_members) != list(v90_members):
        raise SystemExit("v89/v90 member order differs")

    mapping = load_mapping()
    payload = encode_text(TARGET_TEXT, mapping)
    original_s3032 = v89_members[S3032_MEMBER]
    patched_s3032 = bytearray(original_s3032)
    patched_s3032[TARGET_OFFSET : TARGET_OFFSET + SLOT_SIZE] = b"\x00" * SLOT_SIZE
    patched_s3032[TARGET_OFFSET : TARGET_OFFSET + len(payload)] = payload
    patched_s3032[TARGET_OFFSET + SLOT_SIZE - 1] = TARGET_MARKER

    members = dict(v90_members)
    members[PSX_MEMBER] = v89_members[PSX_MEMBER]
    members[S3032_MEMBER] = bytes(patched_s3032)

    if members[PSX_MEMBER] != v89_members[PSX_MEMBER]:
        raise SystemExit("PSX.EXE did not restore to v89")
    if (
        members[S3032_MEMBER][:TARGET_OFFSET]
        != original_s3032[:TARGET_OFFSET]
        or members[S3032_MEMBER][TARGET_OFFSET + SLOT_SIZE :]
        != original_s3032[TARGET_OFFSET + SLOT_SIZE :]
    ):
        raise SystemExit("S3032 changed outside the target E2 slot")
    if members[S3032_MEMBER][TARGET_OFFSET : TARGET_OFFSET + len(payload)] != payload:
        raise SystemExit("target E2 payload differs")
    if any(
        members[S3032_MEMBER][
            TARGET_OFFSET + len(payload) : TARGET_OFFSET + SLOT_SIZE - 1
        ]
    ):
        raise SystemExit("target E2 padding is not zero")
    if members[S3032_MEMBER][TARGET_OFFSET + SLOT_SIZE - 1] != TARGET_MARKER:
        raise SystemExit("target E2 capacity marker differs")
    for offset, expected in (
        (0x47994, b"\xE2\x81"),
        (0x479EE, b"\xE2\x82"),
        (0x47A40, b"\xE2\x83"),
    ):
        if members[S3032_MEMBER][offset : offset + 2] != expected:
            raise SystemExit(f"S3032 E2 call differs at 0x{offset:X}")

    changed = [
        name for name in members if members[name] != v90_members[name]
    ]
    if changed != [PSX_MEMBER, S3032_MEMBER]:
        raise SystemExit(f"unexpected members changed: {changed}")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w") as target:
        for info in infos:
            target.writestr(clone_info(info), members[info.filename])

    with ZipFile(OUTPUT, "r") as archive:
        built_infos = archive.infolist()
        if [info.filename for info in built_infos] != [info.filename for info in infos]:
            raise SystemExit("output member order differs")
        for name, expected in members.items():
            if archive.read(name) != expected:
                raise SystemExit(f"output member differs: {name}")

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    report = [
        "Arc the Lad Korean patch v91 build report",
        "",
        f"base_v90={V90.name}",
        f"base_v90_sha256={V90_SHA256}",
        f"stable_v89={V89.name}",
        f"stable_v89_sha256={V89_SHA256}",
        f"output={OUTPUT.name}",
        f"output_sha256={sha256(OUTPUT.read_bytes())}",
        "",
        "changed_members:",
        f"- {PSX_MEMBER}: restored byte-for-byte from v89",
        (
            f"- {S3032_MEMBER}: only 0x{TARGET_OFFSET:X}-"
            f"0x{TARGET_OFFSET + SLOT_SIZE - 1:X} rewritten"
        ),
        "",
        f"target_text={TARGET_TEXT.replace(chr(10), ' / ')}",
        f"payload_length={len(payload)}",
        f"payload_hex={payload.hex(' ').upper()}",
        f"psx_sha256={sha256(members[PSX_MEMBER])}",
        f"s3032_sha256={sha256(members[S3032_MEMBER])}",
        "",
        "static_verification=PASS",
        "runtime_verification=PENDING",
    ]
    REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")

    print(OUTPUT)
    print(f"SHA256={sha256(OUTPUT.read_bytes())}")
    print(f"payload_length={len(payload)}")
    print(REPORT)


if __name__ == "__main__":
    main()
