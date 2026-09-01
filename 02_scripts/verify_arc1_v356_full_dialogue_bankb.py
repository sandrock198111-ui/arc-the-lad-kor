#!/usr/bin/env python3
"""Independent static verifier for the V356 full-dialogue Bank-B build.

This verifier deliberately does not import the V356 builder or trust its
placement audit.  It reconstructs structural spans from the hash-pinned source
ledger, expands final E2 calls directly from each DAT, decodes the resulting
glyph stream, and compares the visible prose with the canonical target.
"""
from __future__ import annotations

import csv
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

from v354_dialogue_codec import LINEBREAK, SLOT_BASE, SLOT_COUNT, SLOT_SIZE, load_v354  # noqa: E402


BASE = ROOT / "03_output/arc1_v354_dialogue_identity_wording_repair_TEST_ONLY_2AA6C42A.zip"
BASE_SHA256 = "2AA6C42AC1F62B5D1C7121F27B77807610C9E05D423C548429CB38653DF9C194"
FULL = ROOT / "03_output/arc1_v356_full_dialogue_bankb_REVIEW_ONLY_TEST_ONLY_17DC9646.zip"
FULL_SHA256 = "17DC9646D172E38DF6EB49055C92B994293DE70AF7129CF155AD7067BF6DDF85"
DELTA = ROOT / "03_output/arc1_v356_full_dialogue_bankb_REVIEW_ONLY_TEST_ONLY_delta_from_v354_EC79FA53.zip"
DELTA_SHA256 = "EC79FA53DEED117EC86B76C43FE518E4443FDA3DFE62C1AE9C92D1D12B507380"
PRISTINE = ROOT / "00_original/arc.zip"
PRISTINE_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"
V355 = ROOT / "03_output/arc1_v355_bankb_runtime_probe_TEST_ONLY_F8F2E262.zip"
V355_SHA256 = "F8F2E26253BA05D72CD1C667A0F2047ABF189873FE65DC2433D42364CD93E032"

TARGETS = ROOT / "05_docs/v356_full_dialogue_targets.csv"
TARGETS_SHA256 = "8CEA13B26C2A304178E93A5775F07E2FF31AA127AF5F4ED83940B5F5E6031636"
ORIGINAL = ROOT / "05_docs/script_original_full.csv"
ORIGINAL_SHA256 = "D20D44522A9ECDC9894BAB46D49BC0B9BB7E4573D19BA8627AFCEDA3C2BA1188"
NON_TEXT = ROOT / "05_docs/v356_nontext_exclusions.csv"
NON_TEXT_SHA256 = "FA3F58EA14724D688181E1904063AB258FE209B597954EDE626CDD8234D553C2"
REVIEW = ROOT / "05_docs/v356_bankb_review.csv"
REVIEW_SHA256 = "54E1D5B5F262DF4802AADD3B44B510FF02E3CED2DAD1A00D51F1E4E0BC13F53D"
EXPECTED = ROOT / "01_work/analysis/arc1_v356_full_dialogue_bankb/expected_writes.csv"
MANIFEST = ROOT / "01_work/analysis/arc1_v356_full_dialogue_bankb/build_manifest.json"
ANALYSIS = ROOT / "01_work/analysis/arc1_v356_full_dialogue_bankb"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
HANDLER_FILE = 0x754D0
HANDLER_SIZE = 0xC0
CURSOR_GATE_FILE = 0x75590
CURSOR_GATE_SIZE = 0x10
BANK_B_OFFSET = 0x4200
BANK_B_SLOTS = 28
BANK_B_FIRST_ID = 0xD1
FILL = 0xA1
ROW_PIXELS = 228
NORMAL_ADVANCE = 14
SPACE_ADVANCE = 6
STRUCTURAL_LEADS = {0xE4, 0xE5, 0xE6, 0xE7, 0xE8}
CHOICE = "선택지"
REVIEW_NEEDED = "B검수필요"


class VerifyError(RuntimeError):
    pass


def digest(value: bytes | Path) -> str:
    raw = value.read_bytes() if isinstance(value, Path) else value
    return hashlib.sha256(raw).hexdigest().upper()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def iter_tokens(raw: bytes):
    at = 0
    while at < len(raw):
        width = 1 if raw[at] < 0xDD else 2
        token = raw[at:at + width]
        if len(token) != width:
            raise VerifyError("truncated token")
        yield at, token
        at += width


def structure(raw: bytes) -> tuple[list[tuple[int, int]], list[tuple[int, bytes]]]:
    controls = [
        (at, token) for at, token in iter_tokens(raw)
        if len(token) == 2 and token[0] in STRUCTURAL_LEADS
    ]
    spans: list[tuple[int, int]] = []
    start = 0
    for at, token in controls:
        spans.append((start, at))
        start = at + len(token)
    spans.append((start, len(raw)))
    return spans, controls


def slot_ref(disk_id: int) -> tuple[str, int, int] | None:
    if 0x81 <= disk_id <= 0xA8:
        slot = disk_id - 0x81
        return "A", slot, SLOT_BASE + slot * SLOT_SIZE
    if 0xAA <= disk_id <= 0xD0:
        slot = disk_id - 0x82
        return "A", slot, SLOT_BASE + slot * SLOT_SIZE
    if BANK_B_FIRST_ID <= disk_id < BANK_B_FIRST_ID + BANK_B_SLOTS:
        slot = disk_id - BANK_B_FIRST_ID
        return "B", slot, BANK_B_OFFSET + slot * SLOT_SIZE
    return None


def decode_payload(payload: bytes, decoder: dict[bytes, str], context: str) -> str:
    out: list[str] = []
    for _at, token in iter_tokens(payload):
        if token not in decoder:
            raise VerifyError(f"unmapped final token {token.hex().upper()} in {context}")
        out.append(decoder[token])
    return "".join(out)


def normalize(text: str) -> str:
    return " ".join(text.replace("|", " ").split())


def wrapped_rows(payload: bytes) -> int:
    if not payload:
        return 0
    rows, x = 1, 0
    for _at, token in iter_tokens(payload):
        step = SPACE_ADVANCE if token == bytes((FILL,)) else NORMAL_ADVANCE
        if x + step >= ROW_PIXELS:
            rows, x = rows + 1, 0
        x += step
    return rows


def expand_span(blob: bytes, start: int, end: int, decoder: dict[bytes, str], context: str):
    room = end - start
    span = blob[start:end]
    if not span:
        return b"", None
    if span[0] == 0xE2:
        if room < 2:
            raise VerifyError(f"truncated E2 span in {context}")
        ref = slot_ref(span[1])
        if ref is None:
            raise VerifyError(f"invalid E2 id {span[1]:02X} in {context}")
        if any(value != FILL for value in span[2:]):
            raise VerifyError(f"non-space E2 inline padding in {context}")
        bank, slot, slot_at = ref
        if not 0 <= slot < (SLOT_COUNT if bank == "A" else BANK_B_SLOTS):
            raise VerifyError(f"slot outside bank in {context}")
        raw_slot = blob[slot_at:slot_at + SLOT_SIZE]
        if len(raw_slot) != SLOT_SIZE:
            raise VerifyError(f"truncated {bank} slot in {context}")
        try:
            terminator = raw_slot.index(0, 0, SLOT_SIZE - 1)
        except ValueError as error:
            raise VerifyError(f"slot lacks terminator in {context}") from error
        payload = raw_slot[:terminator]
        if not payload:
            raise VerifyError(f"empty referenced slot in {context}")
        if any(raw_slot[terminator + 1:SLOT_SIZE - 1]):
            raise VerifyError(f"slot padding is not zero in {context}")
        if raw_slot[-1] != room - 2:
            raise VerifyError(
                f"slot skip metadata {raw_slot[-1]} != {room - 2} in {context}"
            )
        decode_payload(payload, decoder, context)
        return payload, (bank, slot, span[1], slot_at)

    if any(token[0] == 0xE2 for _at, token in iter_tokens(span)):
        raise VerifyError(f"E2 appears inside inline glyph span in {context}")
    payload = span.rstrip(bytes((FILL,)))
    decode_payload(payload, decoder, context)
    return payload, None


def ranges_contain(ranges: list[tuple[int, int]], offset: int) -> bool:
    return any(start <= offset < end for start, end in ranges)


def main() -> None:
    pins = {
        BASE: BASE_SHA256, FULL: FULL_SHA256, DELTA: DELTA_SHA256,
        PRISTINE: PRISTINE_SHA256, V355: V355_SHA256,
        TARGETS: TARGETS_SHA256, ORIGINAL: ORIGINAL_SHA256,
        NON_TEXT: NON_TEXT_SHA256, REVIEW: REVIEW_SHA256,
    }
    for path, expected in pins.items():
        if digest(path) != expected:
            raise VerifyError(f"hash drift: {path}")

    with ZipFile(BASE) as archive:
        base_names = archive.namelist()
        base = {name: archive.read(name) for name in base_names}
    with ZipFile(FULL) as archive:
        final_names = archive.namelist()
        final = {name: archive.read(name) for name in final_names}
    with ZipFile(DELTA) as archive:
        delta_names = archive.namelist()
        delta = {name: archive.read(name) for name in delta_names}
    if len(base_names) != 164 or base_names != final_names or len(set(base_names)) != 164:
        raise VerifyError("full archive topology differs from V354")
    if any(len(base[name]) != len(final[name]) for name in base_names):
        raise VerifyError("member size changed")

    changed = [name for name in base_names if base[name] != final[name]]
    if len(changed) != 66 or delta_names != changed:
        raise VerifyError(f"changed/delta member census differs: {len(changed)}")
    if any(delta[name] != final[name] for name in delta_names):
        raise VerifyError("delta member differs from full archive")
    if COMM in changed or final[COMM] != base[COMM]:
        raise VerifyError("COMM.IMG changed")

    with ZipFile(V355) as archive:
        v355_exe = archive.read(PSX)
    if final[PSX][HANDLER_FILE:HANDLER_FILE + HANDLER_SIZE] != v355_exe[HANDLER_FILE:HANDLER_FILE + HANDLER_SIZE]:
        raise VerifyError("V356 handler differs from runtime-approved V355")
    if final[PSX][CURSOR_GATE_FILE:CURSOR_GATE_FILE + CURSOR_GATE_SIZE] != base[PSX][CURSOR_GATE_FILE:CURSOR_GATE_FILE + CURSOR_GATE_SIZE]:
        raise VerifyError("cursor gate changed")
    for at, (old, new) in enumerate(zip(base[PSX], final[PSX])):
        if old != new and not HANDLER_FILE <= at < HANDLER_FILE + HANDLER_SIZE:
            raise VerifyError(f"PSX write outside Bank-B handler: 0x{at:X}")

    _exe, _comm, _encoder, decoder = load_v354()
    targets = read_csv(TARGETS)
    original_rows = read_csv(ORIGINAL)
    nontext = read_csv(NON_TEXT)
    review = read_csv(REVIEW)
    if len(targets) != 343 or len({(r["source file"], r["offset"]) for r in targets}) != 343:
        raise VerifyError("target ledger census differs")
    if len(original_rows) != 2878:
        raise VerifyError("original dialogue census differs")
    if Counter(row["classification"] for row in targets) != {
        "빌드대기": 162, CHOICE: 134, REVIEW_NEEDED: 47,
    }:
        raise VerifyError("target classification differs")
    review_keys = {(row["source file"], row["offset"]) for row in review}
    target_review_keys = {
        (row["source file"], row["offset"]) for row in targets
        if row["classification"] == REVIEW_NEEDED and row["review_status"] == "needs_human_review"
    }
    if len(review_keys) != 47 or review_keys != target_review_keys:
        raise VerifyError("47-row human-review boundary differs")

    target_ranges: dict[str, list[tuple[int, int]]] = defaultdict(list)
    allowed_ranges: dict[str, list[tuple[int, int]]] = defaultdict(list)
    referenced: dict[str, set[tuple[str, int, int, int]]] = defaultdict(set)
    visible_audit: list[dict[str, object]] = []
    control_total = 0
    no_change = 0
    target_keys = {(row["source file"], row["offset"]) for row in targets}

    # Bank-B IDs were unused by the old grammar.  Prove that no recognized,
    # non-target dialogue body contains an E2 D1..EC token.  Raw byte pairs in
    # unrelated binary regions are not parser references.
    for row in original_rows:
        key = (row["source file"], row["byte offset"])
        if key in target_keys:
            continue
        raw = bytes.fromhex(row["raw bytes as hex"].replace(" ", ""))
        for _at, token in iter_tokens(raw):
            if len(token) == 2 and token[0] == 0xE2 and BANK_B_FIRST_ID <= token[1] < BANK_B_FIRST_ID + BANK_B_SLOTS:
                raise VerifyError(f"pre-existing non-target Bank-B call: {key} id={token[1]:02X}")

    for row in targets:
        name = row["source file"]
        offset = int(row["offset"], 0)
        source = bytes.fromhex(row["raw_hex"].replace(" ", ""))
        if digest(source) != row["raw_sha256"] or len(source) != int(row["raw_length"]):
            raise VerifyError(f"target source ledger drift: {name} 0x{offset:X}")
        if name not in final:
            raise VerifyError(f"target member missing: {name}")
        spans, controls = structure(source)
        body = final[name][offset:offset + len(source)]
        if len(body) != len(source):
            raise VerifyError(f"target body truncated: {name} 0x{offset:X}")
        for position, token in controls:
            if body[position:position + len(token)] != token:
                raise VerifyError(f"control moved: {name} 0x{offset:X}+0x{position:X}")
            allowed_ranges[name].append(
                (offset + position, offset + position + len(token))
            )
        control_total += len(controls)

        decoded_parts: list[str] = []
        choice_rows: list[int] = []
        target_ranges[name].append((offset, offset + len(source)))
        for span_index, (start, end) in enumerate(spans):
            if start == end:
                continue
            context = f"{name}:0x{offset:X}:span{span_index}"
            payload, ref = expand_span(final[name], offset + start, offset + end, decoder, context)
            decoded = decode_payload(payload, decoder, context)
            if decoded.strip():
                decoded_parts.append(decoded.strip())
            allowed_ranges[name].append((offset + start, offset + end))
            if ref is not None:
                bank, slot, disk_id, slot_at = ref
                referenced[name].add(ref)
                allowed_ranges[name].append((slot_at, slot_at + SLOT_SIZE))
            if row["classification"] == CHOICE and payload:
                choice_rows.append(wrapped_rows(payload))

        visible = normalize(" ".join(decoded_parts))
        expected_visible = normalize(row["target_korean"])
        if visible != expected_visible:
            raise VerifyError(
                f"visible text differs: {name} 0x{offset:X}\n"
                f" expected={expected_visible}\n actual={visible}"
            )
        if row["classification"] == CHOICE and any(value != 1 for value in choice_rows):
            raise VerifyError(f"choice phrase wraps: {name} 0x{offset:X} {choice_rows}")
        unchanged = final[name][offset:offset + len(source)] == base[name][offset:offset + len(source)]
        no_change += int(unchanged)
        visible_audit.append({
            "row_number": row["row_number"], "source_file": name,
            "offset": f"0x{offset:X}", "classification": row["classification"],
            "visible_text": visible, "target_text": expected_visible,
            "controls": len(controls), "unchanged_from_v354": int(unchanged),
        })

    if no_change != 5:
        raise VerifyError(f"already-current row census differs: {no_change}")
    if len({row["source_file"] for row in visible_audit}) != 65:
        raise VerifyError("target-file census differs")

    with ZipFile(PRISTINE) as archive:
        pristine_names = set(archive.namelist())
        pristine_needed = {
            name: archive.read(name) for name in
            ({row["source file"] for row in nontext} | set(referenced))
            if name in pristine_names
        }

    # Every target-referenced Bank-A slot must originate from a pristine blank
    # translation slot.  Every Bank-B slot is proven against the zero premise;
    # all unreferenced Bank-B slots must remain zero.
    for name, refs in referenced.items():
        if name not in pristine_needed:
            raise VerifyError(f"pristine target member missing: {name}")
        used_b: set[int] = set()
        for bank, slot, disk_id, slot_at in refs:
            pristine_slot = pristine_needed[name][slot_at:slot_at + SLOT_SIZE]
            if any(pristine_slot):
                raise VerifyError(f"referenced {bank} slot was not pristine blank: {name} {slot}")
            if bank == "B":
                used_b.add(slot)
            if bank == "A":
                pair = bytes((0xE2, disk_id))
                cursor = 0
                while True:
                    found = base[name].find(pair, cursor)
                    if found < 0:
                        break
                    if not ranges_contain(target_ranges[name], found):
                        raise VerifyError(
                            f"allocated slot had a V354 external reference: {name} {bank}{slot} at 0x{found:X}"
                        )
                    cursor = found + 1
        base_b = base[name][BANK_B_OFFSET:BANK_B_OFFSET + BANK_B_SLOTS * SLOT_SIZE]
        pristine_b = pristine_needed[name][BANK_B_OFFSET:BANK_B_OFFSET + BANK_B_SLOTS * SLOT_SIZE]
        if any(base_b) or any(pristine_b):
            raise VerifyError(f"Bank-B zero premise differs: {name}")
        for slot in range(BANK_B_SLOTS):
            at = BANK_B_OFFSET + slot * SLOT_SIZE
            final_slot = final[name][at:at + SLOT_SIZE]
            if slot not in used_b and any(final_slot):
                raise VerifyError(f"unreferenced Bank-B slot is nonzero: {name} B{slot}")

    # The complete 199-row exclusion ledger is protected even when a row belongs
    # to a pristine file outside the 164-member patch archive.
    if len(nontext) != 199:
        raise VerifyError("non-text ledger census differs")
    nonmember_nontext = 0
    for row in nontext:
        name = row["source file"]
        offset = int(row["offset"], 0)
        raw = bytes.fromhex(row["raw_hex"].replace(" ", ""))
        if digest(raw) != row["raw_sha256"]:
            raise VerifyError(f"non-text ledger hash differs: {name} 0x{offset:X}")
        if name in final:
            if final[name][offset:offset + len(raw)] != base[name][offset:offset + len(raw)]:
                raise VerifyError(f"non-text bytes changed: {name} 0x{offset:X}")
        else:
            nonmember_nontext += 1
            if name not in pristine_needed or pristine_needed[name][offset:offset + len(raw)] != raw:
                raise VerifyError(f"non-text nonmember baseline differs: {name} 0x{offset:X}")
    if nonmember_nontext != 31:
        raise VerifyError(f"non-text nonmember census differs: {nonmember_nontext}")

    # Recompute every changed byte and require an exact match with the builder's
    # serialized Expected-Write ledger, then independently check its envelope.
    expected_rows = read_csv(EXPECTED)
    expected_set = {
        (row["member"], int(row["file_offset"], 0), int(row["before"], 16), int(row["after"], 16))
        for row in expected_rows
    }
    actual_set: set[tuple[str, int, int, int]] = set()
    for name in changed:
        for at, (old, new) in enumerate(zip(base[name], final[name])):
            if old == new:
                continue
            actual_set.add((name, at, old, new))
            if name == PSX:
                allowed = HANDLER_FILE <= at < HANDLER_FILE + HANDLER_SIZE
            else:
                allowed = ranges_contain(allowed_ranges[name], at)
            if not allowed:
                raise VerifyError(f"write outside independent envelope: {name} 0x{at:X}")
    if actual_set != expected_set:
        raise VerifyError(
            f"Expected-Write differs: missing={len(actual_set - expected_set)} "
            f"extra={len(expected_set - actual_set)}"
        )

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if manifest["full_sha256"] != FULL_SHA256 or manifest["delta_sha256"] != DELTA_SHA256:
        raise VerifyError("manifest archive hashes differ")
    if manifest["target_rows"] != 343 or manifest["already_current_rows"] != 5:
        raise VerifyError("manifest target census differs")
    if manifest["review_pending"] != 47 or manifest["additional_vram_bytes"] != 0:
        raise VerifyError("manifest review/VRAM boundary differs")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    with (ANALYSIS / "independent_visible_text_audit.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(visible_audit[0]))
        writer.writeheader()
        writer.writerows(visible_audit)
    result = {
        "verdict": "STATIC PASS / REVIEW_ONLY / RUNTIME PENDING / TEST_ONLY",
        "full_sha256": FULL_SHA256,
        "delta_sha256": DELTA_SHA256,
        "archive_members": len(final_names),
        "changed_members": len(changed),
        "target_rows": len(targets),
        "target_files": len({row["source file"] for row in targets}),
        "visible_text_matches": len(visible_audit),
        "choice_rows": sum(row["classification"] == CHOICE for row in targets),
        "protected_control_tokens": control_total,
        "already_current_rows": no_change,
        "referenced_bank_a_slots": sum(
            bank == "A" for refs in referenced.values() for bank, _slot, _disk, _at in refs
        ),
        "referenced_bank_b_slots": sum(
            bank == "B" for refs in referenced.values() for bank, _slot, _disk, _at in refs
        ),
        "nontext_protected": len(nontext),
        "nontext_outside_patch_archive": nonmember_nontext,
        "expected_writes": len(actual_set),
        "comm_byte_identical": True,
        "additional_vram_bytes": 0,
        "review_pending": 47,
    }
    (ANALYSIS / "independent_verification.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (ANALYSIS / "independent_verification.txt").write_text(
        "\n".join([
            "Arc the Lad 1 V356 independent static verification",
            result["verdict"],
            f"visible targets: {result['visible_text_matches']}/{result['target_rows']}",
            f"choices: {result['choice_rows']}/{result['choice_rows']}",
            f"protected control tokens: {result['protected_control_tokens']}",
            f"already current in V354: {result['already_current_rows']}",
            f"non-text protected: {result['nontext_protected']}/199",
            f"changed members: {result['changed_members']}/66",
            f"Expected-Write bytes: {result['expected_writes']}",
            "COMM.IMG: byte-identical; added VRAM: 0",
            "release blocker: 47 newly drafted Korean rows still require user review",
            "runtime: PENDING cold boot and representative traversal",
            "",
        ]),
        encoding="utf-8",
    )
    print("V356 independent verification PASS")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
