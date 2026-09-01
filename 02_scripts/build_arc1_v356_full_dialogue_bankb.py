#!/usr/bin/env python3
"""Build V356: reinsert every real V354 dialogue omission with Bank-B support.

The build starts from the hash-pinned V354 archive.  It does not touch the 199
extractor false positives, COMM.IMG, or any untranslated binary table.  Text is
written only into the original text spans or into translation-owned blank
Bank-A slots / the runtime-proven per-DAT Bank-B area.

This remains REVIEW_ONLY / TEST_ONLY because 47 newly drafted Korean lines have
not yet been individually approved by the user.  The binary layout is intended
for runtime review, not distribution.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v355_bankb_runtime_probe as v355  # noqa: E402
from v354_dialogue_codec import (  # noqa: E402
    BUILD as BASE, BUILD_SHA256 as BASE_SHA256, LINEBREAK, SLOT_BASE,
    SLOT_COUNT, SLOT_SIZE, SPACE_CODE, encode, load_v354, tokens,
)


VERSION = "V356"
OUTPUT_STEM = "arc1_v356_full_dialogue_bankb_REVIEW_ONLY_TEST_ONLY"
DELTA_STEM = OUTPUT_STEM + "_delta_from_v354"
ANALYSIS = ROOT / "01_work/analysis/arc1_v356_full_dialogue_bankb"
OUT = ROOT / "03_output"

PSX = "PSX.EXE"
COMM = "COMM.IMG"
PRISTINE = ROOT / "00_original/arc.zip"
PRISTINE_SHA256 = "AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD"
CANONICAL = ROOT / "05_docs/script_translated_full.csv"
CANONICAL_SHA256 = "6AB19301CF92F51DCCAC5ADC7F4251F43A7032A0FDC8D7271BB5C75F2D856EBE"
ORIGINAL = ROOT / "05_docs/script_original_full.csv"
ORIGINAL_SHA256 = "D20D44522A9ECDC9894BAB46D49BC0B9BB7E4573D19BA8627AFCEDA3C2BA1188"
TARGETS = ROOT / "05_docs/v356_full_dialogue_targets.csv"
TARGETS_SHA256 = "8CEA13B26C2A304178E93A5775F07E2FF31AA127AF5F4ED83940B5F5E6031636"
NON_TEXT = ROOT / "05_docs/v356_nontext_exclusions.csv"
NON_TEXT_SHA256 = "FA3F58EA14724D688181E1904063AB258FE209B597954EDE626CDD8234D553C2"
REVIEW = ROOT / "05_docs/v356_bankb_review.csv"
REVIEW_SHA256 = "54E1D5B5F262DF4802AADD3B44B510FF02E3CED2DAD1A00D51F1E4E0BC13F53D"

BANK_B_OFFSET = 0x4200
BANK_B_SLOTS = 28
BANK_B_FIRST_ID = 0xD1
SLOT_TEXT_MAX = 126
ROW_PIXELS = 228
NORMAL_ADVANCE = 14
SPACE_ADVANCE = 6
FILL = SPACE_CODE[0]

STRUCTURAL_LEADS = {0xE4, 0xE5, 0xE6, 0xE7, 0xE8}
MARKER_RE = re.compile(r"\{(E[478]):([0-9A-Fa-f]{2})\}|(\|)")


# Every non-linebreak control in the target set is explicitly placed relative
# to the Korean prose.  The complete raw control sequence, including E6, must
# match the template before any byte is written.
CONTROL_TEMPLATES: dict[tuple[str, int], str] = {
    ("21/S2041.DAT", 0x483D4):
        "승무원:|아니요{E4:1F}{E4:1F}{E4:1F}",
    ("22/S2046.DAT", 0x4881A):
        "무슨 소리냐!! 남쪽 바다에 떠 있는 이 세상의 낙원, 클라프 섬을 모른단 말이냐, 이놈!"
        "{E4:3D}{E4:3D}",
    ("22/S2055.DAT", 0x47C88):
        "잘 모르겠습니다.{E4:3D}|정령은 아버지와 사람의 미래를|건 약속을 했다고 말했습니다.",
    ("31/S3014.DAT", 0x482B6):
        "초핀:|그때 커서와 {E7:02}버튼으로 링 안의 기술을 고른 뒤 아이콘 위치를 변경할 수 있습니다.",
    ("31/S3024.DAT", 0x45ECA):
        "병사|흥!{E4:1F}|좀 강하다고 잘난 척하지 마.",
    ("4/S4021.DAT", 0x47AFA):
        "병사2:|개조하는 거지,{E4:1F} 살기 좋게.",
    ("4/S4022.DAT", 0x47E1E):
        "두목님...{E4:1F}|동생분들...",
    ("5/S5011.DAT", 0x4815A):
        "장사가 뭐냐고, 이 자식아!|{E4:3D}{E4:3D}{E4:3D}한 대 맞아 볼래, 이 자식아!{E4:3D}",
    ("7/S7026.DAT", 0x488BC):
        "대회 위원:|이번 상품은 그 바람의 오브니까요.{E4:1F}|손에 넣어서 어쩌려는 걸까요?",
    ("7/S7031.DAT", 0x478B8):
        "로크톨:|축하합니다, 당신이 진정한 용사입니다.|{E4:3D}자, 상품인 바람의 오브를 드리지요.",
    ("7/S7032.DAT", 0x478BA):
        "로크톨:|이 무투 대회의 상품은{E4:3D}|저 바람의 오브입니다.{E4:79}",
    ("C2/SC0B6.DAT", 0x463DC):
        "1000회까지 앞으로 {E8:21}회입니다.|포기하지 말고 힘내 주십시오.",
    ("C2/SC0B6.DAT", 0x48064):
        "이제 상품은 없습니다만|힘내 주십시오.{E4:3D}",
    ("D/SD031.DAT", 0x463DA):
        "어라?{E4:1F}|이 돌은 뭐였더라...{E4:3D}",
    ("E5/SE05A.DAT", 0x48894):
        "제법인걸.|이제 용서 안 해!{E4:3D} 받아라!{E4:3D}",
    ("F/SF0E1.DAT", 0x47B56):
        "장로:|정령들은 모두 비밀을 품고 있습니다.|{E4:3D}그것은 이 세계의 비밀입니다.",
}


class BuildError(RuntimeError):
    pass


def sha(value: bytes | Path) -> str:
    raw = value.read_bytes() if isinstance(value, Path) else value
    return hashlib.sha256(raw).hexdigest().upper()


def clone_info(source: ZipInfo) -> ZipInfo:
    clone = ZipInfo(source.filename, source.date_time)
    for attr in (
        "compress_type", "comment", "extra", "create_system", "create_version",
        "extract_version", "flag_bits", "volume", "internal_attr", "external_attr",
    ):
        setattr(clone, attr, getattr(source, attr))
    return clone


def write_archive(path: Path, infos: list[ZipInfo], members: dict[str, bytes], names: list[str]) -> None:
    by_name = {info.filename: info for info in infos}
    with ZipFile(path, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for name in names:
            archive.writestr(
                clone_info(by_name[name]), members[name],
                compress_type=ZIP_DEFLATED, compresslevel=9,
            )


def finalize_archive(temporary: Path, stem: str) -> tuple[Path, str]:
    digest = sha(temporary)
    output = temporary.with_name(f"{stem}_{digest[:8]}.zip")
    if output.exists():
        if sha(output) != digest:
            raise BuildError(f"refusing to replace different archive: {output}")
        temporary.unlink()
    else:
        temporary.replace(output)
    return output, digest


def token_offsets(raw: bytes):
    offset = 0
    while offset < len(raw):
        width = 1 if raw[offset] < 0xDD else 2
        token = raw[offset:offset + width]
        if len(token) != width:
            raise BuildError("truncated token")
        yield offset, token
        offset += width


def structure(raw: bytes) -> tuple[list[tuple[int, int]], list[tuple[int, bytes]]]:
    controls = [
        (offset, token) for offset, token in token_offsets(raw)
        if len(token) == 2 and token[0] in STRUCTURAL_LEADS
    ]
    spans: list[tuple[int, int]] = []
    start = 0
    for offset, token in controls:
        spans.append((start, offset))
        start = offset + len(token)
    spans.append((start, len(raw)))
    return spans, controls


def disk_id_a(slot: int) -> int:
    if not 0 <= slot < SLOT_COUNT:
        raise BuildError(f"Bank-A slot outside range: {slot}")
    return slot + (0x81 if slot < 40 else 0x82)


def slot_of_disk(disk_id: int) -> tuple[str, int] | None:
    if 0x81 <= disk_id <= 0xA8:
        return "A", disk_id - 0x81
    if 0xAA <= disk_id <= 0xD0:
        return "A", disk_id - 0x82
    if 0xD1 <= disk_id <= 0xEC:
        return "B", disk_id - 0xD1
    return None


def advance(token: bytes) -> int:
    return SPACE_ADVANCE if token == SPACE_CODE else NORMAL_ADVANCE


def payload_width(payload: bytes) -> int:
    return sum(advance(token) for token in tokens(payload))


def wrapped_rows(payload: bytes) -> int:
    if not payload:
        return 1
    rows, x = 1, 0
    for token in tokens(payload):
        if x + advance(token) >= ROW_PIXELS:
            rows, x = rows + 1, 0
        x += advance(token)
    return rows


def normalize(text: str) -> str:
    return " ".join(text.replace("|", " ").split())


def encoded(text: str, table: dict[str, bytes]) -> bytes:
    payload, missing = encode(text, table, keep_breaks=False)
    if missing:
        raise BuildError(f"missing glyphs {sorted(set(missing))}: {text}")
    if 0 in payload:
        raise BuildError("encoded payload contains terminator")
    return payload


def split_words(text: str, count: int, rooms: list[int], table: dict[str, bytes]) -> list[str]:
    """Partition prose at spaces for the original E6 row count.

    The cost models the live 228px exclusive wrap edge and slot capacity.  It
    prefers at most four visible rows, then fewer rows, fewer slots, and a more
    even distribution.  A speaker label before ': ' is kept on the original
    first row whenever possible.
    """
    if count != len(rooms) or count < 1:
        raise BuildError("partition geometry mismatch")
    if count == 1:
        return [text.strip()]

    forced: list[str] = []
    remainder = text.strip()
    if ": " in remainder and count >= 2:
        head, tail = remainder.split(": ", 1)
        forced = [head + ":"]
        remainder = tail
        rooms = rooms[1:]
        count -= 1

    words = remainder.split()
    if not words:
        return forced + [""] * count

    @lru_cache(maxsize=None)
    def solve(group: int, index: int):
        if group == count:
            return ((), ()) if index == len(words) else None
        best = None
        groups_left = count - group
        # Empty groups are legal, but only needed when there are fewer words.
        minimum_end = index if len(words) - index < groups_left else index + 1
        for end in range(minimum_end, len(words) + 1):
            if len(words) - end < groups_left - 1:
                continue
            part = " ".join(words[index:end])
            payload = encoded(part, table)
            room = rooms[group]
            if len(payload) > room and (room < 2 or len(payload) > SLOT_TEXT_MAX):
                continue
            tail = solve(group + 1, end)
            if tail is None:
                continue
            tail_score, tail_parts = tail
            rows = wrapped_rows(payload)
            slot = int(len(payload) > room)
            width = payload_width(payload)
            local = (rows, slot, width)
            metrics = (local,) + tail_score
            total_rows = sum(item[0] for item in metrics)
            slots = sum(item[1] for item in metrics)
            max_rows = max(item[0] for item in metrics)
            widths = [item[2] for item in metrics]
            imbalance = max(widths) - min(widths)
            score = (int(total_rows > 4), total_rows, slots, max_rows, imbalance, tuple(widths))
            candidate = (score, (part,) + tail_parts, metrics)
            if best is None or candidate[0] < best[0]:
                best = candidate
        if best is None:
            return None
        return best[2], best[1]

    solved = solve(0, 0)
    if solved is None:
        raise BuildError(f"cannot partition text across {count + len(forced)} rows: {text}")
    metrics, parts = solved
    result = forced + list(parts)
    if len(result) != len(rooms) + len(forced):
        raise BuildError("partition result count drift")
    return result


def parse_template(template: str) -> tuple[list[str], list[bytes]]:
    texts: list[str] = []
    controls: list[bytes] = []
    start = 0
    for match in MARKER_RE.finditer(template):
        texts.append(template[start:match.start()])
        if match.group(3):
            controls.append(LINEBREAK)
        else:
            controls.append(bytes((int(match.group(1), 16), int(match.group(2), 16))))
        start = match.end()
    texts.append(template[start:])
    return texts, controls


@dataclass
class Allocation:
    bank: str
    slot: int
    disk_id: int
    payload: bytes
    skip: int
    users: list[str]


class FilePlanner:
    def __init__(self, name: str, current: bytes, pristine: bytes,
                 target_ranges: list[tuple[int, int]], table: dict[str, bytes]):
        self.name = name
        self.before = current
        self.data = bytearray(current)
        self.pristine = pristine
        self.table = table
        self.target_ranges = target_ranges
        self.allocations: list[Allocation] = []
        self.by_payload: dict[tuple[bytes, int], Allocation] = {}
        self.used_b: set[int] = set()

        if len(pristine) < SLOT_BASE + SLOT_COUNT * SLOT_SIZE:
            safe: set[int] = set()
        else:
            safe = {
                slot for slot in range(SLOT_COUNT)
                if not any(pristine[SLOT_BASE + slot * SLOT_SIZE:
                                    SLOT_BASE + (slot + 1) * SLOT_SIZE])
            }

        fixed: set[int] = set()
        for slot in safe:
            pair = bytes((0xE2, disk_id_a(slot)))
            start = 0
            while True:
                at = current.find(pair, start)
                if at < 0:
                    break
                if not any(lo <= at < hi for lo, hi in target_ranges):
                    fixed.add(slot)
                    break
                start = at + 1
        self.safe_slots = safe
        self.fixed_slots = fixed
        self.free_a = sorted(safe - fixed)

        self.bank_b_available = False
        end_b = BANK_B_OFFSET + BANK_B_SLOTS * SLOT_SIZE
        if end_b <= len(current) and end_b <= len(pristine):
            current_b = current[BANK_B_OFFSET:end_b]
            pristine_b = pristine[BANK_B_OFFSET:end_b]
            self.bank_b_available = not any(current_b) and not any(pristine_b)
        self.free_b = list(range(BANK_B_SLOTS)) if self.bank_b_available else []

    def _slot_offset(self, bank: str, slot: int) -> int:
        return SLOT_BASE + slot * SLOT_SIZE if bank == "A" else BANK_B_OFFSET + slot * SLOT_SIZE

    def allocate(self, payload: bytes, skip: int, user: str) -> Allocation:
        key = (payload, skip)
        if key in self.by_payload:
            allocation = self.by_payload[key]
            allocation.users.append(user)
            return allocation
        if not payload or len(payload) > SLOT_TEXT_MAX or not 0 <= skip <= 0x7F:
            raise BuildError(f"invalid slot payload/skip in {self.name}: {len(payload)}B skip={skip}")
        if self.free_a:
            bank, slot = "A", self.free_a.pop(0)
            disk = disk_id_a(slot)
        elif self.free_b:
            bank, slot = "B", self.free_b.pop(0)
            disk = BANK_B_FIRST_ID + slot
            self.used_b.add(slot)
        else:
            raise BuildError(f"no E2 slot remains in {self.name} for {user}")
        replacement = bytearray(SLOT_SIZE)
        replacement[:len(payload)] = payload
        replacement[len(payload)] = 0
        replacement[-1] = skip
        at = self._slot_offset(bank, slot)
        self.data[at:at + SLOT_SIZE] = replacement
        allocation = Allocation(bank, slot, disk, payload, skip, [user])
        self.allocations.append(allocation)
        self.by_payload[key] = allocation
        return allocation

    def place(self, absolute: int, room: int, text: str, user: str) -> dict[str, object]:
        payload = encoded(text, self.table)
        if len(payload) <= room:
            self.data[absolute:absolute + room] = payload + bytes((FILL,)) * (room - len(payload))
            return {
                "mode": "inline", "bytes": len(payload), "room": room,
                "rows": wrapped_rows(payload), "slot": "", "disk_id": "",
            }
        if room < 2:
            raise BuildError(f"span too short for E2 in {user}: {room}")
        allocation = self.allocate(payload, room - 2, user)
        self.data[absolute:absolute + room] = (
            bytes((0xE2, allocation.disk_id)) + bytes((FILL,)) * (room - 2)
        )
        return {
            "mode": f"slot-{allocation.bank}", "bytes": len(payload), "room": room,
            "rows": wrapped_rows(payload), "slot": allocation.slot,
            "disk_id": f"{allocation.disk_id:02X}",
        }


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def differences(before: bytes, after: bytes):
    if len(before) != len(after):
        raise BuildError("member size changed")
    return [(offset, old, new) for offset, (old, new) in enumerate(zip(before, after)) if old != new]


def main() -> None:
    pins = {
        BASE: BASE_SHA256, PRISTINE: PRISTINE_SHA256, CANONICAL: CANONICAL_SHA256,
        ORIGINAL: ORIGINAL_SHA256, TARGETS: TARGETS_SHA256, NON_TEXT: NON_TEXT_SHA256,
        REVIEW: REVIEW_SHA256,
    }
    for path, expected in pins.items():
        if sha(path) != expected:
            raise BuildError(f"input hash drift: {path}")

    nontext_rows = read_csv(NON_TEXT)
    _exe, _comm, table, decoder = load_v354()
    del decoder
    with ZipFile(BASE) as archive:
        infos = [info for info in archive.infolist() if not info.is_dir()]
        names = [info.filename for info in infos]
        base = {name: archive.read(name) for name in names}
    with ZipFile(PRISTINE) as archive:
        needed_pristine = set(base) | {row["source file"] for row in nontext_rows}
        pristine = {
            name: archive.read(name) for name in archive.namelist()
            if name in needed_pristine
        }
    if len(names) != 164 or len(set(names)) != 164:
        raise BuildError("V354 archive topology drift")

    canonical_rows = read_csv(CANONICAL)
    canonical = {(row["source file"], row["offset"]): row for row in canonical_rows}
    original_rows = read_csv(ORIGINAL)
    original = {(row["source file"], row["byte offset"]): row for row in original_rows}
    target_rows = read_csv(TARGETS)
    review_rows = read_csv(REVIEW)
    if (len(canonical), len(original), len(target_rows), len(nontext_rows), len(review_rows)) != (
        2878, 2878, 343, 199, 47,
    ):
        raise BuildError("input census drift")
    target_keys = {(row["source file"], row["offset"]) for row in target_rows}
    nontext_keys = {(row["source file"], row["offset"]) for row in nontext_rows}
    if target_keys & nontext_keys:
        raise BuildError("target/non-text ledgers overlap")
    if Counter(row["review_status"] for row in review_rows) != {"needs_human_review": 47}:
        raise BuildError("47 review drafts are no longer in the expected pending state")

    targets_by_file: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in target_rows:
        key = (row["source file"], row["offset"])
        source = original.get(key)
        current = canonical.get(key)
        if source is None or current is None:
            raise BuildError(f"target missing from canonical/original CSV: {key}")
        raw = bytes.fromhex(row["raw_hex"].replace(" ", ""))
        source_raw = bytes.fromhex(source["raw bytes as hex"].replace(" ", ""))
        if raw != source_raw or sha(raw) != row["raw_sha256"]:
            raise BuildError(f"target raw drift: {key}")
        if current["korean"] != row["target_korean"]:
            raise BuildError(f"target prose drift: {key}")
        targets_by_file[row["source file"]].append(row)

    output = dict(base)
    handler_at = v355.file_offset(v355.LOOKUP_HANDLER)
    current_handler = base[PSX][handler_at:handler_at + v355.HANDLER_SIZE]
    if sha(current_handler) != v355.BASE_HANDLER_SHA256:
        raise BuildError("V354 E2 handler drift")
    gate_at = v355.file_offset(v355.CURSOR_GATE)
    if base[PSX][gate_at:gate_at + len(v355.CURSOR_GATE_PREFIX)] != v355.CURSOR_GATE_PREFIX:
        raise BuildError("range-cursor gate drift")
    exe = bytearray(base[PSX])
    exe[handler_at:handler_at + v355.HANDLER_SIZE] = v355.build_handler()
    output[PSX] = bytes(exe)

    placement_rows: list[dict[str, object]] = []
    control_rows: list[dict[str, object]] = []
    slot_rows: list[dict[str, object]] = []
    file_rows: list[dict[str, object]] = []
    all_used_b: dict[str, set[int]] = {}

    for name in sorted(targets_by_file):
        if name not in base or name not in pristine:
            raise BuildError(f"target member missing from archives: {name}")
        entries = sorted(targets_by_file[name], key=lambda row: int(row["offset"], 0))
        ranges = [
            (int(row["offset"], 0), int(row["offset"], 0) + int(row["raw_length"]))
            for row in entries
        ]
        if any(ranges[i][1] > ranges[i + 1][0] for i in range(len(ranges) - 1)):
            raise BuildError(f"overlapping target bodies: {name}")
        planner = FilePlanner(name, base[name], pristine[name], ranges, table)

        for row in entries:
            offset = int(row["offset"], 0)
            raw = bytes.fromhex(row["raw_hex"].replace(" ", ""))
            target = row["target_korean"]
            spans, controls = structure(raw)
            before_body = base[name][offset:offset + len(raw)]
            pristine_body = pristine[name][offset:offset + len(raw)]
            if pristine_body != raw:
                raise BuildError(f"pristine target body drift: {name} 0x{offset:X}")
            for position, token in controls:
                # V354 may already externalize this body through an E2 slot, so
                # its live bytes need not retain the Japanese control offsets.
                # The target ledger is hash-pinned to the pristine body; restore
                # only those verified structural bytes, while every text span is
                # overwritten below by the new payload or explicit padding.
                planner.data[offset + position:offset + position + len(token)] = token
            key = (name, offset)
            user = f"{name}:0x{offset:X}"
            placements: list[dict[str, object]] = []

            if row["classification"] == "선택지":
                if any(token[0] not in (0xE5, 0xE6) for _position, token in controls):
                    raise BuildError(f"choice has non-choice controls: {user}")
                content = [(index, span) for index, span in enumerate(spans) if span[1] > span[0]]
                target_parts = target.split("|")
                nonempty = [part.strip() for part in target_parts if part.strip()]
                assignments: dict[int, str] = {}
                if target.startswith("|") and spans[0][1] > spans[0][0]:
                    if len(content) != len(nonempty) + 1:
                        raise BuildError(f"choice heading geometry mismatch: {user}")
                    assignments[content[0][0]] = ""
                    for (span_index, _span), part in zip(content[1:], nonempty):
                        assignments[span_index] = part
                elif len(content) == len(nonempty):
                    for (span_index, _span), part in zip(content, nonempty):
                        assignments[span_index] = part
                elif len(content) == len(nonempty) + 1 and not target.startswith("|"):
                    first_two = [content[0][1][1] - content[0][1][0],
                                 content[1][1][1] - content[1][1][0]]
                    prompt = split_words(nonempty[0], 2, first_two, table)
                    assignments[content[0][0]] = prompt[0]
                    assignments[content[1][0]] = prompt[1]
                    for (span_index, _span), part in zip(content[2:], nonempty[1:]):
                        assignments[span_index] = part
                else:
                    raise BuildError(
                        f"choice phrase geometry mismatch: {user} spans={len(content)} parts={len(nonempty)}"
                    )
                if set(assignments) != {index for index, _span in content}:
                    raise BuildError(f"choice span assignment incomplete: {user}")
                for span_index, (start, end) in enumerate(spans):
                    if end == start:
                        continue
                    part = assignments[span_index]
                    payload = encoded(part, table)
                    if part and wrapped_rows(payload) != 1:
                        raise BuildError(f"choice phrase exceeds one row after split: {user}: {part}")
                    result = planner.place(offset + start, end - start, part, user)
                    result.update({"span": span_index, "text": part})
                    placements.append(result)
            else:
                template = CONTROL_TEMPLATES.get(key)
                special = [token for _position, token in controls if token[0] != 0xE6]
                if special:
                    if template is None:
                        raise BuildError(f"missing protected control template: {user}")
                    parts, template_controls = parse_template(template)
                    raw_controls = [token for _position, token in controls]
                    if template_controls != raw_controls or len(parts) != len(spans):
                        raise BuildError(f"protected template control topology mismatch: {user}")
                    if normalize(" ".join(parts)) != normalize(target):
                        raise BuildError(f"protected template prose differs from canonical: {user}")
                else:
                    if template is not None:
                        raise BuildError(f"unnecessary control template: {user}")
                    if any(token != LINEBREAK for _position, token in controls):
                        raise BuildError(f"unsupported ordinary control: {user}")
                    rooms = [end - start for start, end in spans]
                    parts = split_words(target.replace("|", " "), len(spans), rooms, table)
                if len(parts) != len(spans):
                    raise BuildError(f"ordinary span assignment incomplete: {user}")
                for span_index, ((start, end), part) in enumerate(zip(spans, parts)):
                    if end == start:
                        if part:
                            raise BuildError(f"text assigned to zero-length span: {user}")
                        continue
                    result = planner.place(offset + start, end - start, part, user)
                    result.update({"span": span_index, "text": part})
                    placements.append(result)

            after_body = bytes(planner.data[offset:offset + len(raw)])
            binary_changed = int(after_body != before_body)
            after_controls = [
                (position, after_body[position:position + len(token)]) for position, token in controls
            ]
            if after_controls != controls:
                raise BuildError(f"control position changed: {user}")
            if sum(int(item["rows"]) for item in placements) > 4 and row["classification"] != "선택지":
                # E4/E7/E8 spans share a row, so templates are verified later by
                # expanded-stream simulation rather than this conservative sum.
                if key not in CONTROL_TEMPLATES:
                    raise BuildError(f"dialogue exceeds four rows: {user}")

            placement_rows.append({
                "row_number": row["row_number"], "source_file": name,
                "offset": f"0x{offset:X}", "classification": row["classification"],
                "target_korean": target,
                "span_count": len(spans), "control_count": len(controls),
                "inline_spans": sum(item["mode"] == "inline" for item in placements),
                "slot_a_spans": sum(item["mode"] == "slot-A" for item in placements),
                "slot_b_spans": sum(item["mode"] == "slot-B" for item in placements),
                "binary_changed": binary_changed,
                "placement_json": json.dumps(placements, ensure_ascii=False, separators=(",", ":")),
                "review_status": row["review_status"],
            })
            control_rows.append({
                "source_file": name, "offset": f"0x{offset:X}",
                "controls": " ".join(f"+0x{position:X}:{token.hex().upper()}" for position, token in controls),
                "controls_byte_exact": 1,
            })

        output[name] = bytes(planner.data)
        all_used_b[name] = set(planner.used_b)
        for allocation in planner.allocations:
            slot_rows.append({
                "source_file": name, "bank": allocation.bank, "slot": allocation.slot,
                "disk_id": f"{allocation.disk_id:02X}", "payload_length": len(allocation.payload),
                "skip": allocation.skip, "payload_sha256": sha(allocation.payload),
                "users": "|".join(allocation.users),
            })
        file_rows.append({
            "source_file": name, "targets": len(entries),
            "safe_bank_a": len(planner.safe_slots), "fixed_bank_a": len(planner.fixed_slots),
            "used_bank_a": sum(item.bank == "A" for item in planner.allocations),
            "used_bank_b": len(planner.used_b), "bank_b_zero_premise": int(planner.bank_b_available),
            "remaining_bank_a": len(planner.free_a), "remaining_bank_b": len(planner.free_b),
        })

    if len(placement_rows) != 343 or len(control_rows) != 343:
        raise BuildError("placement/control audit census drift")
    if len(CONTROL_TEMPLATES) != 16:
        raise BuildError("protected control-template census drift")
    if not any(all_used_b.values()):
        raise BuildError("V356 unexpectedly did not exercise Bank-B")
    if output[COMM] != base[COMM]:
        raise BuildError("COMM.IMG changed; additional VRAM must remain zero")
    if output[PSX][gate_at:gate_at + len(v355.CURSOR_GATE_PREFIX)] != v355.CURSOR_GATE_PREFIX:
        raise BuildError("range-cursor gate changed")
    if output[PSX][handler_at:handler_at + v355.HANDLER_SIZE] != v355.build_handler():
        raise BuildError("Bank-B handler readback differs")

    # False-positive rows remain byte-identical to V354 and to their raw ledger.
    for row in nontext_rows:
        name = row["source file"]
        offset = int(row["offset"], 0)
        raw = bytes.fromhex(row["raw_hex"].replace(" ", ""))
        if name not in output:
            if name not in pristine or pristine[name][offset:offset + len(raw)] != raw:
                raise BuildError(f"non-text nonmember baseline drift: {name} 0x{offset:X}")
            continue
        if output[name][offset:offset + len(raw)] != base[name][offset:offset + len(raw)]:
            raise BuildError(f"non-text protected bytes changed: {name} 0x{offset:X}")

    changed_members = [name for name in names if output[name] != base[name]]
    allowed_members = {PSX} | set(targets_by_file)
    unexpected_members = set(changed_members) - allowed_members
    if unexpected_members or PSX not in changed_members or len(changed_members) < 2:
        raise BuildError(
            f"changed-member envelope differs: unexpected={sorted(unexpected_members)} "
            f"members={changed_members}"
        )
    if any(len(output[name]) != len(base[name]) for name in names):
        raise BuildError("archive member length changed")

    ANALYSIS.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    for path, rows in (
        (ANALYSIS / "placement_audit.csv", placement_rows),
        (ANALYSIS / "control_audit.csv", control_rows),
        (ANALYSIS / "slot_audit.csv", slot_rows),
        (ANALYSIS / "file_capacity_audit.csv", file_rows),
    ):
        with path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)

    expected_rows: list[dict[str, str]] = []
    for member in changed_members:
        reason = "V355 runtime-approved E2 Bank-B handler" if member == PSX else "V356 dialogue reinsertion"
        for at, old, new in differences(base[member], output[member]):
            expected_rows.append({
                "member": member, "file_offset": f"0x{at:X}",
                "before": f"{old:02X}", "after": f"{new:02X}", "reason": reason,
            })
    with (ANALYSIS / "expected_writes.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(expected_rows[0]))
        writer.writeheader()
        writer.writerows(expected_rows)

    full_temp = OUT / f"{OUTPUT_STEM}_TEMP.zip"
    delta_temp = OUT / f"{DELTA_STEM}_TEMP.zip"
    if full_temp.exists() or delta_temp.exists():
        raise BuildError("temporary output already exists")
    write_archive(full_temp, infos, output, names)
    write_archive(delta_temp, infos, output, changed_members)
    full_path, full_sha = finalize_archive(full_temp, OUTPUT_STEM)
    delta_path, delta_sha = finalize_archive(delta_temp, DELTA_STEM)

    with ZipFile(full_path) as archive:
        if archive.namelist() != names:
            raise BuildError("full archive member order changed")
        for name in names:
            if archive.read(name) != output[name]:
                raise BuildError(f"full archive readback differs: {name}")
    with ZipFile(delta_path) as archive:
        if archive.namelist() != changed_members:
            raise BuildError("delta archive member order changed")
        for name in changed_members:
            if archive.read(name) != output[name]:
                raise BuildError(f"delta archive readback differs: {name}")

    manifest = {
        "version": VERSION,
        "status": "STATIC CANDIDATE / REVIEW_ONLY / RUNTIME PENDING / TEST_ONLY",
        "release_blocker": "47 newly drafted Korean rows require user review",
        "base": str(BASE.relative_to(ROOT)).replace("\\", "/"),
        "base_sha256": BASE_SHA256,
        "full_zip": str(full_path.relative_to(ROOT)).replace("\\", "/"),
        "full_sha256": full_sha,
        "delta_zip": str(delta_path.relative_to(ROOT)).replace("\\", "/"),
        "delta_sha256": delta_sha,
        "changed_members": changed_members,
        "member_sha256": {name: sha(output[name]) for name in changed_members},
        "actual_changed_bytes": {name: len(differences(base[name], output[name])) for name in changed_members},
        "target_rows": len(placement_rows),
        "already_current_rows": sum(not row["binary_changed"] for row in placement_rows),
        "target_files": len(targets_by_file),
        "target_classification": dict(Counter(row["classification"] for row in target_rows)),
        "nontext_protected": len(nontext_rows),
        "review_pending": 47,
        "additional_vram_bytes": 0,
        "comm_byte_identical": True,
        "control_templates": len(CONTROL_TEMPLATES),
        "slot_allocations": {
            "bank_a": sum(row["bank"] == "A" for row in slot_rows),
            "bank_b": sum(row["bank"] == "B" for row in slot_rows),
            "deduplicated_users": sum(max(0, len(row["users"].split("|")) - 1) for row in slot_rows),
        },
        "handler": {
            "ram_range": "0x8018FCD0..0x8018FD8F",
            "bank_b_ids": "D1..EC",
            "bank_b_file_range_per_dat": "0x4200..0x4FFF",
            "cursor_gate": "0x8018FD90 unchanged",
        },
        "input_sha256": {
            "canonical": CANONICAL_SHA256, "original": ORIGINAL_SHA256,
            "targets": TARGETS_SHA256, "nontext": NON_TEXT_SHA256, "review": REVIEW_SHA256,
        },
    }
    (ANALYSIS / "build_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = [
        "Arc the Lad 1 V356 full dialogue Bank-B review build",
        "status: STATIC CANDIDATE / REVIEW_ONLY / RUNTIME PENDING / TEST_ONLY",
        f"base: {BASE.name}",
        f"full: {full_path.name}",
        f"full sha256: {full_sha}",
        f"delta: {delta_path.name}",
        f"delta sha256: {delta_sha}",
        f"targets: {len(placement_rows)} rows in {len(targets_by_file)} DAT files",
        f"classification: {dict(Counter(row['classification'] for row in target_rows))}",
        f"non-text protected: {len(nontext_rows)} rows byte-identical",
        f"slot allocations: Bank-A {manifest['slot_allocations']['bank_a']}, "
        f"Bank-B {manifest['slot_allocations']['bank_b']}",
        "choice/control policy: original E5/E6/E4/E7/E8 offsets byte-identical",
        "additional VRAM: 0 bytes; COMM.IMG byte-identical",
        "release blocker: 47 draft translations require user review",
        "runtime: PENDING cold boot and representative dialogue/choice traversal",
        "",
    ]
    (ANALYSIS / "build_report.txt").write_text("\n".join(report), encoding="utf-8")
    (ANALYSIS / "runtime_checklist.txt").write_text(
        "\n".join([
            "V356 REVIEW_ONLY TEST_ONLY runtime checklist",
            "1. Cold boot V356; do not resume a pre-V356 RAM snapshot directly.",
            "2. Verify the first dialogue and advance to the next dialogue.",
            "3. Exercise tutorial/help choices, battle-entry choices, tournament choices, and prize choices.",
            "4. Verify E7 button and E8 dynamic-count lines still show their icon/number.",
            "5. Review the 47 rows marked B검수필요 in the editor; this build is not distributable before approval.",
            "6. Save states for any visual, timing, cursor, freeze, or wording defect.",
            "",
        ]), encoding="utf-8"
    )
    print(f"V356 build complete: {full_path.name}")
    print(f"full sha256:  {full_sha}")
    print(f"delta sha256: {delta_sha}")
    print(f"targets: {len(placement_rows)}, changed members: {len(changed_members)}")
    print(f"slots: A={manifest['slot_allocations']['bank_a']} B={manifest['slot_allocations']['bank_b']}")


if __name__ == "__main__":
    main()
