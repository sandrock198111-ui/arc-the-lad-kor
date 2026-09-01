"""V354 desktop dialogue editor with live, game-accurate constraints.

The browser tool is replaced because it could not be worked in; this is a plain Tk
window, no server and no browser. Run it with:

    python 02_scripts/review_editor.py

The list shows every canonical dialogue row, the Japanese, the Korean V354 actually
draws, an editable proposal, and a non-authoritative review flag.  Everything else on
screen exists to answer one question -- will this line fit -- and there are three ways
for it not to.

  row budget    V354 uses 16px sprites, 14px normal advance, 6px physical-160 space,
                and an exclusive 228px wrap edge.  V335 moved dialogue text upward so a
                normal window has four visible rows.  E6 is drawn rather than obeyed
                inside an external slot, so shortening remains the safe way to fit.

  byte budget   A line is written into the bytes the Japanese occupied. If it no longer
                fits it must take an external slot, and a slot holds 126 bytes of text
                -- 128 less the terminator and the completion metadata.

  the alphabet  Not every character has a glyph.  The encoder is reconstructed from the
                hash-pinned V354 16px assignment/atlas data plus the audited V321/V325/
                V339 additions, and its live E9/EA lookup destinations are verified.

The proposal column starts as a copy of the Korean. Where a line is over the row budget
the tool offers a mechanical suggestion -- the same words with the spaces the renderer
does not need -- which is a starting point, not an answer; read it before taking it.
Yellow/lavender rows are only review candidates, never automatic corrections. Saving
writes only the Korean column, and keeps the previous file as `.editor.bak`.
"""
from __future__ import annotations

import csv
import re
import shutil
import sys
import tkinter as tk
import zipfile
from collections import defaultdict
from pathlib import Path
from tkinter import font as tkfont, messagebox, ttk

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from v354_dialogue_codec import (  # noqa: E402
    BUILD, BUILD_SHA256, CHOICE, LINEBREAK, SLOT_BASE, SLOT_COUNT, SLOT_SIZE,
    SLOT_TEXT_MAX, SPACE_CODE, encode, has_marker, load_v354, tokens,
)

TRANSLATED = ROOT / "05_docs/script_translated_full.csv"
ORIGINAL = ROOT / "05_docs/script_original_full.csv"
PRISTINE = ROOT / "00_original/arc.zip"
EXPORT = ROOT / "05_docs/dialogue_all.csv"
ROW_PIXELS = 228           # exclusive wrap edge, measured from runtime packets
NORMAL_ADVANCE = 14
SPACE_ADVANCE = 6
MIN_WINDOW_ROWS = 4        # V335 top/bottom dialogue Y supports four 16px rows
REGISTER_REVIEW = ROOT / "05_docs/review_translation_by_story.csv"
PROVENANCE = "source of the translation (existing / new)"
VALID_PROVENANCE = {"", "existing", "new"}


# A character with no code is not one problem but four, and they need different answers.
SUBSTITUTES = {"‘": "'", "’": "'", "“": '"', "”": '"', "–": "-", "—": "-"}
OVERWRITTEN = {"R": "DF 03"}    # the original drew it at index 732; a Korean syllable sits there now

# These are known regression spellings or phrases the user has already called out.
# They are review signals only: the editor never rewrites them automatically.
KNOWN_REVIEW_PATTERNS = {
    "존개": "존재 오인코딩 흔적",
    "개미있": "재미있 오인코딩 흔적",
    "느레벨": "레벨업 접두 글리프 흔적",
    "밀마나": "미르마나 명칭 확인",
    "올카스": "오르카스 명칭 확인",
    "스톤 서서": "스톤 서클 오기 가능성",
    "찾자의": "문장/포인터 결합 확인",
    "좋아터": "문장/포인터 결합 확인",
    "일단이 있": "一団을 '일단'으로 옮긴 오역 가능성",
    "수상한 일행": "一団/일행 문맥 재검토",
    "해왔는지에.": "조사로 끝나는 문장",
    "4 호": "전투 질문 슬롯 오표시 흔적",
}

JAPANESE_RE = re.compile(r"[ぁ-ゖァ-ヺ一-龯]")
REPEATED_WORD_RE = re.compile(r"(?:^|\s)([가-힣]{2,})(?:\s+\1)(?:\s|[.!?,]|$)")
DANGLING_END_RE = re.compile(
    r"(?:에서|에게|으로|부터|까지|처럼|보다|하고|인지에|것을|것이|것은|다는)[.!?]?$"
)


def explain_missing(chars: list[str], text: str) -> list[str]:
    """Say why each character cannot be written, because the cure differs."""
    notes: list[str] = []
    if "<CTRL" in text:
        notes.append("제어 마커 <CTRL:..>가 글자로 남아 있습니다. 지우세요.")
    if any(c in text for c in "\n\r\f\v"):
        notes.append("줄바꿈/제어문자가 들어 있습니다. 슬롯에서는 무시되니 지우세요.")
    swap = sorted({c for c in chars if c in SUBSTITUTES})
    if swap:
        notes.append("바꿔 쓰면 됩니다: " + ", ".join(f"{c} → {SUBSTITUTES[c]}" for c in swap))
    lost = sorted({c for c in chars if c in OVERWRITTEN})
    if lost:
        notes.append(f"{' '.join(lost)} 는 원판 폰트에 있지만 그 칸을 한글로 덮어썼습니다."
                     " 복원 전에는 쓸 수 없습니다.")
    hangul = sorted({c for c in chars if "가" <= c <= "힣"})
    if hangul:
        notes.append(f"{' '.join(hangul)} 는 폰트에 아예 없습니다. 새 글리프 칸이 필요합니다.")
    return notes


def advance(token: bytes) -> int:
    """How far the renderer moves after drawing this token."""
    return SPACE_ADVANCE if token == SPACE_CODE else NORMAL_ADVANCE


def wrapped_rows(payload: bytes) -> int:
    rows, x = 1, 0
    for token in tokens(payload):
        # Runtime wrap is exclusive: a run that reaches exactly 228px already
        # consumes the next row (the V191/V192 choice-cursor regression).
        if x + advance(token) >= ROW_PIXELS:
            rows, x = rows + 1, 0
        x += advance(token)
    return rows


def slot_of_disk(disk_id: int) -> int | None:
    """Convert the E2 disk id to a standard 0..78 slot, rejecting reserved A9."""
    if 0x81 <= disk_id <= 0xA8:
        return disk_id - 0x81
    if 0xAA <= disk_id <= 0xD0:
        return disk_id - 0x82
    return None


def active_slot_refs(body: bytes) -> set[int]:
    """Return standard E2 slots reached by one current dialogue body.

    A leading E2 redirects the whole body, so its old tail is skipped and must not be
    scanned as live text.  Inline choice bodies can contain E2 after an E5/E6 marker;
    those references are conservatively retained as fixed owners.
    """
    if len(body) >= 2 and body[0] == 0xE2:
        slot = slot_of_disk(body[1])
        return {slot} if slot is not None else set()
    refs: set[int] = set()
    for token in tokens(body):
        if len(token) == 1 and token[0] == 0:
            break
        if len(token) == 2 and token[0] == 0xE2:
            slot = slot_of_disk(token[1])
            if slot is not None:
                refs.add(slot)
    return refs


class Line:
    __slots__ = ("n", "file", "offset", "japanese", "korean", "proposal", "disc",
                 "capacity", "rows", "is_choice", "raw", "redirected",
                 "current_slot", "provenance", "csv_issue", "mixed_register")

    def __init__(self, n, row, raw, rows, disc="", mixed_register=False):
        self.n = n
        self.file = row["source file"]
        self.offset = row["offset"]
        self.japanese = row["japanese"] or ""
        self.korean = (row["korean"] or "").strip()
        self.proposal = self.korean
        self.disc = disc            # what the game actually draws, decoded from the build
        self.raw = raw
        self.capacity = len(raw) if raw else 0
        self.rows = rows
        self.is_choice = bool(raw) and has_marker(raw, CHOICE)
        self.redirected = False     # the disc body already points at an external slot
        self.current_slot: int | None = None
        self.provenance = (row.get(PROVENANCE) or "").strip()
        self.csv_issue = "" if self.provenance in VALID_PROVENANCE else self.provenance
        self.mixed_register = mixed_register


class Editor:
    def __init__(self, master: tk.Tk) -> None:
        self.master = master
        master.title("Arc the Lad 1 - V354 전체 대화 편집기")
        master.geometry("1500x880")

        self.load()
        self.view: list[Line] = []
        self.current: Line | None = None
        self._build_widgets()
        self.refresh()
        master.protocol("WM_DELETE_WINDOW", self.close)

    def load(self) -> None:
        """Read the canonical CSV and the exact, hash-pinned V354 build."""
        exe, _font, self.table, self.back = load_v354()
        self.exe = exe
        with zipfile.ZipFile(BUILD) as archive:
            blobs = {n: archive.read(n) for n in archive.namelist() if n.upper().endswith(".DAT")}
        with zipfile.ZipFile(PRISTINE) as pristine:
            originals = {n: pristine.read(n) for n in pristine.namelist() if n in blobs}
        self.blobs = blobs
        self.originals = originals
        self.build_name = BUILD.name

        # Only slots that were blank on the pristine disc belong to the translation.
        # Current zero-filled blocks are not the capacity: a prior build can leave dead
        # text in a now-unreferenced safe slot, and an edit that moves a line inline can
        # release its current slot.  The live proposal plan below accounts for both.
        self.safe_slots: dict[str, set[int]] = {}
        for name, original in originals.items():
            if len(original) < SLOT_BASE + SLOT_COUNT * SLOT_SIZE:
                self.safe_slots[name] = set()
                continue
            self.safe_slots[name] = {
                slot for slot in range(SLOT_COUNT)
                if not any(original[
                    SLOT_BASE + slot * SLOT_SIZE:SLOT_BASE + (slot + 1) * SLOT_SIZE
                ])
            }

        raws: dict[tuple[str, str], bytes] = {}
        with ORIGINAL.open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
            for row in reader:
                raw = bytes.fromhex(row["raw bytes as hex"].replace(" ", ""))
                raws[(row["source file"], str(int(row[key], 0)))] = raw

        mixed: set[tuple[str, int, str]] = set()
        if REGISTER_REVIEW.exists():
            with REGISTER_REVIEW.open(encoding="utf-8-sig", newline="") as handle:
                for row in csv.DictReader(handle):
                    if (row.get("mixed_register") or "").strip() == "MIXED":
                        mixed.add((row["file"], int(row["offset"], 0), (row.get("korean") or "").strip()))

        self.loaded_at = TRANSLATED.stat().st_mtime_ns
        with TRANSLATED.open(encoding="utf-8-sig", newline="") as handle:
            self.fieldnames = (reader := csv.DictReader(handle)).fieldnames
            self.rows = list(reader)
        self.lines = []
        for n, row in enumerate(self.rows, start=1):
            name = row["source file"]
            raw = raws.get((name, str(int(row["offset"], 0))), b"")
            rows_ = sum(1 for t in tokens(raw) if len(t) == 2 and t[0] == 0xE6) + 1 if raw else 1
            disc, redirected = "", False
            if raw and name in blobs and name in originals:
                offset = int(row["offset"], 0)
                disc = self.read_disc(blobs[name], originals[name], offset, raw)
                if offset + 1 < len(blobs[name]) and blobs[name][offset] == 0xE2:
                    current_slot = slot_of_disk(blobs[name][offset + 1])
                else:
                    current_slot = None
                redirected = current_slot is not None
            else:
                current_slot = None
            key_ = (name, int(row["offset"], 0), (row.get("korean") or "").strip())
            line = Line(n, row, raw, rows_, disc, key_ in mixed)
            line.redirected = redirected
            line.current_slot = current_slot
            self.lines.append(line)

        self.lines_by_file: dict[str, list[Line]] = defaultdict(list)
        for line in self.lines:
            self.lines_by_file[line.file].append(line)

        # Choice/special E2 owners cannot be released by ordinary prose edits.  Reserve
        # only owners that consume pristine-blank translation slots; original game slots
        # are already outside safe capacity.
        fixed: dict[str, set[int]] = defaultdict(set)
        for line in self.lines:
            if not line.raw or line.file not in blobs:
                continue
            offset = int(line.offset, 0)
            body = blobs[line.file][offset:offset + len(line.raw)]
            refs = active_slot_refs(body)
            if line.is_choice or line.current_slot is None:
                fixed[line.file].update(refs & self.safe_slots.get(line.file, set()))
        self.fixed_slot_refs = {name: set(fixed.get(name, set())) for name in blobs}
        self.recalculate_slot_plan()

    def reload(self) -> None:
        edited = [l for l in self.lines if l.proposal != l.korean]
        if edited and not messagebox.askyesno(
                "다시 읽기",
                f"적용만 하고 저장하지 않은 줄이 {len(edited)}개 있습니다. "
                "다시 읽으면 사라집니다. 계속할까요?"):
            return
        self.load()
        self.current = None
        self.file_box.configure(values=["(전체)"] + sorted({l.file for l in self.lines}))
        self.refresh()
        self.status.configure(text=f"다시 읽음 — V354 {BUILD_SHA256[:8]}   "
                                   f"코드맵 {len(self.table)}자, 한 줄 < {ROW_PIXELS}px, "
                                   f"창 높이 max(원문 줄 수, {MIN_WINDOW_ROWS})")

    # ---------------------------------------------------------------- measuring

    def decode(self, payload: bytes) -> str:
        out = []
        for token in tokens(payload):
            if len(token) == 1 and token[0] == 0:
                break
            if len(token) == 2 and token[0] in (CHOICE, 0xE6):
                out.append("|")
                continue
            if len(token) == 2 and token[0] == 0xE7:
                out.append("[아이콘]")
                continue
            if len(token) == 2 and (token[0] in (0xE2, 0xE3, 0xE4, 0xE8) or token[0] >= 0xEB):
                continue
            out.append(self.back.get(token, f"<{token.hex().upper()}>"))
        return re.sub(r"\|+", "|", "".join(out)).strip().strip("|")

    def slot_text(self, blob: bytes, disk: int) -> str:
        slot = disk - (0x81 if disk < 0xA9 else 0x82)
        if not 0 <= slot < SLOT_COUNT or len(blob) < SLOT_BASE + SLOT_COUNT * SLOT_SIZE:
            return ""
        seg = blob[SLOT_BASE + slot * SLOT_SIZE:SLOT_BASE + (slot + 1) * SLOT_SIZE]
        return self.decode(seg[:seg.index(0)] if 0 in seg[:SLOT_SIZE - 1] else seg[:SLOT_SIZE - 1])

    def read_disc(self, blob: bytes, original: bytes, offset: int, raw: bytes) -> str:
        """What the game draws here: the body, or the slot the body redirects to."""
        if blob[offset:offset + len(raw)] == original[offset:offset + len(raw)]:
            return "(일본어 그대로)"
        if blob[offset] != 0xE2:
            body = blob[offset:offset + len(raw)]
            if CHOICE in {t[0] for t in tokens(raw) if len(t) == 2}:
                # a choice span may itself be an E2 redirect; expand it or the column
                # shows the two marker bytes as if they were a syllable
                out, run = [], []
                def flush():
                    if run and len(run[0]) == 2 and run[0][0] == 0xE2:
                        out.append(self.slot_text(blob, run[0][1]))
                    elif run:
                        out.append(self.decode(b"".join(run)))
                for token in tokens(body):
                    if len(token) == 1 and token[0] == 0:
                        break
                    if len(token) == 2 and token[0] in (CHOICE, 0xE6):
                        flush(); run.clear(); continue
                    run.append(token)
                flush()
                return " | ".join(x for x in out if x)
            return self.decode(body)
        slot = blob[offset + 1] - (0x81 if blob[offset + 1] < 0xA9 else 0x82)
        if not 0 <= slot < SLOT_COUNT or len(blob) < SLOT_BASE + SLOT_COUNT * SLOT_SIZE:
            return "(슬롯 번호가 범위 밖)"
        seg = blob[SLOT_BASE + slot * SLOT_SIZE:SLOT_BASE + (slot + 1) * SLOT_SIZE]
        return self.decode(seg[:seg.index(0)] if 0 in seg[:SLOT_SIZE - 1] else seg[:SLOT_SIZE - 1])

    def choice_fit(self, line: Line, text: str) -> list[str]:
        """Show useful choice measurements without pretending to rebuild the body.

        Choice bodies can contain external E2 slots and control-only padding runs, so
        the number of E5/E6-separated byte runs is not a reliable one-to-one map to the
        editable ``|`` phrases.  The editor therefore reports each proposed phrase's
        encoded size and width, but leaves marker-position and row-sharing validation
        to ``check_build.py`` after reinsertion.  A false green/red light here is worse
        than an explicit build-time check.
        """
        parts = [p.strip() for p in text.split("|")]
        out = [f"수정안 선택지 {len(parts)}칸 (E5/E6 위치는 빌드 때 원판과 대조)"]
        for i, phrase in enumerate(parts, 1):
            payload, missing = encode(phrase, self.table, keep_breaks=False)
            pixels = sum(advance(token) for token in tokens(payload))
            mark = "!" if missing or pixels >= ROW_PIXELS else "o"
            out.append(
                f"  {mark} {i:>2}번  {len(payload):>3}B  {pixels:>3}/227px  {phrase[:20]}"
            )
        return out

    def measure(self, line: Line, text: str) -> dict:
        """Everything that decides whether this text can go on the disc."""
        payload, missing = encode(text, self.table, keep_breaks=False)
        inline, _ = encode(text, self.table, keep_breaks=True)
        need = wrapped_rows(payload) if payload else 0
        window = max(line.rows, MIN_WINDOW_ROWS)
        fits_inline = len(inline) <= line.capacity
        return {
            "missing": sorted(set(missing)),
            "bytes": len(payload),
            "inline": len(inline),
            "width": sum(advance(t) for t in tokens(payload)),
            "need_rows": need,
            "window": window,
            "fits_inline": fits_inline,
            "needs_slot": not fits_inline,
            "over_slot": (not fits_inline) and len(payload) > SLOT_TEXT_MAX,
            "over_rows": need > window,
        }

    def slot_plan_for_file(self, name: str,
                           overrides: dict[int, str] | None = None) -> dict:
        """Plan the standard external slots from every proposal in one DAT.

        This is deliberately a final-plan calculation, not a count of zero blocks in
        V354.  A valid proposal that now fits inline releases its current safe slot;
        every other valid long proposal consumes one.  Choice/special owners and a
        current slot whose proposal is not buildable remain reserved.
        """
        overrides = overrides or {}
        safe = set(self.safe_slots.get(name, set()))
        fixed = set(self.fixed_slot_refs.get(name, set()))
        retained: set[int] = set()
        held_safe: list[Line] = []
        held_legacy: list[Line] = []
        new_demand: list[Line] = []

        for line in self.lines_by_file.get(name, []):
            if line.is_choice:
                continue
            text = overrides.get(line.n, line.proposal).strip()
            measured = self.measure(line, text)
            buildable = (
                bool(text)
                and any("가" <= char <= "힣" for char in text)
                and not measured["missing"]
                and not measured["over_rows"]
                and not measured["over_slot"]
            )
            if not buildable:
                if line.current_slot in safe:
                    retained.add(line.current_slot)
                continue
            if measured["fits_inline"]:
                continue
            if line.current_slot is not None:
                if line.current_slot in safe:
                    held_safe.append(line)
                else:
                    # One audited V354 line preserves a legacy original-owned slot.
                    # It remains usable in place but is not part of translation capacity.
                    held_legacy.append(line)
            else:
                new_demand.append(line)

        held_slots = {line.current_slot for line in held_safe}
        occupied = fixed | retained | held_slots
        free_for_new = len(safe - occupied)

        # Match the reinserter's stable file/offset order after preserving existing
        # assignments.  This makes the exact lines labelled shortage deterministic.
        new_demand.sort(key=lambda line: int(line.offset, 0))
        newly_assigned = new_demand[:free_for_new]
        shortage = new_demand[free_for_new:]
        assigned = {
            line.n for line in held_safe + held_legacy + newly_assigned
        }
        return {
            "capacity": len(safe),
            "fixed": len(fixed),
            "retained": len(retained - fixed),
            "ordinary_demand": len(held_safe) + len(new_demand),
            "legacy_held": len(held_legacy),
            "balance": free_for_new - len(new_demand),
            "assigned": assigned,
            "shortage": {line.n for line in shortage},
        }

    def recalculate_slot_plan(self) -> None:
        """Refresh cached slot states after any proposal changes."""
        self.slot_assigned: set[int] = set()
        self.slot_shortage: set[int] = set()
        self.slot_stats: dict[str, dict] = {}
        self.slot_balance: dict[str, int] = {}
        for name in self.lines_by_file:
            plan = self.slot_plan_for_file(name)
            self.slot_stats[name] = plan
            self.slot_balance[name] = plan["balance"]
            self.slot_assigned.update(plan["assigned"])
            self.slot_shortage.update(plan["shortage"])

    def review_reasons(self, line: Line, text: str) -> list[str]:
        """Return non-authoritative language-review hints for a row."""
        reasons: list[str] = []
        if line.csv_issue:
            reasons.append(f"CSV 열 분리 의심: 뒤쪽 값={line.csv_issue!r}")
        if line.mixed_register and text == line.korean:
            reasons.append("기존 화자 분석에서 존댓말/반말 혼합")
        if JAPANESE_RE.search(text):
            reasons.append("한국어 열에 일본어/한자가 남음")
        if "???" in text or "�" in text:
            reasons.append("미확정/깨진 문자 표시")
        if "<CTRL" in text or re.search(r"<[A-Z]+:[^>]+>", text):
            reasons.append("편집 문장에 제어 마커가 남음")
        for pattern, reason in KNOWN_REVIEW_PATTERNS.items():
            if pattern in text:
                reasons.append(reason)
        if REPEATED_WORD_RE.search(text):
            reasons.append("같은 단어가 연속 반복됨")
        if DANGLING_END_RE.search(text):
            reasons.append("조사/연결어미로 문장이 끝남")
        # Stable order, no duplicate labels when two heuristics describe one symptom.
        return list(dict.fromkeys(reasons))

    def review_kind(self, line: Line, text: str) -> str:
        reasons = self.review_reasons(line, text)
        if not reasons:
            return ""
        if line.csv_issue:
            return "CSV"
        if line.mixed_register and len(reasons) == 1:
            return "문체"
        return "표현"

    def state_of(self, line: Line) -> str:
        """What stands between this line and the game, and what to do about it.

        `미적용` used to cover two very different situations and that cost real time:
        a line whose edit is simply waiting for the next build looked exactly like a
        line the game still draws in Japanese. They are separated here, because the
        first needs a build and the second needs room in its file.
        """
        if not line.korean:
            return "미번역"
        m = self.measure(line, line.proposal)
        if m["missing"]:
            return "글자없음"
        if m["over_rows"]:
            return "줄넘침"
        if m["over_slot"]:
            return "슬롯초과"
        if re.sub(r"[|\s]+", "", line.disc) == re.sub(r"[|\s]+", "", line.proposal):
            return "적용됨"
        if line.is_choice:
            return "선택지"
        if m["fits_inline"] or line.n in self.slot_assigned:
            return "빌드대기"
        return "슬롯부족"

    def suggest(self, line: Line) -> str:
        """Close up the spaces the renderer does not need, shortest joins first.

        The wrap is automatic, so a space is only there for reading. Joining the two
        shortest neighbours first gives `수있습니다`, which a reader passes over; joining
        the longest would give one unreadable run instead. It is still a mechanical cut
        and it is offered, never applied on its own.
        """
        text = line.proposal
        if not self.measure(line, text)["over_rows"]:
            return text
        parts = text.split(" ")
        while len(parts) > 1 and self.measure(line, " ".join(parts))["over_rows"]:
            join = min(range(len(parts) - 1), key=lambda i: len(parts[i]) + len(parts[i + 1]))
            parts[join:join + 2] = [parts[join] + parts[join + 1]]
        return " ".join(parts)

    # ---------------------------------------------------------------- widgets

    def _build_widgets(self) -> None:
        mono = tkfont.Font(family="Consolas", size=10)
        top = ttk.Frame(self.master, padding=6)
        top.pack(fill="x")
        ttk.Label(top, text="파일").pack(side="left")
        self.file_var = tk.StringVar(value="(전체)")
        files = ["(전체)"] + sorted({l.file for l in self.lines})
        self.file_box = ttk.Combobox(top, textvariable=self.file_var, values=files,
                                     width=18, state="readonly")
        self.file_box.pack(side="left", padx=(4, 14))
        self.file_box.bind("<<ComboboxSelected>>", lambda _e: self.refresh())

        ttk.Label(top, text="상태").pack(side="left")
        self.state_var = tk.StringVar(value="(전체)")
        states = ["(전체)", "빌드대기", "슬롯부족", "줄넘침", "슬롯초과", "글자없음",
                  "선택지", "미번역", "적용됨", "수정됨", "게임에 일본어",
                  "검토후보", "문체혼합", "CSV열오류"]
        box = ttk.Combobox(top, textvariable=self.state_var, values=states,
                           width=10, state="readonly")
        box.pack(side="left", padx=(4, 14))
        box.bind("<<ComboboxSelected>>", lambda _e: self.refresh())

        ttk.Label(top, text="검색").pack(side="left")
        self.search_var = tk.StringVar()
        entry = ttk.Entry(top, textvariable=self.search_var, width=28)
        entry.pack(side="left", padx=4)
        entry.bind("<Return>", lambda _e: self.refresh())
        ttk.Button(top, text="찾기", command=self.refresh).pack(side="left", padx=(2, 14))

        self.count_label = ttk.Label(top, text="")
        self.count_label.pack(side="left")
        ttk.Button(top, text="저장", command=self.save).pack(side="right")
        ttk.Button(top, text="전체 내보내기", command=self.export).pack(side="right", padx=6)
        ttk.Button(top, text="다시 읽기", command=self.reload).pack(side="right")

        panes = ttk.PanedWindow(self.master, orient="vertical")
        panes.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        holder = ttk.Frame(panes)
        cols = ("n", "file", "japanese", "disc", "proposal", "review", "state")
        self.tree = ttk.Treeview(holder, columns=cols, show="headings", selectmode="browse")
        for key, title, width in (("n", "행번호", 70), ("file", "파일", 110),
                                  ("japanese", "원문", 320), ("disc", "V354 화면", 350),
                                  ("proposal", "내 수정안", 350), ("review", "검토", 70),
                                  ("state", "제약", 80)):
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, anchor="w",
                             stretch=(key in ("japanese", "disc", "proposal")))
        bar = ttk.Scrollbar(holder, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=bar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        bar.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        for tag, colour in (("줄넘침", "#ffd6d6"), ("슬롯초과", "#ffe8cc"),
                            ("글자없음", "#ffe8cc"),
                            ("수정됨", "#d8f0d8"),
                            ("선택지", "#ececec"), ("미번역", "#f0f0f0"),
                             ("빌드대기", "#d8ecff"), ("슬롯부족", "#ffe0e0"),
                             ("적용됨", "#ffffff"), ("일본어", "#ffd0d0"),
                             ("검토후보", "#fff3b8"), ("문체혼합", "#eee4ff"),
                             ("CSV열오류", "#ffcfdf")):
            self.tree.tag_configure(tag, background=colour)
        panes.add(holder, weight=3)

        lower = ttk.Frame(panes, padding=(0, 6))
        left = ttk.Frame(lower)
        left.pack(side="left", fill="both", expand=True)
        ttk.Label(left, text="원문").pack(anchor="w")
        self.jp = tk.Text(left, height=4, wrap="word", font=mono,
                          background="#f6f6f6", state="disabled")
        self.jp.pack(fill="x")
        ttk.Label(left, text="디스크 — 지금 게임에 나오는 문장").pack(anchor="w", pady=(6, 0))
        self.kr = tk.Text(left, height=3, wrap="word", font=mono,
                          background="#f0f4f8", state="disabled")
        self.kr.pack(fill="x")
        ttk.Label(left, text="수정제안  (Ctrl+Enter 적용)").pack(anchor="w", pady=(6, 0))
        self.edit = tk.Text(left, height=4, wrap="word", font=mono, undo=True)
        self.edit.pack(fill="x")
        self.edit.bind("<KeyRelease>", lambda _e: self.update_budget())
        self.edit.bind("<Control-Return>", lambda _e: (self.apply(), "break")[1])

        right = ttk.Frame(lower, padding=(12, 0, 0, 0))
        right.pack(side="right", fill="y")
        self.budget = tk.Text(right, width=50, height=20, font=mono,
                              background="#fbfbfb", state="disabled")
        self.budget.pack()
        row = ttk.Frame(right)
        row.pack(fill="x", pady=6)
        ttk.Button(row, text="적용", command=self.apply).pack(side="left")
        ttk.Button(row, text="되돌리기", command=self.revert).pack(side="left", padx=6)
        self.suggest_button = ttk.Button(row, text="공백 줄여 맞추기", command=self.take_suggestion)
        self.suggest_button.pack(side="left")
        ttk.Button(row, text="정리", command=self.tidy).pack(side="left", padx=6)
        panes.add(lower, weight=1)

        self.status = ttk.Label(self.master, anchor="w", padding=(8, 2))
        self.status.pack(fill="x")
        self.status.configure(
            text=f"기준: V354 {BUILD_SHA256[:8]}   코드맵 {len(self.table)}자   "
                 f"한 줄 < {ROW_PIXELS}px (일반 {NORMAL_ADVANCE}px, 공백 {SPACE_ADVANCE}px)   "
                 f"창 높이 = max(원문 줄 수, {MIN_WINDOW_ROWS})   "
                 "색: 노랑=표현 / 보라=문체 / 분홍=CSV 열 / 빨강·주황=제약")

    # ---------------------------------------------------------------- behaviour

    def capture_current(self) -> None:
        """Keep text typed in the edit box when the user changes rows or filters."""
        if self.current is None or not hasattr(self, "edit"):
            return
        self.current.proposal = self.edit.get("1.0", "end-1c").strip()

    def matches(self, line: Line) -> bool:
        if self.file_var.get() != "(전체)" and line.file != self.file_var.get():
            return False
        want = self.state_var.get()
        if want != "(전체)":
            if want == "수정됨":
                if line.proposal == line.korean:
                    return False
            elif want == "게임에 일본어":
                if line.disc != "(일본어 그대로)":
                    return False
            elif want == "검토후보":
                if not self.review_reasons(line, line.proposal):
                    return False
            elif want == "문체혼합":
                if not line.mixed_register:
                    return False
            elif want == "CSV열오류":
                if not line.csv_issue:
                    return False
            elif self.state_of(line) != want:
                return False
        needle = self.search_var.get().strip()
        if needle and needle not in line.japanese and needle not in line.korean \
                and needle not in line.proposal and needle not in line.disc \
                and needle not in " ".join(self.review_reasons(line, line.proposal)):
            return False
        return True

    def refresh(self) -> None:
        self.capture_current()
        self.recalculate_slot_plan()
        keep = self.current.n if self.current else None
        self.tree.delete(*self.tree.get_children())
        self.view = [l for l in self.lines if self.matches(l)]
        for line in self.view:
            state = self.state_of(line)
            # a line the game still draws in Japanese gets its own colour whatever its
            # state is: on screen it looks like Korean, because the kana cells now hold
            # Korean glyphs, and that has fooled us more than once
            review = self.review_kind(line, line.proposal)
            hard = state in {
                "줄넘침", "슬롯초과", "글자없음", "슬롯부족", "미번역"
            }
            tag = ("일본어" if line.disc == "(일본어 그대로)" else
                   "수정됨" if line.proposal != line.korean else
                   state if hard else
                   "CSV열오류" if review == "CSV" else
                   "문체혼합" if review == "문체" else
                   "검토후보" if review else state)
            self.tree.insert("", "end", iid=str(line.n), tags=(tag,), values=(
                line.n, line.file,
                line.japanese.replace("\n", " ⏎ ")[:110],
                line.disc[:110], line.proposal[:110], review, state))
        edited = sum(1 for l in self.lines if l.proposal != l.korean)
        notin = sum(1 for l in self.lines if self.state_of(l) in ("빌드대기", "슬롯부족"))
        review_count = sum(bool(self.review_reasons(l, l.proposal)) for l in self.lines)
        missing_chars = sorted({
            char
            for line in self.lines
            for char in self.measure(line, line.proposal)["missing"]
        })
        self.count_label.configure(
            text=f"보이는 줄 {len(self.view)} / 전체 {len(self.lines)}   "
                 f"수정 {edited}   검토 후보 {review_count}   "
                 f"미지원 글자 {len(missing_chars)}종   "
                 f"슬롯 부족 {len(self.slot_shortage)}   게임 미반영 {notin}")
        if keep is not None and str(keep) in self.tree.get_children():
            self.tree.selection_set(str(keep))

    def on_select(self, _event=None) -> None:
        picked = self.tree.selection()
        if not picked:
            return
        line = next((l for l in self.lines if l.n == int(picked[0])), None)
        if line is None:
            return
        if self.current is not None and self.current is not line:
            self.capture_current()
            self.recalculate_slot_plan()
        self.current = line
        for widget, text in ((self.jp, line.japanese), (self.kr, line.disc)):
            widget.configure(state="normal")
            widget.delete("1.0", "end")
            widget.insert("1.0", text)
            widget.configure(state="disabled")
        self.edit.delete("1.0", "end")
        self.edit.insert("1.0", line.proposal)
        self.update_budget()

    def update_budget(self) -> None:
        if self.current is None:
            return
        line, text = self.current, self.edit.get("1.0", "end-1c").strip()
        m = self.measure(line, text)
        plan = self.slot_plan_for_file(line.file, {line.n: text})
        balance = plan["balance"]
        baseline_balance = self.slot_balance.get(line.file, balance)
        balance_text = (f"{balance}개 남음" if balance >= 0
                        else f"{-balance}개 부족")
        slot_blocked = line.n in plan["shortage"]
        mark = lambda bad: "X" if bad else "o"
        report = [
            f"행번호      {line.n}",
            f"파일        {line.file} {line.offset}",
            f"안전 슬롯   수정안 후 {balance_text}",
            f"            용량 {plan['capacity']} / 물리 {SLOT_COUNT}",
            f"            고정 {plan['fixed']} + 보류 {plan['retained']}"
            f" + 일반 수요 {plan['ordinary_demand']}",
            "",
            f"{mark(m['over_rows'])} 줄       {m['need_rows']} / {m['window']} 줄"
            f"   (총 전진 {m['width']}px, 한 줄 < {ROW_PIXELS}px)",
            f"{mark(m['over_slot'])} 슬롯     {m['bytes']:>3} / {SLOT_TEXT_MAX:>3} 바이트",
            f"{mark(not m['fits_inline'] and slot_blocked)}"
            f" 제자리   {m['inline']:>3} / {line.capacity:>3} 바이트"
            f"   {'들어감' if m['fits_inline'] else '→ 기존/새 슬롯'}",
            f"{mark(bool(m['missing']))} 글자     "
            f"{'없는 글자: ' + ' '.join(m['missing']) if m['missing'] else '모두 있음'}",
            "",
        ]
        if not m["fits_inline"]:
            short = m["inline"] - line.capacity
            if (not any("가" <= char <= "힣" for char in text)
                    or m["missing"] or m["over_rows"] or m["over_slot"]):
                report.append("글자/줄/126바이트 제약을 먼저 해결해야 슬롯에 배정됩니다.")
            elif line.current_slot is not None and line.n in plan["assigned"]:
                report.append(f"이 줄은 현재 슬롯 {line.current_slot}을 유지합니다.")
                report.append(f"기존 슬롯 안에서는 최대 {SLOT_TEXT_MAX}바이트입니다.")
            elif line.n in plan["assigned"]:
                report.append("전체 수정안 기준으로 새 슬롯을 배정할 수 있습니다.")
                report.append(f"제자리에 넣으려면 {short}바이트 더 줄이면 됩니다.")
            else:
                report.append(f"전체 수정안 기준으로 슬롯이 {-balance}개 부족합니다.")
                report.append(f"→ {short}바이트만 줄이면 제자리에 들어갑니다.")
        elif m["fits_inline"]:
            report.append(f"제자리에 들어갑니다 (여유 {line.capacity - m['inline']}바이트).")
            if line.current_slot in self.safe_slots.get(line.file, set()):
                report.append("→ 현재 사용 중인 안전 슬롯 1개를 회수합니다.")
        delta = balance - baseline_balance
        if delta:
            report.append(
                f"실시간 변화: 이 입력으로 슬롯 {abs(delta)}개를 "
                f"{'회수' if delta > 0 else '추가 사용'}합니다."
            )
        report += [
            "",
        ]
        for note in explain_missing(m["missing"], text):
            report.extend(self.wrap_note(note))
        if line.is_choice:
            report.append("")
            report.extend(self.choice_fit(line, text))
            report.append("선택지는 E5/E6 위치를 고정해야 하므로 빌드 검사가 필수입니다.")
        if m["over_rows"]:
            report.append("창을 넘칩니다. 이 상태로 넣으면")
            report.append("그리다 멈춥니다. 줄이세요.")
        reasons = self.review_reasons(line, text)
        if reasons:
            report.append("")
            report.append("△ 자동 검토 후보 (정답 판정 아님)")
            for reason in reasons:
                report.extend(self.wrap_note("- " + reason))
        self.budget.configure(state="normal")
        self.budget.delete("1.0", "end")
        self.budget.insert("1.0", "\n".join(report))
        self.budget.configure(state="disabled")
        self.suggest_button.configure(state="normal" if m["over_rows"] else "disabled")

    @staticmethod
    def wrap_note(note: str, width: int = 42) -> list[str]:
        out, line = [], ""
        for word in note.split(" "):
            if len(line) + len(word) + 1 > width:
                out.append(line)
                line = word
            else:
                line = f"{line} {word}".strip()
        return out + ([line] if line else [])

    def tidy(self) -> None:
        """Take out what is not text: stray markers, control characters, smart quotes."""
        text = self.edit.get("1.0", "end-1c")

        text = re.sub(r"<CTRL:?[^>]*>", "", text)
        for bad, good in SUBSTITUTES.items():
            text = text.replace(bad, good)
        text = re.sub(r"[\n\r\f\v]+", " ", text)
        text = re.sub(r" {2,}", " ", text).strip()
        self.edit.delete("1.0", "end")
        self.edit.insert("1.0", text)
        self.update_budget()

    def export(self) -> None:
        """Every line in scene order, with what the game draws beside what the CSV says."""
        self.capture_current()
        self.recalculate_slot_plan()
        fields = ["행번호", "파일", "오프셋", "상태", "검토", "원문",
                  "디스크 (지금 게임)", "수정제안"]
        with EXPORT.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for line in self.lines:
                writer.writerow({"행번호": line.n, "파일": line.file, "오프셋": line.offset,
                                 "상태": self.state_of(line),
                                 "검토": " / ".join(self.review_reasons(line, line.proposal)),
                                 "원문": line.japanese,
                                 "디스크 (지금 게임)": line.disc, "수정제안": line.proposal})
        messagebox.showinfo("내보내기", f"{len(self.lines)}줄을 {EXPORT.name} 에 썼습니다.")

    def apply(self) -> None:
        if self.current is None:
            return
        self.current.proposal = self.edit.get("1.0", "end-1c").strip()
        self.refresh()
        self.update_budget()

    def revert(self) -> None:
        if self.current is None:
            return
        self.current.proposal = self.current.korean
        self.edit.delete("1.0", "end")
        self.edit.insert("1.0", self.current.proposal)
        self.refresh()
        self.update_budget()

    def take_suggestion(self) -> None:
        if self.current is None:
            return
        self.edit.delete("1.0", "end")
        self.edit.insert("1.0", self.suggest(self.current))
        self.update_budget()

    def save(self) -> None:
        # 저장 버튼은 현재 편집 상자의 글도 자동으로 적용한다. 별도의 '적용'
        # 버튼을 깜빡했다고 마지막 문장이 사라져서는 안 된다.
        self.capture_current()
        self.recalculate_slot_plan()
        changed = [l for l in self.lines if l.proposal != l.korean]
        # Both editors rewrite this file whole, from what they read at startup. If the
        # other one saved in the meantime, writing now would silently drop its work, so
        # refuse and say so rather than take the newer file's word for it.
        if TRANSLATED.stat().st_mtime_ns != self.loaded_at:
            messagebox.showerror(
                "저장 중단",
                "이 편집기를 연 뒤에 다른 곳에서 CSV가 바뀌었습니다. "
                "지금 저장하면 그 수정이 사라집니다. "
                "이 창을 닫고 다시 열어 주세요.")
            return
        if not changed:
            messagebox.showinfo("저장", "바뀐 줄이 없습니다.")
            return
        problems = {
            state: [line for line in changed if self.state_of(line) == state]
            for state in ("글자없음", "줄넘침", "슬롯초과", "슬롯부족")
        }
        problems = {state: rows for state, rows in problems.items() if rows}
        if problems and not messagebox.askyesno(
                "제약이 남은 초안 저장",
                " / ".join(f"{state} {len(rows)}줄" for state, rows in problems.items())
                + "\n\n게임에 바로 넣을 수 없는 초안이 포함됩니다. CSV에는 저장할까요?"):
            return
        backup = TRANSLATED.with_suffix(".csv.editor.bak")
        shutil.copy2(TRANSLATED, backup)
        for line, row in zip(self.lines, self.rows):
            row["korean"] = line.proposal
        temporary = TRANSLATED.with_suffix(".csv.editor.tmp")
        try:
            with temporary.open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=self.fieldnames)
                writer.writeheader()
                writer.writerows(self.rows)
            temporary.replace(TRANSLATED)
        finally:
            if temporary.exists():
                temporary.unlink()
        for line in self.lines:
            line.korean = line.proposal
        self.loaded_at = TRANSLATED.stat().st_mtime_ns
        self.refresh()
        messagebox.showinfo(
            "저장",
            f"{len(changed)}줄을 원본 번역 CSV의 한국어 열에 저장했습니다.\n"
            f"이전 파일: {backup.name}\n\n게임 반영은 다음 빌드에서 별도로 진행됩니다.")

    def close(self) -> None:
        self.capture_current()
        changed = sum(line.proposal != line.korean for line in self.lines)
        if changed and not messagebox.askyesno(
                "저장하지 않은 수정",
                f"저장하지 않은 수정이 {changed}줄 있습니다. 버리고 닫을까요?"):
            return
        self.master.destroy()


def self_test() -> None:
    editor = Editor.__new__(Editor)
    editor.load()
    assert len(editor.lines) == 2878
    assert editor.table[" "] == SPACE_CODE
    assert editor.table["."] == bytes((0x21,))
    assert editor.table["재"] == bytes.fromhex("DE 52")
    assert editor.table["괄"] == bytes((0xAB,))
    assert wrapped_rows(SPACE_CODE * 38) == 2       # exactly 228px is already a wrap
    assert wrapped_rows(editor.table["가"] * 16) == 1
    assert wrapped_rows(editor.table["가"] * 17) == 2
    missing = sorted({
        char
        for line in editor.lines
        for char in editor.measure(line, line.proposal)["missing"]
    })
    reviews = sum(bool(editor.review_reasons(line, line.proposal)) for line in editor.lines)
    csv_issues = sum(bool(line.csv_issue) for line in editor.lines)
    # 5/S5013 is the user-reported false 0/79 case.  The pristine disc has 48
    # translation-safe slots there.  Moving one currently slotted, buildable line back
    # inline must increase the live final-plan balance by exactly one.
    sample_file = "5/S5013.DAT"
    assert editor.slot_stats[sample_file]["capacity"] == 48
    sample = next(
        line for line in editor.lines_by_file[sample_file]
        if line.current_slot in editor.safe_slots[sample_file]
        and not editor.measure(line, line.proposal)["fits_inline"]
        and not editor.measure(line, line.proposal)["over_rows"]
        and not editor.measure(line, line.proposal)["over_slot"]
    )
    before = editor.slot_stats[sample_file]["balance"]
    after = editor.slot_plan_for_file(sample_file, {sample.n: "가"})["balance"]
    assert after == before + 1
    print(
        f"V354 dialogue editor PASS: rows={len(editor.lines)}, "
        f"encodable={len(editor.table)}, missing_unique={len(missing)}, "
        f"review_candidates={reviews}, csv_field_issues={csv_issues}, "
        f"slot_shortage={len(editor.slot_shortage)}, "
        f"{sample_file}_balance={before}/48"
    )


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()
    else:
        root = tk.Tk()
        Editor(root)
        root.mainloop()
