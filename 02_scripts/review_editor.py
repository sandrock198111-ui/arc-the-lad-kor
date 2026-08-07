"""A desktop editor for the translation, with the budgets that actually break the game.

The browser tool is replaced because it could not be worked in; this is a plain Tk
window, no server and no browser. Run it with:

    python 02_scripts/review_editor.py

Four columns, as asked: line number, the Japanese, the Korean the disc currently holds,
and an editable proposal. Everything else on screen exists to answer one question --
will this line fit -- and there are three ways for it not to.

  row budget    The one that froze save state 6. A row holds 228 pixels: a Korean glyph
                advances 12 and a space 6, measured off the framebuffer of two save
                states -- the wrap in `21/S2041.DAT` breaks after 진행되 at exactly 228
                and would need 240 for the next glyph. The window is at least three rows
                and never fewer than the original Japanese needed, so the budget is
                `max(original rows, 3)`. Past that the renderer fills the window and
                stops, and the game does not come back. E6 is drawn rather than obeyed
                inside an external slot, so line breaks cannot buy a row back; only
                shortening works.

                The three-row floor is inferred, not read out of the code: it is the
                narrowest rule that fits every line observed in game, including one the
                user confirmed renders correctly on a two-row original. Nine lines in
                the current build exceed it.

  byte budget   A line is written into the bytes the Japanese occupied. If it no longer
                fits it must take an external slot, and a slot holds 126 bytes of text
                -- 128 less the terminator and the completion metadata.

  the alphabet  Not every character has a glyph, and a glyph the classifier cannot
                reach is worse than none: it draws twelve rows of some other cell. The
                encoder is read out of the built archive, so what it says is what the
                disc can do.

The proposal column starts as a copy of the Korean. Where a line is over the row budget
the tool offers a mechanical suggestion -- the same words with the spaces the renderer
does not need -- which is a starting point, not an answer; read it before taking it.
Saving writes only the Korean column, and keeps the previous file as `.editor.bak`.
"""
from __future__ import annotations

import csv
import re
import shutil
import sys
import tkinter as tk
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from tkinter import font as tkfont, messagebox, ttk

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from plan_bulk_insertion import (  # noqa: E402
    CHOICE, LOOKUP_SRC, RAM_TO_FILE, SLOT_BASE, SLOT_COUNT, SLOT_SIZE, SLOT_TEXT_MAX,
    bitmap, build_encoder, drawable, encode, has_marker, tokens,
)

TRANSLATED = ROOT / "05_docs/script_translated_full.csv"
ORIGINAL = ROOT / "05_docs/script_original_full.csv"
PRISTINE = ROOT / "00_original/arc.zip"
EXPORT = ROOT / "05_docs/dialogue_all.csv"
ROW_PIXELS = 228           # measured off the framebuffer, not assumed
SPACE = 0x9C
MIN_WINDOW_ROWS = 3


# A character with no code is not one problem but four, and they need different answers.
SUBSTITUTES = {"‘": "'", "’": "'", "“": '"', "”": '"', "–": "-", "—": "-"}
OVERWRITTEN = {"R": "DF 03"}    # the original drew it at index 732; a Korean syllable sits there now


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
    return 6 if len(token) == 1 and token[0] == SPACE else 12


def wrapped_rows(payload: bytes) -> int:
    rows, x = 1, 0
    for token in tokens(payload):
        if x + advance(token) > ROW_PIXELS:
            rows, x = rows + 1, 0
        x += advance(token)
    return rows


def newest_build() -> Path:
    found = sorted((ROOT / "03_output").glob("arc1_v1*.zip"), key=lambda p: p.stat().st_mtime)
    if not found:
        raise SystemExit("no arc1_v1*.zip in 03_output to read the alphabet from")
    return found[-1]


class Line:
    __slots__ = ("n", "file", "offset", "japanese", "korean", "proposal", "disc",
                 "capacity", "rows", "is_choice", "raw", "redirected")

    def __init__(self, n, row, raw, rows, disc=""):
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


class Editor:
    def __init__(self, master: tk.Tk) -> None:
        self.master = master
        master.title("Arc the Lad 1 - 번역 편집기")
        master.geometry("1500x880")

        self.load()
        self.view: list[Line] = []
        self.current: Line | None = None
        self._build_widgets()
        self.refresh()

    def load(self) -> None:
        """Read the CSV and the newest build. Called again by 다시 읽기."""
        build = newest_build()
        with zipfile.ZipFile(build) as archive:
            exe, font = archive.read("PSX.EXE"), archive.read("COMM.IMG")
            self.exe = exe
            self.table = build_encoder(exe, font)
            blobs = {n: archive.read(n) for n in archive.namelist() if n.upper().endswith(".DAT")}
        with zipfile.ZipFile(PRISTINE) as pristine:
            originals = {n: pristine.read(n) for n in pristine.namelist() if n in blobs}
        self.build_name = build.name
        # the encoder read backwards, so the disc column and the edit box speak the
        # same language: whatever the builder can write, this can read
        self.back = {code: char for char, code in self.table.items()}
        self.back[bytes((0x9C,))] = " "

        # how much room each file has left, so "needs a slot" can be told apart from
        # "needs a slot and there is none" -- the first is a build away, the second
        # is editing work in that file
        self.free_slots: dict[str, int] = {}
        for name, blob in blobs.items():
            if len(blob) < SLOT_BASE + SLOT_COUNT * SLOT_SIZE:
                self.free_slots[name] = 0
                continue
            self.free_slots[name] = sum(
                1 for s in range(SLOT_COUNT)
                if not any(blob[SLOT_BASE + s * SLOT_SIZE:SLOT_BASE + (s + 1) * SLOT_SIZE]))

        raws: dict[tuple[str, str], bytes] = {}
        seen: dict[bytes, Counter] = defaultdict(Counter)
        with ORIGINAL.open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
            for row in reader:
                raw = bytes.fromhex(row["raw bytes as hex"].replace(" ", ""))
                raws[(row["source file"], str(int(row[key], 0)))] = raw
                # Learn what the untranslatable codes draw by aligning the original
                # script's bytes against its own decoded text. Punctuation and kana are
                # not in the Hangul table, so without this the disc column is littered
                # with <E060> where the game simply draws a dot.
                text = row["decoded Japanese"] or ""
                if "<" in text:
                    continue
                i, pairs, ok = 0, [], True
                for token in tokens(raw):
                    if token == bytes((0xE6, 0x01)):
                        if i < len(text) and text[i] == chr(10):
                            i += 1
                            continue
                        ok = False
                        break
                    if len(token) == 1 and token[0] == 0:
                        break
                    if i >= len(text):
                        ok = False
                        break
                    pairs.append((token, text[i]))
                    i += 1
                if ok and i == len(text):
                    for token, char in pairs:
                        seen[token][char] += 1
        for token, counter in seen.items():
            self.back.setdefault(token, counter.most_common(1)[0][0])

        # The same glyph often sits in several cells, and the encoder only ever hands
        # out one of them. A code pointing at a duplicate has no name and used to show
        # as <E060> -- which is the full stop the builder itself writes. Resolve those
        # by picture: if an unnamed code draws exactly what a named one draws, it is
        # that character.
        by_picture = {}
        for char, code in self.table.items():
            index = self.index_of(code)
            if index is None:
                continue
            bits = bitmap(exe, font, index)
            if bits and any(bits):
                by_picture.setdefault(bits, char)
        # Two punctuation cells the game draws centred rather than left-aligned, so
        # they are not the same picture as the encoder's own . and ! and cannot be
        # matched that way. Earlier builds wrote text with them, which is why the disc
        # column showed <E060> where the screen simply shows a full stop.
        self.back.setdefault(bytes((0xE0, 0x60)), ".")
        self.back.setdefault(bytes((0xDF, 0xE3)), "!")

        for code in list(self.codes()):
            if code in self.back:
                continue
            index = self.index_of(code)
            if index is None or not drawable(exe, index):
                continue
            bits = bitmap(exe, font, index)
            if bits and (char := by_picture.get(bits)):
                self.back[code] = char

        self.loaded_at = TRANSLATED.stat().st_mtime_ns
        with TRANSLATED.open(encoding="utf-8-sig", newline="") as handle:
            self.fieldnames = (reader := csv.DictReader(handle)).fieldnames
            self.rows = list(reader)
        self.lines = []
        for n, row in enumerate(self.rows, start=1):
            name = row["source file"]
            raw = raws.get((name, str(int(row["offset"], 0))), b"")
            rows_ = sum(1 for t in tokens(raw) if t == b"\xE6\x01") + 1 if raw else 1
            disc, redirected = "", False
            if raw and name in blobs and name in originals:
                offset = int(row["offset"], 0)
                disc = self.read_disc(blobs[name], originals[name], offset, raw)
                redirected = blobs[name][offset] == 0xE2
            line = Line(n, row, raw, rows_, disc)
            line.redirected = redirected
            self.lines.append(line)

    def codes(self):
        for c in range(0x01, 0xDD):
            yield bytes((c,))
        for lead in range(0xDD, 0xE9):
            for trail in range(0x01, 0xFF):
                yield bytes((lead, trail))
        for slot in range(508):
            yield bytes((0xE9 + slot // 254, slot % 254 + 1))

    def index_of(self, code: bytes):
        """The font index a code resolves to, by the decoder's own arithmetic."""
        if len(code) == 1:
            return code[0] - 1
        if code[0] in (0xE9, 0xEA):
            slot = 254 * (code[0] - 0xE9) + code[1] - 1
            if not 0 <= slot < 508:
                return None
            at = LOOKUP_SRC - RAM_TO_FILE + slot * 2
            return int.from_bytes(self.exe[at:at + 2], "little")
        if 0xDD <= code[0] <= 0xE8:
            return (code[0] - 0xDD) * 255 + code[1] + 0xDB
        return None

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
        self.status.configure(text=f"다시 읽음 — {self.build_name}   "
                                   f"한 줄 {ROW_PIXELS}px, 창 높이 max(원문 줄 수, {MIN_WINDOW_ROWS})")

    # ---------------------------------------------------------------- measuring

    def decode(self, payload: bytes) -> str:
        out = []
        for token in tokens(payload):
            if len(token) == 1 and token[0] == 0:
                break
            if token[0] == CHOICE or token == bytes((0xE6, 0x01)):
                out.append("|")
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
                    if token[0] == CHOICE or token == bytes((0xE6, 0x01)):
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
        """For a choice body, how each phrase measures against its own run.

        A choice body is written where it stands -- the E5 and E6 bytes must not move
        or the menu cursor drifts off the option it points at -- so each phrase has to
        fit the bytes the Japanese phrase occupied. There is no slot to escape to and
        no room to grow, which is why these need shortening rather than rewording.
        """
        runs, position, start, length = [], 0, 0, 0
        for token in tokens(line.raw):
            if len(token) == 1 and token[0] == 0:
                break
            if token[0] == CHOICE or token == bytes((0xE6, 0x01)):
                if length:
                    runs.append(length)
                position += len(token)
                start, length = position, 0
                continue
            position += len(token)
            length += len(token)
        if length:
            runs.append(length)
        parts = [p.strip() for p in text.split("|")]
        out = [f"선택지 {len(runs)}칸 / 수정안 {len(parts)}칸"
               + ("" if len(parts) == len(runs) else "   <-- | 개수를 맞추세요")]
        for i, room in enumerate(runs):
            phrase = parts[i] if i < len(parts) else ""
            payload, missing = encode(phrase, self.table, keep_breaks=False)
            mark = "X" if (missing or len(payload) > room) else "o"
            out.append(f"  {mark} {len(payload):>3}/{room:<3} {phrase[:20]}")
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
        if m["fits_inline"] or line.redirected or self.free_slots.get(line.file, 0) > 0:
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
                  "선택지", "미번역", "적용됨", "수정됨", "게임에 일본어"]
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
        cols = ("n", "file", "japanese", "disc", "proposal", "state")
        self.tree = ttk.Treeview(holder, columns=cols, show="headings", selectmode="browse")
        for key, title, width in (("n", "행번호", 70), ("file", "파일", 110),
                                  ("japanese", "원문", 360), ("disc", "디스크 (지금 게임)", 400),
                                  ("proposal", "수정제안", 400), ("state", "상태", 80)):
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, anchor="w",
                             stretch=(key in ("japanese", "disc", "proposal")))
        bar = ttk.Scrollbar(holder, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=bar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        bar.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        for tag, colour in (("줄넘침", "#ffd6d6"), ("슬롯초과", "#ffe8cc"),
                            ("글자없음", "#ffe8cc"), ("수정됨", "#d8f0d8"),
                            ("선택지", "#ececec"), ("미번역", "#f0f0f0"),
                            ("빌드대기", "#d8ecff"), ("슬롯부족", "#ffe0e0"),
                            ("적용됨", "#ffffff"), ("일본어", "#ffd0d0")):
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
        self.budget = tk.Text(right, width=44, height=13, font=mono,
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
        self.status.configure(text=f"알파벳 출처: {self.build_name}   한 줄 {ROW_PIXELS}px (한글 12px, 공백 6px)   창 높이 = max(원문 줄 수, {MIN_WINDOW_ROWS})")

    # ---------------------------------------------------------------- behaviour

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
            elif self.state_of(line) != want:
                return False
        needle = self.search_var.get().strip()
        if needle and needle not in line.japanese and needle not in line.korean \
                and needle not in line.proposal:
            return False
        return True

    def refresh(self) -> None:
        keep = self.current.n if self.current else None
        self.tree.delete(*self.tree.get_children())
        self.view = [l for l in self.lines if self.matches(l)]
        for line in self.view:
            state = self.state_of(line)
            # a line the game still draws in Japanese gets its own colour whatever its
            # state is: on screen it looks like Korean, because the kana cells now hold
            # Korean glyphs, and that has fooled us more than once
            tag = ("일본어" if line.disc == "(일본어 그대로)" else
                   "수정됨" if line.proposal != line.korean else state)
            self.tree.insert("", "end", iid=str(line.n), tags=(tag,), values=(
                line.n, line.file,
                line.japanese.replace("\n", " ⏎ ")[:110],
                line.disc[:110], line.proposal[:110], state))
        edited = sum(1 for l in self.lines if l.proposal != l.korean)
        notin = sum(1 for l in self.lines if self.state_of(l) in ("빌드대기", "슬롯부족"))
        self.count_label.configure(
            text=f"보이는 줄 {len(self.view)} / 전체 {len(self.lines)}   "
                 f"수정 {edited}   아직 게임에 안 들어간 줄 {notin}")
        if keep is not None and str(keep) in self.tree.get_children():
            self.tree.selection_set(str(keep))

    def on_select(self, _event=None) -> None:
        picked = self.tree.selection()
        if not picked:
            return
        line = next((l for l in self.lines if l.n == int(picked[0])), None)
        if line is None:
            return
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
        mark = lambda bad: "X" if bad else "o"
        report = [
            f"행번호      {line.n}",
            f"파일        {line.file} {line.offset}",
            "",
            f"{mark(m['over_rows'])} 줄       {m['need_rows']} / {m['window']} 줄"
            f"   (폭 {m['width']}px, 한 줄 {ROW_PIXELS}px)",
            f"{mark(m['over_slot'])} 슬롯     {m['bytes']:>3} / {SLOT_TEXT_MAX:>3} 바이트",
            # o only when this line has somewhere to go: it fits where the Japanese
            # sat, or the file still has a slot to send it to. A line that fits
            # neither is stuck, and marking it o was hiding exactly that.
            f"{mark(not m['fits_inline'] and self.free_slots.get(line.file, 0) == 0)}"
            f" 제자리   {m['inline']:>3} / {line.capacity:>3} 바이트"
            f"   {'들어감' if m['fits_inline'] else '→ 슬롯 사용'}",
            f"{mark(bool(m['missing']))} 글자     "
            f"{'없는 글자: ' + ' '.join(m['missing']) if m['missing'] else '모두 있음'}",
            "",
        ]
        # The number that actually decides the line's fate: how much has to go before it
        # fits where the Japanese sat. A line that needs a slot in a file with none is
        # stuck until this reaches zero, and until now the reader had to subtract by hand.
        room = self.free_slots.get(line.file, 0)
        if not m["fits_inline"]:
            short = m["inline"] - line.capacity
            if room > 0:
                report.append(f"슬롯을 씁니다 (이 파일 빈 슬롯 {room}개).")
                report.append(f"제자리에 넣으려면 {short}바이트 더 줄이면 됩니다.")
            else:
                report.append(f"이 파일에 빈 슬롯이 없습니다.")
                report.append(f"→ {short}바이트만 줄이면 제자리에 들어갑니다.")
        elif m["fits_inline"]:
            report.append(f"제자리에 들어갑니다 (여유 {line.capacity - m['inline']}바이트).")
        report += [
            "",
        ]
        for note in explain_missing(m["missing"], text):
            report.extend(self.wrap_note(note))
        if line.is_choice:
            report.append("")
            report.extend(self.choice_fit(line, text))
        if m["over_rows"]:
            report.append("창을 넘칩니다. 이 상태로 넣으면")
            report.append("그리다 멈춥니다. 줄이세요.")
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
        fields = ["행번호", "파일", "오프셋", "상태", "원문", "디스크 (지금 게임)", "수정제안"]
        with EXPORT.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for line in self.lines:
                writer.writerow({"행번호": line.n, "파일": line.file, "오프셋": line.offset,
                                 "상태": self.state_of(line), "원문": line.japanese,
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
        broken = [l for l in changed if self.state_of(l) == "줄넘침"]
        if broken and not messagebox.askyesno(
                "저장", f"{len(broken)}줄이 아직 창을 넘칩니다. 그대로 저장할까요?"):
            return
        backup = TRANSLATED.with_suffix(".csv.editor.bak")
        shutil.copy2(TRANSLATED, backup)
        for line, row in zip(self.lines, self.rows):
            row["korean"] = line.proposal
            line.korean = line.proposal
        with TRANSLATED.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=self.fieldnames)
            writer.writeheader()
            writer.writerows(self.rows)
        self.loaded_at = TRANSLATED.stat().st_mtime_ns
        self.refresh()
        messagebox.showinfo("저장", f"{len(changed)}줄 저장했습니다.\n이전 파일: {backup.name}")


if __name__ == "__main__":
    root = tk.Tk()
    Editor(root)
    root.mainloop()
