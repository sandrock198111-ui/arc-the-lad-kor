"""The lines that are NOT on the disc, and why, in one place.

    python 02_scripts/review_not_applied.py

The main editor shows the CSV. This one shows the gap between the CSV and the game: it
decodes what each line actually holds in the newest build and lists only the lines where
the two disagree. That is the list to work from, because a line that never went in reads
in the editor exactly like one that did -- which is how an edit could look applied while
the game still showed the old sentence.

Every line here carries the reason it did not go in, and there are only three:

  선택지(E5)     The body mixes prose with menu choices. Bulk insertion refuses these on
                 purpose: a whole-body relocation puts the menu cursor on a different
                 row from the text. They need the row-by-row repair, which does not
                 exist yet, so no amount of rewriting will get them in today.

  슬롯 부족       The line no longer fits where the Japanese sat, so it needs an external
  / 창 넘침       slot, and its file has none left -- or it fits but needs more rows than
                 the dialogue window has, which freezes the renderer. Shortening fixes
                 both, and the panel says how much.

  글자없음        A character has no glyph. Sometimes that is a stray control marker or a
                 smart quote and 정리 clears it; sometimes the glyph was overwritten, or
                 never existed, and the sentence has to avoid it.

`디스크` is what the game draws right now, decoded from the built archive with the same
table the builder writes with. `수정안` starts from the CSV -- your text -- so the two
columns side by side are the before and after you are actually choosing between.
"""
from __future__ import annotations

import csv
import re
import shutil
import sys
import tkinter as tk
import zipfile
from pathlib import Path
from tkinter import font as tkfont, messagebox, ttk

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from plan_bulk_insertion import (  # noqa: E402
    CHOICE, SLOT_BASE, SLOT_COUNT, SLOT_SIZE, SLOT_TEXT_MAX,
    build_encoder, encode, has_marker, tokens,
)
from review_editor import (  # noqa: E402
    MIN_WINDOW_ROWS, ROW_PIXELS, SUBSTITUTES, advance, explain_missing, newest_build,
    wrapped_rows,
)

TRANSLATED = ROOT / "05_docs/script_translated_full.csv"
ORIGINAL = ROOT / "05_docs/script_original_full.csv"
PRISTINE = ROOT / "00_original/arc.zip"
EXPORT = ROOT / "05_docs/not_applied.csv"

CHOICE_REASON = "선택지(E5)"
SPACE_REASON = "슬롯 부족 / 창 넘침"


def normalise(text: str) -> str:
    """Compare wording, not punctuation of structure.

    The CSV separates menu options with `|`; the disc separates them with a line break
    and a choice marker. Counting that as a difference reported 201 lines as missing
    while the game was already drawing them -- 169 of the choice bodies among them.
    """
    return re.sub(r"[|\s]+", "", text)


class Line:
    __slots__ = ("n", "file", "offset", "japanese", "csv", "disc", "reason",
                 "proposal", "capacity", "rows", "missing")

    def __init__(self, n, row, raw, rows, disc, reason, missing):
        self.n, self.file, self.offset = n, row["source file"], row["offset"]
        self.japanese = row["japanese"] or ""
        self.csv = (row["korean"] or "").strip()
        self.proposal = self.csv
        self.disc, self.reason, self.missing = disc, reason, missing
        self.capacity, self.rows = len(raw), rows


class NotApplied:
    def __init__(self, master: tk.Tk) -> None:
        self.master = master
        master.title("Arc the Lad 1 - 아직 못 넣은 줄")
        master.geometry("1560x900")

        build = newest_build()
        self.build_name = build.name
        with zipfile.ZipFile(build) as archive:
            names = set(archive.namelist())
            self.table = build_encoder(archive.read("PSX.EXE"), archive.read("COMM.IMG"))
            blobs = {n: archive.read(n) for n in names if n.upper().endswith(".DAT")}
        with zipfile.ZipFile(PRISTINE) as pristine:
            originals = {n: pristine.read(n) for n in pristine.namelist() if n in blobs}
        # the encoder read backwards: whatever the builder can write, this can read
        self.back = {code: char for char, code in self.table.items()}
        self.back[bytes((0x9C,))] = " "

        raws: dict[tuple[str, int], bytes] = {}
        with ORIGINAL.open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
            for row in reader:
                raws[(row["source file"], int(row[key], 0))] = bytes.fromhex(
                    row["raw bytes as hex"].replace(" ", ""))

        self.loaded_at = TRANSLATED.stat().st_mtime_ns
        with TRANSLATED.open(encoding="utf-8-sig", newline="") as handle:
            self.fieldnames = (reader := csv.DictReader(handle)).fieldnames
            self.all_rows = list(reader)

        self.lines: list[Line] = []
        self.row_of: dict[int, dict] = {}
        for n, row in enumerate(self.all_rows, start=1):
            korean = (row["korean"] or "").strip()
            if not korean or not any("가" <= c <= "힣" for c in korean):
                continue
            name, offset = row["source file"], int(row["offset"], 0)
            raw = raws.get((name, offset))
            if raw is None or name not in blobs or name not in originals:
                continue
            blob, original = blobs[name], originals[name]
            disc = self.read_disc(blob, original, offset, raw)
            if normalise(disc) == normalise(korean):
                continue
            _, missing = encode(korean, self.table, keep_breaks=False)
            if has_marker(raw, CHOICE):
                reason = CHOICE_REASON
            elif missing:
                reason = "글자없음: " + " ".join(sorted(set(missing))).replace("\n", "\\n")
            else:
                reason = SPACE_REASON
            rows_ = sum(1 for t in tokens(raw) if t == b"\xE6\x01") + 1
            self.lines.append(Line(n, row, raw, rows_, disc, reason, sorted(set(missing))))
            self.row_of[n] = row

        self.view: list[Line] = []
        self.current: Line | None = None
        self._build_widgets()
        self.refresh()

    # ---------------------------------------------------------------- reading

    def decode(self, payload: bytes) -> str:
        """Read the bytes back as text, writing the structure the way the CSV writes it.

        A line break and a choice marker both become `|`, which is what the CSV uses
        between menu options, so the two columns can be read against each other.
        """
        out = []
        for token in tokens(payload):
            if len(token) == 1 and token[0] == 0:
                break
            if token[0] == CHOICE or token == b"\xE6\x01":
                out.append("|")
                continue
            out.append(self.back.get(token, f"<{token.hex().upper()}>"))
        return re.sub(r"\|+", "|", "".join(out)).strip().strip("|")

    def read_disc(self, blob: bytes, original: bytes, offset: int, raw: bytes) -> str:
        """What the game draws here: the body, or the slot the body redirects to."""
        if blob[offset:offset + len(raw)] == original[offset:offset + len(raw)]:
            return "(일본어 그대로)"
        if blob[offset] != 0xE2:
            return self.decode(blob[offset:offset + len(raw)])
        slot = blob[offset + 1] - (0x81 if blob[offset + 1] < 0xA9 else 0x82)
        if not 0 <= slot < SLOT_COUNT or len(blob) < SLOT_BASE + SLOT_COUNT * SLOT_SIZE:
            return "(슬롯 번호가 범위 밖)"
        seg = blob[SLOT_BASE + slot * SLOT_SIZE:SLOT_BASE + (slot + 1) * SLOT_SIZE]
        return self.decode(seg[:seg.index(0)] if 0 in seg[:SLOT_SIZE - 1] else seg[:SLOT_SIZE - 1])

    def measure(self, line: Line, text: str) -> dict:
        payload, missing = encode(text, self.table, keep_breaks=False)
        inline, _ = encode(text, self.table, keep_breaks=True)
        window = max(line.rows, MIN_WINDOW_ROWS)
        need = wrapped_rows(payload) if payload else 0
        fits_inline = len(inline) <= line.capacity
        return {"missing": sorted(set(missing)), "bytes": len(payload), "inline": len(inline),
                "width": sum(advance(t) for t in tokens(payload)), "need_rows": need,
                "window": window, "fits_inline": fits_inline,
                "over_slot": (not fits_inline) and len(payload) > SLOT_TEXT_MAX,
                "over_rows": need > window}

    def solved(self, line: Line) -> bool:
        """Would this text go in now? Choice bodies never would, whatever it says."""
        if line.reason == CHOICE_REASON:
            return False
        m = self.measure(line, line.proposal)
        return not (m["missing"] or m["over_rows"] or m["over_slot"])

    # ---------------------------------------------------------------- widgets

    def _build_widgets(self) -> None:
        mono = tkfont.Font(family="Consolas", size=10)
        top = ttk.Frame(self.master, padding=6)
        top.pack(fill="x")
        ttk.Label(top, text="이유").pack(side="left")
        self.reason_var = tk.StringVar(value="(전체)")
        box = ttk.Combobox(top, textvariable=self.reason_var, width=18, state="readonly",
                           values=["(전체)", SPACE_REASON, CHOICE_REASON, "글자없음",
                                   "지금 넣을 수 있음"])
        box.pack(side="left", padx=(4, 14))
        box.bind("<<ComboboxSelected>>", lambda _e: self.refresh())
        ttk.Label(top, text="파일").pack(side="left")
        self.file_var = tk.StringVar(value="(전체)")
        files = ["(전체)"] + sorted({l.file for l in self.lines})
        fbox = ttk.Combobox(top, textvariable=self.file_var, values=files, width=16,
                            state="readonly")
        fbox.pack(side="left", padx=(4, 14))
        fbox.bind("<<ComboboxSelected>>", lambda _e: self.refresh())
        ttk.Label(top, text="검색").pack(side="left")
        self.search_var = tk.StringVar()
        entry = ttk.Entry(top, textvariable=self.search_var, width=26)
        entry.pack(side="left", padx=4)
        entry.bind("<Return>", lambda _e: self.refresh())
        ttk.Button(top, text="찾기", command=self.refresh).pack(side="left", padx=(2, 14))
        self.count = ttk.Label(top, text="")
        self.count.pack(side="left")
        ttk.Button(top, text="저장", command=self.save).pack(side="right")
        ttk.Button(top, text="목록 내보내기", command=self.export).pack(side="right", padx=6)

        panes = ttk.PanedWindow(self.master, orient="vertical")
        panes.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        holder = ttk.Frame(panes)
        cols = ("n", "file", "reason", "japanese", "disc", "proposal")
        self.tree = ttk.Treeview(holder, columns=cols, show="headings", selectmode="browse")
        for key, title, width, stretch in (
                ("n", "행번호", 70, False), ("file", "파일", 110, False),
                ("reason", "안 들어간 이유", 150, False), ("japanese", "원문", 320, True),
                ("disc", "디스크 (지금 게임)", 360, True), ("proposal", "수정안", 360, True)):
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, anchor="w", stretch=stretch)
        bar = ttk.Scrollbar(holder, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=bar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        bar.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.tag_configure("해결", background="#d8f0d8")
        self.tree.tag_configure(CHOICE_REASON, background="#ececec")
        self.tree.tag_configure("글자없음", background="#ffe8cc")
        self.tree.tag_configure(SPACE_REASON, background="#ffd6d6")
        panes.add(holder, weight=3)

        lower = ttk.Frame(panes, padding=(0, 6))
        left = ttk.Frame(lower)
        left.pack(side="left", fill="both", expand=True)
        ttk.Label(left, text="원문").pack(anchor="w")
        self.jp = tk.Text(left, height=3, wrap="word", font=mono, background="#f6f6f6",
                          state="disabled")
        self.jp.pack(fill="x")
        ttk.Label(left, text="디스크 — 지금 게임에 나오는 문장").pack(anchor="w", pady=(6, 0))
        self.disc = tk.Text(left, height=3, wrap="word", font=mono, background="#f0f4f8",
                            state="disabled")
        self.disc.pack(fill="x")
        ttk.Label(left, text="수정안  (Ctrl+Enter 적용)").pack(anchor="w", pady=(6, 0))
        self.edit = tk.Text(left, height=4, wrap="word", font=mono, undo=True)
        self.edit.pack(fill="x")
        self.edit.bind("<KeyRelease>", lambda _e: self.update_panel())
        self.edit.bind("<Control-Return>", lambda _e: (self.apply(), "break")[1])

        right = ttk.Frame(lower, padding=(12, 0, 0, 0))
        right.pack(side="right", fill="y")
        self.panel = tk.Text(right, width=46, height=14, font=mono, background="#fbfbfb",
                             state="disabled")
        self.panel.pack()
        buttons = ttk.Frame(right)
        buttons.pack(fill="x", pady=6)
        ttk.Button(buttons, text="적용", command=self.apply).pack(side="left")
        ttk.Button(buttons, text="CSV값", command=lambda: self.load(False)).pack(side="left", padx=4)
        ttk.Button(buttons, text="디스크값", command=lambda: self.load(True)).pack(side="left")
        ttk.Button(buttons, text="정리", command=self.tidy).pack(side="left", padx=4)
        self.fit = ttk.Button(buttons, text="공백 줄여 맞추기", command=self.shrink)
        self.fit.pack(side="left")
        panes.add(lower, weight=1)

        self.status = ttk.Label(self.master, anchor="w", padding=(8, 2))
        self.status.pack(fill="x")
        self.status.configure(text=f"디스크 출처: {self.build_name}   "
                                   f"한 줄 {ROW_PIXELS}px, 창 높이 max(원문 줄 수, {MIN_WINDOW_ROWS})")

    # ---------------------------------------------------------------- behaviour

    def matches(self, line: Line) -> bool:
        want = self.reason_var.get()
        if want == "지금 넣을 수 있음":
            if not self.solved(line):
                return False
        elif want != "(전체)" and not line.reason.startswith(want):
            return False
        if self.file_var.get() != "(전체)" and line.file != self.file_var.get():
            return False
        needle = self.search_var.get().strip()
        if needle and needle not in line.japanese and needle not in line.disc \
                and needle not in line.proposal:
            return False
        return True

    def refresh(self) -> None:
        keep = self.current.n if self.current else None
        self.tree.delete(*self.tree.get_children())
        self.view = [l for l in self.lines if self.matches(l)]
        for line in self.view:
            tag = "해결" if self.solved(line) else line.reason.split(":")[0]
            self.tree.insert("", "end", iid=str(line.n), tags=(tag,), values=(
                line.n, line.file, line.reason,
                line.japanese.replace("\n", " ⏎ ")[:110],
                line.disc[:110], line.proposal[:110]))
        ready = sum(1 for l in self.lines if self.solved(l))
        self.count.configure(text=f"보이는 줄 {len(self.view)} / 못 넣은 줄 {len(self.lines)}"
                                  f"   지금 넣을 수 있음 {ready}")
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
        for widget, text in ((self.jp, line.japanese), (self.disc, line.disc)):
            widget.configure(state="normal")
            widget.delete("1.0", "end")
            widget.insert("1.0", text)
            widget.configure(state="disabled")
        self.edit.delete("1.0", "end")
        self.edit.insert("1.0", line.proposal)
        self.update_panel()

    def update_panel(self) -> None:
        if self.current is None:
            return
        line, text = self.current, self.edit.get("1.0", "end-1c").strip()
        m = self.measure(line, text)
        mark = lambda bad: "X" if bad else "o"
        report = [
            f"행번호      {line.n}",
            f"파일        {line.file} {line.offset}",
            f"안 들어간 이유",
            f"  {line.reason}",
            "",
            f"{mark(m['over_rows'])} 줄       {m['need_rows']} / {m['window']} 줄"
            f"   (폭 {m['width']}px)",
            f"{mark(m['over_slot'])} 슬롯     {m['bytes']:>3} / {SLOT_TEXT_MAX} 바이트",
            f"{mark(False)} 제자리   {m['inline']:>3} / {line.capacity} 바이트"
            f"  {'들어감' if m['fits_inline'] else '→ 슬롯 필요'}",
            f"{mark(bool(m['missing']))} 글자     "
            f"{'없는 글자: ' + ' '.join(m['missing']) if m['missing'] else '모두 있음'}",
            "",
        ]
        for note in explain_missing(m["missing"], text):
            report.extend(self.wrap(note))
        if line.reason == CHOICE_REASON:
            report += self.wrap("선택지 본문은 문장을 고쳐도 지금은 못 넣습니다."
                                " 줄 단위 수리가 만들어져야 합니다.")
        elif self.solved(line):
            report.append("이제 들어갑니다. 저장 후 다시 빌드하세요.")
        elif line.reason == SPACE_REASON and not m["over_rows"] and not m["over_slot"]:
            report += self.wrap("길이는 맞습니다. 이 파일에 빈 슬롯이 없어서"
                                " 밀린 줄이라, 같은 파일의 다른 줄을 줄이면 자리가 납니다.")
        self.panel.configure(state="normal")
        self.panel.delete("1.0", "end")
        self.panel.insert("1.0", "\n".join(report))
        self.panel.configure(state="disabled")
        self.fit.configure(state="normal" if m["over_rows"] else "disabled")

    @staticmethod
    def wrap(note: str, width: int = 44) -> list[str]:
        out, line = [], ""
        for word in note.split(" "):
            if len(line) + len(word) + 1 > width:
                out.append(line)
                line = word
            else:
                line = f"{line} {word}".strip()
        return out + ([line] if line else [])

    def load(self, from_disc: bool) -> None:
        if self.current is None:
            return
        self.edit.delete("1.0", "end")
        self.edit.insert("1.0", self.current.disc if from_disc else self.current.csv)
        self.update_panel()

    def tidy(self) -> None:
        text = self.edit.get("1.0", "end-1c")
        text = re.sub(r"<CTRL:?[^>]*>", "", text)
        for bad, good in SUBSTITUTES.items():
            text = text.replace(bad, good)
        text = re.sub(r"[\n\r\f\v]+", " ", text)
        self.edit.delete("1.0", "end")
        self.edit.insert("1.0", re.sub(r" {2,}", " ", text).strip())
        self.update_panel()

    def shrink(self) -> None:
        if self.current is None:
            return
        parts = self.edit.get("1.0", "end-1c").strip().split(" ")
        while len(parts) > 1 and self.measure(self.current, " ".join(parts))["over_rows"]:
            join = min(range(len(parts) - 1), key=lambda i: len(parts[i]) + len(parts[i + 1]))
            parts[join:join + 2] = [parts[join] + parts[join + 1]]
        self.edit.delete("1.0", "end")
        self.edit.insert("1.0", " ".join(parts))
        self.update_panel()

    def apply(self) -> None:
        if self.current is None:
            return
        self.current.proposal = self.edit.get("1.0", "end-1c").strip()
        self.refresh()
        self.update_panel()

    def export(self) -> None:
        fields = ["행번호", "파일", "오프셋", "안 들어간 이유", "원문",
                  "디스크 (지금 게임)", "CSV", "수정안"]
        with EXPORT.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for line in self.lines:
                writer.writerow({"행번호": line.n, "파일": line.file, "오프셋": line.offset,
                                 "안 들어간 이유": line.reason, "원문": line.japanese,
                                 "디스크 (지금 게임)": line.disc, "CSV": line.csv,
                                 "수정안": line.proposal})
        messagebox.showinfo("내보내기", f"{len(self.lines)}줄을 {EXPORT.name} 에 썼습니다.")

    def save(self) -> None:
        changed = [l for l in self.lines if l.proposal != l.csv]
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
        backup = TRANSLATED.with_suffix(".csv.notapplied.bak")
        shutil.copy2(TRANSLATED, backup)
        for line in changed:
            self.row_of[line.n]["korean"] = line.proposal
            line.csv = line.proposal
        with TRANSLATED.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=self.fieldnames)
            writer.writeheader()
            writer.writerows(self.all_rows)
        ready = sum(1 for l in self.lines if self.solved(l))
        self.loaded_at = TRANSLATED.stat().st_mtime_ns
        self.refresh()
        messagebox.showinfo("저장", f"{len(changed)}줄 저장했습니다.\n"
                                    f"이제 넣을 수 있는 줄 {ready}개.\n이전 파일: {backup.name}")


if __name__ == "__main__":
    root = tk.Tk()
    NotApplied(root)
    root.mainloop()
