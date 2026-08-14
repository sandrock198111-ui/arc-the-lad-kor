"""Small GUI for editing only D/SD031.DAT rows in the canonical translation CSV."""
from __future__ import annotations

import csv
import shutil
import sys
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v209_gogen_scene_slots as v209  # noqa: E402

TABLE = ROOT / "05_docs/script_translated_full.csv"
EXTRACT = ROOT / "01_work/analysis/d_sd031_dialogue_for_gui.csv"
TARGET = "D/SD031.DAT"


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title("D/SD031.DAT 대화 줄이기 — v208 기준 (출처 분리)")
        root.geometry("1450x850")
        with TABLE.open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            self.fields, self.all_rows = reader.fieldnames, list(reader)
        with EXTRACT.open(encoding="utf-8-sig", newline="") as handle:
            self.info = list(csv.DictReader(handle))
        self.mapping = v209.mapping()
        self.mapping.update({str(n): bytes((0x11 + n,)) for n in range(10)})
        self.mapping["?"] = bytes.fromhex("E0 47")
        self.by_key = {(r["source file"], r["offset"].lower()): r for r in self.all_rows}

        top = ttk.Frame(root, padding=8); top.pack(fill="x")
        ttk.Label(top, text="v208의 D/SD031.DAT 대화 전체 — '본문회수'가 0이면 외부 슬롯 없이 들어갑니다.").pack(side="left")
        ttk.Button(top, text="저장", command=self.save).pack(side="right")

        cols = ("offset", "storage", "slot", "capacity", "bytes", "need", "text")
        self.tree = ttk.Treeview(root, columns=cols, show="headings", height=23)
        labels = (("offset", "오프셋", 90), ("storage", "저장", 90), ("slot", "슬롯", 55),
                  ("capacity", "본문용량", 75), ("bytes", "한글B", 65),
                  ("need", "본문회수", 75), ("text", "현재 CSV 한글", 760))
        for key, title, width in labels:
            self.tree.heading(key, text=title); self.tree.column(key, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=8)
        self.tree.bind("<<TreeviewSelect>>", self.select)

        bottom = ttk.Frame(root, padding=8); bottom.pack(fill="x")
        self.original = tk.StringVar(); self.current = tk.StringVar(); self.csv_existing = tk.StringVar()
        ttk.Label(bottom, text="원문").grid(row=0, column=0, sticky="nw")
        ttk.Label(bottom, textvariable=self.original, wraplength=1280).grid(row=0, column=1, sticky="w")
        ttk.Label(bottom, text="v208 실제").grid(row=1, column=0, sticky="nw")
        ttk.Label(bottom, textvariable=self.current, wraplength=1280).grid(row=1, column=1, sticky="w")
        ttk.Label(bottom, text="CSV 기존 번역").grid(row=2, column=0, sticky="nw")
        ttk.Label(bottom, textvariable=self.csv_existing, wraplength=1280).grid(row=2, column=1, sticky="w")
        ttk.Label(bottom, text="새 편집안").grid(row=3, column=0, sticky="nw")
        self.edit = tk.Text(bottom, height=4, wrap="word", font=("Malgun Gothic", 12))
        self.edit.grid(row=3, column=1, sticky="ew"); bottom.columnconfigure(1, weight=1)
        ttk.Button(bottom, text="현재 행 적용", command=self.apply).grid(row=4, column=1, sticky="e", pady=4)

        for i, row in enumerate(self.info):
            self.tree.insert("", "end", iid=str(i), values=(row["오프셋"], row["저장방식"],
                row["슬롯번호"], row["본문용량_bytes"], row["CSV한글_bytes"],
                row["본문회수까지_줄일bytes"], row["CSV한글_편집대상"].replace("\n", " / ")))
        if self.info:
            self.tree.selection_set("0"); self.select()

    def select(self, _event=None) -> None:
        selected = self.tree.selection()
        if not selected: return
        row = self.info[int(selected[0])]
        self.original.set(row["원문"].replace("\n", " / "))
        self.current.set(row["v208화면문구"].replace("|", " / "))
        self.csv_existing.set(row["CSV한글_편집대상"].replace("\n", " / "))
        self.edit.delete("1.0", "end"); self.edit.insert("1.0", row["CSV한글_편집대상"])

    def apply(self) -> None:
        selected = self.tree.selection()
        if not selected: return
        i = int(selected[0]); row = self.info[i]
        text = self.edit.get("1.0", "end-1c").strip()
        row["CSV한글_편집대상"] = text
        missing = sorted({char for char in text if char not in self.mapping})
        size = sum(len(self.mapping[char]) for char in text if char in self.mapping)
        capacity = int(row["본문용량_bytes"])
        row["CSV한글_bytes"] = "" if missing else str(size)
        row["본문회수까지_줄일bytes"] = "" if missing else str(max(0, size - capacity))
        row["없는문자"] = "".join(missing)
        key = (TARGET, row["오프셋"].lower())
        self.by_key[key]["korean"] = text
        values = list(self.tree.item(str(i), "values"))
        values[4] = row["CSV한글_bytes"]
        values[5] = row["본문회수까지_줄일bytes"]
        values[-1] = text.replace("\n", " / ")
        self.tree.item(str(i), values=values)

    def save(self) -> None:
        self.apply()
        backup = TABLE.with_suffix(TABLE.suffix + ".sd031.bak")
        shutil.copy2(TABLE, backup)
        with TABLE.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=self.fields)
            writer.writeheader(); writer.writerows(self.all_rows)
        messagebox.showinfo("저장", f"D/SD031.DAT 수정 내용을 저장했습니다.\n백업: {backup.name}")


def main() -> None:
    root = tk.Tk(); App(root); root.mainloop()


if __name__ == "__main__":
    main()
