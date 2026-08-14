"""Export every known D/SD031.DAT dialogue from the v208 test build."""
from __future__ import annotations

import csv
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))

import build_arc1_v186_runtime_text_choice_fixes as v186  # noqa: E402
import build_arc1_v209_gogen_scene_slots as v209  # noqa: E402
from verify_arc1_v191_yagun_choice_local_fixes import runtime_decoder  # noqa: E402

BUILD = ROOT / "03_output/arc1_v208_gogen_scene.zip"
ORIGINAL_ZIP = ROOT / "00_original/arc.zip"
ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"
TRANSLATED_CSV = ROOT / "05_docs/script_translated_full.csv"
OUT = ROOT / "01_work/analysis/d_sd031_dialogue_for_gui.csv"
TARGET = "D/SD031.DAT"


def slot_number(blob: bytes, offset: int) -> int | None:
    if blob[offset] != 0xE2:
        return None
    disk = blob[offset + 1]
    slot = disk - (0x81 if disk < 0xA9 else 0x82)
    return slot if 0 <= slot < v186.SLOT_COUNT else None


def decode_visible(payload: bytes, decode) -> str:
    out: list[str] = []
    for token in v186.tokens(payload):
        if token == b"\0":
            break
        if token == b"\xE6\x01":
            out.append("|")
            continue
        if token == b"\x0D":
            out.append(",")
            continue
        if token[0] in (0xE4, 0xE5, 0xE7, 0xE8):
            out.append(f"<{token.hex(' ').upper()}>")
            continue
        try:
            out.append(decode(token))
        except BaseException:
            out.append(f"<{token.hex(' ').upper()}>")
    return "".join(out).rstrip()


def main() -> None:
    if not BUILD.exists():
        raise SystemExit(f"v208 ZIP이 없다: {BUILD}")
    with zipfile.ZipFile(BUILD) as archive:
        exe, blob = archive.read("PSX.EXE"), archive.read(TARGET)
    with zipfile.ZipFile(ORIGINAL_ZIP) as archive:
        stock = archive.read(TARGET)

    originals = {}
    with ORIGINAL_CSV.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            if row["source file"] == TARGET:
                originals[int(row["byte offset"], 0)] = row
    translated = {}
    with TRANSLATED_CSV.open(encoding="utf-8-sig", newline="") as handle:
        for n, row in enumerate(csv.DictReader(handle), 2):
            if row["source file"] == TARGET:
                translated[int(row["offset"], 0)] = (n, row)

    decode = runtime_decoder(exe)
    mapping = v209.mapping()
    mapping.update({str(n): bytes((0x11 + n,)) for n in range(10)})
    # v208's 0x3C is no longer a question mark; it resolves to Hangul '괄'.
    mapping["?"] = bytes.fromhex("E0 47")
    rows = []
    for offset in sorted(originals):
        original = originals[offset]
        raw = bytes.fromhex(original["raw bytes as hex"])
        csv_line, trans = translated.get(offset, ("", {}))
        slot = slot_number(blob, offset)
        if slot is not None:
            start = v186.SLOT_BASE + slot * v186.SLOT_SIZE
            block = blob[start:start + v186.SLOT_SIZE]
            term = block.find(0)
            payload = block[:term if term >= 0 else v186.SLOT_SIZE - 1]
            storage = "외부슬롯"
        elif blob[offset:offset + len(raw)] == stock[offset:offset + len(raw)]:
            payload = b""
            storage = "원문그대로"
        else:
            current = blob[offset:offset + len(raw)]
            term = current.find(0)
            payload = current[:term if term >= 0 else len(current)]
            storage = "본문직접"

        korean = trans.get("korean", "")
        encoded = b""
        missing = []
        for char in korean:
            if char in mapping:
                encoded += mapping[char]
            else:
                missing.append(char)
        rows.append({
            "CSV행": csv_line,
            "오프셋": f"0x{offset:X}",
            "저장방식": storage,
            "슬롯번호": "" if slot is None else slot,
            "본문용량_bytes": len(raw),
            "CSV한글_bytes": len(encoded) if not missing else "",
            "본문회수까지_줄일bytes": max(0, len(encoded) - len(raw)) if not missing else "",
            "원문": original["decoded Japanese"],
            "v208화면문구": "(일본어 그대로)" if storage == "원문그대로" else decode_visible(payload, decode),
            "CSV한글_편집대상": korean,
            "없는문자": "".join(sorted(set(missing))),
        })

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    occupied = sum(
        1 for slot in range(v186.SLOT_COUNT)
        if any(blob[v186.SLOT_BASE + slot * v186.SLOT_SIZE:
                    v186.SLOT_BASE + (slot + 1) * v186.SLOT_SIZE]))
    print(f"build       {BUILD.name}")
    print(f"dialogues   {len(rows)}")
    print(f"slots       {occupied}/{v186.SLOT_COUNT}")
    print(f"redirected  {sum(r['저장방식'] == '외부슬롯' for r in rows)}")
    print(f"output      {OUT}")


if __name__ == "__main__":
    main()
