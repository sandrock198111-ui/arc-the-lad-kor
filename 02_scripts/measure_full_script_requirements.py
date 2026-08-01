"""Extract the original Arc the Lad 1 text corpus and measure translated glyph needs.

This is read-only with respect to the BIN.  The DAT parser is deliberately the
already-established 17/19 dialogue record grammar; unclassified binary bytes are
not presented as strings or translated.
"""
from __future__ import annotations

import csv
import hashlib
import struct
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "05_docs"
BIN = Path(r"E:\arc\원본\arc1.bin")
RAW = 2352
START = 0x45000
MAX_BODY = 0x180
LINEBREAK, PAGEBREAK = b"\xE6\x01", b"\xE4\x1F"
OFFSET_ONLY_FILES = {
    "story_s2041_bulk_translation.csv": "21/S2041.DAT",
    "story_s3031_bulk_translation.csv": "31/S3031.DAT",
    "story_s4041_bulk_translation.csv": "4/S4041.DAT",
    "story_sf0b1_return_translation.csv": "F/SF0B1.DAT",
}


def sector(raw, lba: int) -> bytes:
    raw.seek(lba * RAW)
    block = raw.read(RAW)
    if len(block) != RAW:
        raise ValueError(f"short sector at LBA {lba}")
    return block[24:2072] if block[15] == 2 else block[16:2064]


def iso_files(path: Path) -> dict[str, tuple[int, int]]:
    with path.open("rb") as raw:
        pvd = sector(raw, 16)
        if pvd[1:6] != b"CD001":
            raise ValueError("not ISO9660")
        root_lba = struct.unpack_from("<I", pvd, 158)[0]
        root_len = struct.unpack_from("<I", pvd, 166)[0]
        todo, found = [("", root_lba, root_len)], {}
        while todo:
            prefix, lba, length = todo.pop()
            data = b"".join(sector(raw, lba + i) for i in range((length + 2047)//2048))
            pos = 0
            while pos < len(data):
                size = data[pos]
                if not size:
                    pos = (pos//2048 + 1)*2048
                    continue
                if pos + size > len(data) or size < 34:
                    raise ValueError(f"malformed ISO9660 directory record at LBA {lba}, offset {pos}")
                rec = data[pos:pos+size]; nlen = rec[32]
                name = rec[33:33+nlen].split(b";")[0].decode("ascii", "replace")
                l, n, isdir = struct.unpack_from("<II", rec, 2)[0], struct.unpack_from("<I", rec, 10)[0], rec[25]&2
                if name not in ("\0", "\1"):
                    if isdir: todo.append((prefix + name + "/", l, n))
                    else: found[prefix + name] = (l, n)
                pos += size
    return found


def read_file(path: Path, entry: tuple[int, int]) -> bytes:
    lba, size = entry
    with path.open("rb") as raw:
        return b"".join(sector(raw, lba+i) for i in range((size+2047)//2048))[:size]


def glyph_map() -> dict[int, str]:
    reviewed = DOCS / "japanese_font_index_map.csv"
    if reviewed.exists():
        with reviewed.open(encoding="utf-8-sig", newline="") as f:
            return {int(row["glyph index"]): row["character"] for row in csv.DictReader(f) if row["character"]}
    result = {}
    with (ROOT / "01_work/analysis/story_corpus/japanese_glyph_map.csv").open(encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            # Manual entries and exact atlas matches only.  Nearest-neighbour hints
            # were never evidence sufficient to silently decode a source string.
            if row["match"] in ("manual", "exact") and row["selected"]:
                result[int(row["index"])] = row["selected"]
    return result


def find_header(data: bytes, marker: int) -> int | None:
    for back in range(6, 18, 2):
        p = marker-back
        if p >= 0 and data[p:p+2] == b"\x29\0" and data[p+4:p+6] == b"\x7F\0": return p
    return None


def decode(body: bytes, chars: dict[int, str]) -> tuple[str, int]:
    out, unknown, p = [], 0, 0
    while p < len(body):
        pair = body[p:p+2]
        if pair == LINEBREAK: out.append("\n"); p += 2; continue
        if pair == PAGEBREAK: out.append("\f"); p += 2; continue
        b = body[p]
        if 1 <= b < 0xDD: idx, p = b-1, p+1
        elif 0xDD <= b <= 0xE0 and p+1 < len(body): idx, p = (b-0xDD)*255+body[p+1]+0xDB, p+2
        else: out.append(f"<CTRL:{b:02X}>"); unknown += 1; p += 1; continue
        if idx in chars: out.append(chars[idx])
        else: out.append(f"<G:{idx}>"); unknown += 1
    return "".join(out), unknown


def records(name: str, data: bytes, chars: dict[int, str]) -> list[dict[str, str]]:
    out, seen = [], set()
    for mark in range(START, len(data)-8, 2):
        marker = int.from_bytes(data[mark:mark+2], "little")
        if marker not in (0x17, 0x19): continue
        header = find_header(data, mark); begin = mark+2; prefix = data[begin:begin+2]
        if prefix in (b"\x01\0", b"\x02\0", b"\x03\0", b"\x04\0", b"\x05\0", b"\x07\0") or (prefix == b"\0\0" and marker == 0x17 and header == mark-6): begin += 2
        if begin in seen: continue
        end = next((p for p in range(begin, min(len(data)-1, begin+MAX_BODY)) if data[p:p+2] == b"\0\0"), None)
        if end is None or not 3 <= end-begin <= 0x100: continue
        raw = data[begin:end]; text, unknown = decode(raw, chars)
        glyphs = len(text) - text.count("\n") - text.count("\f")
        # This keeps the established corpus's acceptance rule; strings with unknown
        # characters are retained but visibly flagged rather than guessed.
        if glyphs == 0 or (glyphs-unknown)/glyphs < .45 and header is None and LINEBREAK not in raw and PAGEBREAK not in raw: continue
        seen.add(begin)
        out.append({"source file":name, "byte offset":f"0x{begin:X}", "length":str(len(raw)), "raw bytes as hex":raw.hex(" ").upper(), "decoded Japanese":text})
    return out


def translations() -> dict[tuple[str, int], list[str]]:
    found: dict[tuple[str, int], list[str]] = {}
    for path in DOCS.glob("*translation*.csv"):
        with path.open(encoding="utf-8-sig", newline="") as f:
            for row in csv.DictReader(f):
                file = (row.get("file") or OFFSET_ONLY_FILES.get(path.name) or "").replace("\\", "/")
                offset, text = row.get("offset", ""), row.get("text", "")
                if not file or not offset or not text: continue
                try: key = file, int(offset, 0)
                except ValueError: continue
                # Keep each distinct source rendition; duplicate manifest rows do
                # not create artificial coverage.
                found.setdefault(key, [])
                if text not in found[key]: found[key].append(text)
    return found


def main() -> None:
    if not BIN.exists(): raise SystemExit(f"original BIN not found: {BIN}")
    listing, chars = iso_files(BIN), glyph_map()
    # The atlas-derived Japanese map is admissible only when its source COMM.IMG
    # is byte-identical to the image on the requested original disc.
    work_comm = ROOT / "01_work/COMM.IMG"
    if hashlib.sha256(read_file(BIN, listing["COMM.IMG"])).digest() != hashlib.sha256(work_comm.read_bytes()).digest():
        raise SystemExit("01_work/COMM.IMG does not match the original disc; rebuild the glyph map first")
    targets = [n for n in sorted(listing) if n.upper().endswith(".DAT")] + (["COMM.DAT"] if "COMM.DAT" in listing else [])
    # COMM.DAT is deliberately scanned with the same grammar. Its pointer/table
    # formats require separate reverse engineering; no unverified direct scan is
    # called "all text" here.
    original = [r for n in targets for r in records(n, read_file(BIN, listing[n]), chars)]
    with (DOCS/"script_original_full.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w=csv.DictWriter(f, fieldnames=["source file","byte offset","length","raw bytes as hex","decoded Japanese"]); w.writeheader(); w.writerows(original)
    old = translations(); translated = 0; result=[]
    for r in original:
        choices=old.get((r["source file"], int(r["byte offset"],0)), [])
        korean = choices[0] if len(choices)==1 else ""
        status = "existing" if len(choices)==1 else ("untranslated" if not choices else "conflicting existing")
        translated += status == "existing"
        # The requested source column remains restricted to actual translations;
        # blank Korean cells must not be labelled as a "new" translation.
        result.append({"source file":r["source file"],"offset":r["byte offset"],"japanese":r["decoded Japanese"],"korean":korean,"source of the translation (existing / new)":"existing" if status == "existing" else "", "_status": status})
    with (DOCS/"script_translated_full.csv").open("w",encoding="utf-8-sig",newline="") as f:
        fields=["source file", "offset", "japanese", "korean", "source of the translation (existing / new)"]
        w=csv.DictWriter(f,fieldnames=fields, extrasaction="ignore"); w.writeheader(); w.writerows(result)
    with (DOCS/"script_translation_reconciliation.csv").open("w",encoding="utf-8-sig",newline="") as f:
        fields=["source file", "offset", "japanese", "translation status", "existing translations"]
        w=csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for row in result:
            key=(row["source file"], int(row["offset"], 0))
            choices=old.get(key, [])
            w.writerow({"source file": row["source file"], "offset": row["offset"], "japanese": row["japanese"], "translation status": row["_status"], "existing translations": " | ".join(choices)})
    maps=set()
    for p in (DOCS/"korean_charmap.csv", DOCS/"korean_charmap_extended.csv"):
        with p.open(encoding="utf-8-sig",newline="") as f: maps|={r["char"] for r in csv.DictReader(f)}
    allfreq=Counter(ch for r in result for ch in r["korean"] if "가" <= ch <= "힣")
    existingfreq=Counter(ch for r in result if r["_status"] == "existing" for ch in r["korean"] if "가" <= ch <= "힣")
    with (DOCS/"syllable_requirement.csv").open("w",encoding="utf-8-sig",newline="") as f:
        w=csv.DictWriter(f,fieldnames=["syllable","frequency","has existing glyph"]); w.writeheader()
        for ch,n in allfreq.most_common(): w.writerow({"syllable":ch,"frequency":n,"has existing glyph":int(ch in maps)})
    print(f"bin_sha256={hashlib.sha256(BIN.read_bytes()).hexdigest()}")
    print(f"dat_files={len(targets)-1} parsed_strings={len(original)} total_decoded_characters={sum(len(r['decoded Japanese']) for r in original)}")
    print(f"existing_translated={translated} untranslated={len(original)-translated}")
    print(f"all_korean_distinct={len(allfreq)} mapped={sum(c in maps for c in allfreq)} new={sum(c not in maps for c in allfreq)}")
    print(f"existing_korean_distinct={len(existingfreq)} mapped={sum(c in maps for c in existingfreq)} new={sum(c not in maps for c in existingfreq)}")

if __name__ == "__main__": main()
