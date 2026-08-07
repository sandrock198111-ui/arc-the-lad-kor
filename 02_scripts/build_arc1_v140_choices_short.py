"""v140: the choice bodies again, on top of the short codes.

Same model as v137 -- every E5 and E6 stays at its original byte offset, a span too
small for its Korean takes a two-byte E2 and the text lives in a slot -- but the Korean
is now written with v138's one-byte codes, so far more of it fits where it appears and
far fewer slots are spent. Runs the whole set from the clean original body again rather
than layering on v137's work.
"""

from __future__ import annotations

import csv
import hashlib
import pickle
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from plan_bulk_insertion import (  # noqa: E402
    CACHE, CHOICE, FILLER, SLOT_BASE, SLOT_COUNT, SLOT_SIZE, SLOT_TEXT_MAX,
    bitmap, build_encoder, disk_id, drawable, encode, has_marker, tokens,
)

BASE_ZIP = ROOT / "03_output/arc1_v139_short_codes_1F756878.zip"
BASE_SHA = "1F7568787B369ABA3847974920780440701D133F6A93746FC4F4F20F6F207975"
ORIGINAL_ZIP = ROOT / "00_original/arc.zip"
ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"
TRANSLATED_CSV = ROOT / "05_docs/script_translated_full.csv"
OUT_DIR, OUT_STEM = ROOT / "03_output", "arc1_v140_choices_short"
ANALYSIS = ROOT / "01_work/analysis/arc1_v140_choices_short"
LINEBREAK = b"\xE6\x01"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system", "create_version",
                 "extract_version", "flag_bits", "volume", "internal_attr",
                 "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def spans(raw: bytes) -> list[tuple[int, int]]:
    """(offset, length) of each text span between markers, empty spans dropped."""
    out: list[tuple[int, int]] = []
    position = start = length = 0
    for token in tokens(raw):
        if len(token) == 1 and token[0] == 0:
            break
        if token[0] == CHOICE or token == LINEBREAK:
            if length:
                out.append((start, length))
            position += len(token)
            start, length = position, 0
            continue
        position += len(token)
        length += len(token)
    if length:
        out.append((start, length))
    return out


def markers(raw: bytes) -> list[tuple[int, bytes]]:
    out, position = [], 0
    for token in tokens(raw):
        if len(token) == 1 and token[0] == 0:
            break
        if token[0] == CHOICE or token == LINEBREAK:
            out.append((position, token))
        position += len(token)
    return out


def realign(parts: list[str], want: int) -> list[str]:
    """Make the CSV's phrase count match the body's, where the cause is mechanical.

    Two habits account for almost all of it: a leading bar, which invents an empty
    first phrase, and writing `이름: 질문` in one phrase where the original keeps the
    speaker on its own row.
    """
    out = list(parts)
    if len(out) > want and out and out[0] == "":
        out = out[1:]
    if len(out) == want - 1 and out and ":" in out[0]:
        head, rest = out[0].split(":", 1)
        out = [head.strip(), rest.strip()] + out[1:]
    while len(out) > want and out and out[-1] == "":
        out = out[:-1]
    return out


def main() -> None:
    if digest(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not v139")
    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}
    table = build_encoder(members["PSX.EXE"], members["COMM.IMG"])
    shapes: dict[tuple[int, ...], str] = pickle.loads(CACHE.read_bytes())
    banned = {}
    for lead in range(0xDD, 0xE9):
        for trail in range(0x01, 0x100):
            index = (lead - 0xDD) * 255 + trail + 0xDB
            if not drawable(members["PSX.EXE"], index):
                bits = bitmap(members["PSX.EXE"], members["COMM.IMG"], index)
                if bits and (char := shapes.get(bits)):
                    banned[bytes((lead, trail))] = char

    raws: dict[tuple[str, int], bytes] = {}
    with ORIGINAL_CSV.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
        for row in reader:
            raws[(row["source file"], int(row[key], 0))] = bytes.fromhex(
                row["raw bytes as hex"].replace(" ", ""))
    with TRANSLATED_CSV.open(encoding="utf-8-sig", newline="") as handle:
        wanted = list(enumerate(csv.DictReader(handle), 1))
    with ZipFile(ORIGINAL_ZIP) as pristine:
        originals = {n: pristine.read(n) for n in pristine.namelist() if n in members}

    # Slots free on the untouched disc, minus the ones ordinary dialogue already took
    # in this build. A choice redirect may only use a slot nobody is pointing at.
    free: dict[str, list[int]] = {}
    for name, blob in members.items():
        if not name.upper().endswith(".DAT") or name not in originals:
            continue
        if len(blob) < SLOT_BASE + SLOT_COUNT * SLOT_SIZE:
            free[name] = []
            continue
        pure = originals[name]
        free[name] = [s for s in range(SLOT_COUNT)
                      if not any(pure[SLOT_BASE + s * SLOT_SIZE:SLOT_BASE + (s + 1) * SLOT_SIZE])
                      and not any(blob[SLOT_BASE + s * SLOT_SIZE:SLOT_BASE + (s + 1) * SLOT_SIZE])]

    plan: dict[str, list] = defaultdict(list)
    skipped: list[tuple[int, str, str]] = []
    inline_count = redirect_count = 0

    for n, row in wanted:
        name, offset = row["source file"], int(row["offset"], 0)
        raw = raws.get((name, offset))
        if raw is None or not has_marker(raw, CHOICE):
            continue
        if name not in members or name not in originals:
            skipped.append((n, name, "파일이 아카이브에 없음"))
            continue
        if originals[name][offset:offset + len(raw)] != raw:
            raise SystemExit(f"{name} 0x{offset:X}: the disc does not hold the recorded bytes")
        korean = (row.get("korean") or "").strip()
        if not korean or not any("가" <= c <= "힣" for c in korean):
            skipped.append((n, name, "한국어 없음"))
            continue

        segments = spans(raw)
        parts = realign([p.strip() for p in korean.split("|")], len(segments))
        if len(parts) != len(segments):
            skipped.append((n, name, f"칸 {len(segments)} / 수정안 {len(parts)}"))
            continue

        writes, redirects, trouble = [], [], ""
        for (start, length), phrase in zip(segments, parts):
            payload, missing = encode(phrase, table, keep_breaks=False)
            if missing:
                trouble = "없는 글자 " + "".join(sorted(set(missing)))
                break
            if any(tok in banned for tok in tokens(payload)):
                trouble = "닿을 수 없는 글리프"
                break
            # E2 is also a glyph lead -- E2 EB is 링, E2 DE is 띠 -- so a phrase carrying
            # one cannot be written inline in a choice body: the renderer would read the
            # syllable as a redirect. Slots do not interpret controls, so those phrases
            # go to a slot even when they would have fitted.
            carries_e2 = any(len(tok) == 2 and tok[0] == 0xE2 for tok in tokens(payload))
            if len(payload) <= length and not carries_e2:
                writes.append((start, payload + bytes((FILLER,)) * (length - len(payload))))
                continue
            if length < 2:
                trouble = f"칸이 {length}바이트라 E2도 못 넣음"
                break
            if len(payload) > SLOT_TEXT_MAX:
                trouble = f"슬롯 {SLOT_TEXT_MAX}바이트 초과"
                break
            redirects.append((start, length, payload))
        if trouble:
            skipped.append((n, name, trouble))
            continue
        if len(free.get(name, [])) < len(redirects):
            skipped.append((n, name, f"슬롯 부족 (필요 {len(redirects)}, 남음 {len(free.get(name, []))})"))
            continue
        for start, length, payload in redirects:
            slot = free[name].pop(0)
            writes.append((start, bytes((0xE2, disk_id(slot)))
                           + bytes((FILLER,)) * (length - 2)))
            plan[name].append(("slot", slot, payload, length))
            redirect_count += 1
        inline_count += len(writes) - len(redirects)
        plan[name].append(("body", offset, raw, writes))

    changed: list[str] = []
    written_bodies = 0
    for name, items in plan.items():
        data = bytearray(members[name])
        allowed: set[int] = set()
        for kind, a, b, c in items:
            if kind == "slot":
                start = SLOT_BASE + a * SLOT_SIZE
                if any(data[start:start + SLOT_SIZE]):
                    raise SystemExit(f"{name}: slot {a} is not empty")
                data[start:start + SLOT_SIZE] = bytes(SLOT_SIZE)
                data[start:start + len(b)] = b
                data[start + SLOT_SIZE - 1] = c - 2      # resume at this span's marker
                allowed |= set(range(start, start + SLOT_SIZE))
                continue
            offset, raw, writes = a, b, c
            body = bytearray(raw)
            for start, payload in writes:
                body[start:start + len(payload)] = payload
            if markers(bytes(body)) != markers(raw):
                raise SystemExit(f"{name} 0x{offset:X}: the markers moved")
            data[offset:offset + len(raw)] = body
            allowed |= set(range(offset, offset + len(raw)))
            written_bodies += 1
        before = members[name]
        stray = [i for i in range(len(before)) if before[i] != data[i] and i not in allowed]
        if stray:
            raise SystemExit(f"{name}: {len(stray)} bytes changed outside the bodies and slots")
        if bytes(data) != before:
            members[name] = bytes(data)
            changed.append(name)

    if members["PSX.EXE"] != ZipFile(BASE_ZIP).read("PSX.EXE"):
        raise SystemExit("the executable changed; this build must not touch it")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tmp = OUT_DIR / f"{OUT_STEM}_building.zip"
    with ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    with ZipFile(tmp) as check:
        if {i.filename: check.read(i.filename) for i in check.infolist()} != members:
            raise SystemExit("the archive did not read back as written")

    stamp = digest(tmp.read_bytes())
    final = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    tmp.replace(final)
    (OUT_DIR / "LATEST.txt").write_text(
        f"ship this one\n  file    {final.name}\n  sha256  {stamp}\n", encoding="utf-8")

    why = Counter(r.split(" (")[0].split(" 없는")[0] for _, _, r in skipped)
    lines = [
        "v140 choice bodies with the short codes",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {final.name}",
        f"        sha256 {stamp}",
        f"members {len(members)}; PSX.EXE and COMM.IMG byte-identical to v139",
        "",
        f"choice bodies written   {written_bodies}",
        f"  spans written inline  {inline_count}",
        f"  spans redirected      {redirect_count}",
        f"files changed           {len(changed)}",
        f"left alone              {len(skipped)}",
        *(f"  {n:>4}  {r}" for r, n in why.most_common()),
        "",
        "verified",
        "  base digest matches v139",
        "  every body's original bytes match the script table read from the disc archive",
        "  every E5 and E6 is still at the byte offset the original put it, compared",
        "    marker by marker after writing -- moving them is what caused the Choppin",
        "    blank-option regression on 2026-07-17",
        "  each redirected span holds E2 plus filler and its slot's metadata is the",
        "    span's own length minus two, so completion resumes at that span's marker",
        "  every slot used was empty on the original disc and unused in this build",
        "  no glyph resolves to a font row the classifier cannot reach",
        "  no byte changed outside the choice bodies and the slots they point at",
        "  PSX.EXE untouched; the archive reads back as written",
        "",
        "NOT verified here: a cold boot. Open a menu and check the cursor sits on the",
        "option it points at, then a battle prompt, then a shop or quiz menu.",
        "",
        "rollback: v139",
        "",
        "left alone, in full:",
        *(f"  행 {n} {f}  {r}" for n, f, r in skipped),
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:24]))


if __name__ == "__main__":
    main()
