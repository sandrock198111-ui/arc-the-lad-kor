"""Repoint glyph references that v171 left aimed at cells it had emptied.

v153 moved 551 glyph planes out of COMM.IMG and into the dynamic cache.  Two
mechanisms reach them again:

    direct range   a static index inside one of the 48 ranges at 0x801A74C0 is
                   redirected to a cache source by the resident decoder
    E9/EA escape   an explicit two-byte code, looked up in the 11-bit table at
                   0x801A7520

A reference is orphaned when its index is blank *and* outside every range.  The
renderer then draws an empty cell, which is what the missing 괜 in the battle
prompt is: the string holds

    0c | e0 3f | df ed | 95 | 00        괜 찮 아

where 찮 (index 966) sits inside range 960..974 and reaches the cache, while 괜
(index 1047) sits outside every range and draws nothing.  Seven .DAT files carry
that exact string, byte-identical to v151 -- v171 simply never rewrote it.

For each orphan this build finds a replacement that renders the same picture,
proven by comparing the 12x12 bitmap of v151's cell against the Huffman-decoded
dynamic sources and against every plane still inked in v177:

    range    the canonical static index the range table maps to that source
    cache    the E9/EA code whose lookup entry names that source
    static   another plane that still holds an identical bitmap

Only two-byte replacements are used, so no string changes length and no pointer
moves.  Orphans with no replacement are reported and left alone.
"""
from __future__ import annotations

import collections
import csv
import hashlib
import struct
import sys
import zipfile
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import plan_arc1_v171_ui_asset_recovery as plan  # noqa: E402

BASE = ROOT / "03_output/arc1_v177_restore_circle_icon.zip"
CONTROL = ROOT / "03_output/arc1_v151_free_the_sprite_cell_A4358FEE.zip"
OUT = ROOT / "03_output/arc1_v178_repoint_orphaned_glyphs.zip"
ART = ROOT / "01_work/analysis/arc1_v171_ui_asset_recovery"

R2F = 0x8011A800
ROW_BYTES, CELL, COLS, ROWS, PLANES = 896, 12, 21, 42, 4
IPR = COLS * PLANES
RANGES_RAM, LOOKUP_RAM = 0x801A74C0, 0x801A7520
POOL_LO, POOL_HI = 0x78000, 0x83000
RAM_LO, RAM_HI = 0x80000000, 0x80200000


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system",
                 "create_version", "extract_version", "flag_bits", "volume",
                 "internal_attr", "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def bitmap(font: bytes, index: int) -> tuple[int, ...]:
    """The 12x12 plane as twelve 12-bit rows, in the dynamic sources' bit order."""
    row, col, plane = index // IPR, (index % IPR) // PLANES, index % PLANES
    bit = 1 << plane
    out = []
    for dy in range(CELL):
        at = (row * CELL + dy) * ROW_BYTES + col * (CELL // 2)
        value = 0
        for k, byte in enumerate(font[at:at + CELL // 2]):
            if byte & 0x0F & bit:
                value |= 1 << (11 - k * 2)
            if (byte >> 4) & bit:
                value |= 1 << (11 - k * 2 - 1)
        out.append(value)
    return tuple(out)


def encode(index: int) -> bytes | None:
    """Two-byte static code.  Leads 0xDD..0xE0 always work; 0xE1 only when the
    classifier at 0x801A77C4 sends it to the glyph path, argument 190..240."""
    k = index - 219
    lead, arg = 0xDD + k // 255, k % 255
    if lead <= 0xE0:
        return bytes((lead, arg))
    if lead == 0xE1 and 190 <= arg <= 240:
        return bytes((lead, arg))
    return None


def tokens(blob: bytes):
    at = 0
    while at < len(blob):
        lead = blob[at]
        if 0x01 <= lead < 0xDD:
            yield at, lead - 1, 1
            at += 1
        elif 0xDD <= lead <= 0xE0 and at + 1 < len(blob):
            yield at, (lead - 0xDD) * 255 + blob[at + 1] + 219, 2
            at += 2
        elif 0xDD <= lead <= 0xEA and at + 1 < len(blob):
            yield at, None, 2
            at += 2
        else:
            yield at, None, 1
            at += 1


def runs(blob: bytes):
    """NUL-delimited stretches that tokenise into at least three glyphs."""
    start = 0
    for at in range(len(blob)):
        if blob[at]:
            continue
        if at - start >= 4:
            chunk = blob[start:at]
            glyphs = [t for t in tokens(chunk) if t[1] is not None]
            if len(glyphs) >= 3:
                yield start, chunk, glyphs
        start = at + 1


def main() -> None:
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}
    with ZipFile(CONTROL) as archive:
        control = {n: archive.read(n) for n in archive.namelist()}
    with ZipFile(ROOT / "00_original/arc.zip") as archive:
        stock_exe = archive.read("PSX.EXE")

    exe, font = members["PSX.EXE"], members["COMM.IMG"]
    old_font = control["COMM.IMG"]

    # --- what the dynamic machinery can reach -------------------------------
    raw = exe[RANGES_RAM - R2F:RANGES_RAM - R2F + 96]
    if raw != (ART / "conflict_ranges_16bit.bin").read_bytes():
        raise SystemExit("실행파일의 범위표가 v171 산출물과 다르다")
    lookup_blob = (ART / "lookup_11bit.bin").read_bytes()
    if exe[LOOKUP_RAM - R2F:LOOKUP_RAM - R2F + len(lookup_blob)] != lookup_blob:
        raise SystemExit("실행파일의 조회표가 v171 산출물과 다르다")

    covered, index_of_source, ordinal = set(), {}, 0
    for i in range(len(raw) // 2):
        word = struct.unpack_from("<H", raw, i * 2)[0]
        start, length = word & 0x7FF, (word >> 11) + 1
        for k in range(length):
            covered.add(start + k)
            index_of_source[ordinal] = start + k
            ordinal += 1

    lookup = [(int.from_bytes(lookup_blob[(n * 11) // 8:(n * 11) // 8 + 4], "little")
               >> ((n * 11) % 8)) & 0x7FF for n in range(409)]
    cache_code = {}
    for n, value in enumerate(lookup):
        if value >= 1536:
            lead = 0xE9 if n < 254 else 0xEA
            cache_code.setdefault(value - 1536, bytes((lead, n + 1 - (0 if n < 254 else 254))))

    rows_blob = (ART / "huffman_rows.bin").read_bytes()
    sources = [plan.decode_huffman_source(
        i, tuple(struct.unpack(f"<{len(rows_blob) // 2}H", rows_blob)),
        (ART / "huffman_counts.bin").read_bytes(),
        tuple(struct.unpack(f"<{(ART / 'source_checkpoints.bin').stat().st_size // 2}H",
                            (ART / "source_checkpoints.bin").read_bytes())),
        (ART / "source_bitstream.bin").read_bytes()) for i in range(462)]
    source_of = {}
    for i, b in enumerate(sources):
        source_of.setdefault(b, i)
    name_of = {int(r["source_id"]): r["char"]
               for r in csv.DictReader(open(ART / "source_manifest.csv", encoding="utf-8-sig"))}

    def inked(f, index):
        return any(bitmap(f, index))

    still_here = {}
    for index in range(ROWS * IPR):
        if inked(font, index):
            still_here.setdefault(bitmap(font, index), index)

    # --- orphans and their replacements -------------------------------------
    orphan = [i for i in range(ROWS * IPR)
              if 219 <= i <= 1479 and inked(old_font, i) and not inked(font, i)
              and i not in covered and encode(i)]
    repair, hopeless = {}, []
    for index in orphan:
        shape = bitmap(old_font, index)
        source = source_of.get(shape)
        chosen = None
        if source is not None and source in index_of_source:
            code = encode(index_of_source[source])
            if code:
                chosen = ("범위", code, name_of.get(source))
        if chosen is None and source is not None and source in cache_code:
            chosen = ("캐시", cache_code[source], name_of.get(source))
        if chosen is None:
            twin = still_here.get(shape)
            if twin is not None and encode(twin):
                chosen = ("살아있는칸", encode(twin), name_of.get(source) if source else "?")
        if chosen:
            repair[encode(index)] = (index, *chosen)
        else:
            hopeless.append((index, name_of.get(source) if source is not None else None))

    # --- rewrite every orphaned reference that sits inside real text --------
    # --- only two places are provably text ---------------------------------
    #
    # (1) executable strings reached from a pointer in the string pool.  A word
    #     that points at them is proof they are strings, not code or tables.
    # (2) the battle prompt "괜찮아", whose bytes the savestate's own OT
    #     identifies: 0x0C, then index 1047, then 966, then 148, then NUL.
    #
    # A .DAT is a script file, not a string pool.  Tokenising it whole turns
    # ordinary binary into 60,000 false glyphs, so this build does not try.
    PROMPT = bytes((0xE0, 0x3F, 0xDF, 0xED, 0x95))
    dead = {encode(i): i for i, _ in hopeless if encode(i)}

    touched = collections.Counter()
    files = collections.Counter()
    unfixed = collections.Counter()
    detail = []

    exe_bytes = bytearray(members["PSX.EXE"])
    seen = set()
    for at in range(POOL_LO, POOL_HI, 4):
        target = struct.unpack_from("<I", exe_bytes, at)[0]
        if not (0x80190000 <= target < 0x801AA000) or target in seen:
            continue
        seen.add(target)
        start = target - R2F
        end = start
        while end < len(exe_bytes) and exe_bytes[end] and end - start < 400:
            end += 1
        chunk = bytes(exe_bytes[start:end])
        for off, index, width in tokens(chunk):
            if width != 2 or index is None:
                continue
            code = bytes(chunk[off:off + 2])
            if code in repair:
                exe_bytes[start + off:start + off + 2] = repair[code][2]
                touched[repair[code][0]] += 1
                files["PSX.EXE"] += 1
                detail.append((f"0x{target:08X}", repair[code][3], code.hex(" "),
                               repair[code][2].hex(" "), repair[code][1]))
            elif code in dead:
                unfixed[index] += 1
    members["PSX.EXE"] = bytes(exe_bytes)

    swap = repair.get(PROMPT[:2])
    if not swap:
        raise SystemExit("괜(1047) 의 대체를 못 찾았다")
    for name in list(members):
        if name in ("COMM.IMG", "PSX.EXE"):
            continue
        blob = bytearray(members[name])
        n = 0
        for at in range(len(blob) - len(PROMPT) - 1):
            if bytes(blob[at:at + len(PROMPT)]) == PROMPT and blob[at + len(PROMPT)] == 0:
                if control.get(name, b"")[at:at + len(PROMPT)] != PROMPT:
                    continue                      # v151 과 다르면 손대지 않는다
                blob[at:at + 2] = swap[2]
                n += 1
        if n:
            members[name] = bytes(blob)
            files[name] += n
            touched[1047] += n

    broken = [i for i in range(POOL_LO, POOL_HI, 4)
              if RAM_LO <= struct.unpack_from("<I", stock_exe, i)[0] < RAM_HI
              and not (RAM_LO <= struct.unpack_from("<I", members["PSX.EXE"], i)[0] < RAM_HI)]
    if broken:
        raise SystemExit(f"문자열 풀 포인터 {len(broken)}개가 RAM 밖")

    with ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])

    print("v178  빈 칸을 가리키던 글자 참조를 살아 있는 주소로 돌림")
    print(f"  base    {BASE.name}")
    print(f"  대조     {CONTROL.name}")
    print(f"\n  범위표 밖에 남은 고아 글리프 {len(orphan)}개")
    print(f"    대체를 찾은 것 {len(repair)}개  " +
          str(dict(collections.Counter(v[1] for v in repair.values()))))
    print(f"    못 찾은 것 {len(hopeless)}개")
    print(f"\n  실제 텍스트에서 고친 참조 {sum(touched.values())}곳,  파일 {len(files)}개")
    for name, n in files.most_common(12):
        print(f"    {name:16} {n}곳")
    named = [(n, repair[encode(i)][3], i) for i, n in touched.most_common(14)]
    print("\n  많이 고친 글자: " + ", ".join(f"'{c}'({n})" for n, c, i in named))
    if unfixed:
        print(f"\n  대체가 없어 그대로 둔 참조 {sum(unfixed.values())}곳: {unfixed.most_common(8)}")
    print(f"\n  포인터 무결성  이상 0개")
    print(f"  output  {OUT.name}")
    print(f"  sha256  {hashlib.sha256(OUT.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
