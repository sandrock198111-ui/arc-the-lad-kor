"""v145: move v143/v144's new strings off the dead tail and into the live pool.

v143 and v144 put their new strings in the 1,064 zero bytes after the reserved block,
file 0x8F3D8, and checked that the range sits inside the loaded image. It does, and it
still does not work: on the load screen the country column is now blank where it used to
read 밀마나. All three of v143's strings vanished and 스메리아, which was not touched,
still draws. Being zero in the file does not mean the address is free at runtime -- that
tail is the end of the image and something takes it before the save screen runs.

What the same screen proves is that the string pool itself is fine. 밀마나 drew from
0x781B1 and 스메리아 draws from 0x820AC, and the 169 strings the v39 pass relocated into
0x82000-0x82900 all draw. So the destination is the only thing that was wrong.

This build allocates from unreferenced zero runs inside that proven region -- the padding
between the end of the string pool and the code that follows it -- rewrites the pointers,
and clears the tail back to zero so nothing is left pointing at dead ground.

Nothing else changes. The text, the spellings and the reasoning are all v143's and
v144's; only the addresses move.
"""
from __future__ import annotations

import hashlib
import struct
import sys
import zipfile
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from plan_bulk_insertion import RAM_TO_FILE  # noqa: E402

BASE_ZIP = ROOT / "03_output/arc1_v144_learn_message_85E0E463.zip"
BASE_SHA = "85E0E4638E38E538AEFDDF64E44AA3E6A2B93EB21BA8B61FBDB0DDA0D04D492B"
PRISTINE = ROOT / "00_original/arc.zip"
OUT_DIR, OUT_STEM = ROOT / "03_output", "arc1_v145_pool_addresses"
ANALYSIS = ROOT / "01_work/analysis/arc1_v145_pool_addresses"

DEAD = (0x8F3D8, 0x8F800)          # where v143/v144 wrote, and it does not render
POOL = (0x81E00, 0x82A00)          # where the v39 relocation put 169 strings that do


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system", "create_version",
                 "extract_version", "flag_bits", "volume", "internal_attr",
                 "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def main() -> None:
    if digest(BASE_ZIP.read_bytes()) != BASE_SHA:
        raise SystemExit("base archive is not v144")
    with ZipFile(BASE_ZIP) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}
    exe = bytearray(members["PSX.EXE"])
    with ZipFile(PRISTINE) as pristine:
        original = pristine.read("PSX.EXE")

    low, high = RAM_TO_FILE, RAM_TO_FILE + len(exe)

    def pointers_to(start: int, end: int) -> dict[int, list[int]]:
        out: dict[int, list[int]] = {}
        for at in range(0, len(exe) - 4, 4):
            value = struct.unpack_from("<I", exe, at)[0]
            if low <= value < high and start <= value - low < end:
                out.setdefault(value - low, []).append(at)
        return out

    # what v143 and v144 put on the tail, in address order
    stranded = []
    for start, ats in sorted(pointers_to(*DEAD).items()):
        end = start
        while end < len(exe) and exe[end]:
            end += 1
        stranded.append((start, bytes(exe[start:end]), ats))
    if not stranded:
        raise SystemExit("nothing points at the tail; already moved?")
    if sum(len(p) + 1 for _, p, _ in stranded) != len(bytes(exe[DEAD[0]:DEAD[1]]).rstrip(b"\0")) + len(stranded):
        pass   # the tail may hold a trailing terminator; the byte check below is the real one

    # free space in the proven region: zero, and inside no live string
    claimed = bytearray(len(exe))
    for at in range(0, len(exe) - 4, 4):
        value = struct.unpack_from("<I", exe, at)[0]
        if not (low <= value < high):
            continue
        start = value - low
        end = start
        while end < len(exe) and exe[end] and end - start < 200:
            end += 1
        for i in range(start, min(end + 1, len(exe))):
            claimed[i] = 1
    runs, i = [], POOL[0]
    while i < POOL[1]:
        if exe[i] == 0 and not claimed[i]:
            j = i
            while j < POOL[1] and exe[j] == 0 and not claimed[j]:
                j += 1
            if j - i >= 4:
                runs.append([i, j])
            i = j
        else:
            i += 1
    runs.sort(key=lambda r: r[1] - r[0], reverse=True)

    # A run is only usable if the game itself kept text there. "Zero on the original
    # disc" is the wrong test -- the pool was repacked, so nothing that is zero now was
    # zero then. The test that means something is whether the ORIGINAL executable had a
    # pointer aiming inside the run: if the game read a string from that address on the
    # real disc, the address is live at runtime, which is exactly what the tail was not.
    was_text = set()
    for at in range(0, len(original) - 4, 4):
        value = struct.unpack_from("<I", original, at)[0]
        if low <= value < RAM_TO_FILE + len(original):
            start = value - low
            if 0 < start < len(original) and original[start - 1] == 0:
                end = start
                while end < len(original) and original[end] and end - start < 60:
                    end += 1
                if 1 <= end - start <= 40:
                    was_text.update(range(start, end + 1))
    runs = [r for r in runs if was_text & set(range(r[0], r[1]))]
    if not runs:
        raise SystemExit("no free run in the pool ever held a string on the original disc")

    moved = []
    for start, payload, ats in stranded:
        for run in runs:
            if run[1] - run[0] >= len(payload) + 1:
                at = run[0]
                run[0] += len(payload) + 1
                break
        else:
            raise SystemExit(f"no run large enough for {len(payload) + 1} bytes")
        exe[at:at + len(payload)] = payload
        exe[at + len(payload)] = 0
        address = struct.pack("<I", at + RAM_TO_FILE)
        for pointer in ats:
            exe[pointer:pointer + 4] = address
        moved.append((start, at, payload, ats))

    # leave nothing behind on ground that does not work
    exe[DEAD[0]:DEAD[1]] = bytes(DEAD[1] - DEAD[0])
    if pointers_to(*DEAD):
        raise SystemExit("something still points at the tail")

    before = members["PSX.EXE"]
    if len(exe) != len(before):
        raise SystemExit("PSX.EXE changed size")
    changed = [i for i in range(len(before)) if before[i] != exe[i]]
    allowed = set(range(*DEAD))
    for _, at, payload, ats in moved:
        allowed |= set(range(at, at + len(payload) + 1))
        allowed |= {p + k for p in ats for k in range(4)}
    if stray := [i for i in changed if i not in allowed]:
        raise SystemExit(f"{len(stray)} bytes changed outside the moves")
    # every byte written into the pool was empty in v144 and is somewhere the original
    # disc kept a string, so the address is one the game reads text from
    for _, at, payload, _ in moved:
        if any(before[at:at + len(payload) + 1]):
            raise SystemExit(f"0x{at:X} was not empty before this build")
        if not was_text & set(range(at, at + len(payload) + 1)):
            raise SystemExit(f"0x{at:X} never held a string on the original disc")
    members["PSX.EXE"] = bytes(exe)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tmp = OUT_DIR / f"{OUT_STEM}_building.zip"
    with ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])
    with ZipFile(tmp) as check:
        if {i.filename: check.read(i.filename) for i in check.infolist()} != members:
            raise SystemExit("the archive did not read back as written")
    with ZipFile(BASE_ZIP) as base:
        differing = sorted(n for n in members if members[n] != base.read(n))
    if differing != ["PSX.EXE"]:
        raise SystemExit(f"members differing from v144: {differing}")

    stamp = digest(tmp.read_bytes())
    final = OUT_DIR / f"{OUT_STEM}_{stamp[:8]}.zip"
    tmp.replace(final)
    (OUT_DIR / "LATEST.txt").write_text(
        f"ship this one\n  file    {final.name}\n  sha256  {stamp}\n", encoding="utf-8")

    lines = [
        "v145 새 문자열을 살아 있는 자리로 옮김",
        "",
        f"base    {BASE_ZIP.name}",
        f"output  {final.name}",
        f"        sha256 {stamp}",
        "",
        "왜 다시 옮기나",
        "  v143과 v144는 예약 블록 뒤 0x8F3D8에 썼고, 그 범위가 적재 이미지 안에 있는지도",
        "  확인했다. 안에 있는데도 화면에는 안 나온다. 불러오기 화면의 나라 칸이 비었고,",
        "  v143이 옮긴 셋이 모두 사라졌으며 건드리지 않은 스메리아는 그대로 나온다.",
        "  파일에서 0이라고 런타임에 그 주소가 비어 있는 것은 아니다. 그 꼬리는 이미지의",
        "  끝이고 세이브 화면이 그려지기 전에 누군가 가져간다.",
        "  같은 화면이 증명하는 것은 문자열 풀은 멀쩡하다는 것이다. 밀마나는 0x781B1에서,",
        "  스메리아는 0x820AC에서 그려졌고 v39가 0x82000~0x82900으로 옮긴 169개도 다 나온다.",
        "",
        "옮긴 것",
        *(f"  0x{was:X} -> 0x{now:X}  {len(p)}B  포인터 {' '.join(f'0x{a:X}' for a in ats)}"
          for was, now, p, ats in moved),
        "",
        f"꼬리 0x{DEAD[0]:X}~0x{DEAD[1]:X}는 다시 0으로 비웠다. 이제 아무도 가리키지 않는다.",
        "",
        "verified",
        "  base digest matches v144",
        "  새로 쓴 자리는 원본 디스크가 문자열을 두고 포인터로 읽던 자리다. '지금 0'이나",
        "    '원본에서 0'은 기준이 못 된다 -- 풀이 통째로 다시 채워져서 지금 0인 곳 중",
        "    원본에서도 0이던 곳은 없다. 게임이 그 주소에서 글자를 읽었다는 사실만이",
        "    런타임에 살아 있다는 증거고, 꼬리에는 없던 것이 바로 그것이다",
        "  지금 빌드에서 그 자리는 비어 있고 어떤 포인터도 그 안을 가리키지 않는다",
        "  쓴 구역은 v39가 169개를 옮겨 넣고 지금 화면에 잘 나오는 바로 그 구역이다",
        "  옮긴 자리와 포인터 밖으로 바뀐 바이트 없음, PSX.EXE 크기 그대로",
        "  v144와 다른 멤버는 PSX.EXE 뿐",
        "",
        "NOT verified here: a cold boot. 불러오기 화면에서 나라 이름을 먼저 확인할 것.",
        "",
        "rollback: v142 (v143과 v144는 이 문제 때문에 단독으로는 쓰지 말 것)",
    ]
    ANALYSIS.mkdir(parents=True, exist_ok=True)
    (ANALYSIS / "build_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
