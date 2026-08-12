"""Pull two prompts back under the row limit so the options stop sliding down.

The battle-house prompt reads

    y 36   어머니: 아버지가 남긴 편지를 읽을래?
    y 64   (blank row)
    y 78   괜찮아
    y 92   읽는다

and the cursor sits beside y 64, one row above the first option.  The options did
not move down; the prompt grew.  Row spacing is 14px everywhere except 36 -> 64,
which is 28 -- the prompt occupies two rows.  Its width is exactly 228px, the row
limit, and the renderer wraps once more at the boundary.

v192 accepted that width because it tested `> ROW_PIXELS`.  The limit is
exclusive, so 228 must be rejected too.  Of the twelve speaker prompts only two
reach it: this one and 7/S7026 "대회 위원: 오브 쟁탈전 준비됐습니까?".  The other
ten are 216px or less and are left alone.

Only the external slot text changes.  The .DAT body, its E5/E6 geometry, the
slot's completion byte, PSX.EXE and COMM.IMG are all untouched, so nothing about
the row structure the cursor reads is disturbed.
"""
from __future__ import annotations

import hashlib
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

BASE = ROOT / "03_output/arc1_v196_levelup_suffix_orphan.zip"
BASE_SHA256 = "88FCDA5F90A7C2F12EC73A539B175C642303AD39C2A4F84E5F4639278B6F98D3"
OUT = ROOT / "03_output/arc1_v197_prompt_width_off_by_one.zip"

TARGETS = (
    ("1/S1023.DAT", 0x47952, 0,
     "어머니: 아버지가 남긴 편지를 읽을래?", "어머니: 아버지가 남긴 편지 볼래?"),
    ("7/S7026.DAT", 0x48D28, 7,
     "대회 위원: 오브 쟁탈전 준비됐습니까?", "대회 위원: 쟁탈전 준비됐습니까?"),
)


def clone(info: ZipInfo) -> ZipInfo:
    out = ZipInfo(info.filename, info.date_time)
    for attr in ("compress_type", "comment", "extra", "create_system",
                 "create_version", "extract_version", "flag_bits", "volume",
                 "internal_attr", "external_attr"):
        setattr(out, attr, getattr(info, attr))
    return out


def main() -> None:
    if hashlib.sha256(BASE.read_bytes()).hexdigest().upper() != BASE_SHA256:
        raise SystemExit("base 아카이브 해시가 다르다")
    with ZipFile(BASE) as archive:
        infos = archive.infolist()
        members = {i.filename: archive.read(i.filename) for i in infos}

    import build_arc1_v186_runtime_text_choice_fixes as v186
    import build_arc1_v171_ui_asset_recovery as v171
    import verify_arc1_v191_yagun_choice_local_fixes as v191_verify
    import build_arc1_v191_yagun_choice_local_fixes as v191
    import build_arc1_v192_choice_speaker_rows as v192

    mapping = v171.current_char_mapping()
    mapping[":"] = bytes.fromhex("DF 80")
    decode_token = v191_verify.runtime_decoder(members["PSX.EXE"])

    def spell(payload: bytes) -> str:
        return "".join(decode_token(t) for t in v186.tokens(payload))

    def width(payload: bytes) -> int:
        return v186.structural.row_width(list(v186.tokens(payload)))

    report = []
    for member, offset, slot, was_text, now_text in TARGETS:
        data = bytearray(members[member])
        body_before = bytes(data[offset:offset + 64])
        stored = v192.slot_bytes(data, slot)
        end = stored.find(b"\0")
        payload, completion = stored[:end], stored[-1]
        if spell(payload) != was_text:
            raise SystemExit(f"{member} 슬롯{slot} 이 '{was_text}' 가 아니다: '{spell(payload)}'")
        if width(payload) < v186.ROW_PIXELS:
            raise SystemExit(f"{member} 슬롯{slot} 은 이미 한계 미만이다. 대상이 아니다")
        refs_before = v191.slot_references(bytes(data), slot)

        fresh = v186.encode_text(now_text, mapping)
        if spell(fresh) != now_text:
            raise SystemExit(f"새 문구가 되읽히지 않는다: '{spell(fresh)}'")
        new_width = width(fresh)
        if new_width >= v186.ROW_PIXELS:
            raise SystemExit(f"새 문구가 {new_width}px 로 아직 한계 이상이다")
        v192.write_slot(data, slot, fresh, completion)

        again = v192.slot_bytes(data, slot)
        if again[-1] != completion or again[:len(fresh)] != fresh or any(again[len(fresh):-1]):
            raise SystemExit(f"{member} 슬롯{slot} 기록이 어긋났다")
        if bytes(data[offset:offset + 64]) != body_before:
            raise SystemExit(f"{member} 0x{offset:X} 본문이 변했다")
        if v191.slot_references(bytes(data), slot) != refs_before:
            raise SystemExit(f"{member} 슬롯{slot} 소유자가 변했다")
        if len(data) != len(members[member]):
            raise SystemExit(f"{member} 길이가 변했다")
        members[member] = bytes(data)
        report.append((member, slot, was_text, width(payload), now_text, new_width))

    with ZipFile(BASE) as archive:
        original = {name: archive.read(name) for name in archive.namelist()}
    changed = [n for n in members if members[n] != original[n]]
    if sorted(changed) != sorted(m for m, *_ in TARGETS):
        raise SystemExit(f"바뀐 멤버가 {changed} 다")

    with ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in infos:
            archive.writestr(clone(info), members[info.filename])

    print("v197  창 폭 한계에 걸친 질문 두 개를 줄임")
    print(f"  base    {BASE.name}")
    print(f"  한계    {v186.ROW_PIXELS}px, 이 값과 같으면 한 줄 더 넘어간다")
    for member, slot, was, w0, now, w1 in report:
        print(f"\n  {member} 슬롯{slot}")
        print(f"    이전  {w0:3}px  '{was}'")
        print(f"    이후  {w1:3}px  '{now}'")
    print(f"\n  바뀐 멤버  {sorted(changed)}")
    print(f"  본문·E5/E6 기하·완료값·슬롯 소유자  모두 불변")
    print(f"  PSX.EXE 와 COMM.IMG  v196 과 동일")
    print(f"  output  {OUT.name}")
    print(f"  sha256  {hashlib.sha256(OUT.read_bytes()).hexdigest().upper()}")


if __name__ == "__main__":
    main()
