"""Independent final-archive checks; does not import the restoration builder."""
from pathlib import Path
from zipfile import ZipFile
import struct
from v354_dialogue_codec import load_v354, tokens, _resolve_index

ROOT = Path(__file__).resolve().parents[1]
codec_exe, _, encode, decode = load_v354()
# Current UI uses the direct alias of the same physical '택' glyph that
# the editor normally encodes as E9 33. Verify equivalence, don't substitute it.
assert _resolve_index(codec_exe,b'\xdf\x9a') == _resolve_index(codec_exe,encode['택']) == 883
decode[b'\xdf\x9a'] = '택'
with ZipFile(ROOT/'03_output/arc1_v359_thin_font_all_TEST_ONLY_D38CAB43.zip') as z:
    before = {n:z.read(n) for n in z.namelist()}
with ZipFile(ROOT/'03_output/arc1_v359_thin_prep_icons_TEST_ONLY.zip') as z:
    after = {n:z.read(n) for n in z.namelist()}
assert list(before) == list(after)
assert [n for n in after if after[n] != before[n]] == ['PSX.EXE']
old, exe = before['PSX.EXE'], after['PSX.EXE']
assert len(old) == len(exe)
allowed = set(range(0x80224,0x80230)) | set(range(0x80D8E,0x80DA1)) | set(range(0x82374,0x8237C))
assert all(i in allowed for i,(a,b) in enumerate(zip(old,exe)) if a != b)
icons = {b'\xe7\x03':'[SQUARE]', b'\xe7\x05':'[CROSS]',b'\xe7\x08':'[START]'}
expected = ('[SQUARE][CROSS] 인물을 선택하세요','[START] 전투 시작')
for pointer, text, start, limit in zip((0x82374,0x82378),expected,(0x80D8E,0x80224),(0x80DA1,0x80230)):
    at = struct.unpack_from('<I',exe,pointer)[0] - (struct.unpack_from('<I',exe,0x18)[0]-0x800)
    assert at == start
    end = exe.index(0,at)
    assert at <= end < limit
    stream = list(tokens(exe[at:end]))
    decoded = ''.join(icons[t] if t in icons else decode[t] for t in stream)
    assert decoded == text, repr(decoded)
    # 14px Hangul advance, 6px spaces; use conservative 24px for every
    # icon rather than assuming its measured 12/20px width.
    extent = sum(24 if t in icons else 6 if t==b'\xa1' else 14 for t in stream)+2
    assert extent <= 182, extent  # 198px panel minus two 8px insets
    # One icon sprite or one glyph sprite each; spaces don't draw.
    packets = sum(t != b'\xa1' for t in stream)
    print(f'row at {at:X}: extent bound={extent}px; packets={packets}; NUL in owned span PASS')
assert exe[0x4C2C4:0x4C388] == old[0x4C2C4:0x4C388]
print('PASS: 164-member preservation, exact change whitelist, decoded prose/icons, owned boundaries, panel unchanged')
print('RUNTIME PENDING: actual icon colors/alignment, select/start, exit and re-entry')
