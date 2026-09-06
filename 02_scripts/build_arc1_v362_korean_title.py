"""V362: encode localized subtitle artwork into the native RGB555 title.

Artwork is authored with image_gen, not painted procedurally. This packer
resamples that frozen raster to the proven native texture coordinates, then
copies only the declared subtitle patch, protecting the original sword.
The explicitly pinned V361 legacy archive is applied to original-disc staging.
No font allocation, engine hook, pointer, compressed data or VRAM layout changes.
"""
from pathlib import Path
from zipfile import ZipFile
import hashlib, io, json, struct, sys
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / '03_output/arc1_v361_skill_compact_TEST_ONLY.zip'
PIN = 'B0AA760222B6F9AE3CB063FC49531DB5E9A735BD4EDDA56759F5CAD7CE2426C8'
ORIGINAL = ROOT / '00_original/arc.zip'
ORIGINAL_PIN = 'AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD'
COMM_PIN = '6C7565B6C326A99A29266482868F17A144FF7D15B871D7D8F8B852EC41014A26'
ART = ROOT / '01_work/assets/v362_title/localized_source.png'
ART_PIN = '278BDDB4BF1397078D5D5E415272A988748E4FFABED7EC829F596EB4A755B1B5'
OUT = ROOT / '03_output/arc1_v362_korean_title_TEST_ONLY.zip'
AN = ROOT / '01_work/analysis/v362_korean_title'
CSV_PINS = {
    'script_translated_full.csv': '90DB5C0E984C6EED14BD747736F023053DC87E7A09D0BFDE2681003EB40F6E51',
    'dialogue_all.csv': 'CEBB7E2C575F3669873693B2C6BC03AA239DAF801474DC3A326F31A58383EEC5',
}
# Half-open, texture-local coordinates. COMM is 448 words wide, title x=64.
ROI = (90, 149, 234, 192)
SOURCE_FRAME = (46, 81, 1410, 1069)
NATIVE_FRAME = (12, 24, 309, 232)
# Visually inspected original blade silhouette; x is [left, right).
# Protect the original antialiased edge as well as its bright central facets.
BLADE_SPANS = ((144, 165, 158, 165), (165, 174, 159, 164),
               (174, 182, 159, 163), (182, 187, 160, 163),
               (187, 192, 160, 162))


def digest(data):
    return hashlib.sha256(data).hexdigest().upper()


def blade(x, y):
    return any(y0 <= y < y1 and x0 <= x < x1 for y0, y1, x0, x1 in BLADE_SPANS)


def offset(x, y):
    return 2 * (448 * y + 64 + x)


def texture(comm):
    return b''.join(comm[offset(0, y):offset(344, y)] for y in range(256))


def decode(data, size):
    words = struct.unpack('<' + 'H' * (len(data) // 2), data)
    rgb = bytes(v * 255 // 31 for w in words for v in (w & 31, (w >> 5) & 31, (w >> 10) & 31))
    return Image.frombytes('RGB', size, rgb)


def localized_region():
    assert digest(ART.read_bytes()) == ART_PIN, 'Artwork is not the reviewed frozen source'
    art = Image.open(ART)
    assert art.size == (1455, 1081) and art.mode == 'RGB'
    sx0, sy0, sx1, sy1 = SOURCE_FRAME
    nx0, ny0, nx1, ny1 = NATIVE_FRAME
    x0, y0, x1, y1 = ROI
    scale_x, scale_y = (sx1 - sx0) / (nx1 - nx0), (sy1 - sy0) / (ny1 - ny0)
    box = (sx0 + (x0 - nx0) * scale_x, sy0 + (y0 - ny0) * scale_y,
           sx0 + (x1 - nx0) * scale_x, sy0 + (y1 - ny0) * scale_y)
    # Ordinary native-size import. No artificial pixel texture or sharpening.
    return art.resize((x1 - x0, y1 - y0), Image.Resampling.LANCZOS, box=box)


def prepare():
    assert digest(BASE.read_bytes()) == PIN
    assert digest(ORIGINAL.read_bytes()) == ORIGINAL_PIN
    for name, want in CSV_PINS.items():
        assert digest((ROOT / '05_docs' / name).read_bytes()) == want, name
    with ZipFile(BASE) as z:
        infos = z.infolist()
        old = {i.filename: z.read(i) for i in infos}
        comment = z.comment
    with ZipFile(ORIGINAL) as z:
        original = z.read('COMM.IMG')
    assert digest(original) == COMM_PIN and len(original) == 458752
    assert len(old) == 164 and len(old['COMM.IMG']) == len(original)
    assert texture(old['COMM.IMG']) == texture(original), 'Baseline title was already modified'
    comm = bytearray(old['COMM.IMG'])
    patch = localized_region()
    x0, y0, x1, y1 = ROI
    writable = set()
    blade_pixels = 0
    opaque_black_texels = 0
    for y in range(y0, y1):
        for x in range(x0, x1):
            at = offset(x, y)
            if blade(x, y):
                blade_pixels += 1
                continue
            r, g, b = patch.getpixel((x - x0, y - y0))
            before = struct.unpack_from('<H', comm, at)[0]
            # Native import coverage tapers in the surrounding background
            # margin only; both the original and localized letters are inside
            # full coverage. Preserve exact boundary pixels (coverage zero).
            coverage = min(256, (x - x0) * 256 // 10, (x1 - 1 - x) * 256 // 10,
                           (y - y0) * 256 // 2, (y1 - 1 - y) * 256 // 8)
            if coverage == 0:
                continue
            old_rgb = ((before & 31) * 255 // 31, ((before >> 5) & 31) * 255 // 31,
                       ((before >> 10) & 31) * 255 // 31)
            r, g, b = ((a * coverage + o * (256 - coverage) + 128) // 256
                       for a, o in zip((r, g, b), old_rgb))
            # Preserve STP; round each 8-bit RGB channel to its 5-bit value.
            value = ((r * 31 + 127) // 255) | (((g * 31 + 127) // 255) << 5) | (((b * 31 + 127) // 255) << 10)
            # RGB555 zero is a transparent PS1 texel. Reserve it: an opaque
            # dark shadow rounds instead to the first neutral nonzero level.
            if value == 0:
                value = 0x0421
                opaque_black_texels += 1
            value |= before & 0x8000
            struct.pack_into('<H', comm, at, value)
            writable.update((at, at + 1))
    changes = [i for i, (a, b) in enumerate(zip(old['COMM.IMG'], comm)) if a != b]
    assert changes and set(changes) <= writable
    assert all((a & 0x80) == (b & 0x80) for a, b in zip(old['COMM.IMG'][1::2], comm[1::2]))
    current = dict(old)
    current['COMM.IMG'] = bytes(comm)
    stream = io.BytesIO()
    with ZipFile(stream, 'w') as z:
        z.comment = comment
        for info in infos:
            z.writestr(info, current[info.filename])
    payload = stream.getvalue()
    report = {
        'baseline_zip_sha256': PIN, 'original_zip_sha256': ORIGINAL_PIN,
        'zip_sha256': digest(payload), 'comm_sha256': digest(comm),
        'artwork_sha256': ART_PIN, 'artwork_path': str(ART.relative_to(ROOT)),
        'format': 'uncompressed little-endian RGB555+STP, 448x512 words',
        'native_title_rectangle': [64, 0, 344, 256],
        'texture_local_roi': ROI, 'source_frame': SOURCE_FRAME, 'native_frame': NATIVE_FRAME,
        'original_blade_spans': BLADE_SPANS, 'protected_blade_pixels_in_roi': blade_pixels,
        'changed_members': ['COMM.IMG'], 'unchanged_members': 163,
        'comm_changed_bytes': len(changes), 'comm_changed_pixels': len({i // 2 for i in changes}),
        'outside_roi_and_sword_byte_exact': True, 'stp_bits_unchanged': True,
        'opaque_black_substitutions': opaque_black_texels,
        'import_coverage_margin_lrtb': [10, 10, 2, 8],
        'csv_sha256': CSV_PINS, 'engine_font_dialogue_unchanged': True,
        'runtime_verified': False,
        'build_dependency': 'Pinned V361 legacy archive + frozen image_gen artwork; original-disc staging; not full historical source replay',
    }
    return payload, report, current


def main():
    payload, report, current = prepare()
    assert prepare()[0] == payload, 'Non-deterministic output'
    AN.mkdir(parents=True, exist_ok=True)
    im = decode(texture(current['COMM.IMG']), (344, 256))
    im.save(AN / 'title_native.png')
    im.resize((1032, 768), Image.Resampling.BILINEAR).save(AN / 'title_native_3x.png')
    if '--preview' in sys.argv:
        print('PREVIEW ONLY; no game archive written')
    elif OUT.exists():
        assert OUT.read_bytes() == payload, 'Refusing to overwrite different output'
    else:
        OUT.write_bytes(payload)
    (AN / 'build_report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
