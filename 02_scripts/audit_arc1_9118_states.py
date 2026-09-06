"""Read-only inventory of user-reported UI/battle states; never edits inputs."""
from pathlib import Path
import json, hashlib
from PIL import Image, ImageDraw
import analyze_arc1_v320c_savestates as legacy
from extract_duckstation_savestate import decompress

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / '01_work/analysis/issues_9118_20260906'

def run():
    OUT.mkdir(parents=True, exist_ok=True)
    paths = sorted(Path('C:/Users/Administrator/.paseo/uploads').glob('upload_*/HASH-9118D5AA9448C036_*.sav'))
    assert len(paths) == 8, len(paths)
    sheet = Image.new('RGB', (1024, 424), '#303030')
    draw = ImageDraw.Draw(sheet)
    report = []
    for p in paths:
        n = int(p.stem.rsplit('_', 1)[1])
        thumbnail = decompress(p, 'first')
        assert len(thumbnail) == 256*192*4
        im = Image.frombytes('RGBA', (256, 192), thumbnail, 'raw', 'BGRA').convert('RGB')
        im.save(OUT / f'slot{n}.png')
        x, y = ((n-1)%4)*256, ((n-1)//4)*212
        sheet.paste(im, (x,y+20))
        draw.text((x+5,y+3), f'Slot {n}', fill='white')
        report.append({'slot': n, 'path': str(p), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest(),
                       'format': p.read_bytes()[:5].decode('ascii'),
                       'title': p.read_bytes()[8:128].split(b'\0')[0].decode('ascii'),
                       'thumbnail_bytes': len(thumbnail)})
    sheet.save(OUT / 'contact.png')
    (OUT / 'inventory.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    run()
