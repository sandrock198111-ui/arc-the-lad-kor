"""Isolated pristine staging; never touches emulator memory cards or old images."""
from pathlib import Path
import subprocess
import argparse
import package_test_iso as p
ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser()
parser.add_argument('--recovery',action='store_true')
parser.add_argument('--remaining-names',action='store_true')
args=parser.parse_args()
if args.recovery and args.remaining_names:raise SystemExit('choose only one package variant')
stem='V359_REVIEW_UPDATE2' if args.remaining_names else ('V359_REVIEW_UPDATE' if args.recovery else 'V359_REVIEW_ALL')
p.WORK=ROOT/'01_work'/('package_v359_review_update2' if args.remaining_names else ('package_v359_review_update' if args.recovery else 'package_v359_review_all'))
p.FILES=p.WORK/'files'
p.STATE=p.WORK/'applied.json'
binary=ROOT/'03_output'/f'{stem}.bin'
cue=ROOT/'03_output'/f'{stem}.cue'
archive=ROOT/'03_output'/('arc1_v359_review_215_TEST_ONLY.zip' if args.remaining_names else ('arc1_v359_slot_recovery2_TEST_ONLY.zip' if args.recovery else 'arc1_v359_review_all_final_TEST_ONLY.zip'))
if binary.exists() or cue.exists():raise SystemExit('Output exists; do not overwrite')
p.ensure_tree()
p.restore_and_apply(archive)
xml=p.WORK/f'{stem}.xml'
p.write_xml(xml,binary,cue)
subprocess.run([str(p.MKPSXISO),'-y','-q','-lba',str(p.WORK/f'{stem}_lba.txt'),str(xml)],cwd=ROOT,check=True)
subprocess.run(['python',str(ROOT/'02_scripts/verify_iso_layout.py'),str(binary),str(archive)],cwd=ROOT,check=True)
print('BIN SHA256',p.digest(binary))
print('CUE',cue)
