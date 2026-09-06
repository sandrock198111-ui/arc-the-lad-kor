"""Read-only raw-sector audit: title payload vs filesystem timestamps.

EDC polynomial / GF(256) parity parameters cross-checked against mkpsxiso's
EDCECC (Neill Corlett ecmtools routines):
https://github.com/Lameguy64/mkpsxiso/blob/master/src/mkpsxiso/edcecc.cpp
This script never regenerates or writes disc sectors.
"""
from pathlib import Path
import hashlib, json, struct
from verify_iso_layout import read_iso

ROOT=Path(__file__).resolve().parents[1]
OLD=ROOT/'03_output/V361_SKILL_COMPACT_TEST.bin'
NEW=ROOT/'03_output/V362_KOREAN_TITLE_TEST.bin'
AN=ROOT/'01_work/analysis/v362_korean_title'


def edc(data):
    value=0
    for byte in data:
        value^=byte
        for _ in range(8):value=(value>>1)^(0xD8018001 if value&1 else 0)
    return value


DOUBLE=bytes(((i<<1)^(0x11d if i&128 else 0)) for i in range(256))
INVERSE_XOR_DOUBLE={i^DOUBLE[i]:i for i in range(256)}


def parity(data, columns, rows, spacing, step):
    result=bytearray(columns*2)
    assert len(data)==columns*rows
    for col in range(columns):
        j=(col//2)*spacing+(col&1)
        accum=total=0
        for _ in range(rows):
            symbol=data[j];total^=symbol;accum=DOUBLE[accum^symbol]
            j=(j+step)%len(data)
        p=INVERSE_XOR_DOUBLE[DOUBLE[accum]^total]
        result[col]=p;result[col+columns]=p^total
    return bytes(result)


def check_form1(sector):
    assert sector[:12]==b'\0'+b'\xff'*10+b'\0'
    assert sector[15]==2 and not sector[18]&0x20
    assert sector[16:20]==sector[20:24]
    assert edc(sector[16:2072])==struct.unpack_from('<I',sector,2072)[0]
    body=b'\0'*4+sector[16:2076]
    p=parity(body,86,24,2,86)
    assert p==sector[2076:2248]
    q=parity(body+p,52,43,86,88)
    assert q==sector[2248:2352]


def timestamp_bytes(path):
    allowed={}
    with path.open('rb') as stream:
        def sector(lba):
            stream.seek(lba*2352);raw=stream.read(2352)
            assert raw[15]==2
            return raw[24:2072]
        pvd=sector(16)
        pending=[(struct.unpack_from('<I',pvd,158)[0],struct.unpack_from('<I',pvd,166)[0])]
        seen=set()
        while pending:
            lba,size=pending.pop()
            if (lba,size) in seen:continue
            seen.add((lba,size))
            data=b''.join(sector(lba+i) for i in range((size+2047)//2048))
            at=0
            while at<len(data):
                n=data[at]
                if not n:
                    at=(at//2048+1)*2048;continue
                rec=data[at:at+n]
                assert n>=34 and len(rec)==n and at//2048==(at+n-1)//2048
                for k in range(18,25):allowed.setdefault(lba+at//2048,set()).add(24+at%2048+k)
                if rec[25]&2 and rec[33:33+rec[32]] not in (b'\0',b'\1'):
                    pending.append((struct.unpack_from('<I',rec,2)[0],struct.unpack_from('<I',rec,10)[0]))
                at+=n
    return allowed


def main():
    assert hashlib.sha256(OLD.read_bytes()).hexdigest().upper()=='3BC1E6B99238B02174BD2009491DF3ED7ACA697523C4DD993F44E62CC2057BB8'
    assert OLD.stat().st_size==NEW.stat().st_size
    assert read_iso(OLD)==read_iso(NEW),'ISO file topology/extent/size changed'
    times=timestamp_bytes(NEW)
    assert times==timestamp_bytes(OLD)
    image_lba,image_size=read_iso(NEW)['COMM.IMG']
    assert (image_lba,image_size)==(667,458752)
    changed=[];art=[];metadata=[]
    with OLD.open('rb') as a,NEW.open('rb') as b:
        for lba in range(OLD.stat().st_size//2352):
            before,after=a.read(2352),b.read(2352)
            if before==after:continue
            changed.append(lba)
            check_form1(before);check_form1(after)
            assert before[:24]==after[:24],'Sector header/subheader changed'
            payload_changes={i for i in range(24,2072) if before[i]!=after[i]}
            if image_lba<=lba<image_lba+image_size//2048:
                art.append(lba)
            else:
                assert payload_changes<=times.get(lba,set()),('unexplained sector change',lba)
                metadata.append(lba)
    assert art==list(range(732,751)) and len(metadata)==27
    result={'bin_sha256':hashlib.sha256(NEW.read_bytes()).hexdigest().upper(),
            'comparison':'V361 preserved baseline; comparison only, not build input',
            'total_sectors':OLD.stat().st_size//2352,'changed_sectors':len(changed),
            'title_sectors':art,'directory_timestamp_sectors':metadata,
            'all_other_raw_sectors_byte_exact':True,'unexplained_payload_changes':0,
            'changed_sector_edc_ecc_checks':len(changed)*2,
            'all_507_file_extents_sizes_identical':True,'runtime_verified':False}
    (AN/'disc_delta.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print('PASS: 19 title sectors + 27 directory timestamp sectors; other raw sectors exact.')
    print('PASS: EDC / P / Q for all 46 changed sectors and their 46 baseline counterparts.')


if __name__=='__main__':main()
