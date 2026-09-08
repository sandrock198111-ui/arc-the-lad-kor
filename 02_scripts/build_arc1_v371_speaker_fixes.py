"""Four user-approved speaker fixes, preserving controls and event boundaries."""
import io,json
from zipfile import ZipFile
import build_arc1_v370_event_restore as previous
from build_arc1_v364_cursor_speaker import stream
from v354_dialogue_codec import load_v354,encode
ROOT=previous.ROOT; ORIGINAL=previous.ORIGINAL; ORIGINAL_PIN=previous.ORIGINAL_PIN
digest=previous.digest; BASE=previous.OUT
PIN='8FE8CF805C571C40E7215CF71CBFEB559F639DB71CF0AF48C40AEF691D7BB404'
OUT=ROOT/'03_output/arc1_v371_speaker_fixes_TEST_ONLY.zip'
AN=ROOT/'01_work/analysis/v371_speaker_fixes'
TARGETS=[(2148,'7/S7032.DAT',0x478ba,0x478e1),
         (2151,'7/S7032.DAT',0x479ec,0x47a39),
         (2152,'7/S7032.DAT',0x47a72,0x47acf),
         (1742,'6/S6054.DAT',0x45d02,0x45d1c)]
SPEECH='항상 목적을 가지고 행동하십시오.'

def prepare():
    assert digest(BASE.read_bytes())==PIN and previous.prepare()[0]==BASE.read_bytes()
    with ZipFile(BASE) as z:
        infos=z.infolist();old={i.filename:z.read(i) for i in infos};comment=z.comment
    writes=[]
    for row,fn,start,end in TARGETS[:1]:
        seq=stream(old[fn],start,end-start)
        assert [t.hex() for t,_ in seq[:5]]==['d5','58','ddf0','dd02','e601']
        at=seq[4][1]
        writes.append(dict(file=fn,offset=at,before='e601',after='a1a1',reason=f'#{row} speaker join'))
    fn='7/S7032.DAT';d=old[fn]
    # #2151: explicit word-boundary rows, retaining E4 order and all text.
    # Recover two skipped filler bytes from its unique A2 caller.
    assert [i for i in range(len(d)-1) if d[i:i+2]==b'\xe2\x83']==[0x479f4]
    assert d[0x4517f]==7
    original=d[0x479ec:0x47a39]
    assert original.hex()=='d558ddf0dd02e601e283a1a1a1a1a1a1a1e43de284a1a1a1e41f6c95a134030e25a1a1a1a1a1e43ddd53dd6bdd18a1e429e285a1a1a1e43d4f2ba1e41f473cdd5ca1e43d6ddd167f070121e43d'
    target=bytes.fromhex('d558ddf0dd02a1a1e283a1a1a1a1a1e43de601e284a1a1a1a1e41f6c95a134030e25e601e43ddd53dd6bdd18a1e429e285a1a1a1e43de6014f2ba1e41f473cdd5ca1e43d6ddd167f070121e43d')
    assert len(target)==len(original),(len(target),len(original))
    writes.extend([dict(file=fn,offset=0x479ec,before=original.hex(),after=target.hex(),reason='#2151 join speaker and wrap at word boundaries'),
                   dict(file=fn,offset=0x4517f,before='07',after='05',reason='#2151 unique E283 reclaim two skipped filler bytes')])
    # #2152: move the existing second break before '이'; preserve total size.
    original=d[0x47a78:0x47a98]
    assert original.hex()=='e60115491bd5e43d03a1e41fe286a1a1a1a1a1a1a1e6015fdd39a1377a0fa1a1'
    target=bytes.fromhex('a1a115491bd5e43de60103a1e41fe286a1a1a1a1a1a1a1a15fdd39a1377a0fa1')
    assert len(target)==len(original)
    target+=d[0x47a98:0x47acf]
    target=target.replace(bytes.fromhex('e286')+b'\xa1'*7,bytes.fromhex('e286')+b'\xa1'*5,1)
    target=target.replace(bytes.fromhex('377a0fa1e41f69'),bytes.fromhex('377a0fa1e601e41f69'),1)
    target=target.replace(bytes.fromhex('36e40b8e'),bytes.fromhex('36e40ba18e'),1)
    target=target.replace(bytes.fromhex('03e40b09'),bytes.fromhex('03e40ba109'),1)
    target=target.replace(bytes.fromhex('e407a1e407a1e407a1e43d'),bytes.fromhex('e407e407e407a1e43d'),1)
    original=d[0x47a78:0x47acf];assert len(target)==len(original)
    assert [i for i in range(len(d)-1) if d[i:i+2]==b'\xe2\x86']==[0x47a84] and d[0x452ff]==7
    writes.append(dict(file=fn,offset=0x47a78,before=original.hex(),after=target.hex(),reason='#2152 four word-boundary rows; E4 sequence preserved'))
    writes.append(dict(file=fn,offset=0x452ff,before='07',after='05',reason='#2152 unique E286 reclaim two skipped filler bytes'))
    fn='6/S6054.DAT';d=old[fn];at=0x4880
    assert [i for i in range(len(d)-1) if d[i:i+2]==b'\xe2\xde']==[0x45d09]
    assert d[0x45d02:0x45d1d]==bytes.fromhex('e2d2a1a1a1a1a1e2dea1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a100')
    expected=bytes.fromhex('ddf28ba1dd33dd090da10c041ca1dd31dd321933dd72a119328f2100')
    assert d[at:at+len(expected)]==expected and d[at+127]==17
    encoded,missing=encode(SPEECH,load_v354()[2],True)
    assert not missing and len(encoded)==23 and len(encoded)<len(expected)
    head,missing=encode('항상 목적을',load_v354()[2],True);assert not missing
    tail,missing=encode('가지고 행동하십시오.',load_v354()[2],True);assert not missing
    assert head+b'\xa1'+tail==encoded
    replacement=head+b'\0'*(len(expected)-len(head))
    writes.append(dict(file=fn,offset=at,before=expected.hex(),after=replacement.hex(),reason='#1742 approved polite speech head in existing unique slot'))
    inline=b'\xa1\xe2\xde'+b'\xa1'*3+b'\xe6\x01'+tail
    assert len(inline)==0x45d1c-0x45d07
    writes.append(dict(file=fn,offset=0x45d07,before=d[0x45d07:0x45d1c].hex(),after=inline.hex(),reason='#1742 inline break and polite tail, no leading continuation space'))
    writes.append(dict(file=fn,offset=0x48ff,before='11',after='03',reason='#1742 unique E2DE returns to inline break; original final NUL retained'))
    # Validate complete, non-overlapping plan before mutating copies.
    allowed={n:set() for n in old}
    for w in writes:
        before=bytes.fromhex(w['before']);after=bytes.fromhex(w['after']);a=w['offset'];n=w['file']
        assert len(before)==len(after) and old[n][a:a+len(before)]==before
        region=set(range(a,a+len(before)));assert not region&allowed[n];allowed[n]|=region
    final={n:bytearray(d) for n,d in old.items()}
    for w in writes:
        a=w['offset'];v=bytes.fromhex(w['after']);final[w['file']][a:a+len(v)]=v
    final={n:bytes(d) for n,d in final.items()}
    for n in old:
        assert len(old[n])==len(final[n])
        assert all(a==b or i in allowed[n] for i,(a,b) in enumerate(zip(old[n],final[n])))
    for row,n,start,end in TARGETS:
        assert final[n][end]==old[n][end]==0
        before=[t for t,_ in stream(old[n],start,end-start)]
        after=[t for t,_ in stream(final[n],start,end-start)]
        controls=lambda ts:[t for t in ts if t[0] in (0xe4,0xe5,0xe7)]
        assert controls(before)==controls(after)
        if row!=1742:
            compact=lambda ts:[t for t in ts if t not in (b'\xa1',b'\xe6\x01')]
            assert compact(after)==compact(before)
    assert final['PSX.EXE']==old['PSX.EXE'] and final['COMM.IMG']==old['COMM.IMG']
    buf=io.BytesIO()
    with ZipFile(buf,'w') as z:
        z.comment=comment
        for info in infos:z.writestr(info,final[info.filename])
    return buf.getvalue(),dict(zip_sha256=digest(buf.getvalue()),baseline_sha256=PIN,writes=writes,
        changed_members=[n for n in old if old[n]!=final[n]],
        changed_bytes=sum(sum(a!=b for a,b in zip(old[n],final[n])) for n in old),
        static_pass=True,runtime_verified=False,
        scope='Four approved reports only; remaining speaker census and whole-game speech review not completed.')

if __name__=='__main__':
    from verify_arc1_v371_speaker_fixes import verify
    blob,report=prepare();assert prepare()[0]==blob
    report['cpu']=verify(blob)
    if OUT.exists():assert OUT.read_bytes()==blob
    else:OUT.write_bytes(blob)
    AN.mkdir(exist_ok=True)
    for name in ('build_report.json','verification.json'):
        (AN/name).write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(report['zip_sha256'],report['changed_bytes'],'changed bytes')
