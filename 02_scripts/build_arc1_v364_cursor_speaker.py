"""V364 TEST_ONLY: choice anchor/pitch and bounded speaker line joins."""
from pathlib import Path
from zipfile import ZipFile
import sys,struct,json,hashlib,io,csv
from check_build import slot_ref
from v354_dialogue_codec import tokens,load_v354
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'03_output/arc1_v363_dialogue_trial_TEST_ONLY.zip'
PIN='3AA4546914715171B40E617FD6944E9DF0C375EE0909E1CCE3340A86D51A58BC'
OUT=ROOT/'03_output/arc1_v364_cursor_speaker_TEST_ONLY.zip'
AN=ROOT/'01_work/analysis/v364_cursor_speaker'
ORIGINAL=ROOT/'00_original/arc.zip'
ORIGINAL_PIN='AE9F4366A1E7DA3805BB3BED3DDA9567E4CD4E669AF890E4E2A620D7861F11DD'
BIAS=0x8011a800
def digest(b):return hashlib.sha256(b).hexdigest().upper()

def stream(data,offset,length):
    result=[];at=offset;end=offset+length
    while at<end and data[at]:
        w=1 if data[at]<0xdd else 2;t=data[at:at+w]
        if t[0]==0xe2 and (ref:=slot_ref(data,t[1])):
            bank,n,s=ref;start=(0x45000 if bank=='A' else 0x4200)+n*128
            stop=s.index(0);p=0
            for token in tokens(s[:stop]):result.append((token,start+p));p+=len(token)
            at+=2+s[127];continue
        result.append((t,at));at+=w
    return result

def rows(ts):
    y=x=0
    for t in ts:
        if t==b'\xe6\x01':y+=1;x=0;continue
        adv=8 if t==b'\xa1' else 14
        if x+adv>=228:y+=1;x=0
        x+=adv
    return y+1

def prepare():
    assert digest(BASE.read_bytes())==PIN
    assert digest(ORIGINAL.read_bytes())==ORIGINAL_PIN
    with ZipFile(BASE) as z:infos=z.infolist();old={i.filename:z.read(i) for i in infos};comment=z.comment
    _,_,_,dec=load_v354();writes=[];applied=[];deferred=[]
    def add(fn,at,expected,after,reason):
        assert old[fn][at:at+len(expected)]==expected and len(expected)==len(after)
        for w in writes:
            if w['file']==fn and w['offset']==at:
                assert w['after']==after;return
            assert fn!=w['file'] or at+len(after)<=w['offset'] or w['offset']+len(w['after'])<=at
        writes.append({'file':fn,'offset':at,'before':expected,'after':after,'reason':reason})
    # Fixed MIPS32 little-endian block: no new jump, cave, pointer, ABI or code movement.
    sys.path.insert(0,str(ROOT/'01_work/tools/cursor_verify'))
    from keystone import Ks,KS_ARCH_MIPS,KS_MODE_MIPS32,KS_MODE_LITTLE_ENDIAN
    import capstone
    ks=Ks(KS_ARCH_MIPS,KS_MODE_MIPS32|KS_MODE_LITTLE_ENDIAN)
    md=capstone.Cs(capstone.CS_ARCH_MIPS,capstone.CS_MODE_MIPS32|capstone.CS_MODE_LITTLE_ENDIAN)
    specs=[(0x8015a6e0,'sll $v1, $a0, 3','sll $v1, $a0, 4'),
           (0x8015a6e4,'subu $v1, $v1, $a0','nop'),(0x8015a6e8,'sll $v1, $v1, 1','nop'),
           (0x8015a708,'sll $v0, $a1, 3','sll $v0, $a1, 4'),
           (0x8015a70c,'subu $v0, $v0, $a1','nop'),
           (0x8015a71c,'sll $v0, $v0, 1','addiu $a0, $a0, 14'),
           (0x8015a72c,'addiu $a1, $a1, -1','addiu $a1, $a1, 2')]
    for address,before,after in specs:
        enc=lambda s:bytes(ks.asm(s,addr=address)[0])
        target=enc(after);ins=list(md.disasm(target,address));assert len(ins)==1 and ins[0].size==4
        assert enc(ins[0].mnemonic+' '+ins[0].op_str)==target
        add('PSX.EXE',address-BIAS,enc(before),target,'choice-specific X+14, Y center+2, vertical pitch16')
    originals=list(csv.DictReader((ROOT/'05_docs/script_original_full.csv').open(encoding='utf-8-sig')))
    for number,r in enumerate(originals,1):
        fn=r['source file']
        if fn not in old:continue
        seq=stream(old[fn],int(r['byte offset'],16),len(bytes.fromhex(r['raw bytes as hex'])))
        ts=[t for t,_ in seq]
        if b'\xe6\x01' not in ts:continue
        k=ts.index(b'\xe6\x01');prefix=''.join(dec.get(t,'?') for t in ts[:k]).rstrip()
        if not prefix.endswith(':') or len(prefix)>25:continue
        info={'row':number,'file':fn,'offset':r['byte offset']}
        if any(t not in dec and t!=b'\xe6\x01' for t in ts):
            deferred.append({**info,'reason':'special controls/choice require separate layout validation'});continue
        after=ts[:k]+[b'\xa1',b'\xa1']+ts[k+1:]
        count=sum(t!=b'\xe6\x01' for t in after)
        if count>64 or rows(after)>4:
            deferred.append({**info,'reason':'64-packet or conservative 4-row bound','packets':count,'rows':rows(after)});continue
        add(fn,seq[k][1],b'\xe6\x01',b'\xa1\xa1','same-size speaker break to blank join')
        applied.append({**info,'packets':count,'rows':rows(after)})
    # Low-address two-choice prompt: retain two rows before E5 by natural wrap.
    fn='6/S6054.DAT';raw=old[fn][0x4395a:0x43972]
    ts=list(tokens(raw));assert ts[4]==b'\xe6\x01'
    changed=ts[:4]+[b'\xa1',b'\xa1']+ts[5:]
    assert rows(ts)==rows(changed)==2
    add(fn,0x4395f,b'\xe6\x01',b'\xa1\xa1','speaker joined; same two prompt rows, choice E5/E6 positions retained')
    final=dict(old)
    for w in writes:
        b=bytearray(final[w['file']]);at=w['offset'];b[at:at+len(w['after'])]=w['after'];final[w['file']]=bytes(b)
    for fn in old:
        allowed={i for w in writes if w['file']==fn for i in range(w['offset'],w['offset']+len(w['after']))}
        assert len(final[fn])==len(old[fn])
        assert all(a==b or i in allowed for i,(a,b) in enumerate(zip(old[fn],final[fn])))
    assert final['COMM.IMG']==old['COMM.IMG']
    buf=io.BytesIO()
    with ZipFile(buf,'w') as z:
        z.comment=comment
        for info in infos:z.writestr(info,final[info.filename])
    result={'zip_sha256':digest(buf.getvalue()),'baseline_sha256':PIN,'runtime_verified':False,
            'writes':[{**w,'before':w['before'].hex(),'after':w['after'].hex()} for w in writes],
            'applied':applied,'deferred':deferred,'extra_low_address_join':True,
            'changed_members':[fn for fn in old if old[fn]!=final[fn]],
            'policy':'TEST_ONLY; spacing/layout only, canonical/export CSV preserved; inherited V363 legacy dependency'}
    return buf.getvalue(),result

if __name__=='__main__':
    payload,report=prepare();assert prepare()[0]==payload
    if OUT.exists():assert OUT.read_bytes()==payload
    else:OUT.write_bytes(payload)
    AN.mkdir(exist_ok=True)
    (AN/'build_report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(report['zip_sha256'],'joined',len(report['applied'])+1,'deferred',len(report['deferred']))
