"""A local page for reading and editing the translation, line by line.

Everything needed to judge a line is on its row: the Japanese, the Korean, and the
byte budget. That last one is the reason this exists rather than a spreadsheet. A line
is written back into the bytes the Japanese sentence occupied, and if it no longer fits
it has to move to an external slot, of which a scene file has 79. So the length of an
edit is not a detail -- it decides whether the line can be inserted at all -- and the
count here updates as you type, from the same character-to-code table the builder uses,
read out of the built archive rather than a map.

Run it and a browser opens on the table:

    python 02_scripts/review_server.py

Saving writes `05_docs/script_translated_full.csv` and keeps the previous contents in
`script_translated_full.csv.gui.bak`. Only the Korean column is ever written; the
Japanese, the file and the offset are what the builder keys on and are never touched.
"""
from __future__ import annotations

import csv
import http.server
import json
import re
import shutil
import socketserver
import sys
import threading
import webbrowser
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02_scripts"))
sys.path.insert(0, str(ROOT / "06_tools" / "python_packages"))

from plan_bulk_insertion import (  # noqa: E402
    CHOICE, SLOT_COUNT, SLOT_TEXT_MAX, build_encoder, has_marker,
)

TABLE = ROOT / "05_docs/script_translated_full.csv"
BACKUP = ROOT / "05_docs/script_translated_full.csv.gui.bak"
ORIGINAL_CSV = ROOT / "05_docs/script_original_full.csv"
BUILD = ROOT / "03_output/story_v122_slot_e6_swept_patch_only.zip"
CTRL = re.compile(r"<(?:CTRL|G):[^>]*>")
PORT = 8731

PAGE = """<!doctype html><meta charset="utf-8"><title>번역 검수</title>
<style>
 :root{--bg:#14161a;--fg:#e8e6e3;--dim:#8b8b8b;--line:#2a2d33;--ok:#4a9d5f;--warn:#c9a227;--bad:#c05252}
 body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 system-ui,"Malgun Gothic",sans-serif}
 header{position:sticky;top:0;background:#1a1d22;border-bottom:1px solid var(--line);padding:10px 14px;z-index:5}
 header input,header select{background:#0f1114;color:var(--fg);border:1px solid var(--line);border-radius:5px;padding:6px 9px;font:inherit}
 header input[type=search]{width:260px}
 button{background:#2b6cb0;color:#fff;border:0;border-radius:5px;padding:7px 14px;font:inherit;cursor:pointer}
 button:disabled{background:#3a3d44;color:#777;cursor:default}
 .muted{color:var(--dim)}
 .row{border-bottom:1px solid var(--line);padding:10px 14px;display:grid;grid-template-columns:190px 1fr;gap:14px}
 .row:hover{background:#171a1f}
 .meta{font-size:12px;color:var(--dim);line-height:1.7}
 .jp{white-space:pre-wrap;color:#a8b6c8;margin-bottom:6px}
 textarea{width:100%;background:#0f1114;color:var(--fg);border:1px solid var(--line);border-radius:5px;
   padding:7px 9px;font:inherit;resize:vertical;min-height:2.6em;box-sizing:border-box}
 textarea:focus{outline:2px solid #2b6cb0;border-color:#2b6cb0}
 .row.dirty textarea{border-color:var(--warn)}
 .fit{font-size:12px;margin-top:4px}
 .tag{display:inline-block;border-radius:3px;padding:1px 6px;margin-right:5px;font-size:11px}
 .t-inline{background:#1e3a24;color:#8fd6a3}.t-slot{background:#3a3320;color:#e0c778}
 .t-over{background:#4a2020;color:#f0a0a0}.t-flag{background:#2a2f3a;color:#9fb4d8}
 #more{display:block;margin:16px auto 40px;background:#3a3d44}
</style>
<header>
 <input type=search id=q placeholder="검색: 한국어 · 일본어 · 파일">
 <select id=file></select>
 <select id=flag>
  <option value="">전체</option>
  <option value="dirty">고친 것만</option>
  <option value="over">예산 초과</option>
  <option value="slot">슬롯 사용</option>
  <option value="mixed">말투 혼용(MIXED)</option>
  <option value="choice">선택지 본문</option>
 </select>
 <span id=count class=muted></span>
 <button id=save disabled>저장</button>
 <span id=status class=muted></span>
</header>
<div id=list></div>
<button id=more hidden>더 보기</button>
<script>
let ROWS=[],WIDTH={},SHOWN=0,PAGE=150;
const $=s=>document.querySelector(s);
const bytes=t=>{let n=0;for(const c of t)n+=(c===' ')?1:(c==='|'?2:(WIDTH[c]??2));return n};
function classify(r){
  const n=bytes(r.korean);
  if(n<=r.budget)return{k:'inline',label:'제자리 '+n+'/'+r.budget};
  if(r.choice)return{k:'over',label:'선택지 본문 — 지금은 삽입 불가 '+n+'/'+r.budget};
  if(n>127)return{k:'over',label:'슬롯 한도 초과 '+n+'/127'};
  return{k:'slot',label:'슬롯 '+n+'B (원문 '+r.budget+')'};
}
function visible(){
  const q=$('#q').value.trim().toLowerCase(),f=$('#file').value,g=$('#flag').value;
  return ROWS.filter(r=>{
    if(f&&r.file!==f)return false;
    if(q&&!(r.korean.toLowerCase().includes(q)||r.japanese.toLowerCase().includes(q)||r.file.toLowerCase().includes(q)))return false;
    const c=classify(r);
    if(g==='dirty'&&!r.dirty)return false;
    if(g==='over'&&c.k!=='over')return false;
    if(g==='slot'&&c.k!=='slot')return false;
    if(g==='mixed'&&!r.mixed)return false;
    if(g==='choice'&&!r.choice)return false;
    return true;
  });
}
function render(reset){
  const v=visible();
  if(reset){SHOWN=0;$('#list').innerHTML=''}
  const slice=v.slice(SHOWN,SHOWN+PAGE);SHOWN+=slice.length;
  const frag=document.createDocumentFragment();
  for(const r of slice){
    const c=classify(r);
    const d=document.createElement('div');
    d.className='row'+(r.dirty?' dirty':'');
    d.innerHTML=`<div class=meta><b>${r.file}</b><br>${r.offset}
      ${r.speaker?'<br>화자 '+r.speaker:''}
      ${r.mixed?'<br><span class="tag t-flag">MIXED</span>':''}
      ${r.choice?'<br><span class="tag t-flag">선택지</span>':''}</div>
      <div><div class=jp></div><textarea rows=2></textarea>
      <div class=fit><span class="tag t-${c.k}">${c.label}</span></div></div>`;
    d.querySelector('.jp').textContent=r.japanese;
    const ta=d.querySelector('textarea');
    ta.value=r.korean;
    ta.addEventListener('input',()=>{
      r.korean=ta.value;r.dirty=r.korean!==r.original;
      d.classList.toggle('dirty',r.dirty);
      const c2=classify(r);
      d.querySelector('.fit').innerHTML=`<span class="tag t-${c2.k}">${c2.label}</span>`;
      $('#save').disabled=!ROWS.some(x=>x.dirty);
      updateCount();
    });
    frag.appendChild(d);
  }
  $('#list').appendChild(frag);
  $('#more').hidden=SHOWN>=v.length;
  $('#more').textContent=`더 보기 (${v.length-SHOWN}행 남음)`;
  updateCount(v.length);
}
function updateCount(total){
  const d=ROWS.filter(r=>r.dirty).length;
  const t=total??visible().length;
  $('#count').textContent=`${t}행 표시 · 고친 것 ${d}행`;
}
async function boot(){
  const j=await (await fetch('/api/rows')).json();
  ROWS=j.rows;WIDTH=j.width;
  ROWS.forEach(r=>{r.original=r.korean;r.dirty=false});
  const files=[...new Set(ROWS.map(r=>r.file))].sort();
  $('#file').innerHTML='<option value="">파일 전체</option>'+files.map(f=>`<option>${f}</option>`).join('');
  ['#q','#file','#flag'].forEach(s=>$(s).addEventListener('input',()=>render(true)));
  $('#more').addEventListener('click',()=>render(false));
  $('#save').addEventListener('click',save);
  render(true);
}
async function save(){
  const edits=ROWS.filter(r=>r.dirty).map(r=>({file:r.file,offset:r.offset,korean:r.korean}));
  $('#save').disabled=true;$('#status').textContent='저장 중…';
  const res=await fetch('/api/save',{method:'POST',body:JSON.stringify(edits)});
  const j=await res.json();
  if(j.ok){ROWS.forEach(r=>{r.original=r.korean;r.dirty=false});
    document.querySelectorAll('.row.dirty').forEach(e=>e.classList.remove('dirty'));
    $('#status').textContent=`${j.changed}행 저장됨 · 백업 ${j.backup}`;updateCount();}
  else{$('#status').textContent='실패: '+j.error;$('#save').disabled=false}
}
boot();
</script>"""


def load() -> tuple[list[dict], dict[str, int]]:
    with zipfile.ZipFile(BUILD) as archive:
        table = build_encoder(archive.read("PSX.EXE"), archive.read("COMM.IMG"))
    width = {ch: len(code) for ch, code in table.items()}

    budgets: dict[tuple[str, str], tuple[int, bytes]] = {}
    with ORIGINAL_CSV.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        key = "offset" if "offset" in (reader.fieldnames or []) else "byte offset"
        for row in reader:
            budgets[(row["source file"], row[key])] = (
                int(row["length"]),
                bytes.fromhex(row["raw bytes as hex"].replace(" ", "")))

    speaker = re.compile(r"^\s*([^:：|]{1,10})\s*[:：]\s*")
    out = []
    with TABLE.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            korean = (row.get("korean") or "").strip()
            if not any("가" <= c <= "힣" for c in korean):
                continue
            budget, raw = budgets.get((row["source file"], row["offset"]), (0, b""))
            m = speaker.match(korean)
            out.append({
                "file": row["source file"], "offset": row["offset"],
                "japanese": CTRL.sub("", row.get("japanese") or "").replace("\n", " / "),
                "korean": korean, "budget": budget,
                "speaker": m.group(1).strip() if m else "",
                "choice": has_marker(raw, CHOICE),
                "mixed": False,
            })
    # a speaker whose lines disagree on register is flagged, as in the exported review
    polite = ("습니다", "ㅂ니다", "세요", "어요", "지요", "네요", "군요", "죠", "요")
    plain = ("는다", "ㄴ다", "이다", "거야", "야", "어", "지", "네", "군", "자", "라", "다")
    levels: dict[str, set[str]] = {}
    for r in out:
        if not r["speaker"]:
            continue
        body = speaker.sub("", r["korean"]).rstrip("\"')」』.…~- ")
        for end, tag in [(polite, "p"), (plain, "n")]:
            if any(body.endswith(e) for e in end):
                levels.setdefault(r["speaker"], set()).add(tag)
                break
    for r in out:
        r["mixed"] = len(levels.get(r["speaker"], ())) > 1
    return out, width


class Handler(http.server.BaseHTTPRequestHandler):
    rows: list[dict] = []
    width: dict[str, int] = {}

    def log_message(self, *args):        # keep the console readable
        pass

    def _send(self, body: bytes, kind: str):
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/api/rows"):
            payload = json.dumps({"rows": self.rows, "width": self.width},
                                 ensure_ascii=False).encode()
            self._send(payload, "application/json; charset=utf-8")
        else:
            self._send(PAGE.encode(), "text/html; charset=utf-8")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            edits = json.loads(self.rfile.read(length) or b"[]")
            changed = write_back(edits)
            for e in edits:                       # keep the served copy in step
                for r in self.rows:
                    if r["file"] == e["file"] and r["offset"] == e["offset"]:
                        r["korean"] = e["korean"]
            body = {"ok": True, "changed": changed, "backup": BACKUP.name}
        except Exception as exc:                  # report, do not crash the session
            body = {"ok": False, "error": str(exc)}
        self._send(json.dumps(body, ensure_ascii=False).encode(),
                   "application/json; charset=utf-8")


def write_back(edits: list[dict]) -> int:
    """Only the Korean column moves. The keys the builder relies on are untouched."""
    with TABLE.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        rows = list(reader)
    index = {(r["source file"], r["offset"]): r for r in rows}
    changed = 0
    for edit in edits:
        row = index.get((edit["file"], edit["offset"]))
        if row is None:
            raise KeyError(f"{edit['file']} {edit['offset']} is not in the table")
        text = edit["korean"].strip()
        if row["korean"] != text:
            row["korean"] = text
            changed += 1
    if changed:
        shutil.copy2(TABLE, BACKUP)
        with TABLE.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
    return changed


def main() -> None:
    Handler.rows, Handler.width = load()
    print(f"{len(Handler.rows)} lines loaded")
    print(f"open http://127.0.0.1:{PORT}/   (Ctrl+C to stop)")
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", PORT), Handler) as server:
        threading.Timer(0.6, lambda: webbrowser.open(f"http://127.0.0.1:{PORT}/")).start()
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")


if __name__ == "__main__":
    main()
