<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/security.php';
if (session_status() === PHP_SESSION_NONE) session_start();
sendSecurityHeaders();
$csrf  = csrfTokenGenerate();
$maxMB = round(MAX_FILE_SIZE / 1024 / 1024);
?>
<!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= htmlspecialchars(APP_NAME) ?> — Transfer securizat</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#f8fafc;--surface:#fff;--border:#e2e8f0;--border-2:#cbd5e1;
  --text:#0f172a;--t2:#475569;--t3:#94a3b8;
  --accent:#6366f1;--a2:#8b5cf6;--success:#10b981;--err:#ef4444;
  --shadow:0 1px 3px rgba(0,0,0,.06),0 1px 2px rgba(0,0,0,.04);
  --shadow-lg:0 8px 32px rgba(0,0,0,.08),0 2px 8px rgba(0,0,0,.04);
}
body{font-family:'Inter',-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px 16px;-webkit-font-smoothing:antialiased}
.logo{text-align:center;margin-bottom:28px}
.logo-icon{width:52px;height:52px;background:linear-gradient(135deg,var(--accent),var(--a2));border-radius:16px;display:inline-flex;align-items:center;justify-content:center;font-size:24px;margin-bottom:12px;box-shadow:0 4px 16px rgba(99,102,241,.25)}
.logo h1{font-size:21px;font-weight:700;letter-spacing:-.4px}
.logo p{font-size:13px;color:var(--t3);margin-top:3px}
.card{width:100%;max-width:520px;background:var(--surface);border:1px solid var(--border);border-radius:20px;padding:28px;box-shadow:var(--shadow-lg)}
.dropzone{border:2px dashed var(--border-2);border-radius:14px;padding:36px 20px;text-align:center;cursor:pointer;transition:all .2s;position:relative;background:var(--bg)}
.dropzone:hover,.dropzone.over{border-color:var(--accent);background:rgba(99,102,241,.04)}
.dropzone input{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%}
.dz-icon{width:44px;height:44px;background:linear-gradient(135deg,#ede9fe,#ddd6fe);border-radius:12px;display:inline-flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:10px}
.dz-title{font-size:14px;font-weight:600;color:var(--t2)}
.dz-sub{font-size:11px;color:var(--t3);margin-top:4px}

/* Lista fisiere selectate */
.file-list{display:none;margin-top:12px;display:flex;flex-direction:column;gap:6px}
.file-list:empty{display:none}
.file-chip{display:flex;align-items:center;gap:10px;background:rgba(99,102,241,.06);border:1px solid rgba(99,102,241,.2);border-radius:10px;padding:10px 13px}
.fc-ico{font-size:20px;flex-shrink:0}
.fc-info{flex:1;min-width:0}
.fc-name{font-size:12px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.fc-size{font-size:11px;color:var(--t3);margin-top:1px}
.fc-rm{background:none;border:none;color:var(--t3);cursor:pointer;padding:4px;border-radius:6px;font-size:13px;line-height:1;transition:color .2s;flex-shrink:0}
.fc-rm:hover{color:var(--err)}
.file-summary{display:none;align-items:center;justify-content:space-between;margin-top:8px;font-size:12px;color:var(--t3)}
.file-summary.show{display:flex}

.divider{display:flex;align-items:center;gap:10px;margin:18px 0 14px}
.divider span{font-size:11px;font-weight:600;color:var(--t3);text-transform:uppercase;letter-spacing:.5px;white-space:nowrap}
.divider::before,.divider::after{content:'';flex:1;height:1px;background:var(--border)}
.field{margin-bottom:13px}
.field label{display:block;font-size:12px;font-weight:600;color:var(--t2);margin-bottom:5px;letter-spacing:.2px}
.field input,.field textarea,.field select{width:100%;border:1.5px solid var(--border);border-radius:10px;padding:10px 14px;font-size:13px;color:var(--text);outline:none;transition:border-color .2s,box-shadow .2s;font-family:inherit;background:#fafbfc}
.field input:focus,.field textarea:focus,.field select:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(99,102,241,.1);background:var(--surface)}
.field textarea{resize:vertical;min-height:68px;line-height:1.5}
.field select{appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%2394a3b8' stroke-width='1.5' fill='none' stroke-linecap='round'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 14px center;padding-right:36px}
.field .hint{font-size:11px;color:var(--t3);margin-top:4px}
.pw-wrap{position:relative}
.pw-wrap input{padding-right:40px}
.pw-eye{position:absolute;right:11px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--t3);cursor:pointer;font-size:15px;padding:0;line-height:1}

/* Expiry pills */
.expiry-pills{display:flex;gap:6px;flex-wrap:wrap}
.ep{flex:1;min-width:70px;padding:9px 6px;border:1.5px solid var(--border);border-radius:10px;text-align:center;cursor:pointer;font-size:12px;font-weight:600;color:var(--t2);background:var(--surface);transition:all .15s;line-height:1.3}
.ep span{display:block;font-size:10px;font-weight:400;color:var(--t3);margin-top:2px}
.ep.on{border-color:var(--accent);background:rgba(99,102,241,.08);color:var(--accent)}
.ep:hover:not(.on){border-color:var(--border-2);color:var(--text)}

.progress{display:none;margin-top:14px}
.progress.show{display:block}
.prog-track{height:5px;background:var(--border);border-radius:99px;overflow:hidden}
.prog-fill{height:100%;background:linear-gradient(90deg,var(--accent),var(--a2));border-radius:99px;transition:width .3s;width:0}
.prog-label{font-size:11px;color:var(--t3);text-align:center;margin-top:7px}
.btn-up{width:100%;margin-top:18px;padding:13px;background:linear-gradient(135deg,var(--accent),var(--a2));border:none;border-radius:12px;color:#fff;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit;transition:opacity .2s,transform .1s;box-shadow:0 4px 14px rgba(99,102,241,.28);letter-spacing:.1px}
.btn-up:hover{opacity:.91}
.btn-up:active{transform:scale(.99)}
.btn-up:disabled{opacity:.42;cursor:not-allowed;box-shadow:none}
.result{display:none;margin-top:18px;background:rgba(16,185,129,.05);border:1px solid rgba(16,185,129,.22);border-radius:14px;padding:16px}
.result.show{display:block}
.result-head{display:flex;align-items:center;gap:8px;font-size:13px;font-weight:600;color:#065f46;margin-bottom:11px}
.result-url{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:10px 13px;font-size:12px;font-family:ui-monospace,monospace;color:var(--accent);word-break:break-all;line-height:1.5}
.btn-copy{width:100%;margin-top:9px;padding:9px;background:var(--surface);border:1.5px solid var(--border);border-radius:8px;color:var(--t2);font-size:13px;font-weight:500;cursor:pointer;font-family:inherit;transition:all .2s}
.btn-copy:hover{border-color:var(--accent);color:var(--accent)}
.btn-copy.done{border-color:var(--success);color:var(--success)}
.result-meta{font-size:11px;color:var(--t3);margin-top:9px;display:flex;gap:12px;flex-wrap:wrap}
.err-box{display:none;margin-top:11px;background:#fff5f5;border:1px solid #fecaca;border-radius:10px;padding:11px 14px;font-size:13px;color:#991b1b}
.err-box.show{display:block}
.badges{display:flex;gap:6px;flex-wrap:wrap;justify-content:center;margin-top:18px}
.badge{display:inline-flex;align-items:center;gap:4px;background:var(--surface);border:1px solid var(--border);border-radius:99px;padding:4px 11px;font-size:11px;font-weight:500;color:var(--t3);box-shadow:var(--shadow)}
footer{margin-top:14px;font-size:11px;color:var(--t3);text-align:center}
</style>
</head>
<body>

<div class="logo">
  <div class="logo-icon">🔒</div>
  <h1><?= htmlspecialchars(APP_NAME) ?></h1>
  <p>Transfer securizat de fișiere</p>
</div>

<div class="card">
  <div class="dropzone" id="dz">
    <input type="file" id="fi" multiple>
    <div class="dz-icon">📂</div>
    <div class="dz-title">Trage fișierele aici sau apasă pentru a selecta</div>
    <div class="dz-sub">Maxim <?= $maxMB ?> MB per fișier &nbsp;·&nbsp; Poți selecta mai multe fișiere</div>
  </div>

  <div class="file-list" id="fileList"></div>
  <div class="file-summary" id="fileSummary">
    <span id="summaryText"></span>
    <button style="background:none;border:none;color:var(--err);font-size:12px;cursor:pointer;font-family:inherit" onclick="clearAll()">✕ Șterge tot</button>
  </div>

  <div class="divider"><span>Opțiuni</span></div>

  <div class="field">
    <label>⏳ Expiră după</label>
    <div class="expiry-pills">
      <div class="ep" data-h="1" onclick="setExpiry(this)">1 oră<span>rapid</span></div>
      <div class="ep" data-h="24" onclick="setExpiry(this)">24 ore<span>1 zi</span></div>
      <div class="ep" data-h="168" onclick="setExpiry(this)">7 zile<span>o săptămână</span></div>
      <div class="ep on" data-h="720" onclick="setExpiry(this)">30 zile<span>implicit</span></div>
    </div>
    <input type="hidden" id="expiryHours" value="720">
  </div>

  <div class="field">
    <label>🔑 Parolă de protecție <span style="color:var(--t3);font-weight:400">(opțional)</span></label>
    <div class="pw-wrap">
      <input type="password" id="pw" placeholder="Lasă gol dacă nu dorești parolă" maxlength="100">
      <button type="button" class="pw-eye" id="pwe">👁</button>
    </div>
    <div class="hint">Destinatarul va trebui să introducă această parolă.</div>
  </div>

  <div class="field">
    <label>💬 Mesaj pentru destinatar <span style="color:var(--t3);font-weight:400">(opțional)</span></label>
    <textarea id="msg" placeholder="Un mesaj care va fi afișat destinatarului..." maxlength="1000"></textarea>
  </div>

  <div class="progress" id="prog">
    <div class="prog-track"><div class="prog-fill" id="pFill"></div></div>
    <div class="prog-label" id="pLabel">Se încarcă...</div>
  </div>

  <div class="err-box" id="errBox"></div>

  <button class="btn-up" id="upBtn" disabled>Selectează fișiere mai întâi</button>

  <div class="result" id="res">
    <div class="result-head"><span>✅</span> <span id="resHead">Fișier încărcat cu succes!</span></div>
    <div class="result-url" id="resUrl"></div>
    <button class="btn-copy" id="btnCopy">📋 Copiază link-ul</button>
    <div class="result-meta" id="resMeta"></div>
  </div>
</div>

<div class="badges">
  <span class="badge">🔒 HTTPS</span>
  <span class="badge">🛡 Scanare fișiere</span>
  <span class="badge">🗑 Auto-ștergere</span>
  <span class="badge">🔑 Parolă bcrypt</span>
  <span class="badge">📦 Multi-fișier</span>
</div>
<footer>Fișierele sunt stocate pe un server separat față de aplicația web, pe un disc criptat cu LUKS, și șterse automat la expirare.</footer>

<script>
const MAX=<?= MAX_FILE_SIZE ?>,CSRF='<?= $csrf ?>';
const dz=document.getElementById('dz'),fi=document.getElementById('fi');
const fileList=document.getElementById('fileList'),fileSummary=document.getElementById('fileSummary');
const summaryText=document.getElementById('summaryText'),upBtn=document.getElementById('upBtn');
const prog=document.getElementById('prog'),pFill=document.getElementById('pFill'),pLabel=document.getElementById('pLabel');
const errBox=document.getElementById('errBox'),res=document.getElementById('res');
const resUrl=document.getElementById('resUrl'),btnCopy=document.getElementById('btnCopy'),resMeta=document.getElementById('resMeta');
const pw=document.getElementById('pw'),pwe=document.getElementById('pwe');

let files=[];
const ico={pdf:'📑',doc:'📝',docx:'📝',xls:'📊',xlsx:'📊',ppt:'📊',pptx:'📊',txt:'📄',csv:'📊',
  jpg:'🖼',jpeg:'🖼',png:'🖼',gif:'🖼',webp:'🖼',mp4:'🎬',avi:'🎬',mov:'🎬',mkv:'🎬',
  mp3:'🎵',wav:'🎵',flac:'🎵',zip:'📦',rar:'📦','7z':'📦',gz:'📦',
  json:'📋',xml:'📋',sql:'🗃',psd:'🎨'};
const fmt=b=>b<1024?b+' B':b<1<<20?(b/1024).toFixed(1)+' KB':b<1<<30?(b/1048576).toFixed(1)+' MB':(b/1073741824).toFixed(2)+' GB';
const getExt=n=>(n.split('.').pop()||'').toLowerCase();
const showE=m=>{errBox.textContent='⚠️ '+m;errBox.classList.add('show')};
const hideE=()=>errBox.classList.remove('show');

function setExpiry(el){
  document.querySelectorAll('.ep').forEach(e=>e.classList.remove('on'));
  el.classList.add('on');
  document.getElementById('expiryHours').value=el.dataset.h;
}

function renderFiles(){
  fileList.innerHTML='';
  files.forEach((f,i)=>{
    const d=document.createElement('div');
    d.className='file-chip';
    d.innerHTML=`<div class="fc-ico">${ico[getExt(f.name)]||'📄'}</div>
      <div class="fc-info"><div class="fc-name" title="${f.name}">${f.name}</div><div class="fc-size">${fmt(f.size)}</div></div>
      <button class="fc-rm" data-i="${i}">✕</button>`;
    fileList.appendChild(d);
  });
  fileList.querySelectorAll('.fc-rm').forEach(b=>b.addEventListener('click',()=>{files.splice(+b.dataset.i,1);renderFiles();updateState()}));
  updateState();
}

function updateState(){
  if(files.length===0){
    fileSummary.classList.remove('show');
    upBtn.disabled=true;upBtn.textContent='Selectează fișiere mai întâi';
  } else {
    const total=files.reduce((s,f)=>s+f.size,0);
    summaryText.textContent=`${files.length} fișier${files.length>1?'e':''} · ${fmt(total)}`;
    fileSummary.classList.add('show');
    upBtn.disabled=false;
    upBtn.textContent=files.length===1?'🚀 Încarcă fișierul':`🚀 Încarcă ${files.length} fișiere`;
  }
}

function addFiles(newFiles){
  hideE();res.classList.remove('show');
  let errs=[];
  Array.from(newFiles).forEach(f=>{
    if(f.size>MAX){errs.push(`"${f.name}" depășește ${fmt(MAX)}`);return;}
    if(files.find(x=>x.name===f.name&&x.size===f.size))return; // dedup
    files.push(f);
  });
  if(errs.length) showE(errs.join('; '));
  renderFiles();
}

function clearAll(){files=[];renderFiles();fi.value='';hideE();res.classList.remove('show');}

dz.addEventListener('dragover',e=>{e.preventDefault();dz.classList.add('over')});
dz.addEventListener('dragleave',()=>dz.classList.remove('over'));
dz.addEventListener('drop',e=>{e.preventDefault();dz.classList.remove('over');addFiles(e.dataTransfer.files)});
fi.addEventListener('change',()=>{addFiles(fi.files);fi.value=''});
pwe.addEventListener('click',()=>{pw.type=pw.type==='password'?'text':'password';pwe.textContent=pw.type==='password'?'👁':'🙈'});
btnCopy.addEventListener('click',()=>{navigator.clipboard.writeText(resUrl.textContent).then(()=>{btnCopy.textContent='✅ Copiat!';btnCopy.classList.add('done');setTimeout(()=>{btnCopy.textContent='📋 Copiază link-ul';btnCopy.classList.remove('done')},2000)})});

upBtn.addEventListener('click',()=>{
  if(!files.length)return;
  hideE();res.classList.remove('show');
  const fd=new FormData();
  files.forEach(f=>fd.append('files[]',f));
  fd.append('csrf_token',CSRF);
  fd.append('password',pw.value.trim());
  fd.append('message',document.getElementById('msg').value.trim());
  fd.append('expiry_hours',document.getElementById('expiryHours').value);
  const xhr=new XMLHttpRequest();
  xhr.upload.onprogress=e=>{
    if(!e.lengthComputable)return;
    const p=Math.round(e.loaded/e.total*100);
    pFill.style.width=p+'%';
    pLabel.textContent=p<100?'Se încarcă... '+p+'%':'Se procesează...';
  };
  xhr.onload=()=>{
    upBtn.disabled=false;prog.classList.remove('show');
    try{
      const r=JSON.parse(xhr.responseText);
      if(r.success){
        resUrl.textContent=r.url;
        document.getElementById('resHead').textContent=
          r.file_count>1?`${r.file_count} fișiere încărcate cu succes!`:'Fișier încărcat cu succes!';
        const exp=new Date(r.expires_at.replace(' ','T'));
        const expiryLabels={1:'1 oră',24:'24 ore',168:'7 zile',720:'30 zile'};
        const pts=['⏳ Expiră în '+(expiryLabels[r.expiry_hours]||r.expiry_hours+'h')];
        if(r.has_password) pts.push('🔑 Protejat cu parolă');
        if(r.file_count>1) pts.push(`📦 ${r.file_count} fișiere`);
        resMeta.textContent=pts.join('  ·  ');
        res.classList.add('show');
        // Resetam formularul fara a ascunde caseta cu link-ul (clearAll() ar apela res.classList.remove('show'))
        files=[];renderFiles();fi.value='';hideE();
        pw.value='';document.getElementById('msg').value='';
      } else showE(r.error||'Eroare necunoscută.');
    }catch(e){showE('Răspuns invalid de la server.')}
  };
  xhr.onerror=()=>{upBtn.disabled=false;prog.classList.remove('show');showE('Eroare de rețea.')};
  upBtn.disabled=true;
  upBtn.textContent=files.length===1?'Se încarcă...':'Se încarcă fișierele...';
  pFill.style.width='0%';prog.classList.add('show');
  xhr.open('POST','upload.php');xhr.send(fd);
});
</script>
</body>
</html>
