const API_URL = 'http://localhost:8000';

let userEmail   = null;
let scannedEmails = new Set();
let resultCache   = new Map();
let scanQueue     = Promise.resolve();

async function init() {
  userEmail = await getUserEmail();
  console.log('PhishGuard ✅ user:', userEmail);
  observeEmailChanges();
  setTimeout(scanVisibleEmails, 2000);
  setInterval(scanVisibleEmails, 3000);
}

function getUserEmail() {
  return new Promise(resolve => {
    const iv = setInterval(() => {
      const el = document.querySelector('[data-hovercard-id]') ||
                 document.querySelector('[email]') ||
                 document.querySelector('.gb_d');
      if (el) {
        const email = el.getAttribute('data-hovercard-id') ||
                      el.getAttribute('email') ||
                      el.textContent.trim();
        if (email && email.includes('@')) {
          clearInterval(iv);
          chrome.storage.local.set({ userEmail: email });
          resolve(email);
        }
      }
    }, 500);
    setTimeout(() => {
      clearInterval(iv);
      chrome.storage.local.get(['userEmail'], r =>
        resolve(r.userEmail || 'user@gmail.com'));
    }, 10000);
  });
}

function observeEmailChanges() {
  const main = document.querySelector('[role="main"]');
  if (!main) { setTimeout(observeEmailChanges, 2000); return; }
  let timer = null;
  new MutationObserver(() => {
    clearTimeout(timer);
    timer = setTimeout(scanVisibleEmails, 400);
  }).observe(main, { childList: true, subtree: true });
  console.log('PhishGuard 👁 watching');
}

function getEmailRows() {
  const byThread = Array.from(
    document.querySelectorAll('[data-legacy-thread-id],[data-thread-id]')
  ).filter(el => el.tagName === 'TR' || el.getAttribute('role') === 'row');
  if (byThread.length) return byThread;

  const byClass = Array.from(document.querySelectorAll('tr.zA, tr.zE'));
  if (byClass.length) return byClass;

  return Array.from(document.querySelectorAll('[role="row"]')).filter(row =>
    row.querySelector('.yW, .zF, .bog, .y6') &&
    !row.querySelector('[role="columnheader"]')
  );
}

function getRowId(row) {
  return row.getAttribute('data-legacy-thread-id') ||
         row.getAttribute('data-thread-id') ||
         row.getAttribute('data-message-id') ||
         hashRow(row);
}

function hashRow(row) {
  const siblings = Array.from(row.parentElement?.children || []);
  const pos = siblings.indexOf(row);
  const sender  = row.querySelector('.yW span,.zF,[email],.yP')?.textContent?.trim() || '';
  const subject = row.querySelector('.bog,.y6,[data-subject]')?.textContent?.trim() || '';
  const str = `${sender}|${subject}|${pos}`;
  let h = 5381;
  for (const c of str) { h = ((h << 5) + h) ^ c.charCodeAt(0); h |= 0; }
  return 'pg_' + Math.abs(h).toString(36);
}

function extractEmailData(row) {
  const subjectEl = row.querySelector('.bog,[data-subject],.y6,span[title]');
  const senderEl  = row.querySelector('.yW span,.zF,[email],.yP');
  const previewEl = row.querySelector('.y2,.Zt');
  return {
    subject: subjectEl?.textContent?.trim() || 'ללא נושא',
    sender:  senderEl?.getAttribute('email') || senderEl?.textContent?.trim() || 'לא ידוע',
    content: previewEl?.textContent?.trim() || '',
  };
}

async function scanVisibleEmails() {
  const rows = getEmailRows();
  if (!rows.length) return;
  console.log(`PhishGuard: found ${rows.length} rows`);

  for (const row of rows) {
    const id = getRowId(row);
    if (row.querySelector('.pg-badge')) continue;
    if (resultCache.has(id)) {
      addBadge(row, resultCache.get(id));
      continue;
    }
    if (!scannedEmails.has(id)) {
      scannedEmails.add(id);
      addBadge(row, { risk_score: -1 });
      scanQueue = scanQueue.then(() => scanEmail(row, id));
    }
  }
}

async function scanEmail(row, id) {
  const data = extractEmailData(row);
  try {
    const res = await fetch(`${API_URL}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_email: userEmail || 'user@gmail.com',
        sender:     data.sender,
        subject:    data.subject,
        content:    data.content,
      }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const result = await res.json();
    resultCache.set(id, result);
    const currentRow = findRowById(id) || row;
    addBadge(currentRow, result);
  } catch (err) {
    console.warn('PhishGuard scan error:', err.message);
    const errResult = { risk_score: 0, risk_level: 'שגיאה', indicators: [], recommendation: '' };
    resultCache.set(id, errResult);
    addBadge(row, errResult);
  }
}

function findRowById(id) {
  for (const row of getEmailRows()) {
    if (getRowId(row) === id) return row;
  }
  return null;
}

function addBadge(row, result) {
  row.querySelector('.pg-badge')?.remove();
  const score = result.risk_score;

  if (score === -1) {
    const b = document.createElement('span');
    b.className = 'pg-badge';
    b.style.cssText = `
      display:inline-flex;align-items:center;gap:4px;direction:ltr;
      padding:3px 10px;margin:0 6px;vertical-align:middle;
      background:#1e293b;border:1.5px solid #475569;
      border-radius:20px;font-size:11px;font-weight:600;
      color:#94a3b8;font-family:-apple-system,sans-serif;
      box-shadow:0 1px 4px rgba(0,0,0,.3);
    `;
    b.textContent = '⏳ סורק...';
    insertBadge(row, b);
    return;
  }

  const s = Math.round(score);
  let color, bgColor, icon, label, pulse;
  if (s >= 80)      { color='#ef4444'; bgColor='#450a0a'; icon='🚨'; label='סכנה';   pulse=true;  }
  else if (s >= 50) { color='#f97316'; bgColor='#431407'; icon='⚡'; label='חשוד';   pulse=false; }
  else if (s >= 30) { color='#fbbf24'; bgColor='#422006'; icon='⚠️'; label='זהירות'; pulse=false; }
  else              { color='#34d399'; bgColor='#022c22'; icon='✓';  label='בטוח';   pulse=false; }

  const b = document.createElement('span');
  b.className = 'pg-badge';
  b.style.cssText = `
    display:inline-flex;align-items:center;gap:5px;direction:ltr;
    padding:3px 10px 3px 6px;margin:0 6px;vertical-align:middle;
    background:${bgColor};border:1.5px solid ${color};border-radius:20px;
    font-size:12px;font-weight:700;color:${color};
    cursor:pointer;white-space:nowrap;font-family:-apple-system,sans-serif;
    box-shadow:0 1px 6px rgba(0,0,0,.4);
    animation:${pulse
      ? 'pg-in .3s ease,pg-pulse 1.5s ease-in-out .3s infinite'
      : 'pg-in .4s cubic-bezier(.34,1.56,.64,1)'};
  `;
  b.innerHTML = `
    <span style="font-size:13px;line-height:1">${icon}</span>
    <span style="font-size:11px">${label}</span>
    <span style="
      background:${color};color:#000;
      padding:1px 6px;border-radius:10px;
      font-size:10px;font-weight:800;
    ">${s}%</span>
  `;
  b.title = `PhishGuard: ${result.risk_level || ''}\n${(result.indicators || []).join(' • ')}`;
  b.addEventListener('click', e => { e.stopPropagation(); showModal(result); });
  insertBadge(row, b);
}

function insertBadge(row, badge) {
  const subjectSpan = row.querySelector('.bog, .y6');
  if (subjectSpan) {
    const td = subjectSpan.closest('td, div[role="gridcell"]') || subjectSpan.parentElement;
    td.style.cssText += ';overflow:visible !important;white-space:nowrap;';
    subjectSpan.after(badge);
    return;
  }
  const senderEl = row.querySelector('.yW, .zF, .bA4');
  if (senderEl) {
    const td = senderEl.closest('td, div[role="gridcell"]') || senderEl.parentElement;
    td.style.cssText += ';overflow:visible !important;';
    td.appendChild(badge);
    return;
  }
  const td = Array.from(row.querySelectorAll('td, div[role="gridcell"]'))
    .find(c => c.textContent.trim().length > 3);
  if (td) { td.appendChild(badge); return; }
  row.appendChild(badge);
}

function showModal(result) {
  document.getElementById('pg-modal')?.remove();
  const s = Math.round(result.risk_score || 0);
  let color = '#34d399', bg = 'rgba(52,211,153,.2)';
  if (s >= 80)      { color = '#ef4444'; bg = 'rgba(239,68,68,.2)';  }
  else if (s >= 50) { color = '#f97316'; bg = 'rgba(249,115,22,.2)'; }
  else if (s >= 30) { color = '#fbbf24'; bg = 'rgba(251,191,36,.2)'; }

  const chips = (result.indicators || [])
    .map(i => `<span class="pg-chip">⚡ ${i}</span>`).join('');

  const m = document.createElement('div');
  m.id = 'pg-modal';
  m.innerHTML = `
    <div class="pg-overlay">
      <div class="pg-box">
        <div class="pg-head">
          <span>🛡️ ניתוח PhishGuard</span>
          <button class="pg-x">✕</button>
        </div>
        <div class="pg-body">
          <div class="pg-score-row">
            <div>
              <div class="pg-lbl">מדד סיכון</div>
              <div class="pg-num" style="color:${color}">${s}</div>
              <div class="pg-sub">מתוך 100</div>
            </div>
            <div class="pg-lvl" style="background:${bg};color:${color};border:1.5px solid ${color}">
              ${result.risk_level || ''}
            </div>
          </div>
          <div class="pg-bar-t"><div class="pg-bar-f" style="width:${s}%"></div></div>
          <div class="pg-stitle">אינדיקטורים שזוהו</div>
          <div class="pg-chips">${chips || '<span class="pg-chip">✅ לא נמצאו</span>'}</div>
          <div class="pg-rec">💡 <strong>המלצה:</strong> ${result.recommendation || ''}</div>
          <div class="pg-time">⚡ זמן תגובה: ${result.response_time || 0}s</div>
        </div>
        <div class="pg-foot">
          <button class="pg-close-btn">סגור</button>
        </div>
      </div>
    </div>`;
  document.body.appendChild(m);
  m.querySelector('.pg-x').onclick         = () => m.remove();
  m.querySelector('.pg-close-btn').onclick = () => m.remove();
  m.querySelector('.pg-overlay').onclick   = e => {
    if (e.target.classList.contains('pg-overlay')) m.remove();
  };
}

chrome.runtime.onMessage.addListener((req, _, sendResponse) => {
  if (req.action === 'scanAll') {
    scannedEmails.clear();
    resultCache.clear();
    scanVisibleEmails().then(() => sendResponse({ success: true }));
    return true;
  }
  if (req.action === 'getUserEmail') sendResponse({ email: userEmail });
});

const style = document.createElement('style');
style.textContent = `
  @keyframes pg-in {
    from { opacity:0; transform:scale(.7); }
    to   { opacity:1; transform:scale(1); }
  }
  @keyframes pg-pulse {
    0%,100% { box-shadow:0 0 0 0 rgba(239,68,68,.5); }
    50%      { box-shadow:0 0 0 5px rgba(239,68,68,0); }
  }
  .pg-overlay {
    position:fixed;inset:0;z-index:999999;
    background:rgba(0,0,0,.75);backdrop-filter:blur(8px);
    display:flex;align-items:center;justify-content:center;
    animation:pg-in .2s ease;
  }
  .pg-box {
    background:linear-gradient(135deg,#1e1b4b,#312e81);
    border:1px solid rgba(255,255,255,.15);border-radius:20px;
    width:420px;max-width:92vw;color:#fff;overflow:hidden;
    font-family:-apple-system,'Segoe UI',sans-serif;direction:rtl;
    animation:pg-slide .3s cubic-bezier(.34,1.56,.64,1);
  }
  @keyframes pg-slide {
    from { transform:translateY(24px) scale(.96); opacity:0; }
    to   { transform:translateY(0) scale(1); opacity:1; }
  }
  .pg-head {
    padding:16px 20px;display:flex;justify-content:space-between;
    align-items:center;font-size:15px;font-weight:700;
    border-bottom:1px solid rgba(255,255,255,.1);
    background:rgba(255,255,255,.05);
  }
  .pg-x { background:rgba(255,255,255,.1);border:none;color:#fff;
    width:26px;height:26px;border-radius:7px;cursor:pointer;font-size:13px; }
  .pg-x:hover { background:rgba(255,255,255,.2); }
  .pg-body { padding:20px; }
  .pg-score-row { display:flex;justify-content:space-between;align-items:center;margin-bottom:12px; }
  .pg-lbl  { font-size:11px;color:rgba(255,255,255,.4);margin-bottom:4px; }
  .pg-num  { font-size:50px;font-weight:800;line-height:1; }
  .pg-sub  { font-size:11px;color:rgba(255,255,255,.35); }
  .pg-lvl  { padding:6px 14px;border-radius:20px;font-size:13px;font-weight:700; }
  .pg-bar-t { height:8px;background:rgba(255,255,255,.1);border-radius:4px;overflow:hidden;margin-bottom:16px; }
  .pg-bar-f { height:100%;border-radius:4px;background:linear-gradient(90deg,#34d399,#fbbf24,#f97316,#ef4444); }
  .pg-stitle { font-size:11px;font-weight:600;color:rgba(255,255,255,.4);
    text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px; }
  .pg-chips { margin-bottom:14px; }
  .pg-chip {
    display:inline-flex;align-items:center;gap:4px;
    background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.12);
    border-radius:20px;padding:4px 10px;font-size:12px;margin:3px;color:#fff;
  }
  .pg-rec {
    background:rgba(255,255,255,.06);border-radius:12px;
    padding:12px;font-size:13px;line-height:1.5;margin-bottom:12px;
  }
  .pg-time { font-size:11px;color:rgba(255,255,255,.3);text-align:center; }
  .pg-foot { padding:14px 20px;border-top:1px solid rgba(255,255,255,.1); }
  .pg-close-btn {
    width:100%;padding:11px;
    background:linear-gradient(135deg,#6366f1,#8b5cf6);
    color:#fff;border:none;border-radius:12px;
    font-size:14px;font-weight:700;cursor:pointer;font-family:inherit;
  }
  .pg-close-btn:hover { opacity:.9; }
`;
document.head.appendChild(style);

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}