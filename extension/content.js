const API_URL = 'http://localhost:8000';

const config = { riskThresholds: { high: 80, medium: 50, low: 30 } };

let userEmail = null;
let scannedEmails = new Set();   // IDs that were sent to API
let resultCache   = new Map();   // ID → scan result (for virtual scroll re-render)
let scanQueue     = Promise.resolve();

// ── Init ──────────────────────────────────────────────────────────────────
async function init() {
  userEmail = await getUserEmail();
  console.log('PhishGuard ✅ משתמש:', userEmail);
  observeEmailChanges();
  setTimeout(scanVisibleEmails, 2000);
}

// ── Get user email ────────────────────────────────────────────────────────
function getUserEmail() {
  return new Promise(resolve => {
    const interval = setInterval(() => {
      const el = document.querySelector('[data-hovercard-id]') ||
                 document.querySelector('[email]') ||
                 document.querySelector('.gb_d');
      if (el) {
        const email = el.getAttribute('data-hovercard-id') ||
                      el.getAttribute('email') ||
                      el.textContent.trim();
        if (email && email.includes('@')) {
          clearInterval(interval);
          persistUserEmail(email);
          resolve(email);
        }
      }
    }, 500);
    setTimeout(() => {
      clearInterval(interval);
      chrome.storage.local.get(['userEmail'], r =>
        resolve(r.userEmail || 'user@gmail.com'));
    }, 10000);
  });
}

function persistUserEmail(email) {
  if (email?.includes('@')) chrome.storage.local.set({ userEmail: email });
}

// ── Observe DOM changes ───────────────────────────────────────────────────
function observeEmailChanges() {
  const main = document.querySelector('[role="main"]');
  if (!main) { setTimeout(observeEmailChanges, 2000); return; }

  let timer = null;
  new MutationObserver(() => {
    clearTimeout(timer);
    timer = setTimeout(scanVisibleEmails, 400);
  }).observe(main, { childList: true, subtree: true });

  console.log('PhishGuard 👁 צופה בשינויים');
}

// ── Find email rows ───────────────────────────────────────────────────────
function getEmailRows() {
  // Most reliable: Gmail attaches thread ID directly to the row
  const byThread = Array.from(
    document.querySelectorAll('[data-legacy-thread-id], [data-thread-id]')
  ).filter(el => el.tagName === 'TR' || el.getAttribute('role') === 'row');
  if (byThread.length > 0) return byThread;

  // Gmail's read/unread row classes
  const byClass = Array.from(document.querySelectorAll('tr.zA, tr.zE'));
  if (byClass.length > 0) return byClass;

  // Generic fallback
  return Array.from(document.querySelectorAll('[role="row"]')).filter(row =>
    row.querySelector('.yW, .zF, .bog, .y6') &&
    !row.querySelector('[role="columnheader"]')
  );
}

// ── Get stable ID ─────────────────────────────────────────────────────────
function getRowId(row) {
  return row.getAttribute('data-legacy-thread-id') ||
         row.getAttribute('data-thread-id') ||
         row.getAttribute('data-message-id') ||
         hashRow(row);
}

function hashRow(row) {
  const s = (row.querySelector('.bog,.y6,[data-subject]')?.textContent || '') +
            (row.querySelector('.yW span,.zF,[email]')?.textContent || '');
  let h = 5381;
  for (const c of s) { h = ((h << 5) + h) ^ c.charCodeAt(0); h |= 0; }
  return 'pg_' + Math.abs(h).toString(36);
}

// ── Extract email data ────────────────────────────────────────────────────
function extractEmailData(row) {
  const subjectEl = row.querySelector('.bog, [data-subject], .y6, span[title]');
  const senderEl  = row.querySelector('.yW span, .zF, [email], .yP');
  const previewEl = row.querySelector('.y2, .Zt');
  return {
    subject: subjectEl?.textContent?.trim() || 'ללא נושא',
    sender:  senderEl?.getAttribute('email') || senderEl?.textContent?.trim() || 'לא ידוע',
    content: previewEl?.textContent?.trim() || '',
  };
}

// ── Scan all visible emails ───────────────────────────────────────────────
async function scanVisibleEmails() {
  const rows = getEmailRows();
  console.log(`PhishGuard: נמצאו ${rows.length} שורות`);

  for (const row of rows) {
    const id = getRowId(row);

    // ✅ KEY FIX: if badge already on this exact DOM node — skip
    if (row.querySelector('.pg-badge')) continue;

    // ✅ Virtual scroll fix: row was scanned before, result cached → re-add badge
    if (resultCache.has(id)) {
      addBadge(row, resultCache.get(id));
      continue;
    }

    // New email — send to API
    if (!scannedEmails.has(id)) {
      scannedEmails.add(id);
      scanQueue = scanQueue.then(() => scanEmail(row, id));
    }
  }
}

// ── Scan single email ─────────────────────────────────────────────────────
function getEmailRows() {
  // Gmail החדש — div עם thread ID
  const byThread = Array.from(
    document.querySelectorAll('[data-thread-id], [data-legacy-thread-id]')
  );
  if (byThread.length > 0) return byThread;

  // Gmail קלאסי — tr.zA
  const byClass = Array.from(document.querySelectorAll('tr.zA, tr.zE'));
  if (byClass.length > 0) return byClass;

  // Fallback רחב — כל row עם תוכן
  return Array.from(document.querySelectorAll('[role="row"]')).filter(row =>
    row.textContent.trim().length > 20 &&
    row.children.length >= 2 &&
    !row.querySelector('[role="columnheader"]')
  );
}


// ── Add badge to row ──────────────────────────────────────────────────────
function addBadge(row, result) {
  row.querySelector('.pg-badge')?.remove();

  const score = result.risk_score;

  // "scanning" state
  if (score === -1) {
    const b = document.createElement('span');
    b.className = 'pg-badge';
    b.style.cssText = `
      display:inline-flex;align-items:center;gap:4px;
      padding:2px 8px;margin:0 4px;
      background:rgba(255,255,255,.1);border:1.5px solid rgba(255,255,255,.3);
      border-radius:20px;font-size:11px;font-weight:600;
      color:rgba(255,255,255,.6);font-family:-apple-system,sans-serif;
    `;
    b.textContent = '⏳ סורק...';
    insertBadge(row, b);
    return;
  }

  let color, bg, icon, label, pulse;
  const s = Math.round(score);
  if (s >= 80)      { color='#ef4444'; bg='rgba(239,68,68,.15)';  icon='🚨'; label='סכנה';   pulse=true;  }
  else if (s >= 50) { color='#f97316'; bg='rgba(249,115,22,.15)'; icon='⚡'; label='חשוד';   pulse=false; }
  else if (s >= 30) { color='#fbbf24'; bg='rgba(251,191,36,.15)'; icon='⚠️'; label='זהירות'; pulse=false; }
  else              { color='#34d399'; bg='rgba(52,211,153,.15)';  icon='✓'; label='בטוח';   pulse=false; }

  const b = document.createElement('span');
  b.className = 'pg-badge';
  b.style.cssText = `
    display:inline-flex;align-items:center;gap:4px;
    padding:2px 8px;margin:0 4px;
    background:${bg};border:1.5px solid ${color};border-radius:20px;
    font-size:11px;font-weight:700;color:${color};
    cursor:pointer;white-space:nowrap;font-family:-apple-system,sans-serif;
    animation:${pulse
      ? 'pg-in .3s ease,pg-pulse 1.5s ease-in-out .3s infinite'
      : 'pg-in .4s cubic-bezier(.34,1.56,.64,1)'};
  `;
  b.innerHTML = `
    <span style="font-size:13px">${icon}</span>
    <span>${label}</span>
    <span style="background:${color};color:#fff;padding:1px 5px;border-radius:8px;font-size:10px">${s}%</span>
  `;
  b.title = `${result.risk_level||''}\n${(result.indicators||[]).join(' • ')}`;
  b.addEventListener('click', e => { e.stopPropagation(); showModal(result); });

  insertBadge(row, b);
}

// ── Insert badge — tries multiple locations ───────────────────────────────
function insertBadge(row, badge) {
  // נסי למצוא תא של שולח
  const senderCell = row.querySelector('.yW, .zF, .bA4');
  if (senderCell) { senderCell.appendChild(badge); return; }

  // תא של נושא
  const subjectCell = row.querySelector('.bog, .y6, td.xY');
  if (subjectCell) { subjectCell.appendChild(badge); return; }

  // כל td/div ראשון עם תוכן
  const firstCell = Array.from(row.querySelectorAll('td, div[role="gridcell"]'))
    .find(c => c.textContent.trim().length > 0);
  if (firstCell) { firstCell.appendChild(badge); return; }

  // אחרון — ישירות על השורה
  row.appendChild(badge);
}


// ── Modal ─────────────────────────────────────────────────────────────────
function showModal(result) {
  document.getElementById('pg-modal')?.remove();

  const s = Math.round(result.risk_score || 0);
  let color, bg;
  if (s >= 80)      { color='#ef4444'; bg='rgba(239,68,68,.2)';  }
  else if (s >= 50) { color='#f97316'; bg='rgba(249,115,22,.2)'; }
  else if (s >= 30) { color='#fbbf24'; bg='rgba(251,191,36,.2)'; }
  else              { color='#34d399'; bg='rgba(52,211,153,.2)'; }

  const chips = (result.indicators||[])
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
              ${result.risk_level||''}
            </div>
          </div>
          <div class="pg-bar-t">
            <div class="pg-bar-f" style="width:${s}%"></div>
          </div>
          <div class="pg-stitle">אינדיקטורים שזוהו</div>
          <div class="pg-chips">${chips||'<span class="pg-chip">✅ לא נמצאו</span>'}</div>
          <div class="pg-rec">💡 <strong>המלצה:</strong> ${result.recommendation||''}</div>
          <div class="pg-time">⚡ ${result.response_time||0}s</div>
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

async function init() {
  userEmail = await getUserEmail();
  console.log('PhishGuard ✅ משתמש:', userEmail);
  observeEmailChanges();
  setTimeout(scanVisibleEmails, 2000);

  // ✅ גיבוי — סרוק מחדש כל 3 שניות (מטפל בכל מקרה שMutationObserver פספס)
  setInterval(scanVisibleEmails, 3000);
}


// ── Message listener ──────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((req, _, sendResponse) => {
  if (req.action === 'scanAll') {
    scannedEmails.clear();
    resultCache.clear();
    scanVisibleEmails().then(() => sendResponse({ success: true }));
    return true;
  }
  if (req.action === 'getUserEmail') sendResponse({ email: userEmail });
});

// ── Styles ────────────────────────────────────────────────────────────────
const style = document.createElement('style');
style.textContent = `
  @keyframes pg-in {
    from{opacity:0;transform:scale(.7)} to{opacity:1;transform:scale(1)}
  }
  @keyframes pg-pulse {
    0%,100%{box-shadow:0 0 0 0 rgba(239,68,68,.5)}
    50%{box-shadow:0 0 0 5px rgba(239,68,68,0)}
  }
  .pg-overlay{
    position:fixed;inset:0;z-index:999999;
    background:rgba(0,0,0,.75);backdrop-filter:blur(8px);
    display:flex;align-items:center;justify-content:center;
    animation:pg-in .2s ease;
  }
  .pg-box{
    background:linear-gradient(135deg,#1e1b4b,#312e81);
    border:1px solid rgba(255,255,255,.15);border-radius:20px;
    width:420px;max-width:92vw;color:#fff;overflow:hidden;
    font-family:-apple-system,'Segoe UI',sans-serif;direction:rtl;
    animation:pg-slide .3s cubic-bezier(.34,1.56,.64,1);
  }
  @keyframes pg-slide{
    from{transform:translateY(24px) scale(.96);opacity:0}
    to{transform:translateY(0) scale(1);opacity:1}
  }
  .pg-head{
    padding:16px 20px;display:flex;justify-content:space-between;
    align-items:center;font-size:15px;font-weight:700;
    border-bottom:1px solid rgba(255,255,255,.1);
    background:rgba(255,255,255,.05);
  }
  .pg-x{background:rgba(255,255,255,.1);border:none;color:#fff;
    width:26px;height:26px;border-radius:7px;cursor:pointer;font-size:13px;}
  .pg-x:hover{background:rgba(255,255,255,.2)}
  .pg-body{padding:20px}
  .pg-score-row{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
  .pg-lbl{font-size:11px;color:rgba(255,255,255,.4);margin-bottom:4px}
  .pg-num{font-size:50px;font-weight:800;line-height:1}
  .pg-sub{font-size:11px;color:rgba(255,255,255,.35)}
  .pg-lvl{padding:6px 14px;border-radius:20px;font-size:13px;font-weight:700}
  .pg-bar-t{height:8px;background:rgba(255,255,255,.1);border-radius:4px;overflow:hidden;margin-bottom:16px}
  .pg-bar-f{height:100%;border-radius:4px;background:linear-gradient(90deg,#34d399,#fbbf24,#f97316,#ef4444)}
  .pg-stitle{font-size:11px;font-weight:600;color:rgba(255,255,255,.4);
    text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px}
  .pg-chips{margin-bottom:14px}
  .pg-chip{display:inline-flex;align-items:center;gap:4px;
    background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.12);
    border-radius:20px;padding:4px 10px;font-size:12px;margin:3px;color:#fff}
  .pg-rec{background:rgba(255,255,255,.06);border-radius:12px;
    padding:12px;font-size:13px;line-height:1.5;margin-bottom:12px}
  .pg-time{font-size:11px;color:rgba(255,255,255,.3);text-align:center}
  .pg-foot{padding:14px 20px;border-top:1px solid rgba(255,255,255,.1)}
  .pg-close-btn{width:100%;padding:11px;
    background:linear-gradient(135deg,#6366f1,#8b5cf6);
    color:#fff;border:none;border-radius:12px;
    font-size:14px;font-weight:700;cursor:pointer;font-family:inherit}
  .pg-close-btn:hover{opacity:.9}
`;
document.head.appendChild(style);

// ── Start ─────────────────────────────────────────────────────────────────
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
