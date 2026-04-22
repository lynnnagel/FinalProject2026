// PhishGuard Content Script — Gmail phishing detection
const API_URL = 'http://localhost:8000';

const config = {
  riskThresholds: { high: 80, medium: 50, low: 30 }
};

let userEmail = null;
let scannedEmails = new Set();
let scanQueue = Promise.resolve();

// ── Init ──────────────────────────────────────────────────────────────────
async function init() {
  userEmail = await getUserEmail();
  console.log('PhishGuard: משתמש מזוהה —', userEmail);
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
        resolve(r.userEmail || 'user@gmail.com')
      );
    }, 10000);
  });
}

function persistUserEmail(email) {
  if (email && email.includes('@')) {
    chrome.storage.local.set({ userEmail: email });
  }
}

// ── Observe changes ───────────────────────────────────────────────────────
function observeEmailChanges() {
  const main = document.querySelector('[role="main"]');
  if (!main) {
    setTimeout(observeEmailChanges, 2000);
    return;
  }

  let debounceTimer = null;
  new MutationObserver(() => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(scanVisibleEmails, 800);
  }).observe(main, { childList: true, subtree: true });
}

// ── Get email rows (Gmail-specific) ───────────────────────────────────────
function getEmailRows() {
  // Gmail marks real email rows with class 'zA'
  const byClass = document.querySelectorAll('tr.zA');
  if (byClass.length > 0) return Array.from(byClass);

  // Fallback: role="row" that contain a sender element
  return Array.from(document.querySelectorAll('[role="row"]')).filter(row =>
    row.querySelector('.yW, .zF, [email], .bog, .y6')
  );
}

// ── Scan all visible emails ───────────────────────────────────────────────
async function scanVisibleEmails() {
  const rows = getEmailRows();
  console.log(`PhishGuard: נמצאו ${rows.length} מיילים לסריקה`);

  for (const row of rows) {
    const id = row.getAttribute('data-legacy-thread-id') ||
               row.getAttribute('data-message-id') ||
               generateId(row);

    if (!scannedEmails.has(id)) {
      scannedEmails.add(id);
      // Queue scans to avoid flooding the API
      scanQueue = scanQueue.then(() => scanEmail(row, id));
    }
  }
}

// ── Generate stable ID ────────────────────────────────────────────────────
function generateId(row) {
  const subject = row.querySelector('.bog, [data-subject], .y6')?.textContent || '';
  const sender  = row.querySelector('.yW span, .zF, [email]')?.textContent || '';
  let hash = 5381;
  for (const ch of sender + subject) {
    hash = ((hash << 5) + hash) ^ ch.charCodeAt(0);
    hash |= 0;
  }
  return 'pg_' + Math.abs(hash).toString(36);
}

// ── Extract email data ────────────────────────────────────────────────────
function extractEmailData(row) {
  const subjectEl = row.querySelector('.bog, [data-subject], .y6, span[title]');
  const senderEl  = row.querySelector('.yW span, .zF, [email], .yP');
  const previewEl = row.querySelector('.y2, .Zt');

  return {
    subject: subjectEl?.textContent?.trim() || 'ללא נושא',
    sender:  senderEl?.getAttribute('email') ||
             senderEl?.textContent?.trim() || 'לא ידוע',
    content: previewEl?.textContent?.trim() || '',
  };
}

// ── Scan single email ─────────────────────────────────────────────────────
async function scanEmail(row, emailId) {
  try {
    const data = extractEmailData(row);
    if (data.sender === 'לא ידוע' && data.subject === 'ללא נושא') return;

    const res = await fetch(`${API_URL}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_email: userEmail,
        sender:     data.sender,
        subject:    data.subject,
        content:    data.content,
      }),
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    addBadge(row, await res.json());

  } catch (err) {
    console.warn('PhishGuard: שגיאה בסריקה —', err.message);
    addBadge(row, {
      risk_score: 0, risk_level: 'שגיאה',
      indicators: ['לא ניתן להגיע לשרת'],
      recommendation: 'ודא שהשרת פועל על port 8000',
      response_time: 0,
    });
  }
}

// ── Badge ─────────────────────────────────────────────────────────────────
function addBadge(row, result) {
  row.querySelector('.pg-badge')?.remove();

  const score = Math.round(result.risk_score || 0);
  let color, bg, icon, label, pulse;

  if (score >= 80)      { color='#ef4444'; bg='rgba(239,68,68,.15)';   icon='🚨'; label='סכנה';   pulse=true;  }
  else if (score >= 50) { color='#f97316'; bg='rgba(249,115,22,.15)';  icon='⚡'; label='חשוד';   pulse=false; }
  else if (score >= 30) { color='#fbbf24'; bg='rgba(251,191,36,.15)';  icon='⚠️'; label='זהירות'; pulse=false; }
  else                  { color='#34d399'; bg='rgba(52,211,153,.15)';   icon='✓'; label='בטוח';   pulse=false; }

  const badge = document.createElement('div');
  badge.className = 'pg-badge';
  badge.style.cssText = `
    display:inline-flex; align-items:center; gap:4px;
    padding:2px 8px; margin:0 4px;
    background:${bg}; border:1.5px solid ${color}; border-radius:20px;
    font-size:11px; font-weight:700; color:${color};
    cursor:pointer; white-space:nowrap; vertical-align:middle;
    font-family:-apple-system,sans-serif;
    animation:${pulse
      ? 'pg-in .3s ease, pg-pulse 1.5s ease-in-out .3s infinite'
      : 'pg-in .4s cubic-bezier(.34,1.56,.64,1)'};
  `;

  badge.innerHTML = `
    <span style="font-size:13px">${icon}</span>
    <span>${label}</span>
    <span style="background:${color};color:#fff;padding:1px 5px;border-radius:8px;font-size:10px">${score}%</span>
  `;

  badge.title = [
    `רמת סיכון: ${result.risk_level}`,
    `אינדיקטורים: ${(result.indicators||[]).join(', ')}`,
    `המלצה: ${result.recommendation||''}`,
  ].join('\n');

  badge.addEventListener('click', e => { e.stopPropagation(); showModal(result); });

  // Try multiple insertion points
  const anchor = row.querySelector('.yW') ||
                 row.querySelector('.bog') ||
                 row.querySelector('.y6') ||
                 row.querySelector('td.xY') ||
                 row;

  if (anchor && anchor !== row) {
    anchor.style.position = 'relative';
    anchor.insertAdjacentElement('afterend', badge);
  } else {
    row.appendChild(badge);
  }
}

// ── Modal ─────────────────────────────────────────────────────────────────
function showModal(result) {
  document.getElementById('pg-modal')?.remove();

  const score = Math.round(result.risk_score || 0);
  let color, bg;
  if (score >= 80)      { color='#ef4444'; bg='rgba(239,68,68,.2)';  }
  else if (score >= 50) { color='#f97316'; bg='rgba(249,115,22,.2)'; }
  else if (score >= 30) { color='#fbbf24'; bg='rgba(251,191,36,.2)'; }
  else                  { color='#34d399'; bg='rgba(52,211,153,.2)'; }

  const chips = (result.indicators||[]).map(i =>
    `<span class="pg-chip">⚡ ${i}</span>`
  ).join('');

  const modal = document.createElement('div');
  modal.id = 'pg-modal';
  modal.innerHTML = `
    <div class="pg-overlay">
      <div class="pg-box">
        <div class="pg-head">
          <span>🛡️ ניתוח PhishGuard</span>
          <button class="pg-x">✕</button>
        </div>
        <div class="pg-body">
          <div class="pg-score-row">
            <div>
              <div class="pg-score-label">מדד סיכון</div>
              <div class="pg-score-num" style="color:${color}">${score}</div>
              <div class="pg-score-sub">מתוך 100</div>
            </div>
            <div class="pg-level" style="background:${bg};color:${color};border:1.5px solid ${color}">
              ${result.risk_level||''}
            </div>
          </div>
          <div class="pg-bar-track">
            <div class="pg-bar-fill" style="width:${score}%;background:linear-gradient(90deg,#34d399,#fbbf24,#f97316,#ef4444)"></div>
          </div>
          <div class="pg-section-title">אינדיקטורים</div>
          <div class="pg-chips">${chips||'<span class="pg-chip">✅ לא נמצאו</span>'}</div>
          <div class="pg-rec">💡 <strong>המלצה:</strong> ${result.recommendation||''}</div>
          <div class="pg-time">⚡ זמן תגובה: ${result.response_time||0}s</div>
        </div>
        <div class="pg-foot">
          <button class="pg-close-btn">סגור</button>
        </div>
      </div>
    </div>`;

  document.body.appendChild(modal);
  modal.querySelector('.pg-x').onclick         = () => modal.remove();
  modal.querySelector('.pg-close-btn').onclick = () => modal.remove();
  modal.querySelector('.pg-overlay').onclick   = e => {
    if (e.target.classList.contains('pg-overlay')) modal.remove();
  };
}

// ── Message listener ──────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((req, _sender, sendResponse) => {
  if (req.action === 'scanAll') {
    scannedEmails.clear();
    scanVisibleEmails().then(() => sendResponse({ success: true }));
    return true;
  }
  if (req.action === 'getUserEmail') {
    sendResponse({ email: userEmail });
  }
});

// ── CSS ───────────────────────────────────────────────────────────────────
const style = document.createElement('style');
style.textContent = `
  @keyframes pg-in {
    from { opacity:0; transform:scale(0.7); }
    to   { opacity:1; transform:scale(1); }
  }
  @keyframes pg-pulse {
    0%,100% { box-shadow:0 0 0 0 rgba(239,68,68,.5); }
    50%      { box-shadow:0 0 0 5px rgba(239,68,68,0); }
  }
  .pg-overlay {
    position:fixed; inset:0; z-index:999999;
    background:rgba(0,0,0,.75); backdrop-filter:blur(8px);
    display:flex; align-items:center; justify-content:center;
    animation:pg-in .2s ease;
  }
  .pg-box {
    background:linear-gradient(135deg,#1e1b4b,#312e81);
    border:1px solid rgba(255,255,255,.15); border-radius:20px;
    width:420px; max-width:92vw; color:#fff; overflow:hidden;
    font-family:-apple-system,'Segoe UI',sans-serif; direction:rtl;
    animation:pg-slide .3s cubic-bezier(.34,1.56,.64,1);
  }
  @keyframes pg-slide {
    from { transform:translateY(24px) scale(.96); opacity:0; }
    to   { transform:translateY(0) scale(1); opacity:1; }
  }
  .pg-head {
    padding:16px 20px; display:flex; justify-content:space-between;
    align-items:center; font-size:15px; font-weight:700;
    border-bottom:1px solid rgba(255,255,255,.1);
    background:rgba(255,255,255,.05);
  }
  .pg-x {
    background:rgba(255,255,255,.1); border:none; color:#fff;
    width:26px; height:26px; border-radius:7px; cursor:pointer; font-size:13px;
  }
  .pg-x:hover { background:rgba(255,255,255,.2); }
  .pg-body { padding:20px; }
  .pg-score-row {
    display:flex; justify-content:space-between; align-items:center;
    margin-bottom:12px;
  }
  .pg-score-label { font-size:11px; color:rgba(255,255,255,.4); margin-bottom:4px; }
  .pg-score-num   { font-size:50px; font-weight:800; line-height:1; }
  .pg-score-sub   { font-size:11px; color:rgba(255,255,255,.35); }
  .pg-level       { padding:6px 14px; border-radius:20px; font-size:13px; font-weight:700; }
  .pg-bar-track   {
    height:8px; background:rgba(255,255,255,.1);
    border-radius:4px; overflow:hidden; margin-bottom:16px;
  }
  .pg-bar-fill    { height:100%; border-radius:4px; }
  .pg-section-title {
    font-size:11px; font-weight:600; color:rgba(255,255,255,.4);
    text-transform:uppercase; letter-spacing:.5px; margin-bottom:8px;
  }
  .pg-chips       { margin-bottom:14px; }
  .pg-chip {
    display:inline-flex; align-items:center; gap:4px;
    background:rgba(255,255,255,.08); border:1px solid rgba(255,255,255,.12);
    border-radius:20px; padding:4px 10px; font-size:12px; margin:3px;
    color:#fff;
  }
  .pg-rec {
    background:rgba(255,255,255,.06); border-radius:12px;
    padding:12px; font-size:13px; line-height:1.5; margin-bottom:12px;
  }
  .pg-time { font-size:11px; color:rgba(255,255,255,.3); text-align:center; }
  .pg-foot { padding:14px 20px; border-top:1px solid rgba(255,255,255,.1); }
  .pg-close-btn {
    width:100%; padding:11px;
    background:linear-gradient(135deg,#6366f1,#8b5cf6);
    color:#fff; border:none; border-radius:12px;
    font-size:14px; font-weight:700; cursor:pointer; font-family:inherit;
  }
  .pg-close-btn:hover { opacity:.9; }
`;
document.head.appendChild(style);

// ── Start ─────────────────────────────────────────────────────────────────
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
