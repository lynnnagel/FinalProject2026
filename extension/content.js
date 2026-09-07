const API_URL = 'http://localhost:8000';

let userEmail   = null;
let scannedEmails = new Set();
let resultCache   = new Map();
let scanQueue     = Promise.resolve();

async function init() {
  userEmail = await getUserEmail();
  console.log('LURA user:', userEmail);
  observeEmailChanges();
  setTimeout(scanVisibleEmails, 2000);
  setInterval(scanVisibleEmails, 3000);
  setInterval(scanOpenEmail, 1500);
}

// ---------------------------------------------------------------------------
// Identifying the mailbox owner. Searching the page for
// [data-hovercard-id] picked whoever appeared first in the DOM, usually a
// sender: accounts named noreply@discord.com ended up in the database
// with the scans under them, and the real user's dashboard stayed empty.
// So: the account signed in to LURA first, which is known rather than
// guessed, then Google's account button - one element, not a search.
// ---------------------------------------------------------------------------
const EMAIL_RE = /[\w.+-]+@[\w-]+\.[\w.-]+/;

function emailFromAccountButton() {
  // The account button carries an aria-label of the form
  // "Google Account: Name (address@gmail.com)"
  const selectors = [
    'a[aria-label*="@"][href*="accounts.google"]',
    'a[aria-label*="@"]',
    '[aria-label*="Google Account"]',
    '[aria-label*="חשבון Google"]',
  ];
  for (const sel of selectors) {
    for (const el of document.querySelectorAll(sel)) {
      const match = (el.getAttribute('aria-label') || '').match(EMAIL_RE);
      if (match) return match[0];
    }
  }
  return null;
}

async function getUserEmail() {
  // 1. The account signed in to LURA. Exact, and what the server will
  //    rely on anyway once the token is sent.
  const { lura_email, userEmail: cached } = await chrome.storage.local.get(
    ['lura_email', 'userEmail']
  );
  if (lura_email) return lura_email;

  // 2. Google's account button, with a short wait for the UI to load.
  for (let i = 0; i < 20; i++) {
    const found = emailFromAccountButton();
    if (found) {
      chrome.storage.local.set({ userEmail: found });
      return found;
    }
    await new Promise(r => setTimeout(r, 500));
  }

  // 3. A value saved on an earlier run, then a placeholder.
  return cached || 'user@gmail.com';
}

// ---------------------------------------------------------------------------
// The authorization header for a scan. The popup stores the token in
// chrome.storage.local, shared by both halves of the extension. When it
// is there the server takes identity from it and ignores the address in
// the body, so scans are recorded under the account signed in.
// ---------------------------------------------------------------------------
function getAuthToken() {
  return new Promise(resolve =>
    chrome.storage.local.get(['lura_token'], r => resolve(r.lura_token || null))
  );
}

async function scanHeaders() {
  const headers = { 'Content-Type': 'application/json' };
  const token = await getAuthToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;
  return headers;
}

function observeEmailChanges() {
  const main = document.querySelector('[role="main"]');
  if (!main) { setTimeout(observeEmailChanges, 2000); return; }
  let timer = null;
  new MutationObserver(() => {
    clearTimeout(timer);
    timer = setTimeout(() => { scanVisibleEmails(); scanOpenEmail(); }, 400);
  }).observe(main, { childList: true, subtree: true });
  console.log('LURA watching');
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
  return 'lura_' + Math.abs(h).toString(36);
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
  console.log(`LURA: found ${rows.length} rows`);

  for (const row of rows) {
    const id = getRowId(row);
    if (row.querySelector('.lura-badge')) continue;
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
      headers: await scanHeaders(),
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
    // A failed scan used to return risk_score 0 and get a green "safe"
    // badge, so mail the server never saw looked approved. -2 marks a
    // failure and gets a grey badge, and is not cached, so the scan
    // retries by itself once the server is back.
    console.warn('LURA scan error:', err.message);
    scannedEmails.delete(id);
    addBadge(row, { risk_score: -2, risk_level: 'לא נסרק', indicators: [], recommendation: '' });
  }
}

// ---------------------------------------------------------------------------
// Scanning the open message, with the full body. A row in Gmail's list
// holds ~100 characters of preview, and that was all the server ever saw,
// so most of the pipeline ran blind: the unsubscribe link sits in the
// footer, the link/IP/shortener and brand-in-body checks read the body,
// and BERT was trained on whole messages but given an opening fragment.
// Opening a message re-scans it with the real text and updates the badge.
// ---------------------------------------------------------------------------
const fullyScanned = new Set();

function extractOpenEmail() {
  const bodyEl = document.querySelector('.a3s');
  if (!bodyEl) return null;

  const body = (bodyEl.innerText || bodyEl.textContent || '').trim();
  if (body.length < 20) return null;

  const senderEl  = document.querySelector('span.gD[email], .gD[email], [email]');
  const subjectEl = document.querySelector('h2.hP');

  return {
    sender:  senderEl?.getAttribute('email') || senderEl?.textContent?.trim() || 'לא ידוע',
    subject: subjectEl?.textContent?.trim() || 'ללא נושא',
    content: trimBody(body),
  };
}

// A long marketing message keeps what matters at both ends: the
// opening is what BERT reads, and the unsubscribe link sits at the
// bottom. Truncating from the front would erase the very sign that
// separates an advertisement from phishing.
function trimBody(text) {
  const MAX = 6000, HEAD = 4000, TAIL = 1500;
  if (text.length <= MAX) return text;
  return text.slice(0, HEAD) + '\n...\n' + text.slice(-TAIL);
}

function openEmailKey(data) {
  return `open|${data.sender}|${data.subject}|${data.content.length}`;
}

async function scanOpenEmail() {
  const data = extractOpenEmail();
  if (!data) return;

  const key = openEmailKey(data);
  if (fullyScanned.has(key)) return;
  fullyScanned.add(key);

  try {
    const res = await fetch(`${API_URL}/scan`, {
      method: 'POST',
      headers: await scanHeaders(),
      body: JSON.stringify({
        user_email: userEmail || 'user@gmail.com',
        sender:     data.sender,
        subject:    data.subject,
        content:    data.content,
      }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const result = await res.json();
    showOpenBadge(result);

    // The badge in the list came from the preview alone. There is a
    // better result now, so the cache updates and the row reflects it.
    for (const row of getEmailRows()) {
      const rowData = extractEmailData(row);
      if (rowData.subject === data.subject) {
        const id = getRowId(row);
        resultCache.set(id, result);
        addBadge(row, result);
      }
    }
  } catch (err) {
    console.warn('LURA open-scan error:', err.message);
  }
}

function showOpenBadge(result) {
  document.querySelector('.lura-open-badge')?.remove();
  const subjectEl = document.querySelector('h2.hP');
  if (!subjectEl) return;

  const s = Math.round(result.risk_score ?? 0);
  const { color, bg, label } = badgeStyle(s);

  const b = document.createElement('span');
  b.className = 'lura-badge lura-open-badge';
  b.style.cssText = `
    display:inline-flex;align-items:center;gap:6px;
    padding:4px 12px;margin-inline-start:10px;vertical-align:middle;
    background:${bg};border:1px solid ${color};border-radius:100px;
    font-size:12px;font-weight:700;color:${color};
    cursor:pointer;font-family:'Rubik',-apple-system,sans-serif;
  `;
  b.innerHTML = `<span>${label}</span><span style="opacity:.75">${s}%</span>`;
  b.addEventListener('click', e => {
    e.stopPropagation();
    showModal(result, extractOpenEmail()?.sender || '');
  });
  subjectEl.appendChild(b);
}

function findRowById(id) {
  for (const row of getEmailRows()) {
    if (getRowId(row) === id) return row;
  }
  return null;
}

// ---------------------------------------------------------------------------
// The risk bands. Must match backend/config.py, where they are derived
// from PHISHING_THRESHOLD. Hard-coded here as 80/50/30 they went stale
// after calibration, and mail the server called phishing showed yellow.
// ---------------------------------------------------------------------------
const BADGE_BANDS = [
  { min: 84, label: 'סכנה',   level: 'סכנה גבוהה', color: '#EF4444', bg: '#450A0A', pulse: true  },
  { min: 70, label: 'חשוד',   level: 'חשוד',       color: '#F97316', bg: '#431407', pulse: false },
  { min: 42, label: 'זהירות', level: 'זהירות',     color: '#EAB308', bg: '#422006', pulse: false },
  { min: -1, label: 'בטוח',   level: 'בטוח',       color: '#34D399', bg: '#022C22', pulse: false },
];

function badgeStyle(score) {
  return BADGE_BANDS.find(b => score >= b.min);
}

// The band for a whole result, not just its number. The server already
// decided and sends the name in risk_level, so matching on that keeps the
// extension right when thresholds move. The numbers above are only the
// fallback for a result with no level - an old cache entry, or offline.
function bandFor(result) {
  const byLevel = BADGE_BANDS.find(b => b.level === result.risk_level);
  return byLevel || badgeStyle(Math.round(result.risk_score || 0));
}

// A band colour at a given opacity, for the fills behind text in the
// details window.
function fade(hex, alpha) {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${alpha})`;
}

function addBadge(row, result) {
  row.querySelector('.lura-badge')?.remove();
  const score = result.risk_score;

  if (score === -2) {
    const b = document.createElement('span');
    b.className = 'lura-badge';
    b.style.cssText = `
      display:inline-flex;align-items:center;gap:4px;direction:rtl;
      padding:3px 10px;margin:0 6px;vertical-align:middle;
      background:#1E293B;border:1.5px solid #64748B;
      border-radius:20px;font-size:11px;font-weight:600;
      color:#CBD5E1;font-family:'Rubik',-apple-system,sans-serif;
      cursor:help;
    `;
    b.textContent = 'לא נסרק';
    b.title = 'LURA: אין חיבור לשרת. ודא ש-uvicorn פועל על פורט 8000.';
    insertBadge(row, b);
    return;
  }

  if (score === -1) {
    const b = document.createElement('span');
    b.className = 'lura-badge';
    b.style.cssText = `
      display:inline-flex;align-items:center;gap:4px;direction:ltr;
      padding:3px 10px;margin:0 6px;vertical-align:middle;
      background:#1e293b;border:1.5px solid #475569;
      border-radius:20px;font-size:11px;font-weight:600;
      color:#94a3b8;font-family:-apple-system,sans-serif;
      box-shadow:0 1px 4px rgba(0,0,0,.3);
    `;
    b.textContent = 'סורק...';
    insertBadge(row, b);
    return;
  }

  const s = Math.round(score);
  const { color, bg: bgColor, label, pulse } = bandFor(result);

  const b = document.createElement('span');
  b.className = 'lura-badge';
  b.style.cssText = `
    display:inline-flex;align-items:center;gap:5px;direction:ltr;
    padding:3px 10px 3px 6px;margin:0 6px;vertical-align:middle;
    background:${bgColor};border:1.5px solid ${color};border-radius:20px;
    font-size:12px;font-weight:700;color:${color};
    cursor:pointer;white-space:nowrap;font-family:'Rubik',-apple-system,sans-serif;
    box-shadow:0 1px 6px rgba(0,0,0,.4);
    animation:${pulse
      ? 'lura-in .3s ease,lura-pulse 1.5s ease-in-out .3s infinite'
      : 'lura-in .4s cubic-bezier(.34,1.56,.64,1)'};
  `;
  b.innerHTML = `
    <span style="font-size:11px">${label}</span>
    <span style="background:${color};color:#000;padding:1px 6px;border-radius:10px;font-size:10px;font-weight:800;">${s}%</span>
  `;
  b.title = `LURA: ${result.risk_level || ''}\n${(result.indicators || []).join(' • ')}`;
  b.addEventListener('click', e => {
    e.stopPropagation();
    showModal(result, extractEmailData(row).sender);
  });
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

function showModal(result, sender = '') {
  document.getElementById('lura-modal')?.remove();
  const s = Math.round(result.risk_score || 0);
  // The same band as the badge that was clicked. This window kept its
  // own copy of the cut-offs (80/50/30), left over from before the
  // threshold was calibrated - so a message the badge showed in orange
  // opened a window that called it yellow.
  const band = bandFor(result);
  const color = band.color;
  const bg = fade(band.color, 0.2);

  const chips = (result.indicators || []).map(i => `<span class="lura-chip">${escapeHtml(i)}</span>`).join('');

  // Shown only when there is something to mark and the message was
  // flagged; on clean mail it does nothing and adds noise. Hidden
  // entirely when the rules found real evidence: the server would refuse
  // anyway, and on a message that looks like impersonation a button
  // reading "I know this sender" is what the attacker wants pressed.
  const hasHardEvidence = (result.indicators || []).some(i =>
    i.includes('מתיימר להיות') || i.includes('דומיין לא תקני') ||
    i.includes('כתובת IP') || i.includes('קיצור URL') ||
    i.includes('חינמית')
  );
  const canTrust = Boolean(sender) && band.level !== 'בטוח' && !hasHardEvidence;

  const m = document.createElement('div');
  m.id = 'lura-modal';
  m.innerHTML = `
    <div class="lura-overlay">
      <div class="lura-box">
        <div class="lura-head">
                    <span><img src="${chrome.runtime.getURL('icons/logo.svg')}" style="width:18px;height:18px;vertical-align:middle;margin-left:6px;">ניתוח LURA</span>
          <button class="lura-x" aria-label="סגירה" title="סגירה">✕</button>
        </div>
        <div class="lura-body">
          <div class="lura-score-row">
            <div>
              <div class="lura-lbl">מדד סיכון</div>
              <div class="lura-num" style="color:${color}">${s}</div>
              <div class="lura-sub">מתוך 100</div>
            </div>
            <div class="lura-lvl" style="background:${bg};color:${color};border:1.5px solid ${color}">
              ${result.risk_level || ''}
            </div>
          </div>
          <div class="lura-bar-t">
            <div class="lura-bar-f" style="width:${s}%;background:${color}"></div>
          </div>
          ${sender ? `<div class="lura-from">
            <span class="lura-from-lbl">נשלח מ־</span>
            <span class="lura-from-val">${escapeHtml(sender)}</span>
          </div>` : ''}
          ${chips ? `<div class="lura-stitle">אינדיקטורים שזוהו</div>
               <div class="lura-chips">${chips}</div>` : ''}
          <div class="lura-rec"><strong>המלצה:</strong> ${result.recommendation || ''}</div>
          ${result.response_time ? `<div class="lura-time">זמן תגובה: ${result.response_time}s</div>` : ''}
        </div>
        <div class="lura-foot">
          ${canTrust ? `<button class="lura-trust-btn">אני מכיר את ${escapeHtml(shortSender(sender))}</button>` : ''}
          <button class="lura-close-btn">סגור</button>
        </div>
      </div>
    </div>`;
  document.body.appendChild(m);

  // One close path, so the key listener is removed with the window and
  // does not pile up every time a badge is clicked.
  const close = () => {
    document.removeEventListener('keydown', onKey, true);
    m.remove();
  };
  function onKey(e) {
    if (e.key !== 'Escape') return;
    // Gmail listens for Escape too, and would act on it behind the
    // window that was just closed.
    e.stopPropagation();
    close();
  }
  document.addEventListener('keydown', onKey, true);

  m.querySelector('.lura-x').onclick         = close;
  m.querySelector('.lura-close-btn').onclick = close;
  m.querySelector('.lura-overlay').onclick   = e => {
    if (e.target.classList.contains('lura-overlay')) close();
  };

  const trustBtn = m.querySelector('.lura-trust-btn');
  if (trustBtn) {
    trustBtn.onclick = async () => {
      // An explicit confirmation when the message was flagged - the user
      // is lowering the guard on mail the system marked. The condition is
      // the server's own verdict, not a threshold repeated here, which
      // would go stale at the next calibration.
      if (result.is_phishing && !confirm(
        `LURA סימנה את המייל הזה כחשוד (${s}%).\n\n` +
        `סימון ${sender} כמוכר יפחית את משקל ניתוח הניסוח עבורו — ` +
        `בדיקות האבטחה ימשיכו לפעול.\n\nלהמשיך?`
      )) return;

      trustBtn.disabled = true;
      trustBtn.textContent = 'שומר...';
      const outcome = await markSenderTrusted(sender);
      trustBtn.textContent = outcome.message;
      if (outcome.ok) {
        // The server queued the stored scores for this sender to be
        // recomputed. Clearing the local cache makes the next scan ask
        // for them again, so the badges update on their own.
        resultCache.clear();
        scannedEmails.clear();
        setTimeout(() => { close(); scanVisibleEmails(); }, 900);
      } else {
        trustBtn.disabled = false;
      }
    };
  }
}

function shortSender(sender) {
  const at = sender.indexOf('@');
  return at > 12 ? sender.slice(at) : sender;
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[ch]));
}

// ---------------------------------------------------------------------------
// Marking a sender as known. The system knows the large brands, but an
// inbox is full of addresses nobody has heard of, where there is no
// positive evidence of legitimacy and ordinary mail scores high on the
// model's guess alone. Marking damps the model only: a user can say they
// know an address, not that the evidence is void.
// ---------------------------------------------------------------------------
async function markSenderTrusted(sender) {
  const token = await getAuthToken();
  if (!token) {
    return { ok: false, message: 'יש להתחבר בתוסף תחילה' };
  }
  try {
    const res = await fetch(`${API_URL}/trusted-senders`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({ value: sender }),
    });
    if (res.status === 401) return { ok: false, message: 'ההתחברות פגה' };
    if (!res.ok) {
      // The server refuses an address with evidence against it and
      // says why. Showing that beats "could not save": it tells the
      // user what was found in the address they were about to approve.
      const body = await res.json().catch(() => ({}));
      return { ok: false, message: body.detail || 'לא ניתן לשמור' };
    }
    return { ok: true, message: 'נשמר. מעדכן...' };
  } catch {
    return { ok: false, message: 'אין חיבור לשרת' };
  }
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
  @keyframes lura-in {
    from { opacity:0; transform:scale(.7); }
    to   { opacity:1; transform:scale(1); }
  }
  @keyframes lura-pulse {
    0%,100% { box-shadow:0 0 0 0 rgba(239,68,68,.5); }
    50%      { box-shadow:0 0 0 5px rgba(239,68,68,0); }
  }
  .lura-overlay {
    position:fixed;inset:0;z-index:999999;
    background:rgba(0,0,0,.75);backdrop-filter:blur(8px);
    display:flex;align-items:center;justify-content:center;
    animation:lura-in .2s ease;
  }
  .lura-box {
    background:#0E1020;
    border:1px solid #282C44;border-radius:14px;
    width:420px;max-width:92vw;color:#fff;overflow:hidden;
    font-family:'Rubik',-apple-system,'Segoe UI',sans-serif;direction:rtl;
    animation:lura-slide .3s cubic-bezier(.34,1.56,.64,1);
  }
  @keyframes lura-slide {
    from { transform:translateY(24px) scale(.96); opacity:0; }
    to   { transform:translateY(0) scale(1); opacity:1; }
  }
  .lura-head {
    padding:16px 20px;display:flex;justify-content:space-between;
    align-items:center;font-size:15px;font-weight:700;
    border-bottom:1px solid rgba(255,255,255,.1);
    background:rgba(255,255,255,.05);
  }
  .lura-x { background:rgba(255,255,255,.1);border:none;color:#fff;
    width:26px;height:26px;border-radius:7px;cursor:pointer;font-size:13px; }
  .lura-x:hover { background:rgba(255,255,255,.2); }
  .lura-body { padding:20px; }
  .lura-score-row { display:flex;justify-content:space-between;align-items:center;margin-bottom:12px; }
  .lura-lbl  { font-size:11px;color:rgba(255,255,255,.4);margin-bottom:4px; }
  .lura-num  { font-size:50px;font-weight:800;line-height:1; }
  .lura-sub  { font-size:11px;color:rgba(255,255,255,.35); }
  .lura-lvl  { padding:6px 14px;border-radius:20px;font-size:13px;font-weight:700; }
  /* The fill carries the band's colour. It used to be a fixed rainbow
     gradient, so a score of 95 still began in green and the length of
     the bar was the only thing saying anything. */
  .lura-bar-t { height:8px;background:rgba(255,255,255,.1);border-radius:4px;overflow:hidden;margin-bottom:16px; }
  .lura-bar-f { height:100%;border-radius:4px;transition:width .3s ease; }
  .lura-from {
    display:flex;align-items:baseline;gap:6px;margin-bottom:14px;
    font-size:12px;overflow:hidden;
  }
  .lura-from-lbl { color:rgba(255,255,255,.4);flex-shrink:0; }
  .lura-from-val { color:#E7E9F2;direction:ltr;unicode-bidi:embed;
    overflow:hidden;text-overflow:ellipsis;white-space:nowrap; }
  /* No uppercase and no letter-spacing: the label is Hebrew, which has
     no capitals, and spacing only pulls the letters apart. */
  .lura-stitle { font-size:11px;font-weight:600;color:rgba(255,255,255,.4);
    margin-bottom:8px; }
  .lura-chips { margin-bottom:14px; }
  /* On a clean message the whole section is dropped. The heading used
     to stay, with a single chip under it reading "none found" - a
     section announcing findings and then denying them - and the line
     below it says the same thing anyway. */
  .lura-chip {
    display:inline-flex;align-items:center;gap:4px;
    background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.12);
    border-radius:20px;padding:4px 10px;font-size:12px;margin:3px;color:#fff;
  }
  .lura-rec {
    background:#181B2E;border:1px solid #282C44;border-radius:8px;
    padding:12px;font-size:13px;line-height:1.5;margin-bottom:12px;
  }
  .lura-time { font-size:11px;color:rgba(255,255,255,.3);text-align:center; }
  .lura-foot {
    padding:14px 20px;border-top:1px solid rgba(255,255,255,.1);
    display:flex;flex-direction:column;gap:8px;
  }
  .lura-trust-btn {
    width:100%;padding:10px;
    background:transparent;color:#9BA1B8;
    border:1px solid #282C44;border-radius:8px;
    font-size:13px;font-weight:600;cursor:pointer;font-family:inherit;
    transition:color .15s,border-color .15s;
  }
  .lura-trust-btn:hover:not(:disabled) { color:#E7E9F2;border-color:#3A3F5C; }
  .lura-trust-btn:disabled { cursor:default;opacity:.7; }
  .lura-close-btn {
    width:100%;padding:11px;
    background:#7C4DFF;
    color:#fff;border:none;border-radius:8px;
    font-size:14px;font-weight:700;cursor:pointer;font-family:inherit;
  }
  .lura-close-btn:hover { opacity:.9; }
`;
document.head.appendChild(style);

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}