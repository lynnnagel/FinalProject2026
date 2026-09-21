const API_URL = 'http://localhost:8000';

let userEmail   = null;
let scannedEmails = new Set();
let resultCache   = new Map();
let scanQueue     = Promise.resolve();

async function init() {
  userEmail = await getUserEmail();
  console.log('LURA user:', userEmail);

  const mismatch = await mailboxMismatch();
  if (mismatch) {
    console.warn(
      `LURA: signed in as ${mismatch.signedIn} but this mailbox is ` +
      `${mismatch.mailbox} - not scanning`
    );
    showMismatchNotice(mismatch);
    return;
  }

  observeEmailChanges();
  setTimeout(scanVisibleEmails, 2000);
  setInterval(scanVisibleEmails, 3000);
  setInterval(scanOpenEmail, 1500);
}

// Who owns this mailbox. Searching the page picked whoever came first in
// the DOM, usually a sender, so scans landed under noreply@discord.com.
// Now: the signed-in LURA account first, then Google's account button.
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

// Is the mailbox on screen the one we are signed in as? Nothing checked
// that, so browsing a second mailbox recorded every message under the
// signed-in account. Only a proven mismatch stops the scan: if the account
// button cannot be read we scan as before.

// Gmail treats dots and a +tag as the same mailbox, and the account
// button always shows the bare address. Without this, testing with
// plus-addressing (lynn+m@gmail.com against lynn@gmail.com) would look
// like a mismatch and scanning would stop.
function sameMailbox(a, b) {
  const norm = (addr) => {
    let [local, domain = ''] = String(addr).toLowerCase().trim().split('@');
    local = local.split('+')[0];
    if (domain === 'gmail.com' || domain === 'googlemail.com') {
      local = local.replace(/\./g, '');
      domain = 'gmail.com';
    }
    return `${local}@${domain}`;
  };
  return norm(a) === norm(b);
}

async function mailboxMismatch() {
  const { lura_email } = await chrome.storage.local.get(['lura_email']);
  if (!lura_email) return null;          // not signed in - nothing to compare

  for (let i = 0; i < 20; i++) {
    const open = emailFromAccountButton();
    if (open) {
      return sameMailbox(open, lura_email)
        ? null
        : { signedIn: lura_email, mailbox: open };
    }
    await new Promise(r => setTimeout(r, 500));
  }
  return null;                            // could not read it - carry on
}

function showMismatchNotice({ signedIn, mailbox }) {
  if (document.querySelector('.lura-mismatch')) return;
  const box = document.createElement('div');
  box.className = 'lura-mismatch';
  box.innerHTML = `
    <div class="lura-mismatch-title">LURA לא סורקת את התיבה הזאת</div>
    <div class="lura-mismatch-body">
      התוסף מחובר כ-<b>${signedIn}</b>, והתיבה הפתוחה היא <b>${mailbox}</b>.
      כדי לסרוק, התחברי בתוסף לאותו חשבון.
    </div>
    <button class="lura-mismatch-x" aria-label="סגירה">×</button>`;
  box.querySelector('.lura-mismatch-x').onclick = () => box.remove();
  document.body.appendChild(box);
}

// The authorization header. The popup stores the token in
// chrome.storage.local, which both halves of the extension share. With
// it, the server ignores the address in the body.
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
  // [email] first, and on its own. In one Gmail layout the address sits
  // on a span nested inside another, and a combined selector returned
  // the outer one - so the row was scanned under a display name while
  // the opened message was scanned under the address. Different senders
  // key different cache rows, and the three sender rules found no domain
  // to read.
  const senderEl  = row.querySelector('[email]')
                 || row.querySelector('.yW span,.zF,.yP');
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

// Scanning the open message, with the full body. A list row holds ~100
// characters of preview, and that was all the server saw, so most checks
// ran blind. Opening a message rescans it and updates the badge.
// key -> the verdict, or null while its scan is still in flight. A Set
// here meant the second visit to a message returned before the badge was
// drawn: the scan was skipped, correctly, but so was the drawing, and
// Gmail had removed the badge on the way out.
const fullyScanned = new Map();

// The message on screen, not the first one in the document. Gmail leaves
// earlier messages mounted - collapsed ones in a thread, and the message
// read before this one - so .a3s matches several bodies and the first is
// rarely the right one. Rendered height tells the open one from the
// leftovers, and the last of those is the one being read.
function openBodyElement() {
  const bodies = [...document.querySelectorAll('.a3s')].filter(el =>
    el.getBoundingClientRect().height > 0
    && (el.innerText || el.textContent || '').trim().length >= 20);
  return bodies[bodies.length - 1] || null;
}

// Gmail puts the subject above the messages, so of the headings on the
// page the one belonging to a body is the last one before it. The badge
// hangs off this element, so it has to be the same heading the scan read
// its subject from.
function openSubjectElement(bodyEl = openBodyElement()) {
  const heads = [...document.querySelectorAll('h2.hP')];
  if (!bodyEl) return heads[heads.length - 1] || null;
  const above = heads.filter(h =>
    h.compareDocumentPosition(bodyEl) & Node.DOCUMENT_POSITION_FOLLOWING);
  return above[above.length - 1] || heads[0] || null;
}

function extractOpenEmail() {
  const bodyEl = openBodyElement();
  if (!bodyEl) return null;

  const body = (bodyEl.innerText || bodyEl.textContent || '').trim();

  // Scoped to the message that body belongs to. A selector list has no
  // priority - querySelector returns whichever alternative appears first
  // in the document - so a bare [email] used to match a list row mounted
  // behind the message, and every message was read as having been sent
  // by the same address.
  const box = bodyEl.closest('.adn, .gs, [role="listitem"]') || document;
  const senderEl  = box.querySelector('.gD[email]')
                 || box.querySelector('[email]')
                 || document.querySelector('.gD[email]')
                 || box.querySelector('.gD');

  const subjectEl = openSubjectElement(bodyEl);

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
  if (fullyScanned.has(key)) {
    // Already scanned, so do not scan again - but redraw when the badge
    // on screen is missing or belongs to another message. Matching on
    // the key rather than on presence keeps the interval from restarting
    // the animation every second and a half.
    const known = fullyScanned.get(key);
    const shown = document.querySelector('.lura-open-badge');
    if (known && shown?.dataset.luraKey !== key) showOpenBadge(known, key);
    return;
  }
  fullyScanned.set(key, null);

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
    fullyScanned.set(key, result);
    showOpenBadge(result, key);

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
    // Drop the key so the scan is tried again, the way a failed row
    // scan is. Left in place, the message stayed unscanned until Gmail
    // was reloaded.
    fullyScanned.delete(key);
    console.warn('LURA open-scan error:', err.message);
  }
}

// key marks which message the badge belongs to. Without it a badge left
// over from the message read a moment ago counted as "a badge is already
// showing", and the one on screen described a different mail.
function showOpenBadge(result, key = '') {
  document.querySelector('.lura-open-badge')?.remove();
  const subjectEl = openSubjectElement();
  if (!subjectEl) return;

  const s = Math.round(result.risk_score ?? 0);
  const { color, bg, label } = badgeStyle(s);

  const b = document.createElement('span');
  b.className = 'lura-badge lura-open-badge';
  b.dataset.luraKey = key;
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

// The risk bands. Must match backend/config.py. Hard-coded as 80/50/30
// they went stale, and mail the server called phishing showed yellow.
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

  // Only when the message was flagged and there is something to mark.
  // Hidden when the rules found real evidence: on an impersonation,
  // "I know this sender" is the button the attacker wants pressed.
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

// Marking a sender as known. An inbox is full of addresses nobody has
// heard of, where ordinary mail scores high on the model's guess alone.
// The mark damps the model only, never the rules.
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
  /* A light surface, the same one the site and the guardian mail use
     (--surface / --border in frontend/css/main.css). The card used to be
     the dark --ink surface: the overlay behind it is already dark and
     blurred, so a dark card on top of it read as one heavy mass, and the
     risk colour - the only thing on the card that carries meaning - had
     to compete with it. */
  .lura-box {
    background:#FFFFFF;
    border:1px solid #E9EAF0;border-radius:14px;
    box-shadow:0 18px 50px rgba(20,20,43,.22);
    width:420px;max-width:92vw;color:#14142B;overflow:hidden;
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
    border-bottom:1px solid #E9EAF0;
    background:#FAFAFB;
  }
  .lura-x { background:#F1F2F6;border:none;color:#565673;
    width:26px;height:26px;border-radius:7px;cursor:pointer;font-size:13px; }
  .lura-x:hover { background:#E4E6EC;color:#14142B; }
  .lura-body { padding:20px; }
  .lura-score-row { display:flex;justify-content:space-between;align-items:center;margin-bottom:12px; }
  .lura-lbl  { font-size:11px;color:#8E8EA8;margin-bottom:4px; }
  .lura-num  { font-size:50px;font-weight:800;line-height:1; }
  .lura-sub  { font-size:11px;color:#8E8EA8; }
  .lura-lvl  { padding:6px 14px;border-radius:20px;font-size:13px;font-weight:700; }
  /* The fill carries the band's colour. It used to be a fixed rainbow
     gradient, so a score of 95 still began in green and the length of
     the bar was the only thing saying anything. */
  .lura-bar-t { height:8px;background:#EDEEF3;border-radius:4px;overflow:hidden;margin-bottom:16px; }
  .lura-bar-f { height:100%;border-radius:4px;transition:width .3s ease; }
  .lura-from {
    display:flex;align-items:baseline;gap:6px;margin-bottom:14px;
    font-size:12px;overflow:hidden;
  }
  .lura-from-lbl { color:#8E8EA8;flex-shrink:0; }
  .lura-from-val { color:#14142B;direction:ltr;unicode-bidi:embed;
    overflow:hidden;text-overflow:ellipsis;white-space:nowrap; }
  /* No uppercase and no letter-spacing: the label is Hebrew, which has
     no capitals, and spacing only pulls the letters apart. */
  .lura-stitle { font-size:11px;font-weight:600;color:#8E8EA8;
    margin-bottom:8px; }
  .lura-chips { margin-bottom:14px; }
  /* On a clean message the whole section is dropped. The heading used
     to stay, with a single chip under it reading "none found" - a
     section announcing findings and then denying them - and the line
     below it says the same thing anyway. */
  /* The brand wash rather than a neutral grey: these are the findings,
     the one part of the card worth reading twice. */
  .lura-chip {
    display:inline-flex;align-items:center;gap:4px;
    background:#F4F0FF;border:1px solid #E4DAFF;
    border-radius:20px;padding:4px 10px;font-size:12px;margin:3px;color:#4A3A8C;
  }
  .lura-rec {
    background:#FAFAFB;border:1px solid #E9EAF0;border-radius:8px;
    padding:12px;font-size:13px;line-height:1.5;margin-bottom:12px;
  }
  .lura-time { font-size:11px;color:#A8A8BC;text-align:center; }
  .lura-foot {
    padding:14px 20px;border-top:1px solid #E9EAF0;
    display:flex;flex-direction:column;gap:8px;
  }
  .lura-trust-btn {
    width:100%;padding:10px;
    background:transparent;color:#565673;
    border:1px solid #D9DCE5;border-radius:8px;
    font-size:13px;font-weight:600;cursor:pointer;font-family:inherit;
    transition:color .15s,border-color .15s;
  }
  .lura-trust-btn:hover:not(:disabled) { color:#14142B;border-color:#B9BCC9; }
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