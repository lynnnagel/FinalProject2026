const API = 'http://localhost:8000';

// ── Escaping ──────────────────────────────────────────────
// Everything from the server passes through here before it reaches
// innerHTML. data.url is user input the server echoes back, so without
// escaping, pasting an <img onerror=...> into the scan field would run.
function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[ch]));
}

// ── Nav state ─────────────────────────────────────────────
// $ returns null quietly for an element that is not on the page. The
// home page no longer has every section it used to, and a direct
// getElementById would throw and take the rest of the setup with it -
// the reveal animations included.
const $ = id => document.getElementById(id);

function show(id, visible) {
  const el = $(id);
  if (el) el.style.display = visible ? '' : 'none';
}

function initNav() {
  const loggedIn = Boolean(localStorage.getItem('pg_token'));
  show('navLogin', !loggedIn);
  show('navLogout', loggedIn);
  show('navDashboard', loggedIn);
}

function logout() {
  localStorage.clear();
  window.location.reload();
}

// Guardian CTA: signed in -> dashboard, otherwise -> sign in
function goGuardian() {
  const token = localStorage.getItem('pg_token');
  if (token) {
    window.location.href = 'dashboard.html#guardian';
  } else {
    localStorage.setItem('pg_after_login', 'dashboard.html#guardian');
    window.location.href = 'login.html';
  }
}

// ── Live stats ────────────────────────────────────────────
async function loadStats() {
  try {
    const r = await fetch(`${API}/metrics`);
    if (!r.ok) return;
    const d = await r.json();
    const scanned = $('totalScanned'), blocked = $('totalBlocked');
    if (scanned) scanned.textContent = (d.total_emails_scanned || 0).toLocaleString();
    if (blocked) blocked.textContent = (d.phishing_blocked || 0).toLocaleString();
  } catch {
    // Server is down - the stats stay as placeholders
  }
}

// ── URL scanner ───────────────────────────────────────────
async function scanURL() {
  const input = $('urlInput');
  if (!input) return;
  const url = input.value.trim();
  if (!url) return;

  const btn      = $('scanBtn');
  const resultEl = $('scanResult');
  if (!btn || !resultEl) return;

  btn.textContent = 'סורק...';
  btn.disabled    = true;
  resultEl.style.display = 'none';

  try {
    const r = await fetch(`${API}/scan-url`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ url }),
    });
    const data = await r.json();
    renderResult(data, resultEl);
  } catch {
    resultEl.innerHTML =
      '<div class="result-error">לא ניתן להתחבר לשרת. ודא שהשרת פועל.</div>';
    resultEl.style.display = 'block';
  }

  btn.textContent = 'נתח';
  btn.disabled    = false;
}

function riskClass(score) {
  if (score >= 70) return 'r-danger';
  if (score >= 50) return 'r-warn';
  if (score >= 30) return 'r-caution';
  return 'r-safe';
}

function renderResult(data, el) {
  const score = data.risk_score ?? 0;
  const cls   = riskClass(score);
  const tags  = (data.indicators || [])
    .map(i => `<span class="indicator-tag">${esc(i)}</span>`)
    .join('');

  el.innerHTML = `
    <div class="result-card ${cls}">
      <div class="result-header">
        <div class="result-meta">
          <div class="result-level">${esc(data.risk_level)}</div>
          <div class="result-url">${esc(data.url)}</div>
        </div>
        <div class="result-score">${esc(score)}%</div>
      </div>
      ${tags ? `<div class="result-indicators">${tags}</div>` : ''}
      ${data.recommendation
        ? `<div class="result-recommendation">${esc(data.recommendation)}</div>`
        : ''}
    </div>`;
  el.style.display = 'block';
}

// ── Smooth scroll for in-page anchors ─────────────────────
function initSmoothScroll() {
  document.querySelectorAll('a[href^="#"]').forEach(a => {
    a.addEventListener('click', e => {
      const target = document.querySelector(a.getAttribute('href'));
      if (!target) return;
      e.preventDefault();
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });
}

// ── Reveal sections on scroll ─────────────────────────────
function initReveal() {
  const io = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('in');
        io.unobserve(entry.target);
      }
    });
  }, { threshold: 0.12 });

  document.querySelectorAll('.rv').forEach(el => io.observe(el));
}

// ── Boot ──────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initNav();
  loadStats();
  initSmoothScroll();
  initReveal();

  $('urlInput')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') scanURL();
  });
});
