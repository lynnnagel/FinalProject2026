const API = 'http://localhost:8000';

// ── Nav state ─────────────────────────────────────────────
function initNav() {
  const token = localStorage.getItem('pg_token');
  if (token) {
    document.getElementById('navLogin').style.display    = 'none';
    document.getElementById('navLogout').style.display   = 'block';
    document.getElementById('navDashboard').style.display = 'block';
  }
}

function logout() {
  localStorage.clear();
  window.location.reload();
}

// ── Guardian CTA: מחובר → דשבורד, לא מחובר → התחברות ──────
function goGuardian() {
  const token = localStorage.getItem('pg_token');
  if (token) {
    window.location.href = 'dashboard.html#guardian';
  } else {
    // נחזור למצב מפקח מיד אחרי ההתחברות
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
    document.getElementById('totalScanned').textContent =
      (d.total_emails_scanned || 0).toLocaleString();
    document.getElementById('totalBlocked').textContent =
      (d.phishing_blocked || 0).toLocaleString();
  } catch {
    // השרת לא פועל — הסטטיסטיקות נשארות "—"
  }
}

// ── URL scanner ───────────────────────────────────────────
async function scanURL() {
  const url = document.getElementById('urlInput').value.trim();
  if (!url) return;

  const btn      = document.getElementById('scanBtn');
  const resultEl = document.getElementById('scanResult');

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
      `<div class="result-error">לא ניתן להתחבר לשרת. ודא שהשרת פועל.</div>`;
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
    .map(i => `<span class="indicator-tag">${i}</span>`)
    .join('');

  el.innerHTML = `
    <div class="result-card ${cls}">
      <div class="result-header">
        <div class="result-meta">
          <div class="result-level">${data.risk_level || ''}</div>
          <div class="result-url">${data.url || ''}</div>
        </div>
        <div class="result-score">${score}%</div>
      </div>
      ${tags ? `<div class="result-indicators">${tags}</div>` : ''}
      ${data.recommendation
        ? `<div class="result-recommendation">${data.recommendation}</div>`
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

  document.getElementById('urlInput')
    .addEventListener('keydown', e => { if (e.key === 'Enter') scanURL(); });
});