const API = 'http://localhost:8000';

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

  // The account buttons say what they will actually do. Offering
  // "create an account" to someone already signed in sends them to a
  // page that bounces straight back to the dashboard.
  const label = loggedIn ? 'ללוח הבקרה' : null;
  const target = loggedIn ? 'dashboard.html' : 'login.html';
  [['installCta', 'צור חשבון'], ['ctaAccount', 'כניסה לחשבון']].forEach(([id, out]) => {
    const el = $(id);
    if (!el) return;
    el.textContent = label || out;
    el.href = target;
  });
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

// ── Smooth scroll for in-page anchors ─────────────────────
function initSmoothScroll() {
  document.querySelectorAll('a[href^="#"]').forEach(a => {
    a.addEventListener('click', e => {
      // A bare "#" is a button dressed as a link (sign out). It is not a
      // selector, and querySelector('#') throws.
      const href = a.getAttribute('href');
      if (href === '#') return;
      const target = document.querySelector(href);
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
});
