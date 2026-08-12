const API = 'http://localhost:8000';
const MIN_PASSWORD_LENGTH = 8;

// האסימון מגיע מהקישור שנשלח למייל: forgot_password.html?token=...
const resetToken = new URLSearchParams(window.location.search).get('token');

function show(el, text) {
  el.textContent = text;
  el.style.display = 'block';
}

function hide(...els) {
  els.forEach(el => { el.style.display = 'none'; });
}

// ── שלב 1 — בקשת קישור איפוס ──────────────────────────────
async function handleRequest(e) {
  e.preventDefault();
  const errEl = document.getElementById('requestError');
  const okEl  = document.getElementById('requestSuccess');
  const btn   = e.target.querySelector('button[type="submit"]');
  hide(errEl, okEl);

  btn.textContent = 'שולח...';
  btn.disabled = true;

  try {
    const r = await fetch(`${API}/auth/forgot-password`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ email: document.getElementById('requestEmail').value }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || 'שגיאה בשליחת הקישור');

    // השרת מחזיר תמיד את אותה הודעה, גם אם הכתובת לא רשומה —
    // כדי לא לחשוף אילו כתובות קיימות במערכת.
    show(okEl, 'אם הכתובת רשומה במערכת, נשלח אליה קישור לאיפוס. הקישור תקף ל-30 דקות.');
    btn.style.display = 'none';

  } catch (err) {
    show(errEl, err.message);
    btn.textContent = 'שלח קישור לאיפוס';
    btn.disabled = false;
  }
}

// ── שלב 2 — בחירת סיסמה חדשה ──────────────────────────────
async function handleReset(e) {
  e.preventDefault();
  const errEl = document.getElementById('resetError');
  const okEl  = document.getElementById('resetSuccess');
  const btn   = e.target.querySelector('button[type="submit"]');
  hide(errEl, okEl);

  const pass  = document.getElementById('resetPassword').value;
  const pass2 = document.getElementById('resetPassword2').value;

  if (pass !== pass2) {
    show(errEl, 'הסיסמאות אינן תואמות');
    return;
  }
  if (pass.length < MIN_PASSWORD_LENGTH) {
    show(errEl, `הסיסמה חייבת להכיל לפחות ${MIN_PASSWORD_LENGTH} תווים`);
    return;
  }

  btn.textContent = 'מעדכן...';
  btn.disabled = true;

  try {
    const r = await fetch(`${API}/auth/reset-password`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ token: resetToken, new_password: pass }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || 'שגיאה באיפוס הסיסמה');

    show(okEl, 'הסיסמה עודכנה בהצלחה. מעביר להתחברות...');
    btn.style.display = 'none';
    setTimeout(() => { window.location.href = 'login.html'; }, 2500);

  } catch (err) {
    show(errEl, err.message);
    btn.textContent = 'עדכני סיסמה';
    btn.disabled = false;
  }
}

// ── בחירת השלב לפי הכתובת ─────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const requestForm = document.getElementById('requestForm');
  const resetForm   = document.getElementById('resetForm');

  if (resetToken) {
    requestForm.style.display = 'none';
    resetForm.style.display   = 'flex';
  }
});
