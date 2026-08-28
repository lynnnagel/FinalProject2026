const API = 'http://localhost:8000';

function showTab(tab) {
  document.getElementById('loginForm').style.display    = tab === 'login'    ? 'flex' : 'none';
  document.getElementById('registerForm').style.display = tab === 'register' ? 'flex' : 'none';
  document.getElementById('resetForm').style.display    = tab === 'reset'    ? 'flex' : 'none';
  document.getElementById('tabLogin').classList.toggle('active',    tab === 'login');
  document.getElementById('tabRegister').classList.toggle('active', tab === 'register');
}

async function handleReset(e) {
  e.preventDefault();
  const errEl = document.getElementById('resetError');
  const okEl  = document.getElementById('resetSuccess');
  errEl.style.display = 'none';
  okEl.style.display  = 'none';

  const pass  = document.getElementById('resetPassword').value;
  const pass2 = document.getElementById('resetPassword2').value;
  if (pass !== pass2) {
    errEl.textContent = 'הסיסמאות אינן תואמות';
    errEl.style.display = 'block';
    return;
  }
  if (pass.length < 8) {
    errEl.textContent = 'הסיסמה חייבת להכיל לפחות 8 תווים';
    errEl.style.display = 'block';
    return;
  }

  try {
    const r = await fetch(`${API}/auth/reset-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email:        document.getElementById('resetEmail').value,
        new_password: pass,
      }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || 'שגיאה באיפוס הסיסמה');
    okEl.textContent = 'הסיסמה עודכנה! מעביר להתחברות...';
    okEl.style.display = 'block';
    setTimeout(() => showTab('login'), 2000);
  } catch (err) {
    errEl.textContent = err.message;
    errEl.style.display = 'block';
  }
}

async function handleLogin(e) {
  e.preventDefault();
  const errEl = document.getElementById('loginError');
  errEl.style.display = 'none';

  try {
    const r = await fetch(`${API}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email:    document.getElementById('loginEmail').value,
        password: document.getElementById('loginPassword').value,
      }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || 'שגיאה בהתחברות');
    localStorage.setItem('pg_token', data.token);
    localStorage.setItem('pg_email', data.email);
    localStorage.setItem('pg_name',  data.name);
    window.location.href = afterLogin();
  } catch (err) {
    errEl.textContent = err.message;
    errEl.style.display = 'block';
  }
}

// Where to land after signing in. A visitor who clicked "Guardian mode"
// on the home page is not asking to see the dashboard overview - they
// are asking for that one screen, and the sign-in is in the way. The
// target is written by the home page and read back here.
//
// Only a same-page relative target is accepted: an attacker who can set
// this key must not be able to bounce the user to another site right
// after they typed their password.
function afterLogin() {
  const want = localStorage.getItem('pg_after_login') || '';
  localStorage.removeItem('pg_after_login');
  return /^[a-z_]+\.html(#[a-z]+)?$/i.test(want) ? want : 'dashboard.html';
}

async function handleRegister(e) {
  e.preventDefault();
  const errEl = document.getElementById('registerError');
  errEl.style.display = 'none';

  const pass  = document.getElementById('regPassword').value;
  const pass2 = document.getElementById('regPassword2').value;
  if (pass !== pass2) {
    errEl.textContent = 'הסיסמאות אינן תואמות';
    errEl.style.display = 'block';
    return;
  }
  if (pass.length < 8) {
    errEl.textContent = 'הסיסמה חייבת להכיל לפחות 8 תווים';
    errEl.style.display = 'block';
    return;
  }

  try {
    const r = await fetch(`${API}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email:    document.getElementById('regEmail').value,
        password: pass,
        name:     document.getElementById('regName').value,
      }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || 'שגיאה בהרשמה');
    localStorage.setItem('pg_token', data.token);
    localStorage.setItem('pg_email', data.email);
    localStorage.setItem('pg_name',  data.name);
    window.location.href = afterLogin();
  } catch (err) {
    errEl.textContent = err.message;
    errEl.style.display = 'block';
  }
}

if (localStorage.getItem('pg_token')) {
  window.location.href = afterLogin();
}