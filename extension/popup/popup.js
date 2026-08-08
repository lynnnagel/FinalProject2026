const API_URL = 'http://localhost:8000';

async function start() {
  const { pg_token, pg_email, pg_name } = await chrome.storage.local.get([
    'pg_token', 'pg_email', 'pg_name',
  ]);
  if (pg_token && pg_email) {
    await loadStats(pg_email, pg_name || pg_email);
  } else {
    showGuestScreen();
  }
}

function showGuestScreen() {
  document.getElementById('content').innerHTML = `
    <div class="guest-box">
      <div class="guest-info">
        <div class="active-badge">
          <span class="status-dot"></span> הגנה פעילה
        </div>
        <p class="guest-sub">
          LURA סורק את המיילים שלך אוטומטית.<br>
          התחבר לחשבון כדי לראות סטטיסטיקות שנשמרות.
        </p>
      </div>
      <button class="btn btn-primary" id="openLoginBtn">
        <span>🔑</span><span>התחבר לחשבון</span>
      </button>
      <button class="btn btn-secondary" id="scanBtn">
        <span>🔍</span><span>סרוק עכשיו</span>
      </button>
    </div>
  `;
  document.getElementById('openLoginBtn').addEventListener('click', showLoginScreen);
  document.getElementById('scanBtn').addEventListener('click', scanNow);
}

function showLoginScreen() {
  document.getElementById('content').innerHTML = `
    <div class="login-box">
      <p class="login-subtitle">התחבר כדי לראות את הסטטיסטיקות שלך</p>
      <div class="form-tabs">
        <button class="tab active" id="tab-login">התחברות</button>
        <button class="tab" id="tab-register">הרשמה</button>
      </div>
      <div id="form-login">
        <div class="field">
          <input id="login-email" type="email" placeholder="כתובת מייל" class="input" />
        </div>
        <div class="field">
          <input id="login-password" type="password" placeholder="סיסמה" class="input" />
        </div>
        <div id="login-error" class="form-error" style="display:none"></div>
        <button class="btn btn-primary" id="loginSubmitBtn">התחבר</button>
        <button class="btn btn-secondary" id="backFromLogin" style="margin-top:8px">← חזור</button>
      </div>
      <div id="form-register" style="display:none">
        <div class="field">
          <input id="reg-name" type="text" placeholder="שם מלא (אופציונלי)" class="input" />
        </div>
        <div class="field">
          <input id="reg-email" type="email" placeholder="כתובת מייל" class="input" />
        </div>
        <div class="field">
          <input id="reg-password" type="password" placeholder="סיסמה (לפחות 6 תווים)" class="input" />
        </div>
        <div id="reg-error" class="form-error" style="display:none"></div>
        <button class="btn btn-primary" id="registerSubmitBtn">צור חשבון</button>
        <button class="btn btn-secondary" id="backFromRegister" style="margin-top:8px">← חזור</button>
      </div>
    </div>
  `;

  document.getElementById('tab-login').addEventListener('click', () => switchTab('login'));
  document.getElementById('tab-register').addEventListener('click', () => switchTab('register'));
  document.getElementById('loginSubmitBtn').addEventListener('click', handleLogin);
  document.getElementById('registerSubmitBtn').addEventListener('click', handleRegister);
  document.getElementById('backFromLogin').addEventListener('click', showGuestScreen);
  document.getElementById('backFromRegister').addEventListener('click', showGuestScreen);
}

function switchTab(tab) {
  document.getElementById('form-login').style.display    = tab === 'login'    ? '' : 'none';
  document.getElementById('form-register').style.display = tab === 'register' ? '' : 'none';
  document.getElementById('tab-login').classList.toggle('active',    tab === 'login');
  document.getElementById('tab-register').classList.toggle('active', tab === 'register');
}

async function handleLogin() {
  const email    = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;
  const errEl    = document.getElementById('login-error');
  if (!email || !password) {
    errEl.textContent = 'נא למלא את כל השדות';
    errEl.style.display = '';
    return;
  }
  try {
    const res = await fetch(`${API_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (!res.ok) {
      errEl.textContent = data.detail || 'שגיאת התחברות';
      errEl.style.display = '';
      return;
    }
    await chrome.storage.local.set({
      pg_token: data.token,
      pg_email: data.email,
      pg_name:  data.name,
    });
    await loadStats(data.email, data.name);
  } catch {
    errEl.textContent = 'שגיאת חיבור לשרת. האם השרת פועל?';
    errEl.style.display = '';
  }
}

async function handleRegister() {
  const name     = document.getElementById('reg-name').value.trim();
  const email    = document.getElementById('reg-email').value.trim();
  const password = document.getElementById('reg-password').value;
  const errEl    = document.getElementById('reg-error');
  if (!email || !password) {
    errEl.textContent = 'נא למלא מייל וסיסמה';
    errEl.style.display = '';
    return;
  }
  try {
    const res = await fetch(`${API_URL}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, name }),
    });
    const data = await res.json();
    if (!res.ok) {
      errEl.textContent = data.detail || 'שגיאת הרשמה';
      errEl.style.display = '';
      return;
    }
    await chrome.storage.local.set({
      pg_token: data.token,
      pg_email: data.email,
      pg_name:  data.name,
    });
    await loadStats(data.email, data.name);
  } catch {
    errEl.textContent = 'שגיאת חיבור לשרת';
    errEl.style.display = '';
  }
}

async function loadStats(email, name) {
  document.getElementById('content').innerHTML = `
    <div class="loading"><div class="spinner"></div><p>טוען נתונים...</p></div>
  `;
  try {
    const res = await fetch(`${API_URL}/stats/${encodeURIComponent(email)}`);
    if (!res.ok) throw new Error();
    renderStats(await res.json(), name, email);
  } catch {
    renderStats(
      { total_scanned:0, phishing_blocked:0, risk_score:0, daily_active:false, recent_alerts:0 },
      name, email,
    );
  }
}

function getRiskColor(s) {
  return s >= 70 ? '#ef4444' : s >= 50 ? '#f97316' : s >= 30 ? '#fbbf24' : '#34d399';
}
function getRiskEmoji(s) {
  return s >= 70 ? '😰' : s >= 50 ? '😐' : s >= 30 ? '🤔' : '😊';
}

function renderStats(stats, name, email) {
  const score = Math.round(stats.risk_score || 0);
  const color = getRiskColor(score);

  document.getElementById('content').innerHTML = `
    <div class="user-pill">
      <span class="user-avatar">${(name||email).charAt(0).toUpperCase()}</span>
      <span class="user-name">${name||email}</span>
      <button class="logout-btn" id="logoutBtn" title="יציאה">↩</button>
    </div>
    <div class="stats">
      <div class="stat-card">
        <div class="stat-icon">📧</div>
        <div class="stat-value">${stats.total_scanned}</div>
        <div class="stat-label">מיילים נסרקו</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon"></div>
        <div class="stat-value">${stats.phishing_blocked}</div>
        <div class="stat-label">פישינג נחסם</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon">🎯</div>
        <div class="stat-value">${stats.total_scanned > 0 ? Math.round((stats.phishing_blocked / stats.total_scanned) * 100) : 0}%</div>
        <div class="stat-label">אחוז זיהוי</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon">⚡</div>
        <div class="stat-value">${stats.recent_alerts}</div>
        <div class="stat-label">התראות היום</div>
      </div>
    </div>
    <div class="risk-section">
      <div class="risk-header">
        <div>
          <div class="risk-title">מדד הסיכון שלך</div>
          <div class="risk-number" style="color:${color}">${score}</div>
          <div class="risk-sub">מתוך 100</div>
        </div>
        <div class="risk-emoji">${getRiskEmoji(score)}</div>
      </div>
      <div class="risk-bar-track">
        <div class="risk-bar-fill" id="riskFill" style="width:0%"></div>
      </div>
    </div>
    <div class="actions">
      <button class="btn btn-primary" id="scanBtn">
        <span>סרוק עכשיו</span>
      </button>
      <button class="btn btn-secondary" id="dashBtn">
        <span>📊</span><span>לוח בקרה מלא</span>
      </button>
    </div>
    <div class="footer">PhishGuard v1.0.0 &nbsp;|&nbsp; מגן עליך 24/7</div>
  `;

  setTimeout(() => {
    const fill = document.getElementById('riskFill');
    if (fill) fill.style.width = `${score}%`;
  }, 100);

  document.getElementById('logoutBtn').addEventListener('click', handleLogout);
  document.getElementById('scanBtn').addEventListener('click', scanNow);
  document.getElementById('dashBtn').addEventListener('click', () => {
    chrome.tabs.create({ url: `${API_URL}/app/dashboard.html` });
  });
}

function scanNow() {
  const btn = document.getElementById('scanBtn');
  btn.disabled = true;
  btn.innerHTML = '<span>⏳</span><span>סורק...</span>';
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    if (!tabs[0]) {
      btn.disabled = false;
      btn.innerHTML = '<span>סרוק עכשיו</span>';
      alert('פתח את Gmail ונסה שוב.');
      return;
    }
    chrome.tabs.sendMessage(tabs[0].id, { action: 'scanAll' }, async () => {
      await new Promise(r => setTimeout(r, 1500));
      const { pg_email, pg_name } = await chrome.storage.local.get(['pg_email', 'pg_name']);
      btn.disabled = false;
      btn.innerHTML = '<span>סרוק עכשיו</span>';
      if (pg_email) await loadStats(pg_email, pg_name);
      else start();
    });
  });
}

async function handleLogout() {
  await chrome.storage.local.remove(['pg_token','pg_email','pg_name','guardianMode','parentEmail','stats']);
  showGuestScreen();
}

start();