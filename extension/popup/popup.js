const API_URL = 'http://localhost:8000';
let userEmail = null;
let guardianMode = false;

async function resolveUserEmail() {
  return new Promise(resolve => {
    chrome.storage.local.get(['userEmail', 'guardianMode'], result => {
      guardianMode = result.guardianMode || false;
      resolve(result.userEmail || null);
    });
  });
}

async function loadStats() {
  userEmail = await resolveUserEmail();

  if (!userEmail) {
    document.getElementById('content').innerHTML = `
      <div class="no-gmail">
        <div class="big-icon">📬</div>
        <h3>פתח את Gmail כדי להתחיל</h3>
        <p>PhishGuard יזהה את המייל שלך אוטומטית<br>ויתחיל לסרוק מיידית</p>
      </div>`;
    return;
  }

  try {
    const res = await fetch(`${API_URL}/stats/${encodeURIComponent(userEmail)}`);
    if (!res.ok) throw new Error();
    renderStats(await res.json());
  } catch {
    renderStats({
      total_scanned: 0, phishing_blocked: 0,
      risk_score: 0, daily_active: false, recent_alerts: 0,
    });
  }
}

function getRiskColor(score) {
  if (score >= 70) return '#ef4444';
  if (score >= 50) return '#f97316';
  if (score >= 30) return '#fbbf24';
  return '#34d399';
}

function getRiskEmoji(score) {
  if (score >= 70) return '😰';
  if (score >= 50) return '😐';
  if (score >= 30) return '🤔';
  return '😊';
}

function renderStats(stats) {
  const score = Math.round(stats.risk_score);
  const color = getRiskColor(score);

  document.getElementById('content').innerHTML = `
    <div class="stats">
      <div class="stat-card">
        <div class="stat-icon">📧</div>
        <div class="stat-value">${stats.total_scanned}</div>
        <div class="stat-label">מיילים נסרקו</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon">🛡️</div>
        <div class="stat-value">${stats.phishing_blocked}</div>
        <div class="stat-label">פישינג נחסם</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon">⚡</div>
        <div class="stat-value">${stats.recent_alerts}</div>
        <div class="stat-label">התראות אחרונות</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon">${stats.daily_active ? '✅' : '⏸️'}</div>
        <div class="stat-value" style="font-size:16px;padding-top:4px">
          ${stats.daily_active ? 'פעיל' : 'לא פעיל'}
        </div>
        <div class="stat-label">סטטוס היום</div>
      </div>
    </div>

    <div class="risk-section">
      <div class="risk-header">
        <div>
          <div class="risk-title">⚠️ מדד הסיכון שלך</div>
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
      <div class="guardian-card">
        <div class="guardian-label">
          <span>👁️</span>
          <span>מצב הורה</span>
        </div>
        <div class="toggle ${guardianMode ? 'on' : ''}" id="guardianToggle">
          <div class="toggle-knob"></div>
        </div>
      </div>

      <button class="btn btn-primary" id="scanBtn">
        <span>🔍</span>
        <span>סרוק עכשיו</span>
      </button>

      <button class="btn btn-secondary" id="dashBtn">
        <span>📊</span>
        <span>לוח בקרה מלא</span>
      </button>
    </div>

    <div class="footer">PhishGuard v1.0.0 &nbsp;|&nbsp; מגן עליך 24/7</div>
  `;

  setTimeout(() => {
    const fill = document.getElementById('riskFill');
    if (fill) fill.style.width = `${score}%`;
  }, 100);

  document.getElementById('guardianToggle').addEventListener('click', toggleGuardian);
  document.getElementById('scanBtn').addEventListener('click', scanNow);
  document.getElementById('dashBtn').addEventListener('click', () =>
    window.open('dashboard.html', '_blank'));
}

async function toggleGuardian() {
  const toggle = document.getElementById('guardianToggle');
  guardianMode = !guardianMode;
  toggle.classList.toggle('on');

  if (guardianMode) {
    const parentEmail = prompt('הזן את כתובת המייל של ההורה המנטר:');
    if (!parentEmail || !parentEmail.includes('@')) {
      guardianMode = false;
      toggle.classList.toggle('on');
      return;
    }
    try {
      const r = await fetch(`${API_URL}/guardian/connect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ child_email: userEmail, parent_email: parentEmail }),
      });
      if (r.ok) {
        chrome.storage.local.set({ guardianMode: true, parentEmail });
        alert(`✅ מצב הורה הופעל!\n${parentEmail} יקבל התראות.`);
      } else {
        guardianMode = false;
        toggle.classList.toggle('on');
        alert('שגיאה בהפעלת מצב הורה.');
      }
    } catch {
      guardianMode = false;
      toggle.classList.toggle('on');
      alert('שגיאת חיבור לשרת.');
    }
  } else {
    chrome.storage.local.set({ guardianMode: false });
  }
}

function scanNow() {
  const btn = document.getElementById('scanBtn');
  btn.classList.add('scanning');
  btn.innerHTML = '<span>⏳</span><span>סורק...</span>';

  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    if (!tabs[0]) {
      btn.classList.remove('scanning');
      btn.innerHTML = '<span>🔍</span><span>סרוק עכשיו</span>';
      alert('פתח את Gmail ונסה שוב.');
      return;
    }
    chrome.tabs.sendMessage(tabs[0].id, { action: 'scanAll' }, () => {
      setTimeout(() => {
        btn.classList.remove('scanning');
        btn.innerHTML = '<span>🔍</span><span>סרוק עכשיו</span>';
        loadStats();
      }, 1500);
    });
  });
}

loadStats();
