    const API = 'http://localhost:8000';
    let userEmail = '';

    // כל ערך שמגיע מהשרת עובר בריחה לפני שהוא נכנס ל-innerHTML
    function esc(value) {
      return String(value ?? '').replace(/[&<>"']/g, ch => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
      }[ch]));
    }

    // נתיבי /stats ו-/guardian דורשים הזדהות — הטוקן נשלח בכל קריאה
    function authHeaders() {
      return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('pg_token')}`,
      };
    }

    function logout() {
      localStorage.clear();
      window.location.href = 'login.html';
    }

    function showSection(name) {
      ['overview','scanner','alerts','guardian'].forEach(s => {
        document.getElementById(`sec-${s}`).style.display = s === name ? 'block' : 'none';
      });
      document.querySelectorAll('.sidebar-link').forEach(l => l.classList.remove('active'));
      event.target.classList.add('active');
    }

    function riskColor(score) {
      return score >= 80 ? '#ef4444' : score >= 50 ? '#f97316' : score >= 30 ? '#eab308' : '#22c55e';
    }
    function riskLabel(score) {
      return score >= 80 ? 'סכנה גבוהה' : score >= 50 ? 'חשוד' : score >= 30 ? 'זהירות' : 'בטוח';
    }

    async function loadDashboard() {
      const token = localStorage.getItem('pg_token');
      userEmail   = localStorage.getItem('pg_email') || '';
      const name  = localStorage.getItem('pg_name')  || userEmail;

      if (!token) { window.location.href = 'login.html'; return; }

      document.getElementById('navUser').textContent       = `שלום, ${name}`;
      document.getElementById('sidebarName').textContent   = name;
      document.getElementById('sidebarEmail').textContent  = userEmail;
      document.getElementById('sidebarInitial').textContent = name.charAt(0).toUpperCase();

      try {
        const r = await fetch(`${API}/stats/${userEmail}`, { headers: authHeaders() });
        if (r.status === 404) return; // no scans yet
        const d = await r.json();

        document.getElementById('statScanned').textContent = d.total_scanned;
        document.getElementById('statBlocked').textContent = d.phishing_blocked;
        document.getElementById('statAlerts').textContent  = d.recent_alerts;
        const detectionRate = d.total_scanned > 0 ? Math.round((d.phishing_blocked / d.total_scanned) * 100) : 0;
        document.getElementById('statStatus').textContent = detectionRate + '%';

        const score = Math.round(d.risk_score || 0);
        const color = riskColor(score);
        document.getElementById('riskNum').textContent   = score;
        document.getElementById('riskNum').style.color   = color;
        document.getElementById('riskLevel').textContent = riskLabel(score);
        document.getElementById('riskLevel').style.color = color;
        document.getElementById('riskBar').style.width   = `${score}%`;
        document.getElementById('riskCircle').style.background =
          `conic-gradient(${color} ${score}%, #334155 ${score}%)`;

        // Alerts
        const list = d.recent_alerts_list || [];
        const alertsEl = document.getElementById('alertsList');
        if (list.length === 0) {
          alertsEl.innerHTML = '<div class="empty-state">✅ אין התראות היום</div>';
        } else {
          alertsEl.innerHTML = list.map(a => `
            <div class="alert-item">
              <div class="alert-dot ${a.risk_level.includes('גבוה') ? 'high' : 'medium'}"></div>
              <div>
                <div class="alert-msg">${esc(a.message)}</div>
                <div class="alert-time">${a.created_at ? new Date(a.created_at).toLocaleTimeString('he-IL') : ''}</div>
              </div>
            </div>`).join('');
        }

        // Try guardian data
        const gr = await fetch(`${API}/guardian/${userEmail}`, { headers: authHeaders() });
        if (gr.ok) {
          const gd = await gr.json();
          document.getElementById('guardianData').innerHTML = `
            <div class="guardian-child-card">
              <h4>${esc(gd.child_name)} (${esc(gd.child_email)})</h4>
              <div class="guardian-stats-row">
                <span>פישינג היום: <b>${esc(gd.phishing_blocked_today)}</b></span>
                <span>מדד סיכון: <b style="color:${riskColor(gd.risk_score)}">${Math.round(gd.risk_score)}</b></span>
              </div>
            </div>`;
        }

      } catch (e) {
        console.error(e);
      }
    }

    async function dashScanURL() {
      const url = document.getElementById('dashUrlInput').value.trim();
      if (!url) return;
      const resultEl = document.getElementById('dashScanResult');
      resultEl.innerHTML = '<div class="empty-state">⏳ סורק...</div>';
      resultEl.style.display = 'block';
      try {
        const r = await fetch(`${API}/scan-url`, {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({ url }),
        });
        const data = await r.json();
        const score = data.risk_score ?? 0;
        const color = score >= 70 ? '#ef4444' : score >= 40 ? '#f97316' : score >= 20 ? '#eab308' : '#22c55e';
        resultEl.innerHTML = `
          <div class="result-card" style="border-color:${color};margin-top:16px;">
            <div class="result-header">
              <div class="result-level" style="color:${color}">${esc(data.risk_level)}</div>
              <div class="result-score" style="background:${color}">${score}%</div>
            </div>
            <div class="result-indicators">
              ${data.indicators.map(i => `<span class="indicator-tag">${esc(i)}</span>`).join('')}
            </div>
            <div class="result-recommendation" style="border-color:${color};background:${color}15">
              ${esc(data.recommendation)}
            </div>
          </div>`;
      } catch {
        resultEl.innerHTML = '<div class="result-error">שגיאת חיבור לשרת</div>';
      }
    }

    async function connectGuardian() {
      const childEmail = document.getElementById('childEmail').value.trim();
      if (!childEmail) return;
      const resultEl = document.getElementById('guardianResult');
      try {
        const r = await fetch(`${API}/guardian/connect`, {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({ child_email: childEmail, parent_email: userEmail }),
        });
        const data = await r.json();
        if (r.ok) {
          resultEl.innerHTML = `<div class="form-success">✅ מצב הורה הופעל עבור ${esc(childEmail)}</div>`;
        } else {
          resultEl.innerHTML = `<div class="form-error">${esc(data.detail)}</div>`;
        }
      } catch {
        resultEl.innerHTML = '<div class="form-error">שגיאת חיבור לשרת</div>';
      }
    }

    async function disconnectGuardian() {
      const childEmail = document.getElementById('childEmail').value.trim();
      if (!childEmail) {
        document.getElementById('guardianResult').innerHTML =
          '<div class="form-error">נא להזין כתובת מייל של הילד</div>';
        return;
      }
      const resultEl = document.getElementById('guardianResult');
      try {
        const r = await fetch(`${API}/guardian/disconnect`, {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({ child_email: childEmail, parent_email: userEmail }),
        });
        const data = await r.json();
        if (r.ok) {
          resultEl.innerHTML = `<div class="form-success">✅ השיוך של ${esc(childEmail)} הוסר בהצלחה</div>`;
          document.getElementById('guardianData').innerHTML = '';
        } else {
          resultEl.innerHTML = `<div class="form-error">${esc(data.detail)}</div>`;
        }
      } catch {
        resultEl.innerHTML = '<div class="form-error">שגיאת חיבור לשרת</div>';
      }
    }
    loadDashboard();
