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
      ['overview','scanner','alerts','trusted','guardian'].forEach(s => {
        document.getElementById(`sec-${s}`).style.display = s === name ? 'block' : 'none';
      });
      document.querySelectorAll('.sidebar-link').forEach(l => l.classList.remove('active'));
      event.target.classList.add('active');
      if (name === 'trusted') loadTrusted();
    }

    // ── שולחים מוכרים ──────────────────────────────────────────────
    async function loadTrusted() {
      const el = document.getElementById('trustedList');
      if (!el) return;
      try {
        const r = await fetch(`${API}/trusted-senders`, { headers: authHeaders() });
        if (r.status === 401) { signOut(); return; }
        if (!r.ok) throw new Error();
        const list = (await r.json()).senders || [];
        el.innerHTML = list.length === 0
          ? '<div class="empty-state">עדיין לא סימנת שולחים.</div>'
          : list.map(s => `
              <div class="guardian-child-card" style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:8px;">
                <div>
                  <div style="font-weight:600;direction:ltr;text-align:right;">${esc(s.value)}</div>
                  <div style="font-size:12.5px;color:var(--muted);">${s.is_domain ? 'דומיין שלם' : 'כתובת בודדת'}</div>
                </div>
                <button class="btn-danger" onclick="removeTrusted('${esc(s.value)}')">הסר</button>
              </div>`).join('');
      } catch {
        el.innerHTML = '<div class="empty-state">לא ניתן לטעון את הרשימה.</div>';
      }
    }

    async function addTrusted() {
      const input = document.getElementById('trustedValue');
      const out   = document.getElementById('trustedResult');
      const value = (input.value || '').trim();
      if (!value) return;

      try {
        const r = await fetch(`${API}/trusted-senders`, {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({ value }),
        });
        const d = await r.json();
        if (!r.ok) {
          out.innerHTML = `<div class="form-error">${esc(d.detail || 'לא ניתן להוסיף')}</div>`;
          return;
        }
        // rescored הוא מספר הסריקות השמורות שסומנו לחישוב מחדש. בלי
        // הביטול הזה הסימון לא היה משנה דבר בתיבה, ולכן שווה להראות
        // אותו: הוא מסביר מה בדיוק קרה.
        out.innerHTML = `<div class="form-success">נוסף. ${d.rescored} מיילים יסומנו מחדש בסריקה הבאה.</div>`;
        input.value = '';
        loadTrusted();
      } catch {
        out.innerHTML = '<div class="form-error">אין חיבור לשרת.</div>';
      }
    }

    async function removeTrusted(value) {
      const out = document.getElementById('trustedResult');
      try {
        const r = await fetch(`${API}/trusted-senders/${encodeURIComponent(value)}`, {
          method: 'DELETE',
          headers: authHeaders(),
        });
        if (!r.ok) throw new Error();
        const d = await r.json();
        out.innerHTML = `<div class="form-success">הוסר. ${d.rescored} מיילים יסומנו מחדש.</div>`;
        loadTrusted();
      } catch {
        out.innerHTML = '<div class="form-error">לא ניתן להסיר.</div>';
      }
    }

    // The bands come from the server, which derives them from one
    // calibrated threshold. They used to be written out here by hand -
    // in two different sets, 80/50/30 in the overview and 70/40/20 in
    // the scanner - and after the threshold was calibrated neither
    // matched the real values any more.
    //
    // The list below is only what to fall back on if the request fails,
    // so a dashboard on a server that is briefly down still labels
    // scores instead of breaking. Keep it in step with config.py.
    let BANDS = [
      { min: 72, label: 'סכנה גבוהה', color: 'var(--danger)' },
      { min: 50, label: 'חשוד',       color: 'var(--orange)' },
      { min: 30, label: 'זהירות',     color: 'var(--yellow)' },
      { min: -1, label: 'בטוח',       color: 'var(--green)'  },
    ];

    const BAND_COLORS = {
      'סכנה גבוהה': 'var(--danger)',
      'חשוד':       'var(--orange)',
      'זהירות':     'var(--yellow)',
      'בטוח':       'var(--green)',
    };

    async function loadBands() {
      try {
        const r = await fetch(`${API}/config/bands`);
        if (!r.ok) return;
        const d = await r.json();
        if (!Array.isArray(d.bands) || d.bands.length !== 4) return;
        BANDS = d.bands.map((b, i) => ({
          // The lowest band has to catch every score, including a
          // negative one used as a marker.
          min: i === d.bands.length - 1 ? -1 : b.min,
          label: b.label,
          color: BAND_COLORS[b.label] || 'var(--muted)',
        }));
      } catch {
        // The server is unreachable. The fallback above still labels.
      }
    }

    const band      = score => BANDS.find(b => score >= b.min);
    const riskColor = score => band(score).color;
    const riskLabel = score => band(score).label;

    // אין עדיין נתונים — מצב תקין לגמרי למשתמש חדש, ולכן הוא מוצג
    // כהנחיה ולא כתקלה.
    function showEmptyDashboard(status) {
      ['statScanned', 'statBlocked', 'statAlerts'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = '0';
      });
      const statusEl = document.getElementById('statStatus');
      if (statusEl) statusEl.textContent = '—';

      const alertsEl = document.getElementById('alertsList');
      if (alertsEl) {
        alertsEl.innerHTML = status === 403
          ? '<div class="empty-state">החשבון המחובר אינו תואם לנתונים המבוקשים.</div>'
          : '<div class="empty-state">עדיין לא נסרקו מיילים.<br>' +
            'התחבר לאותו חשבון בתוסף, ופתח את Gmail.</div>';
      }
    }

    // חובה לנקות את האישורים לפני ההפניה. login.html מפנה מיד
    // לדשבורד כשהוא מוצא pg_token, והדשבורד מפנה להתחברות כשהשרת
    // מחזיר 401 — כך שטוקן שפג תוקפו יצר לולאת הפניות אינסופית בין
    // שני העמודים, שנראית כהבהוב.
    function signOut() {
      localStorage.removeItem('pg_token');
      localStorage.removeItem('pg_email');
      localStorage.removeItem('pg_name');
      window.location.href = 'login.html';
    }

    async function loadDashboard() {
      const token = localStorage.getItem('pg_token');
      userEmail   = localStorage.getItem('pg_email') || '';
      const name  = localStorage.getItem('pg_name')  || userEmail;

      if (!token) { signOut(); return; }

      document.getElementById('navUser').textContent       = `שלום, ${name}`;
      document.getElementById('sidebarName').textContent   = name;
      document.getElementById('sidebarEmail').textContent  = userEmail;
      document.getElementById('sidebarInitial').textContent = name.charAt(0).toUpperCase();

      try {
        const r = await fetch(`${API}/stats/${userEmail}`, { headers: authHeaders() });
        if (r.status === 401) { signOut(); return; }
        if (!r.ok) {
          // 404 = טרם נסרק דבר, 403 = הטוקן שייך לחשבון אחר. קודם רק
          // 404 טופל, ולכן תשובת שגיאה זרמה הלאה כאובייקט ללא השדות
          // המצופים וכל המונים הוצגו כ-undefined בלי שום הסבר.
          showEmptyDashboard(r.status);
          return;
        }
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
          `conic-gradient(${color} ${score}%, var(--border-light) ${score}%)`;

        // Alerts
        const list = d.recent_alerts_list || [];
        const alertsEl = document.getElementById('alertsList');
        if (list.length === 0) {
          alertsEl.innerHTML = '<div class="empty-state">אין התראות היום</div>';
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
      resultEl.innerHTML = '<div class="empty-state">סורק...</div>';
      resultEl.style.display = 'block';
      try {
        const r = await fetch(`${API}/scan-url`, {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({ url }),
        });
        const data = await r.json();
        const score = data.risk_score ?? 0;
        const color = riskColor(score);
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
          resultEl.innerHTML = `<div class="form-success">מצב מפקח הופעל עבור ${esc(childEmail)}</div>`;
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
          resultEl.innerHTML = `<div class="form-success">השיוך של ${esc(childEmail)} הוסר בהצלחה</div>`;
          document.getElementById('guardianData').innerHTML = '';
        } else {
          resultEl.innerHTML = `<div class="form-error">${esc(data.detail)}</div>`;
        }
      } catch {
        resultEl.innerHTML = '<div class="form-error">שגיאת חיבור לשרת</div>';
      }
    }
    // The bands are fetched before the first render, so a score is
    // never labelled by the fallback list when the server could have
    // said otherwise. A failed fetch resolves and the fallback stands.
    loadBands().then(loadDashboard);
