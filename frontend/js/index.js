const API = 'http://localhost:8000';

    // Nav state
    function initNav() {
      const token = localStorage.getItem('pg_token');
      const name  = localStorage.getItem('pg_name');
      if (token) {
        document.getElementById('navLogin').style.display = 'none';
        document.getElementById('navLogout').style.display = 'block';
        document.getElementById('navDashboard').style.display = 'block';
      }
    }

    function logout() {
      localStorage.clear();
      window.location.reload();
    }

    // Load system stats
    async function loadStats() {
      try {
        const r = await fetch(`${API}/metrics`);
        if (r.ok) {
          const d = await r.json();
          document.getElementById('totalScanned').textContent =
            (d.total_emails_scanned || 0).toLocaleString();
          document.getElementById('totalBlocked').textContent =
            (d.phishing_blocked || 0).toLocaleString();
        }
      } catch {}
    }

    // URL Scanner
    async function scanURL() {
      const url = document.getElementById('urlInput').value.trim();
      if (!url) return;

      const btn = document.getElementById('scanBtn');
      btn.textContent = '⏳ סורק...';
      btn.disabled = true;

      const resultEl = document.getElementById('scanResult');
      resultEl.style.display = 'none';

      try {
        const r = await fetch(`${API}/scan-url`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url }),
        });
        const data = await r.json();
        renderResult(data, resultEl);
      } catch {
        resultEl.innerHTML = `<div class="result-error">לא ניתן להתחבר לשרת. ודא שהשרת פועל.</div>`;
        resultEl.style.display = 'block';
      }

      btn.textContent = 'נתח';
      btn.disabled = false;
    }

    function renderResult(data, el) {
      const score = data.risk_score ?? 0;
      const color = score >= 70 ? '#ef4444' : score >= 40 ? '#f97316' : score >= 20 ? '#eab308' : '#22c55e';
      const emoji = score >= 70 ? '🚨' : score >= 40 ? '⚠️' : score >= 20 ? '⚠' : '✅';

      el.innerHTML = `
        <div class="result-card" style="border-color:${color}">
          <div class="result-header">
            <span class="result-emoji">${emoji}</span>
            <div>
              <div class="result-level" style="color:${color}">${data.risk_level}</div>
              <div class="result-url">${data.url || ''}</div>
            </div>
            <div class="result-score" style="background:${color}">${score}%</div>
          </div>
          <div class="result-indicators">
            ${data.indicators.map(i => `<span class="indicator-tag">⚡ ${i}</span>`).join('')}
          </div>
          <div class="result-recommendation" style="border-color:${color};background:${color}15">
            💡 ${data.recommendation}
          </div>
        </div>
      `;
      el.style.display = 'block';
    }

    // Enter key support
    document.addEventListener('DOMContentLoaded', () => {
      initNav();
      loadStats();
      document.getElementById('urlInput').addEventListener('keydown', e => {
        if (e.key === 'Enter') scanURL();
      });
    });