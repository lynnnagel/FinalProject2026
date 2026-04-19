// PhishGuard Content Script - זיהוי פישינג ב-Gmail
const API_URL = 'http://localhost:8000';

// Configuration
const config = {
  scanDelay: 1000, // Wait 1 second before scanning
  riskThresholds: {
    high: 80,
    medium: 50,
    low: 30
  }
};

// State
let userEmail = null;
let scannedEmails = new Set();

// Initialize
async function init() {
  console.log('PhishGuard: מאתחל...');

  // Get user email from Gmail
  userEmail = await getUserEmail();
  console.log('PhishGuard: משתמש מזוהה:', userEmail);

  // Watch for email changes
  observeEmailChanges();

  // Scan visible emails
  setTimeout(scanVisibleEmails, 2000);
}

// Get user email from Gmail DOM
function getUserEmail() {
  return new Promise((resolve) => {
    const checkEmail = setInterval(() => {
      // Try to find email in various Gmail elements
      const emailElement = document.querySelector('[email]') ||
                          document.querySelector('.gb_d') ||
                          document.querySelector('[data-email]');

      if (emailElement) {
        const email = emailElement.getAttribute('email') ||
                     emailElement.getAttribute('data-email') ||
                     emailElement.textContent.trim();

        if (email && email.includes('@')) {
          clearInterval(checkEmail);
          persistUserEmail(email);
          resolve(email);
        }
      }
    }, 500);

    // Timeout after 10 seconds – fall back to stored value or generic placeholder
    setTimeout(() => {
      clearInterval(checkEmail);
      chrome.storage.local.get(['userEmail'], (result) => {
        resolve(result.userEmail || 'user@gmail.com');
      });
    }, 10000);
  });
}

// Observe email list changes
function observeEmailChanges() {
  const emailList = document.querySelector('[role="main"]');
  if (!emailList) {
    console.log('PhishGuard: לא נמצאה רשימת מיילים, מנסה שוב...');
    setTimeout(observeEmailChanges, 2000);
    return;
  }

  const observer = new MutationObserver((mutations) => {
    scanVisibleEmails();
  });

  observer.observe(emailList, {
    childList: true,
    subtree: true
  });

  console.log('PhishGuard: צופה בשינויים במיילים');
}

// Scan all visible emails
async function scanVisibleEmails() {
  const emailRows = document.querySelectorAll('[role="row"]');
  console.log(`PhishGuard: נמצאו ${emailRows.length} מיילים`);

  for (const row of emailRows) {
    const emailId = row.getAttribute('data-message-id') || generateEmailId(row);

    if (!scannedEmails.has(emailId)) {
      scannedEmails.add(emailId);
      await scanEmail(row, emailId);
    }
  }
}

// Generate unique email ID from row
// Uses a simple djb2 hash to handle Hebrew and non-ASCII characters
// (btoa() throws on non-Latin strings)
function generateEmailId(row) {
  const subject = row.querySelector('[data-subject]')?.textContent || '';
  const sender = row.querySelector('.yW span')?.textContent || '';
  const str = sender + subject;
  let hash = 5381;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) + hash) ^ str.charCodeAt(i);
    hash |= 0; // keep as 32-bit integer
  }
  return 'pg_' + Math.abs(hash).toString(36);
}

// Extract email data from DOM
function extractEmailData(row) {
  const subjectEl = row.querySelector('[data-subject]') ||
                   row.querySelector('.bog') ||
                   row.querySelector('span[title]');

  const senderEl = row.querySelector('.yW span') ||
                  row.querySelector('.yP') ||
                  row.querySelector('[email]');

  const subject = subjectEl?.textContent?.trim() || 'ללא נושא';
  const sender = senderEl?.textContent?.trim() ||
                senderEl?.getAttribute('email') || 'לא ידוע';

  // Get preview text
  const previewEl = row.querySelector('.y2');
  const content = previewEl?.textContent?.trim() || '';

  return { sender, subject, content };
}

// Scan single email
async function scanEmail(row, emailId) {
  try {
    const emailData = extractEmailData(row);

    console.log('PhishGuard: סורק מייל:', emailData.subject);

    // Send to API
    const response = await fetch(`${API_URL}/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        user_email: userEmail,
        sender: emailData.sender,
        subject: emailData.subject,
        content: emailData.content
      })
    });

    if (!response.ok) {
      throw new Error(`API Error: ${response.status}`);
    }

    const result = await response.json();
    console.log('PhishGuard: תוצאה:', result);

    // Add visual indicator
    addRiskIndicator(row, result);

  } catch (error) {
    console.error('PhishGuard: שגיאה בסריקה:', error);
    addRiskIndicator(row, {
      risk_score: 50,
      risk_level: 'לא זמין',
      indicators: ['לא ניתן להתחבר לשרת']
    });
  }
}

// Add visual risk indicator to email row
function addRiskIndicator(row, result) {
  // Remove existing indicator
  const existing = row.querySelector('.phishguard-indicator');
  if (existing) existing.remove();

  // Create indicator
  const indicator = document.createElement('div');
  indicator.className = 'phishguard-indicator';
  indicator.setAttribute('data-risk', result.risk_score);

  // Determine color and icon
  let color, icon, text;
  if (result.risk_score >= config.riskThresholds.high) {
    color = '#ef4444';
    icon = '⚠️';
    text = 'סכנה!';
  } else if (result.risk_score >= config.riskThresholds.medium) {
    color = '#f97316';
    icon = '⚡';
    text = 'חשוד';
  } else if (result.risk_score >= config.riskThresholds.low) {
    color = '#eab308';
    icon = '⚠';
    text = 'זהירות';
  } else {
    color = '#22c55e';
    icon = '✓';
    text = 'בטוח';
  }

  indicator.innerHTML = `
    <div style="
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      background: ${color}15;
      border: 2px solid ${color};
      border-radius: 8px;
      font-size: 12px;
      font-weight: 600;
      color: ${color};
      box-shadow: 0 2px 8px ${color}30;
      animation: phishguard-fadein 0.3s ease-in;
    ">
      <span style="font-size: 14px;">${icon}</span>
      <span>${text}</span>
      <span style="
        background: ${color};
        color: white;
        padding: 2px 6px;
        border-radius: 4px;
        font-size: 11px;
      ">${Math.round(result.risk_score)}%</span>
    </div>
  `;

  // Add tooltip with details
  indicator.title = `רמת סיכון: ${result.risk_level}
אינדיקטורים: ${result.indicators?.join(', ') || 'אין'}
המלצה: ${result.recommendation || ''}
זמן תגובה: ${result.response_time || 0}s`;

  // Insert indicator
  const insertPoint = row.querySelector('.yW') || row.querySelector('.bog') || row;
  if (insertPoint.parentElement) {
    insertPoint.parentElement.insertBefore(indicator, insertPoint.nextSibling);
  } else {
    row.appendChild(indicator);
  }

  // Add click listener for details
  indicator.addEventListener('click', (e) => {
    e.stopPropagation();
    showDetailedAnalysis(result);
  });
}

// Show detailed analysis modal
function showDetailedAnalysis(result) {
  const existing = document.getElementById('phishguard-modal');
  if (existing) existing.remove();

  const modal = document.createElement('div');
  modal.id = 'phishguard-modal';
  modal.innerHTML = `
    <div class="phishguard-modal-overlay">
      <div class="phishguard-modal-content">
        <div class="phishguard-modal-header">
          <h2>🛡️ ניתוח PhishGuard</h2>
          <button class="phishguard-close">✕</button>
        </div>

        <div class="phishguard-modal-body">
          <div class="risk-score-display">
            <div class="risk-score-circle" style="
              background: conic-gradient(
                ${result.risk_score >= 80 ? '#ef4444' :
                  result.risk_score >= 50 ? '#f97316' :
                  result.risk_score >= 30 ? '#eab308' : '#22c55e'} ${result.risk_score}%,
                #e5e7eb ${result.risk_score}%
              );
            ">
              <div class="risk-score-inner">
                <span class="risk-score-number">${Math.round(result.risk_score)}</span>
                <span class="risk-score-label">מדד סיכון</span>
              </div>
            </div>
          </div>

          <div class="risk-level">
            <strong>רמת סיכון:</strong> ${result.risk_level}
          </div>

          <div class="indicators">
            <strong>אינדיקטורים שזוהו:</strong>
            <ul>
              ${result.indicators?.map(ind => `<li>${ind}</li>`).join('') || '<li>אין</li>'}
            </ul>
          </div>

          <div class="recommendation ${result.risk_score >= 70 ? 'warning' : 'info'}">
            <strong>💡 המלצה:</strong>
            <p>${result.recommendation}</p>
          </div>

          <div class="response-time">
            ⚡ זמן תגובה: ${result.response_time || 0}s (מטרה: &lt;2s)
          </div>
        </div>

        <div class="phishguard-modal-footer">
          <button class="phishguard-btn phishguard-btn-primary">סגור</button>
        </div>
      </div>
    </div>
  `;

  document.body.appendChild(modal);

  modal.querySelector('.phishguard-close').onclick = () => modal.remove();
  modal.querySelector('.phishguard-btn-primary').onclick = () => modal.remove();
  modal.querySelector('.phishguard-modal-overlay').onclick = (e) => {
    if (e.target.classList.contains('phishguard-modal-overlay')) {
      modal.remove();
    }
  };
}

// Listen for messages from popup / background
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scanAll') {
    scannedEmails.clear(); // force re-scan of all visible emails
    scanVisibleEmails().then(() => sendResponse({ success: true }));
    return true;
  }
  if (request.action === 'getUserEmail') {
    sendResponse({ email: userEmail });
  }
});

// Store detected userEmail in chrome.storage so the popup can retrieve it
function persistUserEmail(email) {
  if (email && email.includes('@')) {
    chrome.storage.local.set({ userEmail: email });
  }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

// Add CSS animation
const style = document.createElement('style');
style.textContent = `
  @keyframes phishguard-fadein {
    from { opacity: 0; transform: translateY(-10px); }
    to { opacity: 1; transform: translateY(0); }
  }
`;
document.head.appendChild(style);
