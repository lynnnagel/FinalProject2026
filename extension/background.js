// PhishGuard Background Service Worker
const API_URL = 'http://localhost:8000';

// Installation handler
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('LURA installed successfully!');

    // Set default settings
    chrome.storage.local.set({
      enabled: true,
      guardianMode: false,
      autoScan: true,
      notificationsEnabled: true,
      stats: {
        totalScanned: 0,
        phishingBlocked: 0,
        riskScore: 0
      }
    });

    // Show welcome notification
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: 'ברוכים הבאים ל-LURA!',
      message: 'התוסף מוכן להגן עליך מפני פישינג בזמן אמת. פתח Gmail כדי להתחיל.',
      priority: 2
    });
  }
});

// Message handler from content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scanEmail') {
    handleEmailScan(request.data)
      .then(result => sendResponse({ success: true, data: result }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true; // Keep channel open for async response
  }

  if (request.action === 'updateStats') {
    updateStats(request.data);
    sendResponse({ success: true });
  }

  if (request.action === 'showNotification') {
    showPhishingNotification(request.data);
    sendResponse({ success: true });
  }

  if (request.action === 'getSettings') {
    chrome.storage.local.get(['enabled', 'guardianMode', 'autoScan'], (settings) => {
      sendResponse(settings);
    });
    return true;
  }
});

// Handle email scan
async function handleEmailScan(emailData) {
  try {
    const response = await fetch(`${API_URL}/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(emailData)
    });

    if (!response.ok) {
      throw new Error(`API Error: ${response.status}`);
    }

    const result = await response.json();

    // Update stats
    await updateStats({
      scanned: true,
      phishing: result.is_phishing,
      riskScore: result.risk_score
    });

    // Show notification if high risk
    if (result.risk_score >= 80) {
      showPhishingNotification({
        sender: emailData.sender,
        subject: emailData.subject,
        riskScore: result.risk_score
      });
    }

    return result;
  } catch (error) {
    console.error('Background: Error scanning email:', error);
    throw error;
  }
}

// Update statistics
async function updateStats(data) {
  return new Promise((resolve) => {
    chrome.storage.local.get(['stats'], (result) => {
      const stats = result.stats || {
        totalScanned: 0,
        phishingBlocked: 0,
        riskScore: 0
      };

      if (data.scanned) {
        stats.totalScanned += 1;
      }

      if (data.phishing) {
        stats.phishingBlocked += 1;
      }

      if (data.riskScore !== undefined) {
        // Calculate rolling average
        stats.riskScore = Math.round(
          (stats.riskScore * 0.8 + data.riskScore * 0.2)
        );
      }

      chrome.storage.local.set({ stats }, () => {
        resolve(stats);
      });
    });
  });
}

// Show phishing notification
function showPhishingNotification(data) {
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: '⚠️ זוהה מייל פישינג!',
    message: `מייל חשוד מ-${data.sender}\nמדד סיכון: ${Math.round(data.riskScore)}%\nאל תלחץ על קישורים במייל זה.`,
    priority: 2,
    requireInteraction: true,
    buttons: [
      { title: 'הצג פרטים' },
      { title: 'התעלם' }
    ]
  });
}

// Notification button clicks
chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
  if (buttonIndex === 0) {
    // Show details - open popup
    chrome.action.openPopup();
  }
  chrome.notifications.clear(notificationId);
});

// Badge updates based on risk
chrome.storage.onChanged.addListener((changes, namespace) => {
  if (namespace === 'local' && changes.stats) {
    const stats = changes.stats.newValue;
    const riskScore = stats.riskScore || 0;

    // Update badge
    if (riskScore >= 70) {
      chrome.action.setBadgeBackgroundColor({ color: '#ef4444' });
      chrome.action.setBadgeText({ text: '!' });
    } else if (riskScore >= 40) {
      chrome.action.setBadgeBackgroundColor({ color: '#f97316' });
      chrome.action.setBadgeText({ text: String(stats.phishingBlocked) });
    } else {
      chrome.action.setBadgeBackgroundColor({ color: '#22c55e' });
      chrome.action.setBadgeText({ text: '' });
    }
  }
});

// Periodic stats sync with server
chrome.alarms.create('syncStats', { periodInMinutes: 30 });

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'syncStats') {
    chrome.storage.local.get(['stats', 'userEmail'], async (data) => {
      if (data.userEmail) {
        try {
          const response = await fetch(`${API_URL}/stats/${data.userEmail}`);
          if (response.ok) {
            const serverStats = await response.json();
            chrome.storage.local.set({
              stats: {
                totalScanned: serverStats.total_scanned,
                phishingBlocked: serverStats.phishing_blocked,
                riskScore: serverStats.risk_score
              }
            });
            console.log('Stats synced with server');
          }
        } catch (error) {
          console.error('Failed to sync stats:', error);
        }
      }
    });
  }
});

// Context menu for manual scan
chrome.contextMenus.create({
  id: 'scanEmail',
  title: 'סרוק מייל זה עם LURA',
  contexts: ['selection']
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'scanEmail') {
    chrome.tabs.sendMessage(tab.id, {
      action: 'scanSelected',
      text: info.selectionText
    });
  }
});

console.log('LURA background service started');
