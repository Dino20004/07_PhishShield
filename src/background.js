/**
 * PhishShield AI Service Worker
 * Purpose: Handles browser navigation, intercepting threat vectors (downloads, redirects), 
 * managing scanning jobs, and pushing user notification alerts.
 */

import { AIRiskEngine } from "./engine.js";
import { storage } from "./storage.js";
import { logger, parseUrl } from "./utils.js";

// Active tab scan results cache
const activeScanCache = new Map();

// Initialize extension defaults
chrome.runtime.onInstalled.addListener(async () => {
  logger.info("PhishShield AI extension successfully installed.");
  await storage.getSettings(); // Ensures default configuration initializes
});

// Clean cache when tabs are closed
chrome.tabs.onRemoved.addListener((tabId) => {
  activeScanCache.delete(tabId);
});

/**
 * Executes a scanning job on page load or navigation commit.
 */
async function executeScan(tabId, url, domMetadata = null) {
  if (!tabId || typeof tabId !== 'number') return;
  if (!url || typeof url !== 'string') return;
  
  if (url.startsWith("chrome://") || url.startsWith("chrome-extension://") || url.startsWith("about:")) {
    const systemScan = {
      domain: "System / Blank page",
      url: url || "",
      riskScore: 0,
      riskCategory: "SAFE",
      scannedAt: new Date().toISOString(),
      modules: {
        ssl: { score: 0, reason: "System protocol" },
        whois: { score: 0, reason: "System protocol" },
        brandImpersonation: { score: 0, reason: "System protocol" }
      },
      threats: [],
      recommendation: "This page is not a standard web domain and cannot be scanned."
    };
    activeScanCache.set(tabId, systemScan);
    updateBadge(tabId, 0, "SAFE");
    chrome.runtime.sendMessage({
      type: "SCAN_COMPLETE",
      tabId: tabId,
      scanResult: systemScan
    }).catch(() => {});
    return;
  }

  const urlObj = parseUrl(url);
  
  // Whitelist/Ignore validation
  const whitelisted = await storage.isWhitelisted(urlObj.hostname);
  const ignored = await storage.isIgnored(urlObj.hostname);
  
  if (whitelisted) {
    const safeScan = {
      domain: urlObj.hostname,
      url: url,
      riskScore: 0,
      riskCategory: "SAFE",
      scannedAt: new Date().toISOString(),
      modules: {
        ssl: { score: 0, reason: "Trusted connection" },
        whois: { score: 0, reason: "Trusted domain" },
        brandImpersonation: { score: 0, reason: "Trusted brand" }
      },
      threats: [],
      recommendation: "This website is whitelisted and trusted."
    };
    activeScanCache.set(tabId, safeScan);
    updateBadge(tabId, 0, "SAFE");
    chrome.runtime.sendMessage({
      type: "SCAN_COMPLETE",
      tabId: tabId,
      scanResult: safeScan
    }).catch(() => {});
    return;
  }

  try {
    // Run full risk suite
    const scanResult = await AIRiskEngine.scan(url, domMetadata);
    activeScanCache.set(tabId, scanResult);

    // Save scan to storage log history
    await storage.saveScan(scanResult);

    // Update extension badge UI
    updateBadge(tabId, scanResult.riskScore, scanResult.riskCategory);

    // Broadcast the scan complete event
    chrome.runtime.sendMessage({
      type: "SCAN_COMPLETE",
      tabId: tabId,
      scanResult: scanResult
    }).catch(() => {});

    // Trigger blocker overlays if threat score crosses critical settings thresholds
    if (scanResult.riskScore >= 70 && !ignored) {
      // 1. Notify Content Script to draw blocker screen
      chrome.tabs.sendMessage(tabId, {
        type: "SHOW_WARNING_OVERLAY",
        scanResult
      }).catch(err => logger.debug("Message delivery skipped (page not fully initialized yet)"));

      // 2. Push desktop popup notifications safely
      const settings = await storage.getSettings();
      if (settings.enableNotifications) {
        showSafeNotification(`threat-${tabId}-${Date.now()}`, {
          type: "basic",
          iconUrl: "/assets/icon128.png",
          title: "PhishShield AI Alert",
          message: `Blocked suspicious site: ${urlObj.hostname}. Risk is ${scanResult.riskCategory} (${scanResult.riskScore}/100)`,
          priority: 2
        });
      }
    }
  } catch (err) {
    logger.error("Scan engine execution exception:", err);
  }
}

/**
 * Modifies extension badge visual markers based on vulnerability score.
 */
function updateBadge(tabId, score, rating) {
  if (!tabId || typeof tabId !== 'number') return;
  let color = "#22C55E"; // Green (SAFE)
  let text = "SAFE";

  if (rating === "CRITICAL") {
    color = "#EF4444"; // Red
    text = "CRIT";
  } else if (rating === "HIGH") {
    color = "#F97316"; // Orange
    text = "HIGH";
  } else if (rating === "MEDIUM") {
    color = "#EAB308"; // Yellow
    text = "MED";
  } else if (rating === "LOW") {
    color = "#3B82F6"; // Blue
    text = "LOW";
  }

  chrome.action.setBadgeBackgroundColor({ color, tabId }, () => {
    chrome.action.setBadgeText({ text, tabId }).catch(() => {});
  });
}

/**
 * Runtime Message Listener. Routes messages between Content Scripts and Popups.
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab ? sender.tab.id : null;

  if (message.type === "PAGE_LOADED") {
    if (tabId) {
      executeScan(tabId, message.url, message.domMetadata);
    }
  }

  else if (message.type === "FORM_SUBMITTING") {
    if (tabId) {
      // Re-run scan with submission context
      AIRiskEngine.scan(message.url, message.domMetadata).then(result => {
        if (result.riskScore >= 70 && !message.bypass) {
          sendResponse({ action: "BLOCK", scanResult: result });
        } else {
          sendResponse({ action: "ALLOW" });
        }
      });
      return true; // Keep response channel open asynchronously
    }
  }

  else if (message.type === "GET_LATEST_SCAN") {
    const cached = activeScanCache.get(message.tabId);
    sendResponse({ scanResult: cached || null });
  }

  else if (message.type === "RUN_MANUAL_SCAN") {
    executeScan(message.tabId, message.url).then(() => {
      const completedScan = activeScanCache.get(message.tabId);
      sendResponse({ scanResult: completedScan || null });
    });
    return true; // Keep response channel open asynchronously
  }

  else if (message.type === "ADD_TO_WHITELIST") {
    storage.addToWhitelist(message.domain).then(() => {
      if (tabId) executeScan(tabId, sender.tab.url);
      sendResponse({ success: true });
    });
    return true;
  }

  else if (message.type === "ADD_TO_IGNORED") {
    storage.addIgnoredWarning(message.domain).then(() => {
      sendResponse({ success: true });
    });
    return true;
  }
});

/**
 * Network Navigation Redirect Tracker.
 */
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId === 0 && details.tabId > 0) {
    // Basic redirect checks could be initialized here if needed
    logger.info(`Navigating to: ${details.url}`);
  }
});

/**
 * Drive-by Download Hook. Intercepts and blocks high-risk payloads.
 */
chrome.downloads.onCreated.addListener(async (downloadItem) => {
  const settings = await storage.getSettings();
  const url = downloadItem.url;
  
  // Scan download url for vulnerabilities
  const scanResult = await AIRiskEngine.scan(url, null, null, { filename: downloadItem.filename });
  
  if (scanResult.riskScore >= 70) {
    if (settings.enableNotifications) {
      showSafeNotification(`download-block-${downloadItem.id}`, {
        type: "basic",
        iconUrl: "/assets/icon128.png",
        title: "Download Aborted",
        message: `PhishShield AI blocked a dangerous file download (${downloadItem.filename}) from an insecure site.`,
        priority: 2
      });
    }
    
    try {
      chrome.downloads.cancel(downloadItem.id);
      logger.warn(`Cancelled download ID ${downloadItem.id} from high-risk URL: ${url}`);
    } catch (e) {
      logger.error("Failed to cancel download:", e);
    }
  }
});

/**
 * Safely creates extension notifications, checking lastErrors to prevent browser exceptions.
 */
function showSafeNotification(id, options) {
  try {
    if (typeof chrome !== 'undefined' && chrome.notifications) {
      chrome.notifications.create(id, options, () => {
        if (chrome.runtime.lastError) {
          logger.warn("Chrome notifications engine error details:", chrome.runtime.lastError.message);
        }
      });
    }
  } catch (err) {
    logger.error("Failed to trigger system notification alert:", err);
  }
}
