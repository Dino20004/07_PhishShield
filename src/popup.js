/**
 * PhishShield AI Popup Controller
 * Purpose: Manages UI events, rendering threat scores, configuring settings, 
 * showing log history, and exporting compliance reports.
 */

import { storage } from "./storage.js";
import { parseUrl } from "./utils.js";

// DOM references
const progressBar = document.getElementById("progress-bar");
const scoreNumber = document.getElementById("score-number");
const riskBadge = document.getElementById("risk-badge");
const activeDomain = document.getElementById("active-domain");
const statSsl = document.getElementById("stat-ssl");
const statAge = document.getElementById("stat-age");
const statBrand = document.getElementById("stat-brand");
const statThreats = document.getElementById("stat-threats");
const recommendationBox = document.getElementById("recommendation-box");
const recommendationText = document.getElementById("recommendation-text");
const threatListContainer = document.getElementById("threat-list-container");
const threatList = document.getElementById("threat-list");

// Nav Buttons
const btnSettings = document.getElementById("btn-settings");
const btnHistory = document.getElementById("btn-history");
const btnWhitelist = document.getElementById("btn-whitelist");
const btnBackSettings = document.getElementById("btn-back-settings");
const btnBackHistory = document.getElementById("btn-back-history");

// Panels
const panelDashboard = document.getElementById("panel-dashboard");
const panelSettings = document.getElementById("panel-settings");
const panelHistory = document.getElementById("panel-history");

// History / Settings elements
const historyList = document.getElementById("history-list");
const btnClearHistory = document.getElementById("btn-clear-history");
const btnExport = document.getElementById("btn-export");
const exportDropdown = document.getElementById("export-dropdown");

let currentTabDomain = "";
let currentTabScan = null;

// Circumference of SVG Progress circle: 2 * Math.PI * r (r=50) -> 314.159
const CIRCUMFERENCE = 314.159;

/**
 * Initializes and draws the circular SVG progress dial.
 */
function setRadialScore(score, rating) {
  scoreNumber.textContent = score;
  
  // Map score offset
  const offset = CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE;
  progressBar.style.strokeDasharray = `${CIRCUMFERENCE} ${CIRCUMFERENCE}`;
  progressBar.style.strokeDashoffset = offset;

  // Set progressive ring colors
  let color = "#22c55e"; // Green
  if (rating === "CRITICAL") color = "#ef4444";
  else if (rating === "HIGH") color = "#f97316";
  else if (rating === "MEDIUM") color = "#eab308";
  else if (rating === "LOW") color = "#3b82f6";
  
  progressBar.style.stroke = color;
}

/**
 * Renders page threat reports.
 */
async function loadTabScanReport() {
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    if (!tabs || tabs.length === 0) return;
    const tab = tabs[0];
    const urlObj = parseUrl(tab.url);
    currentTabDomain = urlObj.hostname;

    // Filter system/unsupported pages
    if (!tab.url || tab.url.startsWith("chrome://") || tab.url.startsWith("chrome-extension://") || tab.url.startsWith("about:")) {
      activeDomain.textContent = "System / New Tab";
      setRadialScore(0, "SAFE");
      riskBadge.textContent = "SAFE";
      riskBadge.className = "risk-badge badge-safe";
      statSsl.textContent = "N/A";
      statAge.textContent = "N/A";
      statBrand.textContent = "N/A";
      statThreats.textContent = "0 Flags";
      recommendationBox.className = "recommendation-box card-safe";
      recommendationText.textContent = "This page is not a standard web domain and cannot be scanned.";
      btnWhitelist.disabled = true;
      return;
    }

    // Check Whitelist status to set default action
    const isWhitelisted = await storage.isWhitelisted(currentTabDomain);
    btnWhitelist.textContent = isWhitelisted ? "Untrust Site" : "Trust Site";

    // Request active scan result from Background Service worker
    chrome.runtime.sendMessage({
      type: "GET_LATEST_SCAN",
      tabId: tab.id
    }, (response) => {
      if (response && response.scanResult) {
        currentTabScan = response.scanResult;
        renderReportDetails(currentTabScan);
      } else {
        // If not cached, trigger a manual scan immediately to resolve it
        activeDomain.textContent = currentTabDomain;
        recommendationText.textContent = "Initiating real-time scan...";
        
        chrome.runtime.sendMessage({
          type: "RUN_MANUAL_SCAN",
          tabId: tab.id,
          url: tab.url
        }, (manualResponse) => {
          if (manualResponse && manualResponse.scanResult) {
            currentTabScan = manualResponse.scanResult;
            renderReportDetails(currentTabScan);
          } else {
            recommendationText.textContent = "Scan complete. Waiting for threat report...";
          }
        });
      }
    });
  });
}

function renderReportDetails(scan) {
  activeDomain.textContent = scan.domain;
  
  // Score & Rating
  setRadialScore(scan.riskScore, scan.riskCategory);
  riskBadge.textContent = scan.riskCategory;
  riskBadge.className = `risk-badge badge-${scan.riskCategory.toLowerCase()}`;

  // Stat Items
  statSsl.textContent = scan.modules.ssl.score >= 50 ? "Insecure HTTP" : "Secure HTTPS";
  
  const ageReason = scan.modules.whois.reason || "";
  statAge.textContent = ageReason.includes("Young") || ageReason.includes("Newly") ? "Recent" : "Established";
  
  statBrand.textContent = scan.modules.brandImpersonation.score >= 50 ? "Spoof Detected" : "None";
  statThreats.textContent = `${scan.threats.length} Flag(s)`;

  // Recommendation Card styling
  recommendationBox.className = `recommendation-box card-${scan.riskScore >= 70 ? 'danger' : (scan.riskScore >= 40 ? 'warning' : 'safe')}`;
  recommendationText.textContent = scan.recommendation;

  // Threats listing
  if (scan.threats.length > 0) {
    threatListContainer.classList.remove("hidden");
    threatList.innerHTML = scan.threats.map(threat => `
      <div class="threat-item">
        <span class="threat-dot">⚡</span>
        <div>
          <span class="threat-name">${threat.module}:</span>
          <span class="threat-desc">${threat.reason}</span>
        </div>
      </div>
    `).join("");
  } else {
    threatListContainer.classList.add("hidden");
  }
}

/**
 * Handles toggling site whitelist credentials.
 */
async function toggleWhitelist() {
  if (!currentTabDomain) return;
  const isWhitelisted = await storage.isWhitelisted(currentTabDomain);
  
  if (isWhitelisted) {
    await storage.removeFromWhitelist(currentTabDomain);
    btnWhitelist.textContent = "Trust Site";
  } else {
    await storage.addToWhitelist(currentTabDomain);
    btnWhitelist.textContent = "Untrust Site";
  }

  // Refresh status
  loadTabScanReport();
}

/**
 * Switch Navigation Panel Views.
 */
function showPanel(panel) {
  [panelDashboard, panelSettings, panelHistory].forEach(p => p.classList.remove("active"));
  panel.classList.add("active");

  if (panel === panelHistory) {
    renderHistoryList();
  } else if (panel === panelSettings) {
    loadSettingsInputs();
  }
}

/**
 * populates the settings toggles from storage.
 */
async function loadSettingsInputs() {
  const settings = await storage.getSettings();
  document.getElementById("setting-ai").checked = settings.enableAI;
  document.getElementById("setting-whois").checked = settings.enableWhois;
  document.getElementById("setting-js").checked = settings.enableJSAnalysis;
  document.getElementById("setting-notifications").checked = settings.enableNotifications;
  document.getElementById("setting-dark").checked = settings.darkMode;
}

/**
 * Binds setting form controls to storage updates.
 */
function bindSettingsEvents() {
  const update = () => {
    storage.updateSettings({
      enableAI: document.getElementById("setting-ai").checked,
      enableWhois: document.getElementById("setting-whois").checked,
      enableJSAnalysis: document.getElementById("setting-js").checked,
      enableNotifications: document.getElementById("setting-notifications").checked,
      darkMode: document.getElementById("setting-dark").checked
    });
  };

  ["setting-ai", "setting-whois", "setting-js", "setting-notifications", "setting-dark"].forEach(id => {
    document.getElementById(id).addEventListener("change", update);
  });
}

/**
 * Renders history logs panel list.
 */
async function renderHistoryList() {
  const logs = await storage.getHistory();
  if (logs.length === 0) {
    historyList.innerHTML = `<div class="history-empty">No scanned pages logged yet.</div>`;
    return;
  }

  historyList.innerHTML = logs.map(log => {
    let ratingColor = "badge-safe";
    if (log.riskCategory === "CRITICAL") ratingColor = "badge-critical";
    else if (log.riskCategory === "HIGH") ratingColor = "badge-high";
    else if (log.riskCategory === "MEDIUM") ratingColor = "badge-medium";
    else if (log.riskCategory === "LOW") ratingColor = "badge-low";

    const date = new Date(log.scannedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    return `
      <div class="history-item">
        <div class="history-item-details">
          <span class="history-domain" title="${log.url}">${log.domain}</span>
          <span class="history-meta">${date} • ${log.threats.length} threat(s)</span>
        </div>
        <span class="history-badge ${ratingColor}">${log.riskScore}%</span>
      </div>
    `;
  }).join("");
}

/**
 * Exports Threat scan report file generation download helper.
 */
async function exportLogs(format) {
  const logs = await storage.getHistory();
  if (logs.length === 0) {
    alert("No log data available to export.");
    return;
  }

  let fileContent = "";
  let mimeType = "text/plain";
  let filename = `phishshield_export_${Date.now()}`;

  if (format === "JSON") {
    fileContent = JSON.stringify(logs, null, 2);
    mimeType = "application/json";
    filename += ".json";
  } 
  
  else if (format === "CSV") {
    mimeType = "text/csv";
    filename += ".csv";
    const headers = ["Timestamp", "Domain", "Risk Score", "Risk Level", "Threats Triggered"];
    const rows = logs.map(log => [
      log.scannedAt,
      log.domain,
      log.riskScore,
      log.riskCategory,
      log.threats.map(t => t.module).join(" | ")
    ]);
    fileContent = [headers.join(","), ...rows.map(r => r.map(cell => `"${cell}"`).join(","))].join("\n");
  } 
  
  else if (format === "TXT") {
    fileContent = logs.map(log => `
========================================
DOMAIN: ${log.domain}
SCORE: ${log.riskScore}% (${log.riskCategory})
TIMESTAMP: ${log.scannedAt}
THREATS DETECTED:
${log.threats.map(t => `  - [${t.module}] ${t.reason}`).join("\n") || "  None"}
RECOMMENDATION: ${log.recommendation}
========================================
`).join("\n");
    filename += ".txt";
  }

  // Create local anchor download trigger
  const blob = new Blob([fileContent], { type: mimeType });
  const downloadUrl = URL.createObjectURL(blob);
  
  const tempLink = document.createElement("a");
  tempLink.href = downloadUrl;
  tempLink.download = filename;
  document.body.appendChild(tempLink);
  tempLink.click();
  document.body.removeChild(tempLink);
  URL.revokeObjectURL(downloadUrl);
  
  exportDropdown.classList.add("hidden");
}

// Bind navigation actions
btnSettings.addEventListener("click", () => showPanel(panelSettings));
btnBackSettings.addEventListener("click", () => showPanel(panelDashboard));
btnHistory.addEventListener("click", () => showPanel(panelHistory));
btnBackHistory.addEventListener("click", () => showPanel(panelDashboard));

btnWhitelist.addEventListener("click", toggleWhitelist);

btnClearHistory.addEventListener("click", async () => {
  if (confirm("Are you sure you want to clear the entire threat log history?")) {
    await storage.clearHistory();
    renderHistoryList();
  }
});

btnExport.addEventListener("click", (e) => {
  e.stopPropagation();
  exportDropdown.classList.toggle("hidden");
});

document.addEventListener("click", () => {
  exportDropdown.classList.add("hidden");
});

document.getElementById("export-json").addEventListener("click", () => exportLogs("JSON"));
document.getElementById("export-csv").addEventListener("click", () => exportLogs("CSV"));
document.getElementById("export-txt").addEventListener("click", () => exportLogs("TXT"));

// Listen for background scan updates reactively
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SCAN_COMPLETE") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs || tabs.length === 0) return;
      const tab = tabs[0];
      if (message.tabId === tab.id && message.scanResult) {
        currentTabScan = message.scanResult;
        renderReportDetails(currentTabScan);
      }
    });
  }
});

// Startup execution
document.addEventListener("DOMContentLoaded", () => {
  loadTabScanReport();
  bindSettingsEvents();
});
