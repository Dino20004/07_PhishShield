/**
 * PhishShield AI Content Injection Script
 * Purpose: Scans page DOM structures, intercepts form posts, analyzes inline JS code, 
 * and draws the full-screen interactive threat warnings if a site is flagged.
 */

// Global reference for the blocking overlay DOM element
let warningOverlayElement = null;

/**
 * Gathers webpage structures and metadata for processing.
 */
function gatherDOMMetadata() {
  const title = document.title || "";
  
  // Extract meta tags
  let description = "";
  const metaDesc = document.querySelector('meta[name="description"]') || document.querySelector('meta[property="og:description"]');
  if (metaDesc) {
    description = metaDesc.getAttribute("content") || "";
  }

  // Count password elements
  const passwordInputs = Array.from(document.querySelectorAll('input[type="password"]'));
  const totalPasswords = passwordInputs.length;
  
  // Scan for invisible or suspiciously styled inputs
  let hiddenPasswords = 0;
  passwordInputs.forEach(input => {
    const style = window.getComputedStyle(input);
    if (style.display === "none" || style.visibility === "hidden" || style.opacity === "0" || 
        input.offsetWidth === 0 || input.offsetHeight === 0 || input.hasAttribute("hidden")) {
      hiddenPasswords++;
    }
  });

  // Analyze form structures
  const forms = Array.from(document.querySelectorAll('form'));
  const formsCount = forms.length;
  
  let loginFormsCount = 0;
  let hasFormActionMismatch = false;
  let hasInsecureFormAction = false;
  let hiddenFormsCount = 0;

  const currentHost = window.location.hostname;

  forms.forEach(form => {
    // Check if form contains credentials inputs
    const hasPassword = form.querySelector('input[type="password"]') !== null;
    const hasEmailOrUser = form.querySelector('input[type="email"], input[type="text"][name*="user"], input[type="text"][name*="login"]') !== null;
    if (hasPassword || hasEmailOrUser) {
      loginFormsCount++;
    }

    // Inspect visibility of forms
    const style = window.getComputedStyle(form);
    if (style.display === "none" || style.visibility === "hidden" || form.hasAttribute("hidden")) {
      hiddenFormsCount++;
    }

    // Inspect form actions
    let action = form.getAttribute("action");
    if (action) {
      action = action.trim();
      if (action.startsWith("http://") || action.startsWith("https://")) {
        try {
          const actionUrl = new URL(action);
          // 1. Domain mismatch on credential form target
          if (actionUrl.hostname !== currentHost && (hasPassword || hasEmailOrUser)) {
            hasFormActionMismatch = true;
          }
          // 2. HTTP post on HTTPS page
          if (window.location.protocol === "https:" && actionUrl.protocol === "http:") {
            hasInsecureFormAction = true;
          }
        } catch (e) {
          // Invalid URL action
        }
      }
    }
  });

  // Scan scripts for signature threats
  const jsDetections = scanJSSignatures();

  return {
    title,
    description,
    totalPasswordsCount: totalPasswords,
    hiddenPasswordsCount: hiddenPasswords,
    formsCount,
    loginFormsCount,
    hiddenFormsCount,
    hasFormActionMismatch,
    hasInsecureFormAction,
    jsDetections
  };
}

/**
 * Scans JavaScript tags and code configurations on the page.
 */
function scanJSSignatures() {
  const scripts = Array.from(document.querySelectorAll('script'));
  let hasObfuscation = false;
  let hasEvalAndWrite = false;
  let hasClipboardSteal = false;
  let hasKeylogger = false;
  let hasCookieSteal = false;

  // Base64 high density threshold regex
  const base64Regex = /([A-Za-z0-9+/]{80,})/g;

  scripts.forEach(script => {
    const content = script.textContent || "";
    
    // 1. Obfuscation indicators
    const b64Matches = content.match(base64Regex) || [];
    if (b64Matches.length > 3 || content.length > 5000 && (content.match(/\\x[0-9a-fA-F]{2}/g) || []).length > 100) {
      hasObfuscation = true;
    }

    // 2. Eval and Document.write usages
    if (content.includes("eval(") || content.includes("document.write(")) {
      hasEvalAndWrite = true;
    }

    // 3. Keystroke Logging
    if (content.includes('keydown') || content.includes('keypress') || content.includes('keyup')) {
      if (content.includes('addEventListener') && (content.includes('input') || content.includes('password'))) {
        hasKeylogger = true;
      }
    }

    // 4. Clipboard modification hooks
    if (content.includes('clipboardData') || content.includes('copy') || content.includes('paste')) {
      if (content.includes('preventDefault(') || content.includes('setData(')) {
        hasClipboardSteal = true;
      }
    }

    // 5. Cookie tracking exfiltrations
    if (content.includes('document.cookie') && (content.includes('fetch(') || content.includes('XMLHttpRequest') || content.includes('.src'))) {
      hasCookieSteal = true;
    }
  });

  return {
    hasObfuscation,
    hasEvalAndWrite,
    hasClipboardSteal,
    hasKeylogger,
    hasCookieSteal
  };
}

/**
 * Triggers full-screen Warning Overlay.
 */
function renderWarningOverlay(scanResult) {
  if (warningOverlayElement) return;

  // Create overlay wrapping element
  warningOverlayElement = document.createElement("div");
  warningOverlayElement.id = "phishshield-warning-overlay";

  // Visual threats HTML listing
  const threatListHTML = scanResult.threats.map(threat => `
    <div class="ps-threat-item">
      <span class="ps-threat-dot">⚠️</span>
      <div class="ps-threat-details">
        <span class="ps-threat-title">${threat.module}</span>
        <span class="ps-threat-reason">${threat.reason}</span>
      </div>
    </div>
  `).join("");

  // Inject UI template
  warningOverlayElement.innerHTML = `
    <style>
      #phishshield-warning-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        background: radial-gradient(circle at center, #1e0b0b 0%, #0c0202 100%);
        color: #ffffff;
        z-index: 2147483647;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        display: flex;
        align-items: center;
        justify-content: center;
        overflow-y: auto;
        padding: 20px;
        box-sizing: border-box;
      }
      .ps-card {
        background: rgba(18, 9, 9, 0.85);
        border: 1px solid rgba(239, 68, 68, 0.35);
        border-radius: 16px;
        padding: 40px;
        max-width: 600px;
        width: 100%;
        box-shadow: 0 16px 36px rgba(0, 0, 0, 0.6), 0 0 40px rgba(239, 68, 68, 0.15);
        backdrop-filter: blur(12px);
        text-align: center;
        animation: ps-fade-in 0.4s ease-out;
      }
      @keyframes ps-fade-in {
        from { opacity: 0; transform: scale(0.95); }
        to { opacity: 1; transform: scale(1); }
      }
      .ps-badge {
        display: inline-block;
        background: rgba(239, 68, 68, 0.15);
        border: 1px solid #ef4444;
        color: #ef4444;
        font-weight: 700;
        font-size: 13px;
        padding: 6px 16px;
        border-radius: 20px;
        letter-spacing: 1px;
        text-transform: uppercase;
        margin-bottom: 24px;
        animation: ps-pulse 2s infinite;
      }
      @keyframes ps-pulse {
        0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4); }
        70% { box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); }
        100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
      }
      .ps-title {
        font-size: 28px;
        font-weight: 800;
        margin-bottom: 12px;
        color: #fca5a5;
        letter-spacing: -0.5px;
      }
      .ps-subtitle {
        font-size: 15px;
        color: #cbd5e1;
        margin-bottom: 30px;
        line-height: 1.5;
      }
      .ps-host {
        background: rgba(255, 255, 255, 0.08);
        padding: 6px 14px;
        border-radius: 6px;
        font-family: monospace;
        color: #ffffff;
        font-weight: 600;
      }
      .ps-threats-container {
        text-align: left;
        background: rgba(0, 0, 0, 0.3);
        border: 1px solid rgba(255, 255, 255, 0.05);
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 30px;
        max-height: 240px;
        overflow-y: auto;
      }
      .ps-threat-item {
        display: flex;
        align-items: flex-start;
        margin-bottom: 16px;
      }
      .ps-threat-item:last-child {
        margin-bottom: 0;
      }
      .ps-threat-dot {
        margin-right: 12px;
        font-size: 16px;
        margin-top: 2px;
      }
      .ps-threat-details {
        display: flex;
        flex-direction: column;
      }
      .ps-threat-title {
        font-weight: 700;
        font-size: 14px;
        color: #f87171;
        margin-bottom: 2px;
      }
      .ps-threat-reason {
        font-size: 13px;
        color: #94a3b8;
        line-height: 1.4;
      }
      .ps-actions {
        display: flex;
        gap: 16px;
        justify-content: center;
      }
      .ps-btn {
        padding: 14px 24px;
        border-radius: 8px;
        font-size: 14px;
        font-weight: 700;
        cursor: pointer;
        transition: all 0.2s ease;
        border: none;
        outline: none;
      }
      .ps-btn-safe {
        background: #ef4444;
        color: #ffffff;
        flex-grow: 2;
        box-shadow: 0 4px 12px rgba(239, 68, 68, 0.3);
      }
      .ps-btn-safe:hover {
        background: #dc2626;
        transform: translateY(-1px);
        box-shadow: 0 6px 16px rgba(239, 68, 68, 0.4);
      }
      .ps-btn-bypass {
        background: rgba(255, 255, 255, 0.08);
        color: #cbd5e1;
        flex-grow: 1;
        border: 1px solid rgba(255, 255, 255, 0.1);
      }
      .ps-btn-bypass:hover {
        background: rgba(255, 255, 255, 0.15);
        color: #ffffff;
      }
    </style>

    <div class="ps-card">
      <div class="ps-badge">⚠️ HIGH RISK WARNING</div>
      <h1 class="ps-title">Deceptive Site Flagged</h1>
      <p class="ps-subtitle">
        PhishShield AI has blocked access to <span class="ps-host">${scanResult.domain}</span>. This page shows characteristics of a phishing scam or credential harvester.
      </p>

      <div class="ps-threats-container">
        ${threatListHTML}
      </div>

      <div class="ps-actions">
        <button id="ps-btn-exit" class="ps-btn ps-btn-safe">Get Me Out of Here</button>
        <button id="ps-btn-ignore" class="ps-btn ps-btn-bypass">Proceed Anyway</button>
      </div>
    </div>
  `;

  document.documentElement.appendChild(warningOverlayElement);

  // Exit/safe navigation action
  document.getElementById("ps-btn-exit").addEventListener("click", () => {
    window.location.href = "https://www.google.com";
  });

  // Dismiss/Bypass action
  document.getElementById("ps-btn-ignore").addEventListener("click", () => {
    chrome.runtime.sendMessage({
      type: "ADD_TO_IGNORED",
      domain: scanResult.domain
    }, () => {
      warningOverlayElement.remove();
      warningOverlayElement = null;
    });
  });
}

/**
 * Submission Hijack Guard. Prevents posting credential details to risky hosts.
 */
function initializeSubmitInterceptors() {
  document.addEventListener("submit", function(event) {
    // If the overlay is already blocking or warning bypass was flagged, allow
    if (warningOverlayElement) {
      event.preventDefault();
      return;
    }

    const form = event.target;
    // Check if it captures passwords or logins
    const hasPassword = form.querySelector('input[type="password"]') !== null;
    if (!hasPassword) return; // Only block credential submissions

    event.preventDefault(); // Pause submission

    // Query scan result
    const metadata = gatherDOMMetadata();
    metadata.isSubmitting = true;

    chrome.runtime.sendMessage({
      type: "FORM_SUBMITTING",
      url: window.location.href,
      domMetadata: metadata
    }, function(response) {
      if (response && response.action === "BLOCK") {
        renderWarningOverlay(response.scanResult);
      } else {
        // Re-submit form natively
        form.submit();
      }
    });
  }, true);
}

// Receive messages from background worker
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SHOW_WARNING_OVERLAY") {
    renderWarningOverlay(message.scanResult);
  }
});

// Run scans on layout load
function init() {
  // Let DOM stabilize slightly
  setTimeout(() => {
    const domMetadata = gatherDOMMetadata();
    chrome.runtime.sendMessage({
      type: "PAGE_LOADED",
      url: window.location.href,
      domMetadata
    });
  }, 100);
  
  initializeSubmitInterceptors();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
