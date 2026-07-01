/**
 * PhishShield AI Storage Wrapper
 * Purpose: Provides a standard interface for local data persistence using chrome.storage.local, with memory fallbacks for testing.
 */

import { DEFAULT_SETTINGS } from "./config.js";
import { logger } from "./utils.js";

const isExtensionEnv = typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local;

// Static hardcoded global whitelist for highly famous, safe brands to guarantee zero false positives
const STATIC_GLOBAL_WHITELIST = [
  "google.com", "google.co.in", "gmail.com", "accounts.google.com", "youtube.com", "www.youtube.com",
  "microsoft.com", "live.com", "outlook.com", "office.com", "login.microsoftonline.com",
  "apple.com", "icloud.com",
  "chatgpt.com", "openai.com",
  "whatsapp.com", "web.whatsapp.com",
  "github.com", "wikipedia.org", "x.com", "twitter.com", "facebook.com", "instagram.com", "linkedin.com", "netflix.com", "amazon.com", "zoom.us", "paypal.com", "discord.com"
];

const mockStorage = {
  settings: { ...DEFAULT_SETTINGS },
  history: [],
  whitelist: [...STATIC_GLOBAL_WHITELIST],
  blacklist: [],
  ignoredWarnings: []
};

function getStorageKey(key) {
  return new Promise((resolve) => {
    if (isExtensionEnv) {
      chrome.storage.local.get([key], (result) => {
        resolve(result[key]);
      });
    } else {
      resolve(mockStorage[key]);
    }
  });
}

function setStorageKey(key, value) {
  return new Promise((resolve) => {
    if (isExtensionEnv) {
      chrome.storage.local.set({ [key]: value }, () => {
        resolve(true);
      });
    } else {
      mockStorage[key] = value;
      resolve(true);
    }
  });
}

export const storage = {
  /**
   * Retrieves active extension settings.
   */
  async getSettings() {
    let settings = await getStorageKey("settings");
    if (!settings) {
      settings = { ...DEFAULT_SETTINGS };
      await setStorageKey("settings", settings);
    }
    return settings;
  },

  /**
   * Updates current configuration settings.
   */
  async updateSettings(newSettings) {
    const current = await this.getSettings();
    const updated = { ...current, ...newSettings };
    await setStorageKey("settings", updated);
    logger.info("Settings updated:", updated);
    return updated;
  },

  /**
   * Retrieves scan history list.
   */
  async getHistory() {
    const hist = await getStorageKey("history");
    return hist || [];
  },

  /**
   * Adds a new scan log entry.
   */
  async saveScan(scan) {
    const history = await this.getHistory();
    const settings = await this.getSettings();
    
    // Add timestamp if missing
    if (!scan.timestamp) {
      scan.timestamp = new Date().toISOString();
    }
    
    // Prevent duplicates in short history - insert at start
    const cleanHistory = history.filter(item => item.domain !== scan.domain);
    cleanHistory.unshift(scan);
    
    const limit = settings.maxHistory || 500;
    if (cleanHistory.length > limit) {
      cleanHistory.pop();
    }
    
    await setStorageKey("history", cleanHistory);
    logger.info(`Scan saved for ${scan.domain}. Threat level: ${scan.riskCategory} (${scan.riskScore})`);
  },

  /**
   * Clears all scan history.
   */
  async clearHistory() {
    await setStorageKey("history", []);
    logger.info("Scan history cleared.");
  },

  /**
   * Retrieves user whitelisted domains.
   */
  async getWhitelist() {
    let list = await getStorageKey("whitelist");
    if (!list) {
      list = [...mockStorage.whitelist];
      await setStorageKey("whitelist", list);
    } else {
      // Self-healing check: Merge new default trusted domains automatically
      let changed = false;
      mockStorage.whitelist.forEach(domain => {
        if (!list.includes(domain)) {
          list.push(domain);
          changed = true;
        }
      });
      if (changed) {
        await setStorageKey("whitelist", list);
      }
    }
    return list;
  },

  /**
   * Adds domain to trusted whitelist.
   */
  async addToWhitelist(domain) {
    const list = await this.getWhitelist();
    const normalized = domain.toLowerCase().trim();
    if (!list.includes(normalized)) {
      list.push(normalized);
      await setStorageKey("whitelist", list);
      logger.info(`Added to whitelist: ${normalized}`);
    }
  },

  /**
   * Removes domain from trusted whitelist.
   */
  async removeFromWhitelist(domain) {
    const list = await this.getWhitelist();
    const normalized = domain.toLowerCase().trim();
    const updated = list.filter(item => item !== normalized);
    await setStorageKey("whitelist", updated);
    logger.info(`Removed from whitelist: ${normalized}`);
  },

  /**
   * Retrieves user blacklisted domains.
   */
  async getBlacklist() {
    const list = await getStorageKey("blacklist");
    return list || [];
  },

  /**
   * Adds domain to untrusted blacklist.
   */
  async addToBlacklist(domain) {
    const list = await this.getBlacklist();
    const normalized = domain.toLowerCase().trim();
    if (!list.includes(normalized)) {
      list.push(normalized);
      await setStorageKey("blacklist", list);
      logger.info(`Added to blacklist: ${normalized}`);
    }
  },

  /**
   * Removes domain from untrusted blacklist.
   */
  async removeFromBlacklist(domain) {
    const list = await this.getBlacklist();
    const normalized = domain.toLowerCase().trim();
    const updated = list.filter(item => item !== normalized);
    await setStorageKey("blacklist", updated);
    logger.info(`Removed from blacklist: ${normalized}`);
  },

  /**
   * Retrieves warning ignored list.
   */
  async getIgnoredWarnings() {
    const list = await getStorageKey("ignoredWarnings");
    return list || [];
  },

  /**
   * Adds warning ignore list.
   */
  async addIgnoredWarning(domain) {
    const list = await this.getIgnoredWarnings();
    const normalized = domain.toLowerCase().trim();
    if (!list.includes(normalized)) {
      list.push(normalized);
      await setStorageKey("ignoredWarnings", list);
      logger.info(`Added to ignored warnings: ${normalized}`);
    }
  },

  /**
   * Verification checks.
   */
  async isWhitelisted(domain) {
    if (!domain || typeof domain !== 'string') return false;
    const normalized = domain.toLowerCase().trim();
    
    // Check static global whitelist first (bypasses database lag/corruption completely)
    const isStaticTrusted = STATIC_GLOBAL_WHITELIST.some(item => 
      normalized === item || normalized.endsWith("." + item)
    );
    if (isStaticTrusted) {
      return true;
    }

    // Fallback to user database whitelist
    const list = await this.getWhitelist();
    return list.some(item => normalized === item || normalized.endsWith("." + item));
  },

  async isBlacklisted(domain) {
    if (!domain || typeof domain !== 'string') return false;
    const list = await this.getBlacklist();
    const normalized = domain.toLowerCase().trim();
    return list.some(item => normalized === item || normalized.endsWith("." + item));
  },

  async isIgnored(domain) {
    if (!domain || typeof domain !== 'string') return false;
    const list = await this.getIgnoredWarnings();
    const normalized = domain.toLowerCase().trim();
    return list.some(item => normalized === item || normalized.endsWith("." + item));
  }
};
