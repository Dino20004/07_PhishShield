/**
 * PhishShield AI Configuration File
 * Purpose: Defines default settings, brand definitions, threat dictionaries, and scoring weights.
 */

export const DEFAULT_SETTINGS = {
  enableAI: true,
  enableWhois: false,
  enableSafeBrowsing: false,
  enableJSAnalysis: true,
  enableNotifications: true,
  darkMode: true,
  maxHistory: 500,
  highRiskThreshold: 70,
  mediumRiskThreshold: 40
};

export const RISK_WEIGHTS = {
  typosquatting: 20,
  brandImpersonation: 20,
  whois: 15,
  ssl: 15,
  dom: 15,
  javascript: 10,
  redirects: 10,
  downloads: 5,
  notifications: 5
};

export const BRAND_DICTIONARY = {
  google: {
    domains: ["google.com", "google.co.in", "gmail.com", "accounts.google.com", "google.net", "youtube.com"],
    keywords: ["google", "gmail", "youtube"]
  },
  microsoft: {
    domains: ["microsoft.com", "live.com", "outlook.com", "office.com", "login.microsoftonline.com", "microsoftonline.com", "sharepoint.com"],
    keywords: ["microsoft", "outlook", "office365", "sharepoint", "livemail"]
  },
  apple: {
    domains: ["apple.com", "icloud.com", "apple-support.com"],
    keywords: ["apple", "icloud", "itunes"]
  },
  amazon: {
    domains: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "amazon.ca", "aws.amazon.com"],
    keywords: ["amazon", "aws"]
  },
  facebook: {
    domains: ["facebook.com", "fb.com", "messenger.com"],
    keywords: ["facebook", "messenger"]
  },
  instagram: {
    domains: ["instagram.com"],
    keywords: ["instagram"]
  },
  paypal: {
    domains: ["paypal.com", "paypal.me"],
    keywords: ["paypal"]
  },
  github: {
    domains: ["github.com", "github.io"],
    keywords: ["github"]
  },
  linkedin: {
    domains: ["linkedin.com"],
    keywords: ["linkedin"]
  },
  netflix: {
    domains: ["netflix.com"],
    keywords: ["netflix"]
  },
  discord: {
    domains: ["discord.com", "discord.gg", "discordapp.com"],
    keywords: ["discord"]
  },
  steam: {
    domains: ["steampowered.com", "steamcommunity.com"],
    keywords: ["steamcommunity", "steampowered", "steam"]
  },
  x: {
    domains: ["x.com", "twitter.com"],
    keywords: ["twitter", "x-corp"]
  },
  chase: {
    domains: ["chase.com"],
    keywords: ["chasebank", "chase-security"]
  },
  wellsfargo: {
    domains: ["wellsfargo.com"],
    keywords: ["wellsfargo"]
  },
  bankofamerica: {
    domains: ["bankofamerica.com"],
    keywords: ["bankofamerica", "bofamobile"]
  }
};

export const SUSPICIOUS_TLDS = [
  "zip", "mov", "cc", "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club",
  "work", "ru", "click", "link", "info", "su", "bid", "stream", "date",
  "download", "loan", "men", "party", "science", "trade", "win"
];

export const SUSPICIOUS_KEYWORDS = [
  "login", "secure", "verify", "account", "update", "banking", "signin",
  "support", "security", "wallet", "claim", "gift", "free", "credential",
  "password", "recovery", "billing", "invoice", "authorize"
];
