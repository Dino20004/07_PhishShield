/**
 * PhishShield AI Threat Engine Test Suite
 * Purpose: Verifies Levenshtein distances, Jaro-Winkler similarities, Unicode homograph checks,
 * brand impersonations, DOM vulnerability scanning rules, and weighted AI score aggregation.
 */

import test from 'node:test';
import assert from 'node:assert';

import { 
  getLevenshteinDistance, 
  getJaroWinkler, 
  getNgramSimilarity, 
  isHomographAttack, 
  normalizeUnicode,
  getRegisteredDomain,
  parseUrl
} from '../src/utils.js';

import { AIRiskEngine } from '../src/engine.js';

// 1. Core Utilities & String Similarity Algorithms
test('String Similarity - Levenshtein Distance', () => {
  assert.strictEqual(getLevenshteinDistance("google", "google"), 0);
  assert.strictEqual(getLevenshteinDistance("gogle", "google"), 1);
  assert.strictEqual(getLevenshteinDistance("faceb00k", "facebook"), 2);
  assert.strictEqual(getLevenshteinDistance("apple", "aple"), 1);
});

test('String Similarity - Jaro-Winkler', () => {
  // Exact match
  assert.strictEqual(getJaroWinkler("facebook", "facebook"), 1.0);
  
  // Similar match
  const similarity = getJaroWinkler("faceb00k", "facebook");
  assert.ok(similarity > 0.85 && similarity < 1.0);
  
  // Entirely different
  assert.ok(getJaroWinkler("apple", "microsoft") < 0.5);
});

test('String Similarity - Character N-grams Jaccard', () => {
  const sim = getNgramSimilarity("google", "gogle", 2);
  assert.ok(sim > 0.5);
});

test('Unicode Spoofing - Homograph Attack Detector', () => {
  // ASCII normal domain
  assert.strictEqual(isHomographAttack("google.com"), false);
  
  // Punycode representation
  assert.strictEqual(isHomographAttack("xn--ggle-c60a.com"), true);

  // Mixed scripts (Cyrillic 'а' + Latin characters)
  const spoofedApple = "\u0430pple.com"; // "аpple.com"
  assert.strictEqual(isHomographAttack(spoofedApple), true);
  
  // Confusable Normalization
  assert.strictEqual(normalizeUnicode("\u0430"), "a");
});

test('URL Processing - Registered Domain Extractor', () => {
  assert.strictEqual(getRegisteredDomain("accounts.google.com"), "google.com");
  assert.strictEqual(getRegisteredDomain("security.update.chase.com"), "chase.com");
  assert.strictEqual(getRegisteredDomain("login.paypal.co.uk"), "paypal.co.uk");
  assert.strictEqual(getRegisteredDomain("my-site.net.au"), "my-site.net.au");
});

// 2. Individual Module Rules inside Threat Engine
test('Threat Detection - URL Analyzer (Typosquatting & IP)', async () => {
  // Safe URL
  const report1 = await AIRiskEngine.scan("https://google.com", null, null, null, null, null, true);
  assert.strictEqual(report1.riskScore, 0); // Whitelisted by default
  assert.strictEqual(report1.riskCategory, "SAFE");

  // Suspicious typosquatting domain
  const report2 = await AIRiskEngine.scan("https://google-login-security.net", null, null, null, null, null, true);
  assert.ok(report2.riskScore >= 70);
  assert.ok(report2.riskCategory === "HIGH" || report2.riskCategory === "CRITICAL");
  assert.ok(report2.threats.some(t => t.module === "URL Analysis"));

  // IP Hostname
  const report3 = await AIRiskEngine.scan("http://192.168.1.100/login", null, null, null, null, null, true);
  assert.ok(report3.riskScore >= 70);
  assert.ok(report3.threats.some(t => t.reason.includes("IP address")));
});

test('Threat Detection - Brand Impersonation', async () => {
  // Impersonating google in title on a non-google domain
  const domMetadata = {
    title: "Google Login - Sign in",
    description: "Access your account",
    totalPasswordsCount: 1,
    hiddenPasswordsCount: 0,
    formsCount: 1,
    loginFormsCount: 1,
    hiddenFormsCount: 0,
    hasFormActionMismatch: false,
    hasInsecureFormAction: false
  };

  const report = await AIRiskEngine.scan("https://secure-login-portal.net", domMetadata, null, null, null, null, true);
  assert.ok(report.riskScore >= 80);
  assert.ok(report.threats.some(t => t.module === "Brand Impersonation"));
});

test('Threat Detection - DOM Scanning Vulnerabilities', async () => {
  // Form targets external domain and contains invisible passwords
  const domMetadata = {
    title: "Secure Portal",
    description: "Login panel",
    totalPasswordsCount: 2,
    hiddenPasswordsCount: 1, // Invisible credential capture
    formsCount: 1,
    loginFormsCount: 1,
    hiddenFormsCount: 0,
    hasFormActionMismatch: true, // Targets mismatched domain
    hasInsecureFormAction: true
  };

  const report = await AIRiskEngine.scan("https://local-domain.com", domMetadata, null, null, null, null, true);
  assert.ok(report.riskScore >= 20);
  assert.ok(report.threats.some(t => t.module === "DOM Scanner"));
});

test('Threat Detection - Dangerous JS signatures', async () => {
  const domMetadata = {
    title: "Page Title",
    description: "Description",
    totalPasswordsCount: 0,
    hiddenPasswordsCount: 0,
    formsCount: 0,
    loginFormsCount: 0,
    hiddenFormsCount: 0,
    jsDetections: {
      hasObfuscation: true,
      hasEvalAndWrite: true,
      hasClipboardSteal: false,
      hasKeylogger: true, // Serious flag
      hasCookieSteal: false
    }
  };

  const report = await AIRiskEngine.scan("https://some-site.org", domMetadata, null, null, null, null, true);
  assert.ok(report.riskScore >= 20);
  assert.ok(report.threats.some(t => t.module === "JavaScript Threat Detection"));
});

test('Threat Detection - Redirects, Downloads & Notifications', async () => {
  // Heavy redirect hops + shorteners
  const redirectInfo = {
    chainCount: 4,
    usesShortener: true,
    hasMetaRefresh: false
  };

  const reportRedirects = await AIRiskEngine.scan("https://short.ly/xyz", null, redirectInfo, null, null, null, true);
  assert.ok(reportRedirects.riskScore >= 30);
  assert.ok(reportRedirects.threats.some(t => t.module === "Redirect Analysis"));

  // Drive-by script download triggers
  const downloadInfo = {
    filename: "update_patch.vbs"
  };

  const reportDownloads = await AIRiskEngine.scan("https://update-server.com", null, null, downloadInfo, null, null, true);
  assert.ok(reportDownloads.riskScore >= 40);
  assert.ok(reportDownloads.threats.some(t => t.module === "Download Protection"));
});
