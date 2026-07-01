/**
 * PhishShield AI Threat Detection Engine
 * Purpose: Contains all 11 core threat detection modules and aggregates their results via a weighted AI risk engine.
 */

import { RISK_WEIGHTS, BRAND_DICTIONARY, SUSPICIOUS_TLDS, SUSPICIOUS_KEYWORDS } from "./config.js";
import { 
  getJaroWinkler, 
  getLevenshteinDistance, 
  getNgramSimilarity, 
  isHomographAttack, 
  normalizeUnicode, 
  getRegisteredDomain,
  parseUrl,
  logger 
} from "./utils.js";

/**
 * Module 1: URL Similarity Analysis
 */
class URLAnalyzer {
  static analyze(urlObj) {
    const hostname = urlObj.hostname;
    let score = 0;
    let confidence = 0.8;
    const reasons = [];

    // 1. IP address check
    const ipPattern = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (ipPattern.test(hostname)) {
      score = 80;
      reasons.push("Hostname is a raw IP address (common in phishing campaigns)");
    }

    // 2. TLD check
    const parts = hostname.split('.');
    const tld = parts[parts.length - 1];
    if (SUSPICIOUS_TLDS.includes(tld)) {
      score = Math.max(score, 40);
      reasons.push(`Uses highly suspicious Top-Level Domain (TLD): .${tld}`);
    }

    // 3. Subdomain count check
    if (parts.length > 4) {
      score = Math.max(score, 50);
      reasons.push(`Excessive subdomains (${parts.length - 2} levels) attempting to obfuscate target host`);
    }

    // 4. Keyword presence check
    const matches = SUSPICIOUS_KEYWORDS.filter(keyword => hostname.includes(keyword));
    if (matches.length > 0) {
      score = Math.max(score, 30 + matches.length * 15);
      reasons.push(`Domain contains phishing keywords: ${matches.join(", ")}`);
    }

    // 5. Typosquatting checks (Levenshtein, Jaro-Winkler, Character Frequency, N-grams)
    const sld = getRegisteredDomain(hostname).split('.')[0];
    for (const [brand, brandData] of Object.entries(BRAND_DICTIONARY)) {
      for (const keyword of brandData.keywords) {
        if (sld === keyword) continue; // Exact brand subdomain/legitimate SLD
        
        // Combosquatting / brand spoofing check: keyword inclusion in SLD
        if (sld.includes(keyword)) {
          score = Math.max(score, 85);
          confidence = 0.9;
          reasons.push(`Contains registered trademark '${keyword}' combined with other terms (brand spoofing indicator)`);
          continue;
        }

        // Calculate similarity distances
        const jw = getJaroWinkler(sld, keyword);
        const lev = getLevenshteinDistance(sld, keyword);
        const ngram = getNgramSimilarity(sld, keyword, 2);

        // Flag potential typosquats
        if (jw > 0.82 && lev <= 3) {
          score = Math.max(score, 90);
          confidence = 0.95;
          reasons.push(`Typosquatting detected: '${sld}' mimics legitimate brand trademark '${keyword}' (Similarity: ${Math.round(jw * 100)}%)`);
        } else if (ngram > 0.6 && lev <= 4) {
          score = Math.max(score, 70);
          confidence = 0.85;
          reasons.push(`N-gram character match suggests typosquatting of '${keyword}'`);
        }
      }
    }

    return {
      name: "URL Analysis",
      score: Math.min(score, 100),
      confidence,
      reason: reasons.join("; ") || "URL looks structurally normal"
    };
  }
}

/**
 * Module 2: Homograph Detection
 */
class HomographDetector {
  static analyze(urlObj) {
    const hostname = urlObj.hostname;
    let score = 0;
    let confidence = 0.9;
    const reasons = [];

    if (isHomographAttack(hostname)) {
      score = 95;
      confidence = 0.98;
      const normalized = normalizeUnicode(hostname);
      reasons.push(`Internationalized Homograph Attack (Unicode spoofing) mimicking: ${normalized}`);
    }

    return {
      name: "Homograph Detection",
      score,
      confidence,
      reason: reasons.join("; ") || "No Unicode homograph spoofing detected"
    };
  }
}

/**
 * Module 3: WHOIS / Domain Age Analyzer (uses RDAP client lookup)
 */
class DomainAgeAnalyzer {
  static async analyze(urlObj, bypassRDAP = false) {
    const registeredDomain = getRegisteredDomain(urlObj.hostname);
    let score = 0;
    let confidence = 0.7;
    const reasons = [];

    // Bypass RDAP query for test scripts / offline execution
    if (bypassRDAP || !registeredDomain || registeredDomain.includes("localhost") || registeredDomain.includes("127.0.0.1")) {
      return {
        name: "Domain Reputation",
        score: 0,
        confidence: 0.5,
        reason: "Offline scanning or localhost domain"
      };
    }

    try {
      // Direct call to public RDAP service
      const response = await fetch(`https://rdap.org/domain/${registeredDomain}`, { signal: AbortSignal.timeout(3000) });
      if (response.ok) {
        const data = await response.json();
        const events = data.events || [];
        const registrationEvent = events.find(e => e.action === 'registration' || e.action === 'creation');
        
        if (registrationEvent && registrationEvent.eventDate) {
          const creationDate = new Date(registrationEvent.eventDate);
          const ageDays = Math.floor((new Date() - creationDate) / (1000 * 60 * 60 * 24));
          
          if (ageDays < 30) {
            score = 90;
            reasons.push(`Newly registered domain: created only ${ageDays} days ago (${creationDate.toLocaleDateString()})`);
          } else if (ageDays < 90) {
            score = 60;
            reasons.push(`Young domain: created ${ageDays} days ago`);
          } else {
            score = 0;
            reasons.push(`Established domain: registered ${ageDays} days ago`);
          }
          confidence = 0.95;
        } else {
          score = 30;
          reasons.push("RDAP details retrieved, but creation date was missing");
        }
      } else {
        // Fallback for failed RDAP registry lookups
        score = 0;
        reasons.push("RDAP domain lookup timed out or domain registry not supported");
      }
    } catch (e) {
      score = 0;
      reasons.push(`Reputation scan bypassed: ${e.message}`);
    }

    return {
      name: "Domain Age & Reputation",
      score,
      confidence,
      reason: reasons.join("; ")
    };
  }
}

/**
 * Module 4: SSL Inspection
 */
class SSLAnalyzer {
  static analyze(urlObj, connectionInfo) {
    let score = 0;
    let confidence = 0.85;
    const reasons = [];

    if (urlObj.protocol === "http:") {
      score = 75;
      reasons.push("Insecure HTTP protocol used - credentials sent over this page can be intercepted");
    } else if (urlObj.protocol === "https:") {
      // Inspect browser-provided certificate state if supplied
      if (connectionInfo) {
        if (connectionInfo.expired) {
          score = 80;
          reasons.push("HTTPS certificate is expired");
        } else if (connectionInfo.selfSigned) {
          score = 70;
          reasons.push("Self-signed SSL certificate detected (untrusted)");
        } else if (connectionInfo.weakCipher) {
          score = 40;
          reasons.push("SSL uses weak encryption protocol (TLS 1.0/1.1)");
        }
      }
    }

    return {
      name: "SSL Security",
      score,
      confidence,
      reason: reasons.join("; ") || "Secure HTTPS connection established"
    };
  }
}

/**
 * Module 5: Brand Impersonation
 */
class BrandDetector {
  static analyze(urlObj, domMetadata) {
    let score = 0;
    let confidence = 0.9;
    const reasons = [];
    
    if (!domMetadata) {
      return { name: "Brand Impersonation", score: 0, confidence: 0.5, reason: "No DOM metadata collected" };
    }

    const title = (domMetadata.title || "").toLowerCase();
    const metaDesc = (domMetadata.description || "").toLowerCase();
    const hostname = urlObj.hostname;

    for (const [brandName, brandData] of Object.entries(BRAND_DICTIONARY)) {
      // If the current domain is legitimately owned by the brand, skip impersonation logic
      const isLegit = brandData.domains.some(domain => hostname === domain || hostname.endsWith("." + domain));
      if (isLegit) continue;

      // Check if title or meta metadata mentions brand keyword
      const mentionsBrand = brandData.keywords.some(keyword => {
        const regex = new RegExp(`\\b${keyword}\\b`, 'i');
        return regex.test(title) || regex.test(metaDesc);
      });

      if (mentionsBrand) {
        // If they use standard login keywords (e.g. "sign in", "login", "password") alongside the brand
        const isLoginPage = /sign\s*in|log\s*in|account|portal|secure|verify/i.test(title);
        if (isLoginPage) {
          score = 95;
          confidence = 0.95;
          reasons.push(`Brand Spoofing: Page claims to be a '${brandName}' portal, but hosting domain is not owned by the brand`);
        } else {
          score = Math.max(score, 60);
          reasons.push(`Suspicious brand reference: Page mentions '${brandName}' brand but operates on an unrelated domain`);
        }
      }
    }

    return {
      name: "Brand Impersonation",
      score,
      confidence,
      reason: reasons.join("; ") || "No brand impersonation signatures detected"
    };
  }
}

/**
 * Module 6: DOM Analysis
 */
class DOMAnalyzer {
  static analyze(domMetadata) {
    let score = 0;
    let confidence = 0.8;
    const reasons = [];

    if (!domMetadata) {
      return { name: "DOM Threat Scanner", score: 0, confidence: 0.5, reason: "No DOM structures collected" };
    }

    // 1. Invisible password fields
    if (domMetadata.hiddenPasswordsCount > 0) {
      score = Math.max(score, 35);
      reasons.push("Invisible password inputs detected (signature of hidden credential harvesting scripts)");
    }

    // 2. Hidden forms
    if (domMetadata.hiddenFormsCount > 0) {
      score = Math.max(score, 20);
      reasons.push("Hidden forms detected on page");
    }

    // 3. Form action mismatch
    if (domMetadata.hasFormActionMismatch) {
      score = Math.max(score, 45);
      confidence = 0.9;
      reasons.push("Form submission targets a different external domain than the host page");
    }

    // 4. Insecure form actions on HTTPS page
    if (domMetadata.hasInsecureFormAction) {
      score = Math.max(score, 40);
      reasons.push("Insecure (HTTP) form submission handler configured on secure page");
    }

    // 5. Multiple login forms
    if (domMetadata.loginFormsCount > 1) {
      score = Math.max(score, 25);
      reasons.push("Multiple separate credential submit forms found on a single page");
    }

    return {
      name: "DOM Scanner",
      score,
      confidence,
      reason: reasons.join("; ") || "Page layout structures appear standard"
    };
  }
}

/**
 * Module 7: JavaScript Threat Detection
 */
class JSAnalyzer {
  static analyze(domMetadata) {
    let score = 0;
    let confidence = 0.75;
    const reasons = [];

    if (!domMetadata || !domMetadata.jsDetections) {
      return { name: "JavaScript Security", score: 0, confidence: 0.5, reason: "No Javascript analysis available" };
    }

    const detections = domMetadata.jsDetections;

    if (detections.hasObfuscation) {
      score = Math.max(score, 30);
      reasons.push("Detected large obfuscated code chunks or high-density Base64 text scripts");
    }
    if (detections.hasEvalAndWrite) {
      score = Math.max(score, 25);
      reasons.push("Javascript compiles execution dynamically via eval() or document.write()");
    }
    if (detections.hasClipboardSteal) {
      score = Math.max(score, 30);
      reasons.push("Code captures or manipulates user clipboard contents");
    }
    if (detections.hasKeylogger) {
      score = Math.max(score, 45);
      confidence = 0.9;
      reasons.push("Active keyboard monitoring listeners installed (keylogging risk)");
    }
    if (detections.hasCookieSteal) {
      score = Math.max(score, 45);
      reasons.push("Detected suspicious document.cookie exfiltration pattern");
    }

    return {
      name: "JavaScript Threat Detection",
      score,
      confidence,
      reason: reasons.join("; ") || "No malicious JavaScript behavioral signatures found"
    };
  }
}

/**
 * Module 8: Redirect Analysis
 */
class RedirectDetector {
  static analyze(redirectsData) {
    let score = 0;
    let confidence = 0.8;
    const reasons = [];

    if (!redirectsData) {
      return { name: "Redirect Analyzer", score: 0, confidence: 0.5, reason: "No redirection info" };
    }

    // 1. Long redirect chains
    if (redirectsData.chainCount >= 3) {
      score = Math.max(score, 70);
      reasons.push(`Suspicious redirect chain detected: ${redirectsData.chainCount} hops in sequence`);
    }

    // 2. URL Shortener abuse
    if (redirectsData.usesShortener) {
      score = Math.max(score, 45);
      reasons.push("URL shortener used to hide final domain destination");
    }

    // 3. Meta Refresh redirect
    if (redirectsData.hasMetaRefresh) {
      score = Math.max(score, 50);
      reasons.push("Automatic navigation triggered via Meta Refresh tags");
    }

    return {
      name: "Redirect Analysis",
      score,
      confidence,
      reason: reasons.join("; ") || "No abnormal navigation paths identified"
    };
  }
}

/**
 * Module 9: Download Protection
 */
class DownloadDetector {
  static analyze(downloadTriggered) {
    let score = 0;
    let confidence = 0.9;
    const reasons = [];

    if (downloadTriggered) {
      const filename = downloadTriggered.filename || "";
      const ext = filename.split('.').pop().toLowerCase();
      const dangerousExtensions = ["exe", "bat", "js", "vbs", "iso", "scr", "cmd", "ps1"];
      const archiveExtensions = ["zip", "rar", "7z", "tar", "gz"];

      if (dangerousExtensions.includes(ext)) {
        score = 90;
        reasons.push(`Drive-by Download: Page attempted an automatic download of dangerous script/binary file: .${ext}`);
      } else if (archiveExtensions.includes(ext)) {
        score = 65;
        reasons.push("Automatic download of archive files (.zip/rar) detected");
      }
    }

    return {
      name: "Download Protection",
      score,
      confidence,
      reason: reasons.join("; ") || "No dangerous file downloads intercepted"
    };
  }
}

/**
 * Module 10: Notification Abuse Detection
 */
class NotificationDetector {
  static analyze(notificationPrompt) {
    let score = 0;
    let confidence = 0.85;
    const reasons = [];

    if (notificationPrompt && notificationPrompt.promptImmediate) {
      score = 60;
      reasons.push("Website requested desktop notification permissions immediately on load (common spam indicator)");
    }

    return {
      name: "Notification Abuse Detection",
      score,
      confidence,
      reason: reasons.join("; ") || "No notification abuse signatures detected"
    };
  }
}

/**
 * Module 11: Credential Submission Protection (Evaluates form post targets)
 */
class CredentialDetector {
  static analyze(formSubmitEvent, parentScore) {
    let score = 0;
    let confidence = 0.9;
    const reasons = [];

    if (formSubmitEvent) {
      if (parentScore >= 70) {
        score = 95;
        reasons.push("User is attempting to submit password credentials to a confirmed high-risk target domain");
      } else if (parentScore >= 40) {
        score = 70;
        reasons.push("Warning: Submitting credentials to a page with suspicious security parameters");
      }
    }

    return {
      name: "Credential Protection",
      score,
      confidence,
      reason: reasons.join("; ") || "Form submissions monitored successfully"
    };
  }
}

/**
 * Module 12: Combined AI Risk Engine
 */
export class AIRiskEngine {
  /**
   * Performs an asynchronous scan on a website using metadata gathered from the content script.
   */
  static async scan(urlStr, domMetadata = null, redirectsData = null, downloadData = null, notificationData = null, connectionInfo = null, bypassRDAP = false) {
    const urlObj = parseUrl(urlStr);
    
    // Run all detection modules
    const m1 = URLAnalyzer.analyze(urlObj);
    const m2 = HomographDetector.analyze(urlObj);
    let settings = { enableWhois: false };
    try {
      settings = await storage.getSettings();
    } catch (e) {}

    const bypass = bypassRDAP || !settings.enableWhois;
    const m3 = await DomainAgeAnalyzer.analyze(urlObj, bypass);
    const m4 = SSLAnalyzer.analyze(urlObj, connectionInfo);
    const m5 = BrandDetector.analyze(urlObj, domMetadata);
    const m6 = DOMAnalyzer.analyze(domMetadata);
    const m7 = JSAnalyzer.analyze(domMetadata);
    const m8 = RedirectDetector.analyze(redirectsData);
    const m9 = DownloadDetector.analyze(downloadData);
    const m10 = NotificationDetector.analyze(notificationData);

    const modules = {
      typosquatting: m1,
      homograph: m2,
      whois: m3,
      ssl: m4,
      brandImpersonation: m5,
      dom: m6,
      javascript: m7,
      redirects: m8,
      downloads: m9,
      notifications: m10
    };

    // Calculate weighted average
    let weightedSum = 0;
    let weightSum = 0;

    for (const [key, moduleResult] of Object.entries(modules)) {
      const weight = RISK_WEIGHTS[key] || 10;
      weightedSum += moduleResult.score * weight;
      weightSum += weight;
    }

    let finalScore = weightSum > 0 ? Math.round(weightedSum / weightSum) : 0;

    // Raise final score to match the highest individual critical signal so they don't get diluted by clean modules
    const maxModuleScore = Math.max(
      m1.score, m2.score, m3.score, m4.score, m5.score, m6.score, m7.score, m8.score, m9.score, m10.score
    );
    if (maxModuleScore >= 70) {
      finalScore = Math.max(finalScore, maxModuleScore);
    } else if (maxModuleScore >= 40) {
      finalScore = Math.max(finalScore, Math.round((finalScore + maxModuleScore) / 2));
    }

    // Apply critical risk floors (AI-style logic overrides)
    // E.g. Brand Impersonation on a young domain or typosquat raises overall risk to critical instantly.
    if (m5.score >= 90 && (m1.score >= 70 || m3.score >= 60 || m2.score >= 90)) {
      finalScore = Math.max(finalScore, 95); // High confidence spoofing
    }
    
    // Whitelist check overrides score
    let whitelisted = false;
    let blacklisted = false;
    
    // In-browser check (skipped in node testing if storage lacks env)
    try {
      whitelisted = await storage.isWhitelisted(urlObj.hostname);
      blacklisted = await storage.isBlacklisted(urlObj.hostname);
    } catch(err) {
      // Fallback
    }

    if (whitelisted) {
      finalScore = 0;
    } else if (blacklisted) {
      finalScore = 100;
    }

    // Determine category rating
    let riskCategory = "SAFE";
    if (finalScore >= 85) {
      riskCategory = "CRITICAL";
    } else if (finalScore >= 70) {
      riskCategory = "HIGH";
    } else if (finalScore >= 40) {
      riskCategory = "MEDIUM";
    } else if (finalScore >= 15) {
      riskCategory = "LOW";
    }

    // Run final credential check using calculated score
    const m11 = CredentialDetector.analyze(domMetadata ? domMetadata.isSubmitting : false, finalScore);
    modules.credentials = m11;

    // Collate threat list
    const activeThreats = [];
    for (const [key, result] of Object.entries(modules)) {
      if (result.score >= 25) {
        activeThreats.push({
          module: result.name,
          score: result.score,
          reason: result.reason
        });
      }
    }

    return {
      domain: urlObj.hostname,
      url: urlObj.full,
      riskScore: finalScore,
      riskCategory,
      scannedAt: new Date().toISOString(),
      modules,
      threats: activeThreats,
      recommendation: finalScore >= 70 ? "Leave immediately. Do not submit login credentials." : (finalScore >= 40 ? "Proceed with caution. Verify URL fields closely." : "Website appears secure.")
    };
  }
}
