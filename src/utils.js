/**
 * PhishShield AI Utility Helper Library
 * Purpose: Implements key string similarity algorithms, Unicode normalizations, URL/domain parsers, and logging configurations.
 */

// Custom confusable mapping for homograph attack detection
const CONFUSABLE_MAP = {
  // Cyrillic to Latin
  '\u0430': 'a', // Cyrillic small letter a
  '\u0440': 'p', // Cyrillic small letter er
  '\u043e': 'o', // Cyrillic small letter o
  '\u0441': 'c', // Cyrillic small letter es
  '\u0435': 'e', // Cyrillic small letter ie
  '\u0456': 'i', // Cyrillic small letter byelorussian-ukrainian i
  '\u0457': 'i', // Cyrillic small letter yi
  '\u0458': 'j', // Cyrillic small letter je
  '\u043a': 'k', // Cyrillic small letter ka
  '\u0445': 'x', // Cyrillic small letter ha
  '\u0443': 'y', // Cyrillic small letter u
  '\u0455': 's', // Cyrillic small letter dze
  '\u04cf': 'l', // Cyrillic small letter palochka
  '\u045d': 'g', // Cyrillic small letter ge upturn
  // Greek to Latin
  '\u03b1': 'a', // Greek small letter alpha
  '\u03bf': 'o', // Greek small letter omicron
  '\u03c1': 'p', // Greek small letter rho
  '\u03c5': 'y', // Greek small letter upsilon
  '\u03bd': 'v', // Greek small letter nu
  '\u03ba': 'k', // Greek small letter kappa
  '\u03c7': 'x', // Greek small letter chi
  '\u03c9': 'w', // Greek small letter omega
};

/**
 * Normalizes Unicode homographs by converting confusable characters to their standard Latin equivalents.
 */
export function normalizeUnicode(str) {
  let result = "";
  for (const char of str) {
    result += CONFUSABLE_MAP[char] || char;
  }
  return result;
}

/**
 * Checks if a domain is a homograph attack.
 * Triggers if it's Punycode or contains mixed scripts (e.g. Cyrillic/Greek characters alongside Latin).
 */
export function isHomographAttack(domain) {
  const lowerDomain = domain.toLowerCase();
  if (lowerDomain.startsWith("xn--")) {
    return true;
  }
  
  let hasCyrillic = /[\u0400-\u04FF]/.test(lowerDomain);
  let hasGreek = /[\u0370-\u03FF]/.test(lowerDomain);
  let hasLatin = /[a-z]/.test(lowerDomain);
  
  // Mixed script represents threat
  if ((hasCyrillic || hasGreek) && hasLatin) {
    return true;
  }
  
  // Check if it matches after normalization but differs originally
  const normalized = normalizeUnicode(lowerDomain);
  if (normalized !== lowerDomain) {
    return true;
  }

  return false;
}

/**
 * Calculates Jaro-Winkler similarity between two strings (returns score from 0.0 to 1.0).
 */
export function getJaroWinkler(s1, s2) {
  const jaro = getJaroDistance(s1, s2);
  if (jaro < 0.7) return jaro;

  // Winkler enhancement
  let prefix = 0;
  for (let i = 0; i < Math.min(s1.length, s2.length, 4); i++) {
    if (s1[i] === s2[i]) {
      prefix++;
    } else {
      break;
    }
  }
  return jaro + prefix * 0.1 * (1 - jaro);
}

function getJaroDistance(s1, s2) {
  const len1 = s1.length;
  const len2 = s2.length;
  if (len1 === 0 && len2 === 0) return 1.0;
  if (len1 === 0 || len2 === 0) return 0.0;

  const matchDistance = Math.floor(Math.max(len1, len2) / 2) - 1;
  const hash1 = new Array(len1).fill(false);
  const hash2 = new Array(len2).fill(false);

  let matches = 0;
  for (let i = 0; i < len1; i++) {
    const start = Math.max(0, i - matchDistance);
    const end = Math.min(len2, i + matchDistance + 1);
    for (let j = start; j < end; j++) {
      if (!hash2[j] && s1[i] === s2[j]) {
        hash1[i] = true;
        hash2[j] = true;
        matches++;
        break;
      }
    }
  }

  if (matches === 0) return 0.0;

  let transpositions = 0;
  let point = 0;
  for (let i = 0; i < len1; i++) {
    if (hash1[i]) {
      while (!hash2[point]) {
        point++;
      }
      if (s1[i] !== s2[point]) {
        transpositions++;
      }
      point++;
    }
  }
  
  const t = transpositions / 2;
  return (matches / len1 + matches / len2 + (matches - t) / matches) / 3.0;
}

/**
 * Calculates Levenshtein edit distance between two strings.
 */
export function getLevenshteinDistance(s1, s2) {
  const matrix = Array(s2.length + 1).fill(null).map(() => Array(s1.length + 1).fill(null));
  for (let i = 0; i <= s1.length; i++) matrix[0][i] = i;
  for (let j = 0; j <= s2.length; j++) matrix[j][0] = j;

  for (let j = 1; j <= s2.length; j++) {
    for (let i = 1; i <= s1.length; i++) {
      const indicator = s1[i - 1] === s2[j - 1] ? 0 : 1;
      matrix[j][i] = Math.min(
        matrix[j - 1][i] + 1, // deletion
        matrix[j][i - 1] + 1, // insertion
        matrix[j - 1][i - 1] + indicator // substitution
      );
    }
  }
  return matrix[s2.length][s1.length];
}

/**
 * Computes Jaccard Similarity of character N-grams.
 */
export function getNgramSimilarity(s1, s2, n = 2) {
  const getNGrams = (str) => {
    const list = [];
    if (str.length < n) return [str];
    for (let i = 0; i <= str.length - n; i++) {
      list.push(str.substring(i, i + n));
    }
    return list;
  };

  const ng1 = getNGrams(s1);
  const ng2 = getNGrams(s2);
  const set1 = new Set(ng1);
  const set2 = new Set(ng2);

  const intersection = new Set([...set1].filter(x => set2.has(x)));
  const union = new Set([...set1, ...set2]);

  return union.size === 0 ? 0 : intersection.size / union.size;
}

/**
 * Parses full URL paths into protocol, hostname, path, etc.
 */
export function parseUrl(urlStr) {
  if (!urlStr || typeof urlStr !== 'string') {
    return { hostname: "", pathname: "", protocol: "", search: "", hash: "", full: "" };
  }
  try {
    const url = new URL(urlStr);
    return {
      hostname: url.hostname.toLowerCase(),
      pathname: url.pathname,
      protocol: url.protocol.toLowerCase(),
      search: url.search,
      hash: url.hash,
      full: url.href
    };
  } catch (e) {
    try {
      const fallbackUrl = new URL("http://" + urlStr);
      return {
        hostname: fallbackUrl.hostname.toLowerCase(),
        pathname: fallbackUrl.pathname,
        protocol: "",
        search: fallbackUrl.search,
        hash: fallbackUrl.hash,
        full: fallbackUrl.href
      };
    } catch (err) {
      return {
        hostname: (urlStr || "").toLowerCase(),
        pathname: "",
        protocol: "",
        search: "",
        hash: "",
        full: urlStr || ""
      };
    }
  }
}

/**
 * Extracts the registered domain (SLD + TLD) e.g., google.com from accounts.google.com
 */
export function getRegisteredDomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;
  
  // Custom double TLD list matching common browser extensions fallback
  const common2Tlds = [
    "co.uk", "com.br", "org.uk", "gov.uk", "co.jp", "com.tw", "com.cn", 
    "com.sg", "co.za", "com.au", "net.au", "org.au", "gov.au", "com.my"
  ];
  
  const lastTwo = parts.slice(-2).join('.');
  if (common2Tlds.includes(lastTwo) && parts.length > 2) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

/**
 * Unified Logger Object
 */
export const logger = {
  info: (msg, ...args) => console.log(`[PhishShield AI] [INFO] [${new Date().toISOString()}] ${msg}`, ...args),
  warn: (msg, ...args) => console.warn(`[PhishShield AI] [WARN] [${new Date().toISOString()}] ${msg}`, ...args),
  error: (msg, ...args) => console.error(`[PhishShield AI] [ERROR] [${new Date().toISOString()}] ${msg}`, ...args),
  debug: (msg, ...args) => console.debug(`[PhishShield AI] [DEBUG] [${new Date().toISOString()}] ${msg}`, ...args)
};
