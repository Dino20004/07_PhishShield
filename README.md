# PhishShield AI

### AI-Powered Real-Time Phishing & Web Threat Detection Extension

PhishShield AI is a production-grade, lightweight browser extension designed to protect users against phishing websites, typosquatting, Unicode homograph attacks, credential harvesting, drive-by downloads, and suspicious JavaScript injection in real-time. It executes all threat analysis locally inside the browser context, ensuring complete privacy with no remote dashboards required.

---

## 🚀 Key Features

*   **URL Similarity & Typosquatting**: Calculates Levenshtein Distance, Jaro-Winkler, and N-gram similarity on-the-fly to check if a domain is mimicking popular brands (e.g. `faceb00k.com`, `google-login-security.net`).
*   **Homograph Spoofing Check**: Detects mixed Unicode scripts and Punycode (`xn--`) used to trick users (e.g. `аррӏе.com` using Cyrillic homographs).
*   **Live Registration Age Check**: Directly queries the modern **RDAP (Registration Data Access Protocol)** registry to calculate domain age and flag newly registered domains (less than 30 days old).
*   **DOM Threat Scanner**: Scans for invisible password forms, mismatched form action handlers, and secure HTTP-to-HTTP submission downgrades.
*   **Malicious JS Analysis**: Scans pages for keyboard monitors (keyloggers), document cookie theft hooks, dynamic evaluation blocks (`eval`), and obfuscated script structures.
*   **Interrupt-level Download Blocker**: Hooks into the browser download layer to dynamically abort executable scripts and binaries (`.exe`, `.vbs`, `.js`, `.bat`, `.iso`) triggered from high-risk domains.
*   **Combined AI Risk Engine**: Weighs multiple independent indicators (0-100 score) to categorize pages into **SAFE**, **LOW**, **MEDIUM**, **HIGH**, or **CRITICAL** risk levels.
*   **In-Page Blocker Overlay**: Blurs and blocks high-risk pages dynamically, presenting a warning card that details the exact threat reason before a user can interact or submit credentials.
*   **Whitelisting & Logs Logging**: Log history scans and allow custom whitelist domains (`company-intranet.local`) to bypass scoring. Export logs to standard **JSON**, **CSV**, or **TXT** format.

---

## 🛠️ Architecture

```text
PhishShield/
├── manifest.json         # Manifest V3 configuration & permission descriptors
├── package.json          # Node dependencies & native test runner configuration
├── README.md             # Product documentation
├── generate_icons.py     # Python script to draw extension shield icons
│
├── assets/               # Production PNG icon assets (16x16, 32x32, 48x48, 128x128)
│   ├── icon16.png
│   ├── icon32.png
│   ├── icon48.png
│   └── icon128.png
│
├── src/                  # Chrome, Firefox (MV3), Edge, Brave runtime
│   ├── config.js         # Settings, brand definitions, and threat thresholds
│   ├── utils.js          # Levenshtein, Jaro-Winkler, N-grams, Unicode normalizer
│   ├── storage.js        # Chrome storage local wrapper with memory fallback
│   ├── engine.js         # Core threat analyzers and combined AI Risk Engine
│   ├── background.js     # Background worker coordinating page hooks & downloads
│   ├── content.js        # Webpage injector, form hijack hook, and block screen
│   ├── popup.html        # Interactive popup overlay panel
│   ├── popup.js          # Controller connecting popup views and whitelists
│   └── popup.css         # Dark theme styling, glassmorphic layout, dial animations
│
└── tests/                # Test suites
    └── engine.test.js    # Comprehensive unit tests for threat matching logic
```

---

## 📦 Installation Guide (Developer Mode)

To install PhishShield AI on Google Chrome, Microsoft Edge, Brave, or Opera:

1.  **Clone or Download** this repository to your local system:
    ```bash
    git clone https://github.com/your-repo/PhishShield.git
    ```
2.  **Open Extensions Settings** in your browser:
    *   Chrome: Navigate to `chrome://extensions/`
    *   Edge: Navigate to `edge://extensions/`
    *   Brave: Navigate to `brave://extensions/`
3.  **Enable Developer Mode** (usually a toggle switch in the top-right corner).
4.  Click **Load unpacked** (top-left button).
5.  Select the `PhishShield` root folder containing `manifest.json`.
6.  The extension shield icon will appear in your toolbar!

*(For future Mozilla Firefox deployments, the extension is written with modular, standards-compliant WebExtensions APIs, requiring minimal path adjustments).*

---

## ⚙️ AI Risk Engine Weights

The risk engine compiles independent scores from each detection module using the following weight breakdown:

| Threat Category | Weight Points | Threat Descriptions Checked |
| :--- | :---: | :--- |
| **Typosquatting** | 20 | Brand similarity matching via Levenshtein / Jaro-Winkler |
| **Brand Impersonation** | 20 | Unofficial pages containing brand names in title / meta |
| **Domain age (WHOIS)** | 15 | Newly registered domains (less than 30/90 days old) via RDAP |
| **SSL Connection** | 15 | Expired certs, HTTP usage, weak cipher negotiations |
| **DOM Structs** | 15 | Mismatched form actions, invisible logins, hidden password forms |
| **JavaScript Threat** | 10 | Keylogging, cookie extraction, clipboard manipulation hooks |
| **Redirection Chains** | 10 | Chain count loops (3+), meta refresh, shortener usage |
| **Downloads Protection**| 5 | Executable script payloads initiated automatically |
| **Notification Spam** | 5 | Immediate notification request prompt abuse |

**Score Categories**:
*   🟢 **SAFE** (0 - 14): Normal legitimate websites.
*   🔵 **LOW** (15 - 39): Minor warnings (e.g., missing HTTPS or young domain).
*   🟡 **MEDIUM** (40 - 69): Suspicious items found. Proceed with caution.
*   🟠 **HIGH** (70 - 84): Phishing indicators identified. Block overlay triggered.
*   🔴 **CRITICAL** (85 - 100): High-confidence malicious threat. Credentials submissions intercepted and blocked.

---

## 🧪 Running Unit Tests

PhishShield AI features a fully native test suite requiring zero external dependencies to build or test. Tests run directly using the native Node.js test runner.

To run the test suite:
```bash
npm test
```

This runs the tests defined in `tests/engine.test.js` validating:
1.  Levenshtein Distance values.
2.  Jaro-Winkler string similarity levels.
3.  Punycode and Cyrillic/Greek homograph spoofing rules.
4.  Registered domain extraction boundaries.
5.  Suspicious DOM, JS obfuscation, and URL typosquat matches.
6.  Weighted risk average equations.

---

## 🔒 Security & Privacy

*   **Zero Data Collection**: All calculations occur strictly on your local browser profile. No scanned URLs or credentials are sent to external cloud servers.
*   **Local Whitelisting**: Trusted domains can be whitelisted at any time in the popup panel, which instantly overrides the risk engine score to 0.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
