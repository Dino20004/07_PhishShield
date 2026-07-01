# Changelog

All notable changes to the PhishShield AI project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-07-01

### Added
- **Core Engine (engine.js)**: Integrated 11 security analyzers including typosquatting distance metrics (Jaro-Winkler, Levenshtein), unicode homograph Spoof check, dynamic form check, keylog signatures scanner, meta refresh navigations tracker, and download interrupts.
- **Combined Threat Scoring**: Implemented a weighted AI Risk Engine aggregation utilizing threat scores with automatic override floors for high-severity signal clusters.
- **RDAP Live Age Lookups**: Enabled browser-level query of the RDAP registry to establish domain age without external paid API keys.
- **Browser Worker Coordination**: Configured background service worker (`background.js`) to handle alarms, update action badges, block high-risk downloads, and communicate reports to popup panels.
- **Secure DOM Injection Scripts**: Structured script injection (`content.js`) to capture DOM parameters, intercept form submissions, and draw fullscreen glassmorphic alerts on threat domains.
- **Popup Control Panel**: Built clean glassmorphic popup panels (`popup.html`/`css`/`js`) displaying risk details, history logs, settings, and file exports (JSON, CSV, TXT).
- **Comprehensive Unit Testing**: Written 10 native Node.js test cases covering core string algorithms, brand impersonations, JS signature checks, and aggregated score calibrations.
