# Clixus – Malicious URL & Phishing Guard (Chrome MV3)

Clixus checks links with VirusTotal and scans page text using NLP to warn you before landing on risky pages.

## Install (Developer Mode, Chrome)
1. Click the green **Code** button → **Download ZIP** and extract it.
2. Open Chrome → go to `chrome://extensions/`.
3. Turn on **Developer mode** (top right).
4. Click **Load unpacked** → select the extracted folder (must contain `manifest.json`).
5. Open the extension **Options** page (or edit `background.js`) to add your **VirusTotal API key**.

## Features
- VirusTotal (multi-vendor) reputation check
- On-device NLP for phishing cues (urgency, brand, keywords)
- Unified risk score + interstitial (Warn/Block)

## Permissions
Minimal required for link interception and analysis. No personal data collected.

## Privacy
We do **not** upload full page content to external servers. VT queries include the URL/hash only. See `PRIVACY.md`.

## License
MIT
