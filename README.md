# Phishing Mail Detector (MVP)

A Chrome extension that scans the currently opened Gmail email for phishing signals, highlights suspicious links in the message body, and generates a SOC-style report you can copy to the clipboard.

## Features

- **Scan current email** — Click the extension icon and use **Scan current email** to analyze the open Gmail message.
- **Risk score & level** — Shows a 0–100 score and risk level (Low / Medium / High).
- **Why it’s suspicious** — Lists reasons such as urgency wording, credential/OTP requests, attachment bait, and link-based issues.
- **Suspicious URLs** — Lists actual link targets (which may differ from visible link text) with reasons (e.g. domain mismatch, shortener, IP-based URL).
- **In-page highlighting** — Suspicious links in the email body are underlined with a wavy style and show a tooltip with the reason.
- **Copy report** — One-click copy of a text report suitable for sharing or SOC workflows.

## Installation

1. Open Chrome and go to `chrome://extensions/`.
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and select the `MailShield` folder (the one containing `manifest.json`).
4. The **Phishing Mail Detector** icon will appear in the toolbar.

## Usage

1. Open [Gmail](https://mail.google.com) and open an email (click to read it).
2. Click the Phishing Mail Detector extension icon.
3. Click **Scan current email**.
4. Review risk level, score, reasons, and suspicious URLs in the popup.
5. Optionally click **Copy report** to copy the report to the clipboard.
6. In the email body, suspicious links are highlighted with a wavy underline; hover for the reason.

**Note:** If you get “Receiving end does not exist”, the extension will try to inject the scripts and resend the scan. If it still fails, refresh the Gmail tab and scan again.

## How it works

- **Content script** (`content.js`) runs on Gmail. It reads the open email (subject, body text, links from the DOM), calls the detector, highlights suspicious links, and responds to the popup via messaging.
- **Detector** (`detector.js`) is rule-based and does not send data off-device. It checks:
  - **Text:** Urgency phrases, credential/OTP/login requests, attachment-bait phrases.
  - **Links:** Trusted hosts (e.g. Google, Microsoft, Apple, LinkedIn) are skipped. For others it scores: dangerous schemes (`javascript:`, `data:`), non-HTTPS, IP-based hosts, URL shorteners, domain mismatch (visible text vs `href`), and simple lookalike/typosquat hints. Many unique external domains can add a small global penalty.
- **Popup** (`popup.html` + `popup.js`) triggers the scan, shows the result, and builds the copyable report.

## Permissions

- **activeTab, scripting** — To run the content script and scan the active Gmail tab.
- **clipboardWrite** — To copy the report when you click **Copy report**.
- **host_permissions: https://mail.google.com/\*** — To run only on Gmail.

## File structure

```
MailShield/
├── manifest.json   # Extension manifest (Manifest V3)
├── popup.html      # Popup UI
├── popup.css       # Popup styles
├── popup.js        # Popup logic & report build
├── content.js      # Gmail DOM extraction, highlighting, messaging
├── detector.js     # Rule-based phishing analysis (analyzeEmail)
├── package.json    # Project metadata (type: module)
└── README.md       # This file
```

