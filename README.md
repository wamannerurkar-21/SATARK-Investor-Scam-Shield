# SATARK — AI-Powered Investor Scam Shield

**Hackathon:** SANGYAN IIT (BHU)  
**Track:** Track A — Digital Fraud & Scam Resilience  
**Tagline:** “Pause. Check. Then Act.”

SATARK helps people review suspicious financial messages and screenshots before transferring money or sharing information. It highlights common scam signals, shows its verification status, and gives practical steps for checking a claim independently.

## Problem

Digital financial scams can exploit urgency, impersonation, unrealistic return claims, and phishing. People often have little time to decide whether a message, link, or investment claim deserves further scrutiny.

## Solution

SATARK provides a simple review flow for pasted text or screenshot content. Its report explains which indicators were found, what remains unverified, and what the user can check before acting.

## Features

- Paste-message and screenshot upload flows.
- Screenshot flow with a consent-gated OCR adapter for the teammate's extraction module; extracted text remains editable before analysis.
- A local, transparent rule-based fallback that works with no API key.
- Optional adapters for the team's analysis, risk engine, URL extraction, OpenPhish, and entity-verification modules.
- Optional analysis and network verification are off by default and require an in-app opt-in.
- Explainable prototype risk indicator with four levels: low concern, needs verification, high risk, and very high risk.
- Claims, detected indicators, URL/entity verification statuses, and verification guidance in the result report.
- English, Hindi, and Marathi interface, risk explanations, indicators, and safety guidance.
- SQLite insights showing scan totals, risk-level counts, top indicators, and recent scan metadata.
- Privacy-first persistence: no message text, OCR output, screenshot, OTP, PIN, password, bank detail, or personally identifying information is written to the database.
- Three offline demo samples, including a high-risk pitch, a registration claim to verify, and financial education content.

## Architecture

```text
Root app.py
  └── Streamlit application (artifacts/satark/app.py)
       ├── Optional teammate adapters and local fallback rules (satark_core.py)
       ├── English / Hindi / Marathi copy (translations.py)
       └── SQLite metadata + aggregate indicators (database/)
```

### Integration points

When the modules are available, SATARK can import:

```python
from ai.analyzer import analyze_text
from detection.risk_engine import calculate_risk
from detection.url_extractor import extract_urls
from ocr.extractor import extract_text_from_image
from verification.openphish import check_url
from verification.sebi import verify_entity
```

Missing or failing modules do not crash the app. The local analysis fallback is clearly identified; unavailable URL and entity checks are labeled as unavailable rather than presented as completed checks.

## Tech stack

- Python 3.11+
- Streamlit
- SQLite (Python standard library)
- Pillow for image validation
- `unittest` for the offline test suite

## Setup

Install the Python requirements:

```bash
python -m pip install -r requirements.txt
```

No API key is required for the local analysis or demo flow.

## Environment variables

| Variable | Purpose | Default |
| --- | --- | --- |
| `SATARK_ENABLE_OPTIONAL_MODULES` | Pre-enable the in-app optional-module checkbox. Enabling modules can send submitted content to their providers. | `false` |
| `PORT` | Streamlit listener port in the Replit workflow. | Supplied by Replit |

Do not put credentials in source code. The local-only mode does not need any credentials.

## Running instructions

Run the app from the project root:

```bash
streamlit run app.py
```

In Replit, use the **Run** button. The app listens on the assigned `PORT` and binds to `0.0.0.0`.

## Demo instructions

1. Leave **Allow optional OCR, analysis, and verification modules** unchecked for local-only processing and manual screenshot text entry.
2. Choose **Try Demo** and select a sample.
3. Run **Analyze demo** to see the report and local insights.
4. To check your own content, paste text or upload a PNG, JPG, or WEBP screenshot.
5. For screenshots, opt in to the connected OCR module if desired, review and edit any extracted text, then analyze it.
6. You can change the interface language at any time; this does not change the underlying risk analysis.

The demo can be used without an API key or network verification.

## Privacy

- SATARK does not request OTPs, PINs, passwords, or bank details. Do not submit these.
- The SQLite database contains only a random scan ID, timestamp, input type, risk level, prototype score, indicator count, verification status, and aggregate indicator totals.
- Raw messages, extracted OCR text, and screenshot bytes are not written to the database. Submitted text can remain in memory during an active session so the report can be displayed.
- Optional analysis and verification modules are off by default. When enabled, their providers may process submitted content.
- No personally identifying information is collected by the local app.

## Limitations

- The local rule-based fallback is a hackathon prototype and can miss new scam patterns or flag benign wording.
- Its score is not an official regulatory score, proof of fraud, or proof of legitimacy.
- URL and entity checks are not performed in local-only mode. They require working optional verification modules.
- OCR requires the team's `ocr.extractor` module. When it is unavailable, screenshot text can still be typed or pasted manually.
- The app does not give investment advice, recommend securities, predict prices, or issue buy/sell/hold signals.

## Future improvements

- Integrate and validate the final team modules against their agreed input/output schemas.
- Add confidence and source attribution for each external verification result.
- Expand evaluated multilingual scam patterns and accessibility testing.
- Add configurable local data-retention controls for metadata.
- Run a broader adversarial test set before any public release.