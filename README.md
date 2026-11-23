# ScamShield AI — درع مكافحة الجريمة الإلكترونية

**AD Police × 42 Abu Dhabi Hackathon, 2026**

ScamShield AI checks any SMS, WhatsApp message, email or link in Arabic or English. It says within a second whether it is a scam, explains **why** in plain language, and drafts a ready-to-send report for Abu Dhabi Police's **Aman** service (8002626 · SMS 2828 · aman@adpolice.gov.ae).

Everything runs **on the user's device**. No message, link or phone number is ever sent to a server.

> **Disclaimer:** this is a prototype built by a participating team for the AD Police × 42 Abu Dhabi hackathon. It is **not an official Abu Dhabi Police product** and is not endorsed by Abu Dhabi Police or 42 Abu Dhabi. All scam examples, domains and phone numbers in this repository are fictional and for testing only.

---

## 1. The problem

Scams in the UAE follow a few repeating scripts:
- fake traffic fines and fake "government" links
- "your parcel is on hold, pay AED 5"
- fake bank staff asking for the OTP
- fake prizes, fake part-time jobs and "guaranteed profit" investments
- "hi dad, this is my new number"
- sextortion

Victims usually lose money in the first few minutes, before they think to check or call anyone. Most of them are not technical, many are elderly, and the messages arrive in Arabic, English or a mix of both.

## 2. The solution

| Feature | What it does |
|---|---|
| **Scan message** | Paste any message → 0–100 risk score, a verdict, the likely scam type, each reason in plain words, and the red flags highlighted in the text. |
| **Check link** | Checks a link **without opening it**. It flags copycat domains (`emlratesnbd.com`), brand names inside fake domains (`adpolice-fines.top`), fake "gov" sites that don't end in `.gov.ae`, link shorteners, raw IP addresses, Punycode look-alike letters, and app/APK downloads. |
| **Report to Aman** | One tap builds a structured report with links made unclickable ("defanged"), plus buttons to call 8002626, SMS 2828 or email Aman. Nothing is sent automatically. |
| **Intel board** | Anonymous on-device statistics: scam types, most-impersonated entities, and a list of malicious links/numbers (IOCs) exportable as CSV for cybercrime teams. |
| **Awareness** | Golden rules, official reporting channels, and a large-text mode for older users. |

The interface is in Arabic (right-to-left) and English, built mobile-first, and works fully offline.

## 3. How it decides: a hybrid AI engine

```
message ──► normalise (Arabic letter forms, diacritics, Arabic-Indic digits)
        ├─► Explainable rules  : 15 bilingual scam-signal families (urgency, OTP request, fee,
        │                        threat, prize, job, investment, parcel, relative, blackmail…)
        ├─► Entity check       : 28 UAE entities ↔ their official domains (impersonation)
        ├─► URL forensics      : look-alike/typosquat, brand-in-domain, fake .gov, TLD risk,
        │                        shorteners, IP, Punycode, APK, "@" trick
        ├─► Phone origin       : foreign numbers while claiming to be a UAE entity
        ├─► AI model           : char n-gram logistic regression (AR+EN), trained offline,
        │                        runs in the browser (~47 KB of weights)
        └─► Combination rules  : e.g. prize + fee = advance-fee fraud
                         ▼
        risk score (0–100) + scam type + reasons + highlighted text + actions + report
```

Full details are in [`docs/TECHNICAL.md`](docs/TECHNICAL.md): architecture, model choices, privacy design and evaluation.

## 4. Results

| Test set | Result |
|---|---|
| Hand-written UAE-style messages, AR + EN (33 messages, `tests/cases.json`, *not* made from training templates) | **33/33 correct**: every scam caught, zero false alarms on real bank OTPs, salary alerts, TAMM receipts and courier tracking |
| AI model on the public UCI SMS Spam benchmark (1,115 held-out English SMS) | **AUC 0.990**, accuracy 98.7%, scam precision 96.6%, recall 94.0% |
| URL forensics cases | 7/7 |
| JavaScript vs Python model parity | max difference 6×10⁻⁶ |
| Browser end-to-end (every button, AR/EN, phone + desktop, offline, XSS) | 242/242 |
| Fuzzing (5,000 random AR/EN/emoji inputs, 200 KB messages) | no crashes, slowest 55 ms |

## 5. Run it

**No build or install is needed to use it.**

```bash
# Option A: open the single-file offline app (also works on a phone)
open dist/scamshield.html            # or double-click it

# Option B: open the source version
open index.html

# Run the tests (Node 18+)
node tests/engine.test.js

# Full browser test: every button, phone + desktop, offline (optional)
pip install playwright && playwright install chromium
python3 tests/e2e_browser.py

# Rebuild the single-file app after editing src/
python3 build.py

# Retrain the AI model (Python 3.10+, scikit-learn)
pip install scikit-learn numpy
python3 ml/gen_uae.py && python3 ml/train.py 3000 && python3 ml/export_model.py
python3 build.py && node tests/engine.test.js
```

## 6. Repository layout

```
index.html            App UI (loads src/)
src/engine.js         Detection engine: rules, entities, URL forensics, ML inference
src/model.js          Trained model weights (generated)
dist/scamshield.html  Single-file offline build
ml/                   Dataset generator + training script + data
tests/              Engine tests, browser end-to-end test, labelled cases, parity data
docs/TECHNICAL.md     Architecture, model choices, privacy design, evaluation
build.py              Bundler for dist/
```

## 7. Technical choices and trade-offs

- **Hybrid rather than a large language model.** A rules + small-model engine runs instantly and offline on any phone. It costs nothing per scan, never sends private messages to a cloud API, and every point of the score can be explained. That matters for police use and for user trust. The trade-off is that it is less flexible than an LLM on brand-new scam scripts. The rules and the model can be updated independently to make up for that.
- **Character n-grams** rather than word tokens. This handles Arabic prefixes and suffixes, Gulf dialect, Arabizi, misspellings and mixed Arabic/English text without needing an Arabic tokenizer.
- **Logistic regression** rather than a neural network. The weights are tiny (~47 KB), it runs in the browser with no library, the scores are calibrated, and each feature's weight can be inspected.
- **Synthetic UAE data.** No public, labelled Arabic UAE scam dataset exists. The UAE part of the training data is generated from templates based on public police awareness patterns. Its 100% score on its own test split is therefore *not* meaningful, so we report the public UCI benchmark and the hand-written test set instead.

**Left out (for now):** reading screenshots (OCR), voice-call scams, real-time threat-intel sync, and app-store packaging.

**With more time, we would:**
1. collect real, anonymised UAE scam reports (with AD Police) to retrain the model
2. add a WhatsApp/Telegram bot and a mobile share-sheet extension ("Share → ScamShield")
3. add OCR for screenshots, and a small Arabic transformer for hard cases (opt-in, server-side)
4. sync the intel board to a secure police backend with abuse-resistant reporting
5. take down reported domains in cooperation with the TDRA

## 8. Data and credits

- UCI SMS Spam Collection (Almeida & Hidalgo, 2011), used for training and benchmarking. See `ml/README.md`.
- Official reporting channels: Abu Dhabi Police Aman service.

## Team

- Abdulla Alqubaisi
- Eissa Alqubaisi
- Reem Alqubaisi

Participants keep full ownership of this prototype, as the hackathon terms state.
