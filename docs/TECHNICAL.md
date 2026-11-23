# ScamShield AI — Technical documentation

## 1. Architecture

```
┌──────────────────────── User's phone / browser (100% client-side) ────────────────────────┐
│                                                                                            │
│  UI (index.html)  ──text/URL──►  Engine (src/engine.js)                                    │
│   • Scan / Link / Intel / Learn        │                                                   │
│   • AR/EN, RTL, large-text             ├─ 1. Normaliser (Arabic letter forms, tashkeel,    │
│                                        │      Arabic-Indic digits, index map for highlights)│
│                                        ├─ 2. Signal detector: 15 bilingual families        │
│                                        ├─ 3. Entity registry: 28 UAE orgs ↔ official domains│
│                                        ├─ 4. URL forensics                                 │
│                                        ├─ 5. Phone-origin check                            │
│                                        ├─ 6. AI model (src/model.js weights)               │
│                                        └─ 7. Combination rules → score, type, reasons      │
│                                                     │                                      │
│  Result view ◄──────────────────────────────────────┘                                      │
│   • gauge, reasons, highlights, actions, Aman report (defanged)                            │
│  Intel store (localStorage, anonymous counters + IOCs) ──► CSV export (user-initiated)     │
└────────────────────────────────────────────────────────────────────────────────────────────┘
      ▲ offline training only (never at runtime)
      │
 ml/train.py: UCI SMS + synthetic UAE AR/EN → char n-grams → χ² selection → LogReg → model.json
```

No backend and no network calls at runtime. The only network action is when the user taps call, SMS or email to Aman.

## 2. Detection pipeline

1. **Normalisation**
   - Arabic: removes diacritics (tashkeel) and tatweel, unifies أ/إ/آ → ا, ى → ي, ة → ه, ؤ → و, ئ → ي, and converts Arabic-Indic digits.
   - English: lower-cased.
   - An index map keeps the positions of the original text, so the red flags can be highlighted exactly.
2. **Signal families.** Each family has English regexes, Arabic stems (MSA and Gulf dialect, e.g. `الرمز اللي وصلك`), a weight, a category and a bilingual explanation:
   - urgency
   - credential request
   - credential mention
   - account-update
   - payment
   - amount
   - threat
   - prize
   - job
   - investment
   - parcel
   - relative-in-trouble
   - sextortion
   - secrecy
   - channel-switch
   - protective warning (negative weight)
3. **Context logic.**
   - "Do not share this code" (a protective warning) cancels a mere *mention* of an OTP, but never cancels a direct *request* for it. This is how genuine bank OTP texts score 0 and fake ones score 85 or more.
   - Amounts alone are weak (+3). "Pay the fee" is strong.
4. **Impersonation.** A message names an entity (e.g. Emirates Post) and contains a link outside that entity's official domain → +28, with the reason spelled out. A government entity asking for a code adds +12.
5. **URL forensics.**
   - Official domain → –25.
   - Otherwise it checks: shorteners; IP hosts; Punycode; high-abuse TLDs; "@" tricks; hyphen-stuffing; deep subdomains; a brand token inside a non-official host; "gov" outside `.gov.ae`; typosquats (Levenshtein distance after undoing look-alike swaps such as 0→o, 1→l, rn→m); login/payment paths; APK/EXE downloads.
6. **AI model.** Its probability *p* is blended in:
   - p ≥ 0.5: adds up to +30 points
   - p < 0.2: subtracts up to 10 points
   - in between: shown to the user as "uncertain"
7. **Combination rules.**
   - prize + fee
   - job + deposit
   - threat/parcel + fee + bad link
   - urgency + data request + outside link/number
   - relative + urgency/secrecy
8. **Score.** `score = 100·(1 − e^(−points/42))`, with floors for "OTP request + bank or government" and for sextortion (85).
   - Levels: < 25 safe · 25–54 suspicious · 55–79 high · ≥ 80 scam.
   - The scam type is the family with the most points.

## 3. Model choices

| Decision | Choice | Why |
|---|---|---|
| Features | Character 3–5-grams on normalised text, digits → 0 | Robust to Arabic prefixes/suffixes, dialect, Arabizi, typos and mixed AR/EN; no tokenizer needed; numbers generalise (OTP values, amounts) |
| Selection | χ² top 3,000 | Keeps the weights at ~47 KB for an instant offline load |
| Classifier | Logistic regression, C=2, class-balanced | Calibrated probabilities, readable weights, exact re-implementation in ~10 lines of JavaScript |
| Rejected: LLM API | No | Privacy (private messages would go to the cloud), cost per scan, latency, needs internet, hard to explain |
| Rejected: transformer on-device | Not for v1 | 50–500 MB download; overkill when rules capture the UAE scripts |
| Parity | `tests/parity.json` | The JavaScript inference reproduces sklearn's probabilities (max difference 6×10⁻⁶) |

**Training data**
- UCI SMS Spam Collection: 5,574 English SMS.
- Synthetic UAE corpus (`ml/gen_uae.py`): 2,357 Arabic and English scam and legitimate messages, built from templates covering every major UAE scam script. Variety comes from randomised entities, amounts, lookalike domains, foreign numbers and dialect forms.

**Evaluation (held-out)**
- **UCI test** (1,115 SMS): AUC 0.990, accuracy 98.7%, scam precision 0.966, recall 0.940.
- **UAE synthetic test:** 100%. This is expected and *not* a meaningful number, because it comes from the same templates as the training data.
- **Independent hand-written set** (`tests/cases.json`, 33 messages, AR + EN, not from templates, including hard legitimate cases): 33/33 for the full engine.

**Known limitations**
- Synthetic Arabic data cannot cover every dialect or every new scam script.
- Sarcastic or very short messages can sit in the "uncertain" band.
- Image-only scams (screenshots, QR codes) are not analysed yet.

## 4. Privacy design

- **Data minimisation by architecture.** Analysis happens in the browser. Messages, links and phone numbers never leave the device: no analytics and no third-party scripts, fonts or CDNs.
- **Links are never opened.** URL forensics is purely lexical, so checking a link cannot trigger a malicious page, tracking pixel or download.
- **The user is in control of reporting.** The Aman report is drafted locally. It is sent only when the user taps call, SMS or email, and the user can edit it first. Links in it are defanged (`hxxps://evil[.]xyz`) so nobody can open them by accident.
- **The intel board is anonymous.** It stores only counters by type and entity, and indicators (malicious domains and phone numbers), in `localStorage` on this device. It does not store message text. Export is a manual CSV download, and "Clear data" wipes it.
- **No accounts and no identifiers.** There is no login and no device ID.
- **Production path.** If AD Police wants a central threat feed, the extension would send only defanged indicators with explicit consent. It would use a rate-limited, signed endpoint, follow UAE PDPL principles (purpose limitation, retention limits), and store no message bodies.

## 5. Security considerations

- The UI escapes all user text before rendering (no HTML injection from pasted messages).
- No `eval`, no remote code; the app works from `file://`.
- The model and rules ship as static files, so an update is a new version that can be reviewed.

## 6. Roadmap

1. Retrain on real anonymised UAE reports from Aman, with a feedback button ("this was wrong").
2. WhatsApp bot, Android/iOS share-sheet extension, and a browser extension that checks links before they open.
3. OCR for screenshots (on-device Tesseract) and QR-code scanning.
4. An opt-in Arabic transformer for the "uncertain" band.
5. A secure police dashboard aggregating indicators across users, with automatic takedown requests.
