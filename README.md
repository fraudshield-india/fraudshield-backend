## 🛡️ FraudShield India

[![Azure](https://img.shields.io/badge/Azure-Functions-0078D4?logo=microsoftazure)](https://azure.microsoft.com/)
[![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python)](https://www.python.org/)
[![Android](https://img.shields.io/badge/Android-SMS%20App-3DDC84?logo=android)](https://developer.android.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-orange.svg)](LICENSE)

---

### ▶️ Demo Video

> **[▶️ Watch 3-minute Demo](URL_TO_BE_ADDED)** — AI Unlocked 2025 submission

---

### 🏆 Evaluation Results

> Evaluated live against Azure OpenAI o4-mini — March 2026

| Metric | Score |
|--------|-------|
| **Scam Detection Accuracy** | **100%** |
| **Precision** | **100%** |
| **Recall** | **100%** |
| **F1 Score** | **100%** |
| Languages Tested | Hindi, Hinglish, English |
| Model | Azure OpenAI o4-mini (Korea Central) |

➡️ Full breakdown in [`evaluation/metrics.md`](evaluation/metrics.md)

---

### What is FraudShield India?

FraudShield India is a real-time **UPI scam detection system** for 230M+ at-risk users in India, built entirely on **Microsoft Azure**.

It scans SMS and chat messages in **Hindi, Hinglish, and English**, flags 8 major UPI scam patterns, explains the risk in plain Hindi, and helps users quickly reach **`cybercrime.gov.in`** or the **1930 helpline**.

The same backend powers an **Android SMS scanner**, a **Telegram bot (@FraudShieldIndiaBot)**, and a **live threat intelligence web dashboard**.

---

### Architecture

```text
Input Channels              Shared API                    AI Pipeline
[Android SMS] ──┐
[Telegram Bot] ─┼──→ Azure Function ──→ Azure OpenAI o4-mini ──→ JSON Response
[Web Dashboard] ┘    /api/classify         (Korea Central)
                                               ↓
                                     Hindi explanation +
                                     Red flags + Complaint form
```

---

### Azure Services

| Service | Usage |
|---------|-------|
| **Azure Functions** | HTTP-triggered `/api/classify`, `/api/health`, `/api/telegram`, `/api/batch` |
| **Azure OpenAI (o4-mini)** | Primary AI model for scam classification — deployed on Azure AI Foundry, Korea Central |
| **Azure AI Language** | Language resource created (fraudshield-lang-model, East Asia F0) |
| **Azure Cosmos DB (Gremlin)** | Graph of scam UPI IDs and phone numbers for investigation workflows |
| **Azure Maps** | India scam heatmap on threat intelligence dashboard |

---

### Features

- **8 scam categories**: fake cashback, digital arrest, KYC freeze, job scam, lottery scam, govt impersonation, phishing links, legitimate
- **3 languages**: Hindi, Hinglish, and English SMS support
- **Hindi explanations**: every alert includes a user-facing Hindi summary
- **Red flag extraction**: highlights suspicious UPI IDs, phone numbers, domains, legal threats
- **Complaint form pre-fill**: prepares incident summary for `cybercrime.gov.in` and 1930 helpline
- **Telegram bot**: @FraudShieldIndiaBot — paste any suspicious message and get instant analysis
- **Android SMS Monitor**: real-time background SMS scanning with Hindi push notifications
- **Scam evolution tracking**: cosine similarity shows how new scam templates inherit patterns from older ones (2020–2025)
- **Live threat dashboard**: India heatmap + scam network graph + real-time message tester

---

### Scam Categories

| Category | Emoji | Description |
|----------|-------|-------------|
| fake_cashback | 💸 | "Cashback" or "refund" via UPI collect requests |
| digital_arrest | 🚓 | CBI/police/ED threats demanding immediate payment |
| kyc_freeze | 🧊 | Bank/UPI KYC warnings threatening account freeze |
| job_scam | 🧳 | Work-from-home jobs requiring upfront registration fees |
| lottery_scam | 🎰 | KBC/Jio/Dream11 prizes with processing or tax fees |
| govt_impersonation | 🏛️ | Fake RBI, Income Tax, Customs, or scheme messages |
| phishing_link | 🕸️ | Suspicious links/QR codes to fake portals or APKs |
| legitimate | ✅ | Normal bank OTPs, deliveries, personal messages |

---

### Scam Evolution (2020–2025)

FraudShield tracks how scam templates evolve over time using text embeddings:

| Template A | Template B | Similarity | Flag |
|------------|------------|------------|------|
| KBC Lottery 2020 | Jio Lucky Draw 2021 | 0.89 | 🔴 HIGH |
| KYC Freeze 2023 | Digital Arrest 2024 | 0.86 | 🔴 HIGH |
| Fake Cashback 2022 | E-Challan Phishing 2025 | 0.84 | 🔴 HIGH |
| Fake Cashback 2022 | Digital Arrest 2024 | 0.83 | 🔴 HIGH |

> New scam variants are detected because they inherit structural patterns from older scams (similarity > 0.82)

---

### API Usage

```bash
curl -X POST "https://fraudshield-api.azurewebsites.net/api/classify" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Aapko Rs.1500 cashback mila hai. Collect request approve karein.",
    "source": "sms",
    "sender": "+91-98765-00001"
  }'
```

Example response:

```json
{
  "is_scam": true,
  "category": "fake_cashback",
  "confidence": 0.97,
  "explanation_hindi": "Yeh message jhootha cashback ka bahana bana kar aap se paise katwane ki koshish kar raha hai.",
  "red_flags": [
    "UPI collect request to receive cashback",
    "no prior transaction context",
    "urgency to approve immediately"
  ],
  "complaint_form": {
    "portal": "cybercrime.gov.in",
    "helpline": "1930",
    "evidence_to_collect": ["screenshot", "sender_id", "transaction_id"]
  }
}
```

Health check:
```bash
curl https://fraudshield-api.azurewebsites.net/api/health
```

---

### Run Evaluation

```bash
git clone https://github.com/fraudshield-india/fraudshield-backend.git
cd fraudshield-backend
pip install requests
python evaluation/evaluate.py --max 8
```

Results saved to `evaluation/metrics.md`.

---

### Deployment

Deployed automatically via **GitHub Actions → Azure Functions** on every push to `main`.

Required GitHub secret:

| Secret | Description |
|--------|-------------|
| `AZURE_FUNCTIONAPP_PUBLISH_PROFILE` | Publish profile XML from fraudshield-api Function App |

Azure environment variables required:

| Variable | Description |
|----------|-------------|
| `AZURE_OPENAI_ENDPOINT` | Azure AI Foundry o4-mini endpoint URL |
| `AZURE_OPENAI_KEY` | Azure OpenAI API key |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token |
| `COSMOS_DB_ENDPOINT` | Cosmos DB Gremlin URI |
| `COSMOS_DB_KEY` | Cosmos DB primary key |

---

### Repos

| Repo | Description |
|------|-------------|
| [fraudshield-backend](https://github.com/fraudshield-india/fraudshield-backend) | Azure Functions API + Dashboard + Evaluation |
| [fraudshield-android](https://github.com/fraudshield-india/fraudshield-android) | Android SMS Monitor app (Kotlin, Material3) |

---

### Team

**Boulevard of Secure Dreams** · MIT Manipal  
**Competition:** AI Unlocked 2025 — Microsoft Azure Track  
**Mission:** Make "forward to FraudShield" as natural as "forward to family group" for every suspicious UPI SMS in India.

> Report scams: **1930** | [cybercrime.gov.in](https://cybercrime.gov.in)
