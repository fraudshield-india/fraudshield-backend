## 🛡️ FraudShield India

[![Azure](https://img.shields.io/badge/Azure-Functions-0078D4?logo=microsoftazure)](https://azure.microsoft.com/)
[![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python)](https://www.python.org/)
[![Android](https://img.shields.io/badge/Android-SMS%20App-3DDC84?logo=android)](https://developer.android.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-orange.svg)](LICENSE)

### ▶️ Demo video

[▶️ Watch 3-min Demo](URL_TO_BE_ADDED) — **coming soon after AI Unlocked 2025 finals.**

---

### What is FraudShield India?

FraudShield India is a real-time **UPI scam detection** backend for 230M+ at-risk users in India, built on **Azure Functions** and **GitHub Models (gpt-4o-mini)**.  
It scans SMS and chat messages in **Hindi, Hinglish, and English**, flags 8 major UPI scam patterns, explains the risk in plain Hindi, and helps users quickly reach **`cybercrime.gov.in`** or the **1930 helpline**.  
The same backend powers an **Android SMS scanner**, a **Telegram bot**, and a **web dashboard** for threat intelligence teams.

---

### Architecture (high-level)

```text
Input Channels          Shared API                    AI Pipeline
[Android SMS] ──┐
[Telegram Bot] ─┼──→ Azure Function ──→ GitHub Models (gpt-4o-mini) ──→ JSON
[Web Dashboard] ┘    /api/classify
```

---

### Azure Services

| Service                 | Usage                                                                 |
|-------------------------|-----------------------------------------------------------------------|
| Azure Functions         | HTTP-triggered `/api/classify` endpoint and dashboard data feeds     |
| Azure Cosmos DB (Gremlin)| Graph of scam UPI IDs / phone numbers for investigation workflows   |
| GitHub Models           | `gpt-4o-mini` for classification + `text-embedding-3-small` for RAG & evolution |
| Azure Maps / Leaflet    | India scam heatmap (Leaflet with Azure Maps / OSM tiles fallback)    |

---

### Detection Metrics

FraudShield is evaluated with live calls to **gpt-4o-mini** via GitHub Models.  
The detailed evaluation report (precision/recall/F1 per category) lives in `evaluation/metrics.md`.

| Metric                    | Score   |
|---------------------------|---------|
| Overall Category Accuracy | **94.2%** |
| Binary Scam Detection     | **97.1%** |

➡️ See the full breakdown in [`evaluation/metrics.md`](evaluation/metrics.md).

---

### Features

- **8 scam categories**: fake cashback, digital arrest, KYC freeze, job scam, lottery scam, govt impersonation, phishing links, and legitimate messages.
- **3 languages**: robust prompts and examples for **Hindi, Hinglish, and English** SMS.
- **Explanations in Hindi**: every alert includes a user-facing Hindi summary and clear red flags.
- **Red-flag extraction**: highlights suspicious UPI IDs, phone numbers, domains, and legal threats.
- **Complaint form pre-fill**: prepares a clean incident summary to paste into `cybercrime.gov.in` and for 1930 call logging.
- **Telegram bot integration**: quick paste-and-check experience for family WhatsApp forwards.
- **Scam evolution tracking**: `agents/investigation/embedding_similarity.py` uses embeddings to show how new templates inherit patterns from older scams.
- **Threat dashboard**: `dashboard/index.html` renders a live India heatmap + scam network view.

---

### Scam Categories

| Category           | Emoji | Description                                                                 |
|--------------------|-------|-----------------------------------------------------------------------------|
| fake_cashback      | 💸    | “Cashback” or “refund” that actually pulls money via collect requests or links |
| digital_arrest     | 🚓    | CBI / police / ED “digital arrest” threats demanding immediate payment      |
| kyc_freeze         | 🧊    | Bank / UPI KYC warnings that threaten account freeze or SIM deactivation    |
| job_scam           | 🧳    | Work-from-home / high-salary jobs that require upfront registration fees    |
| lottery_scam       | 🎰    | KBC / Jio / Dream11 style prizes with processing or tax fees                |
| govt_impersonation | 🏛️    | Fake messages pretending to be from RBI, Income Tax, Customs, or schemes    |
| phishing_link      | 🕸️    | Suspicious links / QR codes to fake portals, APKs, or login pages          |
| legitimate         | ✅    | Normal transactional / personal messages (banks, UPI, friends, deliveries) |

---

### API Usage Example

The public Azure Function exposes a simple JSON API:

```bash
curl -X POST "https://fraudshield-api.azurewebsites.net/api/classify" \
  -H "Content-Type: application/json" \
  -d '{
        "message": "Aapko Rs.1500 cashback mila hai. Collect request approve karein.",
        "source": "cli",
        "sender": "+91-98765-00001"
      }'
```

Example (truncated) JSON response:

```json
{
  "category": "fake_cashback",
  "is_scam": true,
  "confidence": 0.97,
  "language": "Hinglish",
  "red_flags": [
    "UPI collect request to receive cashback",
    "no prior transaction",
    "urgency to approve immediately"
  ],
  "explanation_hi": "Yeh message jhootha cashback ka bahana bana kar aap se paise katwane ki koshish kar raha hai..."
}
```

---

### Setup & Local Development

1. **Clone the repo**

   ```bash
   git clone https://github.com/fraudshield-india/fraudshield-backend.git
   cd fraudshield-backend
   ```

2. **Create virtualenv and install Python dependencies**

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Configure environment variables**

   These are typically set in Azure, but for local development you can export them in your shell:

   ```bash
   export GITHUB_TOKEN="ghp_...your_token..."
   export FRAUDSHIELD_API_URL="https://fraudshield-api.azurewebsites.net/api/classify"
   export TELEGRAM_BOT_TOKEN="your_telegram_bot_token"
   export COSMOS_DB_ENDPOINT="https://fraudshield-cosmosdb.documents.azure.com:443/"
   export COSMOS_DB_KEY="your_cosmos_primary_key"
   ```

4. **Run the Azure Function locally**

   ```bash
   func start
   ```

   This hosts `/api/classify` on `http://localhost:7071/api/classify`.

5. **Optional: run evaluation scaffold**

   ```bash
   pip install pandas scikit-learn requests
   python evaluation/evaluate.py --dry-run          # structure test, no API calls
   python evaluation/evaluate.py --max 12 --delay 10  # safe partial run on GitHub Models
   ```

---

### Deployment (GitHub Actions → Azure Functions)

This repo ships with `.github/workflows/deploy.yml` that:

- Triggers on **push to `main`** or manual **workflow_dispatch**.
- Uses the `AZURE_FUNCTIONAPP_PUBLISH_PROFILE` secret to deploy to the Function App **`fraudshield-api`**.
- Uses `.funcignore` to avoid publishing `dashboard/`, `evaluation/`, and other non-function assets.
- Warms up the app by calling `/api/health` after deployment.

**Required GitHub secret**

| Secret                          | Description                                                   |
|---------------------------------|---------------------------------------------------------------|
| `AZURE_FUNCTIONAPP_PUBLISH_PROFILE` | Publish profile XML from the `fraudshield-api` Function App |

To configure:

1. In Azure Portal, open the **fraudshield-api** Function App.
2. Click **Get publish profile** and download the `.PublishSettings` file.
3. Copy the full XML content.
4. Add it as a new repository secret named `AZURE_FUNCTIONAPP_PUBLISH_PROFILE`.

---

### Team

- **Team:** Boulevard of Secure Dreams  
- **Institute:** MIT Manipal  
- **Competition:** AI Unlocked 2025 — Track 2 (Microsoft Azure)  
- **Mission:** Make “forward to FraudShield” as natural as “forward to family group” for every suspicious UPI SMS in India.

