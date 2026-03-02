# FraudShield — Detection Agent

Classifies UPI messages into fraud categories using a language model.

## Setup

Copy the root `.env.example` to `.env` in the repository root and fill in your credentials:

```bash
cp ../../.env.example ../../.env
# Edit ../../.env with your GITHUB_TOKEN, COSMOS_DB_ENDPOINT, etc.
```

## Usage

```bash
pip install -r requirements.txt
python detection_agent.py
```
