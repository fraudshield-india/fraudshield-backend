import azure.functions as func
import json
import logging
import os
from openai import AzureOpenAI

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

client = AzureOpenAI(
    api_key=os.environ["AZURE_OPENAI_KEY"],
    api_version="2024-12-01-preview",
    azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
)
MODEL = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "o4-mini")  # Deployment name in Azure AI Foundry

SYSTEM_PROMPT = """You are FraudShield India, an expert UPI fraud detection system.
Analyze messages for fraud patterns common in India. Classify into one of:
fake_cashback, digital_arrest, kyc_freeze, job_scam, lottery_scam,
govt_impersonation, phishing_link, legitimate

Respond ONLY with valid JSON (no markdown, no backticks):
{
  "is_scam": true/false,
  "category": "<category>",
  "confidence": <0.0-1.0>,
  "risk_level": "high/medium/low",
  "explanation_en": "<1-2 sentence English explanation>",
  "explanation_hi": "<1-2 sentence Hindi explanation>",
  "red_flags": ["<flag1>", "<flag2>"],
  "complaint_form": {
    "portal": "cybercrime.gov.in",
    "helpline": "1930",
    "evidence_to_collect": ["screenshot", "sender_id", "transaction_id"]
  }
}"""


def classify_message(message, source="unknown", sender="unknown"):
    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Source: {source}\nSender: {sender}\nMessage: {message}"},
        ],
        max_completion_tokens=500,
    )
    raw = response.choices[0].message.content.strip()
    raw = raw.replace("```json", "").replace("```", "").strip()
    result = json.loads(raw)
    result["message"] = message
    result["source"] = source
    result["sender"] = sender
    return result


@app.route(route="classify", methods=["POST", "OPTIONS"], auth_level=func.AuthLevel.FUNCTION)
def classify(req: func.HttpRequest) -> func.HttpResponse:
    cors_headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, x-functions-key",
        "Content-Type": "application/json",
    }
    if req.method == "OPTIONS":
        return func.HttpResponse(status_code=204, headers=cors_headers)
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(json.dumps({"error": "Invalid JSON"}), status_code=400, headers=cors_headers)
    message = body.get("message", "").strip()
    if not message:
        return func.HttpResponse(json.dumps({"error": "'message' required"}), status_code=400, headers=cors_headers)
    try:
        result = classify_message(message, body.get("source", "unknown"), body.get("sender", "unknown"))
        if result.get("is_scam") and result.get("confidence", 0) > 0.7:
            result["action_required"] = True
            result["report_url"] = "https://cybercrime.gov.in"
            result["helpline"] = "1930"
        else:
            result["action_required"] = False
        return func.HttpResponse(json.dumps(result, ensure_ascii=False), status_code=200, headers=cors_headers)
    except Exception as e:
        logging.exception(e)
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500, headers=cors_headers)


@app.route(route="batch", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def batch_classify(req: func.HttpRequest) -> func.HttpResponse:
    cors_headers = {"Access-Control-Allow-Origin": "*", "Content-Type": "application/json"}
    try:
        body = req.get_json()
        messages = body.get("messages", [])
        if not messages or len(messages) > 20:
            return func.HttpResponse(json.dumps({"error": "Provide 1-20 messages"}), status_code=400, headers=cors_headers)
        results = [classify_message(m.get("message", ""), m.get("source", "batch"), m.get("sender", "unknown")) for m in messages]
        return func.HttpResponse(json.dumps({"results": results, "count": len(results)}, ensure_ascii=False), status_code=200, headers=cors_headers)
    except Exception as e:
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500, headers=cors_headers)


@app.route(route="health", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def health(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps({"status": "ok", "service": "FraudShield India", "model": MODEL}),
        status_code=200,
        headers={"Content-Type": "application/json"},
    )


# ── Telegram Bot ───────────────────────────────────────────────────────────────

import requests as _requests

_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
_FUNCTION_KEY = os.environ.get("FUNCTION_KEY", "")
_API_URL = os.environ.get(
    "FRAUDSHIELD_API_URL",
    "https://fraudshield-functions.azurewebsites.net/api/classify",
)
_TELEGRAM_API = f"https://api.telegram.org/bot{_BOT_TOKEN}"

_SCAM_EMOJI = {
    "fake_cashback": "💰",
    "digital_arrest": "🚔",
    "kyc_freeze": "🏦",
    "job_scam": "💼",
    "lottery_scam": "🎰",
    "govt_impersonation": "🏛️",
    "phishing_link": "🔗",
    "legitimate": "✅",
}

_WELCOME_MSG = """🛡️ <b>FraudShield India में आपका स्वागत है!</b>

मुझे कोई भी संदिग्ध SMS, WhatsApp, या ईमेल message भेजें — मैं तुरंत बताऊंगा कि यह <b>Scam है या नहीं</b>।

<b>Commands:</b>
/start — This message
/help — How to use
/report — How to file a cybercrime complaint

🇮🇳 <i>Protecting India from digital fraud</i>"""

_HELP_MSG = """ℹ️ <b>FraudShield India — Help</b>

<b>How to use:</b>
1. Copy the suspicious message
2. Paste it here and send
3. I'll analyze it in seconds

<b>Helpline:</b> 1930 (National Cyber Crime)
<b>Portal:</b> cybercrime.gov.in"""

_REPORT_MSG = """📋 <b>Cybercrime Complaint कैसे करें?</b>

<b>1. Online:</b> 🌐 cybercrime.gov.in
<b>2. Helpline:</b> 📞 <b>1930</b> (24x7)
<b>3. Local Police:</b> नजदीकी police station

🛡️ <i>FraudShield India आपकी मदद के लिए है!</i>"""


def _send_telegram(chat_id: int, text: str):
    _requests.post(
        f"{_TELEGRAM_API}/sendMessage",
        json={"chat_id": chat_id, "text": text, "parse_mode": "HTML"},
        timeout=10,
    )


def _format_result(result: dict) -> str:
    is_scam = result.get("is_scam", False)
    category = result.get("category", "unknown")
    confidence = result.get("confidence", 0.0)
    explanation_hi = result.get("explanation_hi", "")
    red_flags = result.get("red_flags", [])
    complaint = result.get("complaint_form", {})

    emoji = _SCAM_EMOJI.get(category, "⚠️")
    conf_pct = int(confidence * 100)

    if is_scam:
        verdict = f"🚨 <b>SCAM DETECTED</b> — {emoji} {category.replace('_', ' ').title()}"
    else:
        verdict = "✅ <b>Message appears LEGITIMATE</b>"

    lines = [
        verdict,
        f"📊 Confidence: <b>{conf_pct}%</b>",
        "",
        "🗣️ <b>विवरण (Hindi):</b>",
        f"<i>{explanation_hi}</i>",
    ]

    if red_flags:
        lines += ["", "🚩 <b>Red Flags:</b>"]
        for flag in red_flags:
            lines.append(f"  • {flag}")

    if is_scam and complaint:
        portal = complaint.get("portal", "cybercrime.gov.in")
        helpline = complaint.get("helpline", "1930")
        lines += [
            "",
            "📋 <b>Report करें:</b>",
            f"  🌐 {portal}",
            f"  📞 Helpline: <b>{helpline}</b>",
        ]

    lines += ["", "——————————————————", "🛡️ <i>FraudShield India | MIT Manipal</i>"]
    return "\n".join(lines)


def _handle_telegram_update(update: dict):
    message = update.get("message") or update.get("edited_message")
    if not message:
        return
    chat_id: int = message["chat"]["id"]
    text: str = message.get("text", "").strip()
    if not text:
        _send_telegram(chat_id, "⚠️ Please send a text message to analyze.")
        return
    if text.startswith("/start"):
        _send_telegram(chat_id, _WELCOME_MSG)
        return
    if text.startswith("/help"):
        _send_telegram(chat_id, _HELP_MSG)
        return
    if text.startswith("/report"):
        _send_telegram(chat_id, _REPORT_MSG)
        return

    _send_telegram(chat_id, "🔍 <i>Analyzing message... (please wait ~5s)</i>")
    try:
        headers = {"Content-Type": "application/json"}
        if _FUNCTION_KEY:
            headers["x-functions-key"] = _FUNCTION_KEY
        resp = _requests.post(
            _API_URL,
            json={"message": text, "source": "telegram", "sender": "telegram_user"},
            headers=headers,
            timeout=60,
        )
        resp.raise_for_status()
        result = resp.json()
        _send_telegram(chat_id, _format_result(result))
    except Exception as e:
        logging.error("telegram classify error: %s", e)
        _send_telegram(chat_id, "❌ <b>Analysis failed.</b> Please try again in a moment.")


@app.route(route="telegram", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def telegram_webhook(req: func.HttpRequest) -> func.HttpResponse:
    try:
        update = req.get_json()
        _handle_telegram_update(update)
    except Exception as e:
        logging.error("webhook error: %s", e)
    return func.HttpResponse("OK", status_code=200)
