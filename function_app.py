import azure.functions as func
import json
import logging
import os
import requests
from openai import OpenAI

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# ── GitHub Models client (lazy-initialised to avoid startup crash) ────────────
MODEL = "o4-mini"  # reasoning model — no temperature/response_format params
_client: OpenAI | None = None

def _get_client() -> OpenAI:
    """Return a cached OpenAI client; raises RuntimeError if GITHUB_TOKEN is unset."""
    global _client
    if _client is None:
        token = os.getenv("GITHUB_TOKEN")
        if not token:
            raise RuntimeError(
                "GITHUB_TOKEN application setting is not configured. "
                "Add it in Azure Portal → Configuration → Application Settings."
            )
        _client = OpenAI(
            base_url=os.getenv("OPENAI_BASE_URL", "https://models.inference.ai.azure.com"),
            api_key=token,
        )
    return _client

SYSTEM_PROMPT = """You are FraudShield India, an expert UPI fraud detection system.
Analyze messages for fraud patterns common in India. Classify into one of:
fake_cashback, digital_arrest, kyc_freeze, job_scam, lottery_scam,
govt_impersonation, phishing_link, legitimate

Respond ONLY with valid JSON in this exact schema:
{
  "is_scam": true/false,
  "category": "<category>",
  "confidence": <0.0-1.0>,
  "explanation_hindi": "<brief explanation in Hindi>",
  "red_flags": ["<flag1>", "<flag2>"],
  "complaint_form": {
    "portal": "cybercrime.gov.in",
    "helpline": "1930",
    "evidence_to_collect": ["screenshot", "sender_id", "transaction_id"]
  }
}"""

def classify_message(message: str, source: str = "unknown", sender: str = "unknown") -> dict:
    """Call GitHub Models (o4-mini) to classify a UPI fraud message."""
    user_content = f"Source: {source}\nSender: {sender}\nMessage: {message}" 

    response = _get_client().chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        max_completion_tokens=512,
    )

    # o4-mini may wrap output in ```json ... ``` — strip it just in case
    raw = response.choices[0].message.content.strip()
    if raw.startswith("```"):
        raw = raw.split("```") [1]
        if raw.startswith("json"):
            raw = raw[4:]
    result = json.loads(raw.strip())
    result["message"] = message
    result["source"] = source
    result["sender"] = sender
    return result


# ── /api/classify ─────────────────────────────────────────────────────────────
@app.route(route="classify", methods=["POST", "OPTIONS"])
def classify(req: func.HttpRequest) -> func.HttpResponse:
    """Main fraud classification endpoint."""

    cors_headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Content-Type": "application/json",
    }

    if req.method == "OPTIONS":
        return func.HttpResponse(status_code=204, headers=cors_headers)

    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON body"}),
            status_code=400,
            headers=cors_headers,
        )

    message = body.get("message", "").strip()
    if not message:
        return func.HttpResponse(
            json.dumps({"error": "Field 'message' is required"}),
            status_code=400,
            headers=cors_headers,
        )

    source = body.get("source", "unknown")
    sender = body.get("sender", "unknown")

    try:
        result = classify_message(message, source, sender)
        logging.info("Classified [%s] → %s (%.2f)", source, result.get("category"), result.get("confidence", 0))
        return func.HttpResponse(
            json.dumps(result, ensure_ascii=False),
            status_code=200,
            headers=cors_headers,
        )
    except Exception as exc:
        logging.exception("Classification error: %s", exc)
        return func.HttpResponse(
            json.dumps({"error": "Classification failed", "detail": str(exc)}),
            status_code=500,
            headers=cors_headers,
        )


# ── /api/health ───────────────────────────────────────────────────────────────
@app.route(route="health", methods=["GET"])
def health(req: func.HttpRequest) -> func.HttpResponse:
    token_configured = bool(os.environ.get("GITHUB_TOKEN"))
    return func.HttpResponse(
        json.dumps({
            "status": "ok",
            "service": "FraudShield India",
            "model": MODEL,
            "github_token_configured": token_configured,
        }),
        status_code=200,
        headers={"Content-Type": "application/json"},
    )


# ── /api/batch ────────────────────────────────────────────────────────────────
@app.route(route="batch", methods=["POST"])
def batch_classify(req: func.HttpRequest) -> func.HttpResponse:
    """Classify up to 20 messages in one call (used by evaluation script)."""
    cors_headers = {
        "Access-Control-Allow-Origin": "*",
        "Content-Type": "application/json",
    }
    try:
        body = req.get_json()
        messages = body.get("messages", [])
        if not messages or len(messages) > 20:
            return func.HttpResponse(
                json.dumps({"error": "Provide 1–20 messages"}),
                status_code=400,
                headers=cors_headers,
            )
        results = []
        for item in messages:
            try:
                r = classify_message(
                    item.get("message", ""),
                    item.get("source", "batch"),
                    item.get("sender", "unknown"),
                )
                results.append(r)
            except Exception as e:
                results.append({"error": str(e), "message": item.get("message", "")})

        return func.HttpResponse(
            json.dumps({"results": results, "count": len(results)}, ensure_ascii=False),
            status_code=200,
            headers=cors_headers,
        )
    except Exception as exc:
        return func.HttpResponse(
            json.dumps({"error": str(exc)}),
            status_code=500,
            headers=cors_headers,
        )


# ── /api/telegram ─────────────────────────────────────────────────────────────

WELCOME_MSG = """🛡️ <b>FraudShield India में आपका स्वागत है!</b>

मुझे कोई भी संदिग्ध SMS, WhatsApp, या ईमेल message भेजें — मैं तुरंत बताऊंगा कि यह <b>Scam है या नहीं</b>।

<b>Send me any suspicious message to check if it's a scam!</b>

🇮🇳 <i>Protecting India from digital fraud</i>"""


SCAM_EMOJI = {
    "fake_cashback": "💰",
    "digital_arrest": "🚔",
    "kyc_freeze": "🏦",
    "job_scam": "💼",
    "lottery_scam": "🎰",
    "govt_impersonation": "🏛️",
    "phishing_link": "🔗",
    "legitimate": "✅",
}


def _format_telegram_result(result: dict) -> str:
    is_scam: bool = result.get("is_scam", False)
    category: str = result.get("category", "unknown")
    confidence: float = result.get("confidence", 0.0)
    explanation: str = result.get("explanation_hindi", "")
    red_flags: list = result.get("red_flags", [])
    complaint: dict = result.get("complaint_form", {})

    emoji = SCAM_EMOJI.get(category, "⚠️")
    conf_pct = int(confidence * 100)

    if is_scam:
        verdict = f"🚨 <b>SCAM DETECTED</b> — {emoji} {category.replace('_', ' ').title()}"
    else:
        verdict = "✅ <b>Message appears LEGITIMATE</b>"

    lines = [
        verdict,
        f"📊 Confidence: <b>{conf_pct}%</b>",
        "",
        f"🗣️ <b>विवरण (Hindi):</b>",
        f"<i>{explanation}</i>",
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
            "📋 <b>Report करें (File Complaint):</b>",
            f"  🌐 {portal}",
            f"  📞 Helpline: <b>{helpline}</b>",
        ]

    lines += [
        "",
        "——————————————————",
        "🛡️ <i>FraudShield India | MIT Manipal</i>",
    ]

    return "\n".join(lines)


@app.route(route="telegram", methods=["POST"])
def telegram_webhook(req: func.HttpRequest) -> func.HttpResponse:
    """Telegram webhook endpoint — always returns 200 to avoid retries."""
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")

    if not bot_token:
        logging.error("TELEGRAM_BOT_TOKEN is not configured")
        return func.HttpResponse("OK", status_code=200)

    try:
        update = req.get_json()
        message = update.get("message") or update.get("edited_message")
        if not message:
            return func.HttpResponse("OK", status_code=200)

        chat_id = message["chat"]["id"]
        text = (message.get("text") or "").strip()

        if not text:
            return func.HttpResponse("OK", status_code=200)

        # /start command
        if text.startswith("/start"):
            requests.post(
                f"https://api.telegram.org/bot{bot_token}/sendMessage",
                json={"chat_id": chat_id, "text": WELCOME_MSG, "parse_mode": "HTML"},
                timeout=10,
            )
            return func.HttpResponse("OK", status_code=200)

        # All other text — classify directly (no external HTTP hop)
        try:
            result = classify_message(text, "telegram", "telegram_user")
            reply = _format_telegram_result(result)
        except Exception as classify_err:
            logging.exception("Telegram classify error: %s", classify_err)
            reply = "❌ <b>Analysis failed.</b> Please try again in a moment."

        requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json={"chat_id": chat_id, "text": reply, "parse_mode": "HTML"},
            timeout=10,
        )

    except Exception as e:
        logging.exception("Telegram webhook error: %s", e)

    return func.HttpResponse("OK", status_code=200)
