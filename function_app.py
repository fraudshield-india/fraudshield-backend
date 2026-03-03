import azure.functions as func
import json
import logging
import os
import requests
import threading
from openai import OpenAI

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# ── GitHub Models client (lazy-initialised to avoid startup crash) ────────────
MODEL = "gpt-4o-mini"
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
  "risk_level": "high/medium/low",
  "explanation_en": "<brief explanation in English>",
  "explanation_hi": "<brief explanation in Hindi>",
  "red_flags": ["<flag1>", "<flag2>"]
}"""

RESPONSE_AGENT_PROMPT = """You are FraudShield India's Response Agent. Given a scam classification result and the original message, generate a personalized complaint and action plan for the victim.

Respond ONLY with valid JSON (no markdown, no backticks) in this exact schema:
{
  "complaint_category": "<specific NCRP category for this scam, e.g. 'Online Financial Fraud > Impersonation of Government Official'>",
  "complaint_draft_en": "<2-3 sentence ready-to-file complaint in English including sender number and scam details>",
  "complaint_draft_hi": "<same complaint in Hindi>",
  "evidence_to_collect": ["<specific evidence item 1>", "<specific evidence item 2>"],
  "immediate_steps": ["<step 1>", "<step 2>", "<step 3>", "<step 4>"],
  "portal": "cybercrime.gov.in",
  "helpline": "1930"
}

Use the scam category, message content, and sender info to make the response specific and actionable.
Always include the sender number in complaint drafts.
The immediate_steps should be 3-5 specific actionable steps relevant to this exact scam type.
The evidence_to_collect should list specific items relevant to this scam type."""


def _get_fallback_complaint_form(category: str, sender: str) -> dict:
    """Return a basic hardcoded complaint form as fallback if the Response Agent fails."""
    return {
        "portal": "cybercrime.gov.in",
        "helpline": "1930",
        "complaint_category": "Online Financial Fraud",
        "complaint_draft_en": f"I received a fraudulent message from {sender}. This appears to be a {category.replace('_', ' ')} scam. Please investigate.",
        "complaint_draft_hi": f"मुझे {sender} से एक धोखाधड़ी संदेश प्राप्त हुआ। यह {category.replace('_', ' ')} घोटाला प्रतीत होता है। कृपया जांच करें।",
        "evidence_to_collect": ["Screenshot of the message", "Sender phone number or ID", "Any transaction IDs if applicable"],
        "immediate_steps": ["Do NOT share any OTP or personal information", "Block the sender immediately", "File complaint at cybercrime.gov.in", "Call 1930 national cybercrime helpline"],
    }


def generate_response_complaint(category: str, message: str, sender: str, red_flags: list) -> dict:
    """Call the Response Agent (GPT-4o-mini) to generate a customized complaint and action plan."""
    user_content = (
        f"Scam Category: {category}\n"
        f"Sender: {sender}\n"
        f"Red Flags: {', '.join(red_flags)}\n"
        f"Original Message: {message}"
    )

    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    response = _get_client().chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": RESPONSE_AGENT_PROMPT},
            {"role": "user", "content": user_content},
        ],
        temperature=0.1,
        max_tokens=500,
    )

    raw = response.choices[0].message.content.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return json.loads(raw.strip())

def classify_message(message: str, source: str = "unknown", sender: str = "unknown") -> dict:
    """Call GitHub Models (o4-mini) to classify a UPI fraud message."""
    user_content = f"Source: {source}\nSender: {sender}\nMessage: {message}" 

    response = _get_client().chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        temperature=0.1,
        max_tokens=512,
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

        # Response Agent: generate customized complaint if scam detected
        if result.get("is_scam") and result.get("confidence", 0) > 0.7:
            try:
                complaint = generate_response_complaint(
                    category=result.get("category", "unknown"),
                    message=message,
                    sender=sender,
                    red_flags=result.get("red_flags", []),
                )
                result["complaint_form"] = complaint
            except Exception as resp_exc:
                logging.warning("Response Agent failed, using fallback: %s", resp_exc)
                result["complaint_form"] = _get_fallback_complaint_form(
                    result.get("category", "unknown"), sender
                )

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


# ── /api/dashboard-data ───────────────────────────────────────────────────────
@app.route(route="dashboard-data", methods=["GET"])
def dashboard_data(req: func.HttpRequest) -> func.HttpResponse:
    """Return live scam feed, network graph data, and hotspot data for the dashboard."""
    cors_headers = {
        "Access-Control-Allow-Origin": "*",
        "Content-Type": "application/json",
    }
    # Returns empty lists when no live data is available; the dashboard uses its
    # hardcoded fallback in that case.
    payload = {
        "feed": [],
        "network": {"nodes": [], "edges": []},
        "hotspots": [],
    }
    return func.HttpResponse(
        json.dumps(payload, ensure_ascii=False),
        status_code=200,
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
    explanation: str = result.get("explanation_hi", result.get("explanation_hindi", ""))
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


def _send_telegram_message(bot_token: str, chat_id, text: str) -> None:
    """Send a message to a Telegram chat."""
    try:
        requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json={"chat_id": chat_id, "text": text, "parse_mode": "HTML"},
            timeout=10,
        )
    except Exception as e:
        logging.error("Failed to send Telegram message to %s: %s", chat_id, e)


def _process_telegram_update(bot_token: str, update: dict) -> None:
    """Process a Telegram update in a background thread."""
    try:
        message = update.get("message") or update.get("edited_message")
        if not message:
            return

        chat_id = message["chat"]["id"]
        text = (message.get("text") or "").strip()

        if not text:
            return

        # /start command
        if text.startswith("/start"):
            _send_telegram_message(bot_token, chat_id, WELCOME_MSG)
            return

        # Acknowledge receipt immediately so the user knows we're working
        _send_telegram_message(bot_token, chat_id, "🔍 <i>Analyzing your message...</i>")

        # Classify the message
        try:
            result = classify_message(text, "telegram", "telegram_user")
            reply = _format_telegram_result(result)
        except Exception as classify_err:
            logging.exception("Telegram classify error: %s", classify_err)
            reply = "❌ <b>Analysis failed.</b> Please try again in a moment."

        _send_telegram_message(bot_token, chat_id, reply)

    except Exception as e:
        logging.exception("Telegram process error: %s", e)


@app.route(route="telegram", methods=["POST"])
def telegram_webhook(req: func.HttpRequest) -> func.HttpResponse:
    """Telegram webhook endpoint — returns 200 immediately and processes async."""
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")

    if not bot_token:
        logging.error("TELEGRAM_BOT_TOKEN is not configured")
        return func.HttpResponse("OK", status_code=200)

    try:
        update = req.get_json()
        # Fire-and-forget: respond to Telegram in <1 s, process in background
        threading.Thread(target=_process_telegram_update, args=(bot_token, update)).start()
    except Exception as e:
        logging.exception("Telegram webhook error: %s", e)

    return func.HttpResponse("OK", status_code=200)
