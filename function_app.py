import azure.functions as func
import json
import logging
import os
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
@app.route(route="telegram", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def telegram_webhook(req: func.HttpRequest) -> func.HttpResponse:
    import requests as req_lib
    import os, logging, threading

    BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    API_URL = "https://fraudshield-api.azurewebsites.net/api/classify"
    TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"

    def send(chat_id, text):
        req_lib.post(f"{TELEGRAM_API}/sendMessage",
            json={"chat_id": chat_id, "text": text, "parse_mode": "HTML"}, timeout=10)

    def process(update):
        try:
            message = update.get("message") or update.get("edited_message")
            if not message:
                return
            chat_id = message["chat"]["id"]
            text = message.get("text", "").strip()
            if not text:
                return
            if text.startswith("/start"):
                send(chat_id, "🛡️ <b>FraudShield India</b>\n\nकोई भी suspicious message भेजें!\nSend any suspicious SMS to check if it's a scam.")
                return
            send(chat_id, "🔍 <i>Analyzing... (~10 seconds)</i>")
            result = req_lib.post(API_URL,
                json={"message": text, "source": "telegram", "sender": "telegram_user"},
                timeout=55).json()
            is_scam = result.get("is_scam", False)
            category = result.get("category", "unknown")
            confidence = int(result.get("confidence", 0) * 100)
            explanation = result.get("explanation_hindi") or result.get("explanation_hi", "")
            red_flags = result.get("red_flags", [])
            verdict = f"🚨 <b>SCAM DETECTED</b> — {category.replace('_',' ').title()}" if is_scam else "✅ <b>LEGITIMATE MESSAGE</b>"
            flags = "\n".join(f"  • {f}" for f in red_flags) or "None"
            reply = f"{verdict}\n📊 Confidence: <b>{confidence}%</b>\n\n🗣️ <b>विवरण:</b>\n<i>{explanation}</i>\n\n🚩 <b>Red Flags:</b>\n{flags}"
            if is_scam:
                reply += "\n\n📞 Report: <b>1930</b> | cybercrime.gov.in"
            send(chat_id, reply)
        except Exception as e:
            logging.error(f"process error: {e}")

    try:
        update = req.get_json()
        threading.Thread(target=process, args=(update,)).start()
    except Exception as e:
        logging.error(f"webhook error: {e}")
    return func.HttpResponse("OK", status_code=200)
