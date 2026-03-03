import azure.functions as func
import datetime
import json
import logging
import os
import re
from openai import AzureOpenAI
from gremlin_python.driver import client as gremlin_driver, serializer
from agents.language_agent import analyze_message

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# ── Azure OpenAI client (lazy-initialised to avoid startup crash) ─────────────
MODEL = "o4-mini"
_client: AzureOpenAI | None = None

def _get_client() -> AzureOpenAI:
    global _client
    if _client is None:
        endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        key = os.getenv("AZURE_OPENAI_KEY")
        if not endpoint or not key:
            raise RuntimeError(
                "AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_KEY application settings are not configured. "
                "Add them in Azure Portal → Configuration → Application Settings."
            )
        _client = AzureOpenAI(
            azure_endpoint=endpoint,
            api_key=key,
            api_version="2024-12-01-preview",
        )
    return _client


RESPONSE_SYSTEM_PROMPT = """You are FraudShield India Response Agent.
Generate a formal cybercrime complaint for the Indian National Cybercrime Reporting Portal.
Respond ONLY with valid JSON in this exact schema:
{
  "complaint_category": "<category path>",
  "complaint_draft_en": "<formal complaint in English>",
  "complaint_draft_hi": "<formal complaint in Hindi>",
  "evidence_to_collect": ["<item1>", "<item2>"],
  "immediate_steps": ["<step1>", "<step2>"],
  "portal": "cybercrime.gov.in",
  "helpline": "1930"
}"""


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


def lookup_graph(upi_id: str) -> dict:
    """Look up a UPI ID in the Cosmos DB scam graph."""
    try:
        endpoint = os.getenv("COSMOS_DB_ENDPOINT", "")
        key = os.getenv("COSMOS_DB_KEY", "")
        if not endpoint or not key:
            return {}
        endpoint = (
            endpoint.replace("wss://", "")
            .replace("https://", "")
            .replace(":443/", "")
            .replace(":443", "")
            .rstrip("/")
        )
        gc = gremlin_driver.Client(
            f"wss://{endpoint}:443/", "g",
            username="/dbs/FraudShieldDB/colls/ScamNetwork",
            password=key,
            message_serializer=serializer.GraphSONSerializersV2d0(),
        )
        result = gc.submitAsync(
            "g.V().hasLabel('UpiId').has('vpa', vpa).valueMap()",
            bindings={"vpa": upi_id}
        ).result(timeout=10)
        data = result.all().result()
        gc.close()
        if data:
            v = data[0]
            return {
                "found_in_database": True,
                "report_count": v.get("report_count", [0])[0],
                "category": v.get("category", ["unknown"])[0],
                "status": v.get("status", ["unknown"])[0],
                "state": v.get("state", ["unknown"])[0],
                "estimated_victims": v.get("estimated_victims", [0])[0],
            }
        return {"found_in_database": False}
    except Exception as e:
        logging.warning("Graph lookup failed: %s", e)
        return {}


def upsert_scam_upi(upi_id: str, category: str, source: str) -> None:
    """Save or update a scam UPI ID in the Cosmos DB Gremlin graph."""
    try:
        endpoint = os.getenv("COSMOS_DB_ENDPOINT", "")
        key = os.getenv("COSMOS_DB_KEY", "")
        if not endpoint or not key:
            return
        endpoint = (
            endpoint.replace("wss://", "")
            .replace("https://", "")
            .replace(":443/", "")
            .replace(":443", "")
            .rstrip("/")
        )
        gc = gremlin_driver.Client(
            f"wss://{endpoint}:443/", "g",
            username="/dbs/FraudShieldDB/colls/ScamNetwork",
            password=key,
            message_serializer=serializer.GraphSONSerializersV2d0(),
        )
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        result = gc.submitAsync(
            "g.V().hasLabel('UpiId').has('vpa', vpa).valueMap()",
            bindings={"vpa": upi_id}
        ).result(timeout=10)
        data = result.all().result()
        if data:
            current_count = data[0].get("report_count", [0])[0]
            gc.submitAsync(
                "g.V().hasLabel('UpiId').has('vpa', vpa)"
                ".property('report_count', cnt).property('last_reported', ts)",
                bindings={"vpa": upi_id, "cnt": current_count + 1, "ts": now}
            ).result(timeout=10)
        else:
            gc.submitAsync(
                "g.addV('UpiId').property('vpa', vpa).property('report_count', 1)"
                ".property('category', cat).property('status', 'reported')"
                ".property('state', 'unknown').property('estimated_victims', 1)"
                ".property('first_reported', ts).property('last_reported', ts)"
                ".property('source', src)",
                bindings={"vpa": upi_id, "cat": category, "ts": now, "src": source}
            ).result(timeout=10)
        gc.close()
    except Exception as e:
        logging.warning("Graph upsert failed: %s", e)


def _get_fallback_complaint_form(category: str, sender: str) -> dict:
    """Return a static fallback complaint form without calling OpenAI."""
    cat_hr = category.replace("_", " ")
    return {
        "portal": "cybercrime.gov.in",
        "helpline": "1930",
        "complaint_category": f"Online Financial Fraud > {cat_hr.title()}",
        "complaint_draft_en": (
            f"I received a fraudulent {cat_hr} message from {sender}. "
            "I am reporting this to seek appropriate action."
        ),
        "complaint_draft_hi": (
            f"मुझे {sender} से एक फर्जी {cat_hr} संदेश प्राप्त हुआ। "
            "मैं उचित कार्रवाई के लिए इसकी रिपोर्ट कर रहा हूं।"
        ),
        "evidence_to_collect": ["Screenshot of the message", "Sender ID", "Transaction ID if any"],
        "immediate_steps": ["Do NOT transfer any money", "Block the sender", "Report to cybercrime.gov.in"],
    }


def generate_response_complaint(category: str, message: str, sender: str, red_flags: list) -> dict:
    """Call Azure OpenAI (o4-mini) to generate a detailed cybercrime complaint form."""
    user_content = (
        f"Scam Category: {category}\nSender: {sender}\n"
        f"Message: {message}\nRed Flags: {', '.join(red_flags)}"
    )
    response = _get_client().chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": RESPONSE_SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        max_completion_tokens=512,
    )
    raw = response.choices[0].message.content.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return json.loads(raw.strip())


def classify_message(message: str, source: str = "unknown", sender: str = "unknown") -> dict:
    """Call Azure OpenAI (o4-mini) to classify a UPI fraud message."""
    user_content = f"Source: {source}\nSender: {sender}\nMessage: {message}"

    response = _get_client().chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        max_completion_tokens=512,
    )

    raw = response.choices[0].message.content.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    result = json.loads(raw.strip())
    result["message"] = message
    result["source"] = source
    result["sender"] = sender

    # ── INVESTIGATION: Cosmos DB graph lookup + upsert ──
    if result.get("is_scam"):
        upi_pattern = re.findall(r'[\w.\-]+@[\w]+', message)
        if upi_pattern:
            graph_data = lookup_graph(upi_pattern[0])
            if graph_data:
                result["graph_investigation"] = graph_data
            upsert_scam_upi(upi_pattern[0], result.get("category", "unknown"), source)

    return result


# ── /api/classify ─────────────────────────────────────────────────────────────
@app.route(route="classify", methods=["POST", "OPTIONS"])
def classify(req: func.HttpRequest) -> func.HttpResponse:
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

        if result.get("is_scam") and result.get("confidence", 0) >= 0.7:
            # Language analysis
            try:
                lang_data = analyze_message(message)
                if lang_data:
                    result.update(lang_data)
            except Exception as lang_exc:
                logging.warning("Language analysis failed: %s", lang_exc)

            # Complaint form generation
            try:
                complaint = generate_response_complaint(
                    result.get("category", "unknown"),
                    message,
                    sender,
                    result.get("red_flags", []),
                )
            except Exception as resp_exc:
                logging.warning("Response agent failed, using fallback: %s", resp_exc)
                complaint = _get_fallback_complaint_form(result.get("category", "unknown"), sender)
            result["complaint_form"] = complaint

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


# ── /api/analyze ──────────────────────────────────────────────────────────────
@app.route(route="analyze", methods=["POST"])
def analyze(req: func.HttpRequest) -> func.HttpResponse:
    cors_headers = {
        "Access-Control-Allow-Origin": "*",
        "Content-Type": "application/json",
    }
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

    try:
        result = analyze_message(message)
        return func.HttpResponse(
            json.dumps(result, ensure_ascii=False),
            status_code=200,
            headers=cors_headers,
        )
    except Exception as exc:
        logging.exception("Language analysis error: %s", exc)
        return func.HttpResponse(
            json.dumps({"error": "Analysis failed", "detail": str(exc)}),
            status_code=500,
            headers=cors_headers,
        )


# ── /api/health ───────────────────────────────────────────────────────────────
@app.route(route="health", methods=["GET"])
def health(req: func.HttpRequest) -> func.HttpResponse:
    azure_openai_configured = bool(os.environ.get("AZURE_OPENAI_ENDPOINT")) and bool(os.environ.get("AZURE_OPENAI_KEY"))
    cosmos_configured = bool(os.environ.get("COSMOS_DB_ENDPOINT")) and bool(os.environ.get("COSMOS_DB_KEY"))
    return func.HttpResponse(
        json.dumps({
            "status": "ok",
            "service": "FraudShield India",
            "model": MODEL,
            "azure_openai_configured": azure_openai_configured,
            "cosmos_db_configured": cosmos_configured,
        }),
        status_code=200,
        headers={"Content-Type": "application/json"},
    )


# ── /api/batch ────────────────────────────────────────────────────────────────
@app.route(route="batch", methods=["POST"])
def batch_classify(req: func.HttpRequest) -> func.HttpResponse:
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
    import threading

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
            graph = result.get("graph_investigation", {})
            verdict = f"🚨 <b>SCAM DETECTED</b> — {category.replace('_',' ').title()}" if is_scam else "✅ <b>LEGITIMATE MESSAGE</b>"
            flags = "\n".join(f"  • {f}" for f in red_flags) or "None"
            reply = f"{verdict}\n📊 Confidence: <b>{confidence}%</b>\n\n🗣️ <b>विवरण:</b>\n<i>{explanation}</i>\n\n🚩 <b>Red Flags:</b>\n{flags}"
            if graph.get("found_in_database"):
                reply += f"\n\n🔍 <b>Database Match:</b>\n  • Reports: {graph.get('report_count', 0)}\n  • Victims: ~{graph.get('estimated_victims', 0)}\n  • State: {graph.get('state', 'Unknown')}\n  • Status: {graph.get('status', 'Unknown')}"
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

