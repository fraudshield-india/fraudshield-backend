import azure.functions as func
import json
import logging
import os
import re
import uuid
import datetime
from collections import defaultdict
from openai import AzureOpenAI
from gremlin_python.driver import client as gremlin_driver, serializer

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# ── Azure OpenAI client ───────────────────────────────────────────────────────
MODEL = "o4-mini"
_client: AzureOpenAI | None = None

def _get_client() -> AzureOpenAI:
    global _client
    if _client is None:
        endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        key = os.getenv("AZURE_OPENAI_KEY")
        if not endpoint or not key:
            raise RuntimeError(
                "AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_KEY are not configured. "
                "Add them in Azure Portal → Configuration → Application Settings."
            )
        _client = AzureOpenAI(
            azure_endpoint=endpoint,
            api_key=key,
            api_version="2024-12-01-preview",
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


# ── City coordinates for map tracking ────────────────────────────────────────
CITY_COORDS = {
    "Mumbai":        (19.076,  72.8777),
    "Delhi":         (28.6139, 77.209),
    "Bangalore":     (12.9716, 77.5946),
    "Bengaluru":     (12.9716, 77.5946),
    "Hyderabad":     (17.385,  78.4867),
    "Chennai":       (13.0827, 80.2707),
    "Kolkata":       (22.5726, 88.3639),
    "Pune":          (18.5204, 73.8567),
    "Ahmedabad":     (23.0225, 72.5714),
    "Jaipur":        (26.9124, 75.7873),
    "Lucknow":       (26.8467, 80.9462),
    "Chandigarh":    (30.7333, 76.7794),
    "Bhopal":        (23.2599, 77.4126),
    "Patna":         (25.6093, 85.1376),
    "Kochi":         (9.9312,  76.2673),
    "Guwahati":      (26.1445, 91.7362),
    "Manipal":       (13.3525, 74.786),
    "Surat":         (21.1702, 72.8311),
    "Nagpur":        (21.1458, 79.0882),
    "Indore":        (22.7196, 75.8577),
    "Visakhapatnam": (17.6868, 83.2185),
    "Noida":         (28.5355, 77.391),
    "Gurgaon":       (28.4595, 77.0266),
}

SEED_REPORTS = [
    {"city": "Mumbai",     "lat": 19.076,  "lng": 72.8777, "reports": 847, "topScam": "fake_cashback"},
    {"city": "Delhi",      "lat": 28.6139, "lng": 77.209,  "reports": 723, "topScam": "digital_arrest"},
    {"city": "Bangalore",  "lat": 12.9716, "lng": 77.5946, "reports": 534, "topScam": "job_scam"},
    {"city": "Hyderabad",  "lat": 17.385,  "lng": 78.4867, "reports": 412, "topScam": "kyc_freeze"},
    {"city": "Chennai",    "lat": 13.0827, "lng": 80.2707, "reports": 389, "topScam": "phishing_link"},
    {"city": "Kolkata",    "lat": 22.5726, "lng": 88.3639, "reports": 298, "topScam": "lottery_scam"},
    {"city": "Pune",       "lat": 18.5204, "lng": 73.8567, "reports": 267, "topScam": "fake_cashback"},
    {"city": "Ahmedabad",  "lat": 23.0225, "lng": 72.5714, "reports": 234, "topScam": "govt_impersonation"},
    {"city": "Jaipur",     "lat": 26.9124, "lng": 75.7873, "reports": 198, "topScam": "digital_arrest"},
    {"city": "Lucknow",    "lat": 26.8467, "lng": 80.9462, "reports": 176, "topScam": "kyc_freeze"},
    {"city": "Chandigarh", "lat": 30.7333, "lng": 76.7794, "reports": 145, "topScam": "job_scam"},
    {"city": "Bhopal",     "lat": 23.2599, "lng": 77.4126, "reports": 123, "topScam": "phishing_link"},
    {"city": "Patna",      "lat": 25.6093, "lng": 85.1376, "reports": 156, "topScam": "lottery_scam"},
    {"city": "Kochi",      "lat":  9.9312, "lng": 76.2673, "reports":  98, "topScam": "fake_cashback"},
    {"city": "Guwahati",   "lat": 26.1445, "lng": 91.7362, "reports":  87, "topScam": "digital_arrest"},
    {"city": "Manipal",    "lat": 13.3525, "lng": 74.786,  "reports":  45, "topScam": "job_scam"},
]


# ── Cosmos DB helpers ─────────────────────────────────────────────────────────
def _cosmos_client():
    """Return a connected Gremlin client or raise."""
    endpoint = os.getenv("COSMOS_DB_ENDPOINT", "")
    key = os.getenv("COSMOS_DB_KEY", "")
    if not endpoint or not key:
        raise RuntimeError("COSMOS_DB_ENDPOINT / COSMOS_DB_KEY not configured")
    endpoint = (
        endpoint.replace("wss://", "").replace("https://", "")
        .replace(":443/", "").replace(":443", "").rstrip("/")
    )
    return gremlin_driver.Client(
        f"wss://{endpoint}:443/", "g",
        username="/dbs/FraudShieldDB/colls/ScamNetwork",
        password=key,
        message_serializer=serializer.GraphSONSerializersV2d0(),
    )


def _detect_city(text: str) -> str:
    """Keyword-based city detection from message text."""
    text_lower = text.lower()
    for city in CITY_COORDS:
        if city.lower() in text_lower:
            return city
    return "Unknown"


def _log_report_vertex(category: str, city: str, sender: str = "unknown"):
    """Write a Report vertex to Cosmos DB for /api/reports aggregation."""
    try:
        gc = _cosmos_client()
        gc.submitAsync(
            "g.addV('Report')"
            ".property('id', rid)"
            ".property('category', cat)"
            ".property('city', city)"
            ".property('sender', sender)"
            ".property('timestamp', ts)",
            bindings={
                "rid":    str(uuid.uuid4()),
                "cat":    category,
                "city":   city,
                "sender": sender,
                "ts":     datetime.datetime.utcnow().isoformat(),
            }
        ).result(timeout=10)
        gc.close()
    except Exception as e:
        logging.warning("Failed to log Report vertex: %s", e)


def lookup_graph(upi_id: str) -> dict:
    """Look up a UPI ID in the Cosmos DB scam graph."""
    try:
        gc = _cosmos_client()
        result = gc.submitAsync(
            "g.V().hasLabel('UpiId').has('vpa', vpa).valueMap()",
            bindings={"vpa": upi_id}
        ).result(timeout=10)
        data = result.all().result()
        gc.close()
        if data:
            v = data[0]
            return {
                "found_in_database":  True,
                "report_count":       v.get("report_count",       [0])[0],
                "category":           v.get("category",           ["unknown"])[0],
                "status":             v.get("status",             ["unknown"])[0],
                "state":              v.get("state",              ["unknown"])[0],
                "estimated_victims":  v.get("estimated_victims",  [0])[0],
            }
        return {"found_in_database": False}
    except Exception as e:
        logging.warning("Graph lookup failed: %s", e)
        return {}


def get_reports_from_cosmos() -> dict | None:
    """Aggregate Report vertices from Cosmos DB for the map."""
    try:
        gc = _cosmos_client()
        result = gc.submitAsync(
            "g.V().hasLabel('Report').valueMap('category','city','timestamp').limit(500)"
        ).result(timeout=10)
        data = result.all().result()
        gc.close()

        if not data:
            return None

        city_data = defaultdict(lambda: {"reports": 0, "categories": defaultdict(int)})
        total = 0
        scam_count = 0
        category_totals = defaultdict(int)
        recent = []

        for v in data:
            cat  = v.get("category",  ["unknown"])[0] if isinstance(v.get("category"),  list) else v.get("category",  "unknown")
            city = v.get("city",      ["Unknown"])[0] if isinstance(v.get("city"),      list) else v.get("city",      "Unknown")
            ts   = v.get("timestamp", [""])[0]        if isinstance(v.get("timestamp"), list) else v.get("timestamp", "")

            total += 1
            if cat != "legitimate":
                scam_count += 1
                city_data[city]["reports"] += 1
                city_data[city]["categories"][cat] += 1
                category_totals[cat] += 1
                recent.append({"city": city, "category": cat, "timestamp": ts})

        cities = []
        for city_name, cdata in city_data.items():
            coords = CITY_COORDS.get(city_name)
            if not coords:
                continue
            top_scam = max(cdata["categories"], key=cdata["categories"].get) if cdata["categories"] else "unknown"
            cities.append({
                "city":    city_name,
                "lat":     coords[0],
                "lng":     coords[1],
                "reports": cdata["reports"],
                "topScam": top_scam,
            })
        cities.sort(key=lambda x: x["reports"], reverse=True)

        return {
            "total":      total,
            "scam_count": scam_count,
            "cities":     cities if cities else None,
            "categories": dict(category_totals),
            "recent":     sorted(recent, key=lambda x: x.get("timestamp", ""), reverse=True)[:20],
            "live":       True,
        }

    except Exception as e:
        logging.warning("Reports Cosmos query failed: %s", e)
        return None


# ── Core classification ───────────────────────────────────────────────────────
def classify_message(message: str, source: str = "unknown", sender: str = "unknown") -> dict:
    """Call Azure OpenAI o4-mini to classify a UPI fraud message."""
    user_content = f"Source: {source}\nSender: {sender}\nMessage: {message}"

    response = _get_client().chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_content},
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
    result["source"]  = source
    result["sender"]  = sender

    # ── UPI graph investigation ──
    if result.get("is_scam"):
        upi_pattern = re.findall(r'[\w.\-]+@[\w]+', message)
        if upi_pattern:
            graph_data = lookup_graph(upi_pattern[0])
            if graph_data:
                result["graph_investigation"] = graph_data

    # ── Log to Cosmos DB for /api/reports tracking ──
    if result.get("is_scam"):
        detected_city = _detect_city(message)
        _log_report_vertex(result["category"], detected_city, sender)

    return result


# ── /api/classify ─────────────────────────────────────────────────────────────
@app.route(route="classify", methods=["POST", "OPTIONS"])
def classify(req: func.HttpRequest) -> func.HttpResponse:
    cors_headers = {
        "Access-Control-Allow-Origin":  "*",
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
            status_code=400, headers=cors_headers,
        )

    message = body.get("message", "").strip()
    if not message:
        return func.HttpResponse(
            json.dumps({"error": "Field 'message' is required"}),
            status_code=400, headers=cors_headers,
        )

    source = body.get("source", "unknown")
    sender = body.get("sender", "unknown")

    try:
        result = classify_message(message, source, sender)
        logging.info("Classified [%s] → %s (%.2f)", source, result.get("category"), result.get("confidence", 0))
        return func.HttpResponse(
            json.dumps(result, ensure_ascii=False),
            status_code=200, headers=cors_headers,
        )
    except Exception as exc:
        logging.exception("Classification error: %s", exc)
        return func.HttpResponse(
            json.dumps({"error": "Classification failed", "detail": str(exc)}),
            status_code=500, headers=cors_headers,
        )


# ── /api/health ───────────────────────────────────────────────────────────────
@app.route(route="health", methods=["GET"])
def health(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps({
            "status":                  "ok",
            "service":                 "FraudShield India",
            "model":                   MODEL,
            "azure_openai_configured": bool(os.environ.get("AZURE_OPENAI_ENDPOINT")) and bool(os.environ.get("AZURE_OPENAI_KEY")),
            "cosmos_db_configured":    bool(os.environ.get("COSMOS_DB_ENDPOINT")) and bool(os.environ.get("COSMOS_DB_KEY")),
        }),
        status_code=200,
        headers={
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
    )


# ── /api/reports ──────────────────────────────────────────────────────────────
@app.route(route="reports", methods=["GET", "OPTIONS"])
def reports(req: func.HttpRequest) -> func.HttpResponse:
    cors_headers = {
        "Access-Control-Allow-Origin":  "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Content-Type": "application/json",
    }

    if req.method == "OPTIONS":
        return func.HttpResponse(status_code=204, headers=cors_headers)

    live_data = get_reports_from_cosmos()

    if live_data and live_data.get("cities"):
        return func.HttpResponse(
            json.dumps(live_data, ensure_ascii=False),
            status_code=200, headers=cors_headers,
        )

    # Fallback: always return seed data so map is never blank
    seed_total = sum(r["reports"] for r in SEED_REPORTS)
    return func.HttpResponse(
        json.dumps({
            "total":      seed_total,
            "scam_count": seed_total,
            "cities":     SEED_REPORTS,
            "categories": {
                "fake_cashback":      1114,
                "digital_arrest":      810,
                "kyc_freeze":          588,
                "job_scam":            624,
                "lottery_scam":        454,
                "govt_impersonation":  234,
                "phishing_link":       512,
            },
            "recent": [],
            "live":   False,
        }, ensure_ascii=False),
        status_code=200, headers=cors_headers,
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
                status_code=400, headers=cors_headers,
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
            status_code=200, headers=cors_headers,
        )
    except Exception as exc:
        return func.HttpResponse(
            json.dumps({"error": str(exc)}),
            status_code=500, headers=cors_headers,
        )


# ── /api/telegram ─────────────────────────────────────────────────────────────
@app.route(route="telegram", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def telegram_webhook(req: func.HttpRequest) -> func.HttpResponse:
    import requests as req_lib
    import threading

    BOT_TOKEN  = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    API_URL    = "https://fraudshield-api.azurewebsites.net/api/classify"
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
            text    = message.get("text", "").strip()
            if not text:
                return
            if text.startswith("/start"):
                send(chat_id, "🛡️ <b>FraudShield India</b>\n\nकोई भी suspicious message भेजें!\nSend any suspicious SMS to check if it's a scam.")
                return
            send(chat_id, "🔍 <i>Analyzing... (~10 seconds)</i>")
            result     = req_lib.post(API_URL,
                json={"message": text, "source": "telegram", "sender": "telegram_user"},
                timeout=55).json()
            is_scam    = result.get("is_scam", False)
            category   = result.get("category", "unknown")
            confidence = int(result.get("confidence", 0) * 100)
            explanation= result.get("explanation_hindi", "")
            red_flags  = result.get("red_flags", [])
            graph      = result.get("graph_investigation", {})
            verdict    = f"🚨 <b>SCAM DETECTED</b> — {category.replace('_',' ').title()}" if is_scam else "✅ <b>LEGITIMATE MESSAGE</b>"
            flags      = "\n".join(f"  • {f}" for f in red_flags) or "None"
            reply      = f"{verdict}\n📊 Confidence: <b>{confidence}%</b>\n\n🗣️ <b>विवरण:</b>\n<i>{explanation}</i>\n\n🚩 <b>Red Flags:</b>\n{flags}"
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
