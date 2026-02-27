import azure.functions as func
import json
import logging
import os
from openai import OpenAI

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# ── GitHub Models client ─────────────────────────────────────────────────────
client = OpenAI(
    base_url="https://models.inference.ai.azure.com",
    api_key=os.environ["GITHUB_TOKEN"],
)
MODEL = "o4-mini"  # reasoning model — no temperature/response_format params

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

    response = client.chat.completions.create(
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
        raw = raw.split("```")[1]
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
    return func.HttpResponse(
        json.dumps({"status": "ok", "service": "FraudShield India", "model": MODEL}),
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
