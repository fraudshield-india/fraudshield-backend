import json
import logging
import os

import azure.functions as func
from openai import OpenAI


app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)


# ── GitHub Models client (o4-mini) ────────────────────────────────────────────
MODEL = "o4-mini"

client = OpenAI(
    base_url="https://models.inference.ai.azure.com",
    api_key=os.environ.get("GITHUB_TOKEN"),
)


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
    """
    Call GitHub Models (o4-mini) via OpenAI client to classify a UPI fraud message.
    System prompt is merged into the user content because o4-mini does not support
    the system role.
    """
    if not client.api_key:
        raise RuntimeError("GITHUB_TOKEN is not configured in environment variables")

    user_content = (
        SYSTEM_PROMPT
        + "\n\n"
        + f"Source: {source}\nSender: {sender}\nMessage: {message}"
    )

    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {
                "role": "user",
                "content": user_content,
            }
        ],
        # o4-mini uses max_completion_tokens instead of max_tokens
        max_completion_tokens=512,
    )

    raw = response.choices[0].message.content.strip()

    # Strip accidental markdown fences if the model adds them
    if raw.startswith("```"):
        parts = raw.split("```")
        if len(parts) >= 2:
            raw = parts[1]
        if raw.lstrip().startswith("json"):
            raw = raw.lstrip()[4:]

    result = json.loads(raw.strip())
    result["message"] = message
    result["source"] = source
    result["sender"] = sender
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

    message = (body.get("message") or body.get("text") or "").strip()
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
        logging.info(
            "Classified [%s] → %s (%.2f)",
            source,
            result.get("category"),
            result.get("confidence", 0.0),
        )
        return func.HttpResponse(
            json.dumps(result, ensure_ascii=False),
            status_code=200,
            headers=cors_headers,
        )
    except Exception as exc:
        logging.exception("Classification error: %s", exc)
        return func.HttpResponse(
            json.dumps(
                {
                    "error": "Classification failed",
                    "detail": str(exc),
                }
            ),
            status_code=500,
            headers=cors_headers,
        )


# ── /api/health ───────────────────────────────────────────────────────────────
@app.route(route="health", methods=["GET"])
def health(req: func.HttpRequest) -> func.HttpResponse:
    body = {
        "status": "ok",
        "service": "FraudShield India",
        "model": MODEL,
    }
    return func.HttpResponse(
        json.dumps(body),
        status_code=200,
        headers={
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
    )


# ── /api/batch ────────────────────────────────────────────────────────────────
@app.route(route="batch", methods=["POST", "OPTIONS"])
def batch_classify(req: func.HttpRequest) -> func.HttpResponse:
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

    messages = body.get("messages", [])
    if not isinstance(messages, list) or not messages:
        return func.HttpResponse(
            json.dumps({"error": "Provide 1–20 messages as a list in 'messages'."}),
            status_code=400,
            headers=cors_headers,
        )
    if len(messages) > 20:
        return func.HttpResponse(
            json.dumps({"error": "Batch size limit is 20 messages."}),
            status_code=400,
            headers=cors_headers,
        )

    results = []
    for item in messages:
        if isinstance(item, str):
            msg_text = item
            source = "batch"
            sender = "unknown"
        else:
            msg_text = (item.get("message") or item.get("text") or "").strip()
            source = item.get("source", "batch")
            sender = item.get("sender", "unknown")

        if not msg_text:
            results.append({"error": "Empty message in batch item."})
            continue

        try:
            r = classify_message(msg_text, source, sender)
            results.append(r)
        except Exception as e:
            logging.exception("Batch classification error: %s", e)
            results.append({"error": str(e), "message": msg_text})

    return func.HttpResponse(
        json.dumps({"results": results, "count": len(results)}, ensure_ascii=False),
        status_code=200,
        headers=cors_headers,
    )
