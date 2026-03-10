import azure.functions as func
import json
import logging
import os
from openai import OpenAI

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

client = OpenAI(
    base_url="https://models.inference.ai.azure.com",
    api_key=os.environ["GITHUB_TOKEN"],
)
MODEL = "o4-mini"

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


def classify_message(message, source="unknown", sender="unknown"):
    user_content = SYSTEM_PROMPT + f"\n\nSource: {source}\nSender: {sender}\nMessage: {message}"
    response = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": user_content}],
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
    return result


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
        return func.HttpResponse(json.dumps({"error": "Invalid JSON"}), status_code=400, headers=cors_headers)
    message = body.get("message", "").strip()
    if not message:
        return func.HttpResponse(json.dumps({"error": "'message' required"}), status_code=400, headers=cors_headers)
    try:
        result = classify_message(message, body.get("source", "unknown"), body.get("sender", "unknown"))
        return func.HttpResponse(json.dumps(result, ensure_ascii=False), status_code=200, headers=cors_headers)
    except Exception as e:
        logging.exception(e)
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500, headers=cors_headers)


@app.route(route="health", methods=["GET"])
def health(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps({"status": "ok", "service": "FraudShield India", "model": MODEL}),
        status_code=200,
        headers={"Content-Type": "application/json"},
    )


@app.route(route="batch", methods=["POST"])
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
```

Also update `requirements.txt` to exactly:
```
azure-functions==1.21.3
openai==1.30.5
