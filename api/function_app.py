# For now this runs locally, we'll deploy to Azure Functions later
from openai import OpenAI
from dotenv import load_dotenv
import os, json
from http.server import HTTPServer, BaseHTTPRequestHandler

load_dotenv()

client = OpenAI(
    base_url=os.getenv("OPENAI_BASE_URL", "https://models.inference.ai.azure.com"),
    api_key=os.getenv("GITHUB_TOKEN")
)

SYSTEM_PROMPT = '''You are FraudShield, a UPI fraud detection system for India.
Analyze the given message and classify it.

CATEGORIES:
- fake_cashback: Fake cashback/refund, asks to approve collect requests
- digital_arrest: Impersonates police/CBI/customs, threatens arrest
- kyc_freeze: Claims KYC expired, asks for OTP or UPI PIN
- job_scam: Fake job requiring deposit/fee via UPI
- lottery_scam: Fake prize/lottery, asks for processing fee
- govt_impersonation: Fake e-challan, tax notice with phishing link
- phishing_link: Suspicious link to steal credentials
- legitimate: Safe, genuine message

Respond ONLY with valid JSON (no markdown, no backticks):
{
  "is_scam": true/false,
  "category": "category_name",
  "confidence": 0.0 to 1.0,
  "risk_level": "high/medium/low",
  "explanation_en": "1-2 sentence English explanation",
  "explanation_hi": "1-2 sentence Hindi explanation",
  "red_flags": ["flag1", "flag2"]
}'''


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/api/classify":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            message = body.get("message", "")
            source = body.get("source", "unknown")
            sender = body.get("sender", "")

            if not message:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "No message"}).encode())
                return

            try:
                response = client.chat.completions.create(
                    model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": f"Analyze: {message}"}
                    ],
                    temperature=0.1, max_tokens=500
                )
                text = response.choices[0].message.content
                text = text.replace("```json", "").replace("```", "").strip()
                result = json.loads(text)
                result["source"] = source
                result["sender"] = sender
                result["original_message"] = message

                if result.get("is_scam") and result.get("confidence", 0) > 0.7:
                    result["action_required"] = True
                    result["report_url"] = "https://cybercrime.gov.in"
                    result["helpline"] = "1930"
                    result["complaint_form"] = {
                        "form_type": "NCRP_Financial_Fraud",
                        "category": result.get("category", ""),
                        "filing_url": "https://cybercrime.gov.in",
                        "helpline": "1930",
                        "instructions_hi": "Is form ko cybercrime.gov.in par submit karein ya 1930 par call karein."
                    }
                else:
                    result["action_required"] = False

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(result, ensure_ascii=False).encode())

            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            return

        if self.path == "/api/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "healthy"}).encode())
            return

        self.send_response(404)
        self.end_headers()

    def do_GET(self):
        if self.path == "/api/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "healthy", "service": "FraudShield API"}).encode())
            return
        self.send_response(404)
        self.end_headers()


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 7071), Handler)
    print("FraudShield API running on http://localhost:7071")
    print("Test: curl -X POST http://localhost:7071/api/classify -H 'Content-Type: application/json' -d '{\"message\": \"test\"}'")
    server.serve_forever()
