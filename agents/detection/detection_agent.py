import os
import json
from openai import OpenAI
from dotenv import load_dotenv
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

def classify_message(message, language="auto"):
    response = client.chat.completions.create(
        model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Analyze (language: {language}): {message}"}
        ],
        temperature=0.1,
        max_tokens=500
    )
    text = response.choices[0].message.content
    text = text.replace("```json", "").replace("```", "").strip()
    return json.loads(text)

if __name__ == "__main__":
    tests = [
        ("Google Pay se aapko Rs.1500 cashback mila hai. Approve karein: cashback@ybl", True),
        ("CBI officer here. Your Aadhaar linked to money laundering. Transfer Rs.50,000.", True),
        ("Your SBI KYC expired. Update immediately: bit.ly/sbi-kyc", True),
        ("Earn Rs.15,000 daily! Like YouTube videos. Pay Rs.999 deposit: taskpay.earn@ybl", True),
        ("Hey, dinner at 8pm tonight? Send me Rs.300 for my share on GPay.", False),
    ]
    import time
    correct = 0
    for msg, expected in tests:
        result = classify_message(msg)
        got = result.get("is_scam", False)
        match = got == expected
        correct += int(match)
        status = "PASS" if match else "FAIL"
        print(f"[{status}] {result['category']} ({result['confidence']}) - {msg[:50]}...")
        print(f"  Hindi: {result['explanation_hi']}")
        print()
        time.sleep(2)
    print(f"Accuracy: {correct}/{len(tests)}")
