"""
FraudShield India — Telegram Bot
Deploy as Azure Function (HTTP trigger) or run standalone with polling.
Requires env vars: TELEGRAM_BOT_TOKEN, FRAUDSHIELD_API_URL
"""

import os
import json
import logging
import requests
import azure.functions as func

# ── Config ────────────────────────────────────────────────────────────────────
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
API_URL = os.environ.get(
    "FRAUDSHIELD_API_URL",
    "https://fraudshield-api.azurewebsites.net/api/classify",
)
TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("fraudshield-bot")

# ── Telegram helpers ───────────────────────────────────────────────────────────

def send_message(chat_id: int, text: str, parse_mode: str = "HTML") -> dict:
    resp = requests.post(
        f"{TELEGRAM_API}/sendMessage",
        json={"chat_id": chat_id, "text": text, "parse_mode": parse_mode},
        timeout=10,
    )
    return resp.json()


def send_typing(chat_id: int):
    requests.post(
        f"{TELEGRAM_API}/sendChatAction",
        json={"chat_id": chat_id, "action": "typing"},
        timeout=5,
    )


# ── FraudShield API ────────────────────────────────────────────────────────────

def classify_message(text: str) -> dict | None:
    try:
        resp = requests.post(
            API_URL,
            json={"message": text, "source": "telegram", "sender": "telegram_user"},
            timeout=60,  # cold-start buffer
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        log.error("classify error: %s", e)
        return None


# ── Response formatter ─────────────────────────────────────────────────────────

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


def format_result(result: dict) -> str:
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
        verdict_color = "⛔"
    else:
        verdict = "✅ <b>Message appears LEGITIMATE</b>"
        verdict_color = "✅"

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
        "🤖 <i>Powered by Azure + GitHub Models</i>",
    ]

    return "\n".join(lines)


# ── Command handlers ───────────────────────────────────────────────────────────

WELCOME_MSG = """🛡️ <b>FraudShield India में आपका स्वागत है!</b>

मुझे कोई भी संदिग्ध SMS, WhatsApp, या ईमेल message भेजें — मैं तुरंत बताऊंगा कि यह <b>Scam है या नहीं</b>।

<b>Send me:</b>
• Any suspicious SMS or message
• Forwards claiming you won a lottery
• "Digital arrest" threats
• KYC / bank account freeze messages

<b>Commands:</b>
/start — This message
/help — How to use
/report — How to file a cybercrime complaint

🇮🇳 <i>Protecting India from digital fraud</i>"""

HELP_MSG = """ℹ️ <b>FraudShield India — Help</b>

<b>How to use:</b>
1. Copy the suspicious message
2. Paste it here and send
3. I'll analyze it in seconds

<b>Detected scam types:</b>
💰 Fake Cashback / Prize
🚔 Digital Arrest
🏦 KYC / Account Freeze
💼 Fake Job Offer
🎰 Lottery Scam
🏛️ Govt. Impersonation
🔗 Phishing Links

<b>Languages supported:</b> English, Hindi, Hinglish

<b>Helpline:</b> 1930 (National Cyber Crime)
<b>Portal:</b> cybercrime.gov.in"""

REPORT_MSG = """📋 <b>Cybercrime Complaint कैसे करें?</b>

<b>1. Online (Recommended):</b>
🌐 cybercrime.gov.in → "Report Cybercrime" पर click करें

<b>2. Helpline:</b>
📞 <b>1930</b> (24x7 National Helpline)

<b>3. Local Police:</b>
अपने नजदीकी police station में जाएं

<b>Complaint के लिए जरूरी जानकारी:</b>
• Sender का number / email
• Screenshot of the message
• Date and time
• Any amount lost (if any)

🛡️ <i>FraudShield India आपकी मदद के लिए है!</i>"""


def handle_update(update: dict):
    message = update.get("message") or update.get("edited_message")
    if not message:
        return

    chat_id: int = message["chat"]["id"]
    text: str = message.get("text", "").strip()

    if not text:
        send_message(chat_id, "⚠️ Please send a text message to analyze.")
        return

    # Commands
    if text.startswith("/start"):
        send_message(chat_id, WELCOME_MSG)
        return
    if text.startswith("/help"):
        send_message(chat_id, HELP_MSG)
        return
    if text.startswith("/report"):
        send_message(chat_id, REPORT_MSG)
        return

    # Analyze message
    send_typing(chat_id)
    send_message(chat_id, "🔍 <i>Analyzing message... (please wait ~5s)</i>")

    result = classify_message(text)
    if result is None:
        send_message(
            chat_id,
            "❌ <b>Analysis failed.</b> Please try again in a moment.\n"
            "If this persists, the API may be warming up (cold start ~30s).",
        )
        return

    reply = format_result(result)
    send_message(chat_id, reply)


# ── Azure Function entry point ─────────────────────────────────────────────────

app = func.FunctionApp()


@app.function_name("TelegramWebhook")
@app.route(route="telegram", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def telegram_webhook(req: func.HttpRequest) -> func.HttpResponse:
    try:
        update = req.get_json()
        handle_update(update)
    except Exception as e:
        log.error("webhook error: %s", e)
    return func.HttpResponse("OK", status_code=200)


# ── Standalone polling mode (for local testing) ────────────────────────────────

def run_polling():
    """Run bot in polling mode — useful for local dev without webhook."""
    print(f"🤖 FraudShieldIndiaBot starting in polling mode...")
    offset = 0
    while True:
        try:
            resp = requests.get(
                f"{TELEGRAM_API}/getUpdates",
                params={"offset": offset, "timeout": 30},
                timeout=35,
            )
            updates = resp.json().get("result", [])
            for update in updates:
                handle_update(update)
                offset = update["update_id"] + 1
        except KeyboardInterrupt:
            print("\n👋 Bot stopped.")
            break
        except Exception as e:
            log.error("polling error: %s", e)
            import time; time.sleep(5)


if __name__ == "__main__":
    run_polling()
