"""
Direct pipeline for demo reliability.
Calls all three agents sequentially without Event Hub.
"""
import sys, os, json, time
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from agents.detection.detection_agent import classify_message

def run_pipeline(message):
    print("=" * 60)
    print("FRAUDSHIELD PIPELINE")
    print("=" * 60)

    # Stage 1: Detection
    print("\n--- STAGE 1: DETECTION ---")
    result = classify_message(message)
    print(f"Category: {result['category']}")
    print(f"Confidence: {result['confidence']}")
    print(f"Risk: {result['risk_level']}")
    print(f"Hindi: {result['explanation_hi']}")

    if result.get("is_scam") and result.get("confidence", 0) > 0.7:
        # Stage 2: Investigation
        print("\n--- STAGE 2: INVESTIGATION ---")
        print("Checking scam database...")
        # TODO: Add Cosmos DB lookup when Person 2 has it ready
        print("Known scam pattern detected" if result["confidence"] > 0.8 else "New pattern - flagged for review")

        # Stage 3: Response
        print("\n--- STAGE 3: RESPONSE ---")
        print(f"Complaint form: https://cybercrime.gov.in")
        print(f"Helpline: 1930")
        print(f"Red flags: {', '.join(result.get('red_flags', []))}")
    else:
        print("\nMessage appears safe. No action required.")

    return result


if __name__ == "__main__":
    demo_messages = [
        "Google Pay se aapko Rs.1500 cashback mila hai. Approve karein: cashback@ybl",
        "CBI officer here. Transfer Rs.50,000 or face arrest.",
        "Your SBI KYC expired. Update: bit.ly/sbi-kyc",
        "Earn Rs.15,000 daily! Pay Rs.999 deposit: taskpay.earn@ybl",
        "Overspeeding Notice: Pay dues immediately. https://echallane.vip/in",
        "Hey, dinner at 8pm tonight? Send me Rs.300.",
    ]

    for msg in demo_messages:
        run_pipeline(msg)
        print("\n")
        time.sleep(3)
