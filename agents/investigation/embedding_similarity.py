"""
Scam mutation tracking using text embeddings.
Shows how scam templates evolve over time.
"""
import os, json, time
import numpy as np
from openai import OpenAI
from dotenv import load_dotenv
load_dotenv()

client = OpenAI(
    base_url=os.getenv("OPENAI_BASE_URL", "https://models.inference.ai.azure.com"),
    api_key=os.getenv("GITHUB_TOKEN")
)

def get_embedding(text):
    response = client.embeddings.create(
        model="text-embedding-3-small",
        input=text
    )
    return response.data[0].embedding

def cosine_similarity(a, b):
    a, b = np.array(a), np.array(b)
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))

# Scam templates showing evolution over time
SCAM_TEMPLATES = {
    "KBC Lottery 2020": "Badhai ho! Aapne KBC me Rs.25 lakh jeete hain. Registration fee Rs.5,000 bhejein.",
    "Jio Lucky Draw 2021": "Congratulations! Aapne Jio Lucky Draw me Rs.50 lakh jeete. Processing fee Rs.10,000.",
    "Fake Cashback 2022": "Google Pay se aapko Rs.1,500 cashback mila hai. Collect request approve karein.",
    "KYC Freeze 2023": "Your SBI account will be frozen in 24 hours. Update KYC immediately. Share OTP.",
    "Digital Arrest 2024": "CBI officer here. Your Aadhaar is linked to money laundering. Transfer Rs.50,000 or face arrest.",
    "E-Challan Phishing 2025": "Overspeeding Notice: Pay dues immediately to prevent legal action. https://echallane.vip/in",
}

if __name__ == "__main__":
    print("Computing embeddings for scam templates...")
    print("(This may take a minute due to rate limits)\n")

    vectors = {}
    for name, text in SCAM_TEMPLATES.items():
        vectors[name] = get_embedding(text)
        print(f"  Embedded: {name}")
        time.sleep(2)

    print("\n" + "=" * 70)
    print("SCAM TEMPLATE SIMILARITY MATRIX")
    print("=" * 70)

    names = list(vectors.keys())
    results = []

    for i, a in enumerate(names):
        for j, b in enumerate(names):
            if i < j:
                sim = cosine_similarity(vectors[a], vectors[b])
                marker = " *** MUTATION DETECTED ***" if sim > 0.82 else ""
                print(f"  {a} <-> {b}: {sim:.3f}{marker}")
                results.append({"template_a": a, "template_b": b, "similarity": round(sim, 3)})

    # Save results
    with open("data/scam_similarities.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\nResults saved to data/scam_similarities.json")
    print("\nKey insight: Templates with >0.82 similarity share underlying")
    print("social engineering patterns despite different surface text.")
