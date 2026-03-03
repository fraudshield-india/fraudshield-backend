"""
FraudShield India — Scam Template Embedding Similarity

Uses GitHub Models (text-embedding-3-small) to show how common UPI scam
templates evolve over time while inheriting core patterns.

Env vars:
  GITHUB_TOKEN  – GitHub PAT with access to Models inference API

This script:
  1. Calls the GitHub Models embeddings endpoint via `requests`
  2. Computes cosine similarity between all scam template pairs
  3. Prints a similarity matrix (marking HIGH SIMILARITY pairs > 0.82)
  4. Writes results to `data/scam_similarities.json`
"""

import itertools
import json
import math
import os
from pathlib import Path

import requests


GITHUB_MODELS_ENDPOINT = "https://models.inference.ai.azure.com/v1/embeddings"
MODEL_NAME = "text-embedding-3-small"
OUTPUT_PATH = Path("data") / "scam_similarities.json"


SCAM_TEMPLATES = {
    "KBC Lottery 2020": "Badhai ho! Aapne KBC me Rs.25 lakh jeete hain. Registration fee Rs.5,000 bhejein.",
    "Jio Lucky Draw 2021": "Congratulations! Aapne Jio Lucky Draw me Rs.50 lakh jeete. Processing fee Rs.10,000.",
    "Fake Cashback 2022": "Google Pay se aapko Rs.1,500 cashback mila hai. Collect request approve karein.",
    "KYC Freeze 2023": "Your SBI account will be frozen in 24 hours. Update KYC immediately. Share OTP.",
    "Digital Arrest 2024": "CBI officer here. Your Aadhaar is linked to money laundering. Transfer Rs.50,000 or face arrest.",
    "E-Challan Phishing 2025": "Overspeeding Notice: Pay dues immediately. https://echallane.vip/in",
}


def get_github_token() -> str:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError(
            "GITHUB_TOKEN is not set. Export a GitHub PAT with access to the Models API."
        )
    return token


def fetch_embeddings(texts):
    """Call GitHub Models embeddings endpoint for a list of texts."""
    token = get_github_token()

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": MODEL_NAME,
        "input": texts,
    }

    resp = requests.post(GITHUB_MODELS_ENDPOINT, headers=headers, json=payload, timeout=60)
    try:
        resp.raise_for_status()
    except Exception as e:
        raise RuntimeError(f"GitHub Models API error: {e} | body={resp.text[:200]}") from e

    data = resp.json()
    if "data" not in data:
        raise RuntimeError(f"Unexpected response from embeddings API: {data}")

    # `data` is a list of { embedding: [...], index: i, ... }
    embeddings = [item["embedding"] for item in sorted(data["data"], key=lambda d: d["index"])]
    return embeddings


def cosine(a, b) -> float:
    """Cosine similarity between two embedding vectors."""
    if len(a) != len(b):
        raise ValueError("Embedding vectors must have same length")
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def main():
    print("🧬 FraudShield India — Scam Embedding Similarity")
    print("   Model: text-embedding-3-small via GitHub Models\n")

    labels = list(SCAM_TEMPLATES.keys())
    texts = [SCAM_TEMPLATES[l] for l in labels]

    print(f"Embedding {len(texts)} scam templates...")
    embeddings = fetch_embeddings(texts)
    print("✅ Embeddings fetched.\n")

    # Compute pairwise similarities
    pair_results = []
    matrix = {label: {} for label in labels}
    for (i, a), (j, b) in itertools.combinations(enumerate(labels), 2):
        sim = cosine(embeddings[i], embeddings[j])
        sim_rounded = round(sim, 4)
        high = sim_rounded > 0.82

        pair_results.append(
            {
                "template_a": a,
                "template_b": b,
                "similarity": sim_rounded,
                "high_similarity": high,
            }
        )

        matrix[a][b] = sim_rounded
        matrix[b][a] = sim_rounded

    # Fill diagonal
    for l in labels:
        matrix[l][l] = 1.0

    # Pretty-print similarity matrix
    print("📊 Cosine Similarity Matrix (scam templates)")
    header = "{:24}".format("") + " ".join(f"{l[:12]:>12}" for l in labels)
    print(header)
    print("-" * len(header))

    for a in labels:
        row = f"{a[:22]:>24}"
        for b in labels:
            sim = matrix[a][b]
            cell = f"{sim:>7.3f}"
            if a != b and sim > 0.82:
                cell += "*"
            else:
                cell += " "
            row += cell
        print(row)

    print("\n*HIGH SIMILARITY pairs (> 0.82):")
    any_high = False
    for p in pair_results:
        if p["high_similarity"]:
            any_high = True
            print(
                f"  - {p['template_a']}  ↔  {p['template_b']}  "
                f"= {p['similarity']:.3f} (HIGH SIMILARITY)"
            )
    if not any_high:
        print("  (none above threshold in this run)")

    # Persist results
    OUTPUT_PATH.parent.mkdir(exist_ok=True)
    payload = {
        "model": MODEL_NAME,
        "threshold_high_similarity": 0.82,
        "templates": SCAM_TEMPLATES,
        "pairs": pair_results,
        "matrix": matrix,
    }
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    print(f"\n✅ Saved similarity results to {OUTPUT_PATH}")

    print(
        "\nInsight: FraudShield detects new scam variants because they inherit "
        "patterns from older scams (similarity > 0.82)."
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"❌ embedding_similarity failed: {exc}")
        raise

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
    os.makedirs("data", exist_ok=True)
    with open("data/scam_similarities.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\nResults saved to data/scam_similarities.json")
    print("\nKey insight: Templates with >0.82 similarity share underlying")
    print("social engineering patterns despite different surface text.")
