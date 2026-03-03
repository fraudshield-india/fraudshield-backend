"""
FraudShield India — Evaluation Script
Calls the live Azure Function API and generates evaluation/metrics.md

Usage:
  python evaluation/evaluate.py --max 20

Requirements:
  pip install requests pandas
"""

import argparse
import csv
import json
import os
import time
from datetime import datetime

import requests

# ── Config ────────────────────────────────────────────────────────────────────
API_URL = "https://fraudshield-api.azurewebsites.net/api/classify"
DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "scam_messages.csv")
METRICS_PATH = os.path.join(os.path.dirname(__file__), "metrics.md")
REQUEST_DELAY = 8  # seconds between calls to avoid rate limits


# ── Helpers ───────────────────────────────────────────────────────────────────
def classify(message: str, source: str = "evaluation", sender: str = "evaluator") -> dict:
    """Call the FraudShield API with retry logic."""
    for attempt in range(3):  # retry up to 3 times
        try:
            response = requests.post(
                API_URL,
                json={"message": message, "source": source, "sender": sender},
                timeout=90,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            if attempt < 2:
                wait = (attempt + 1) * 5  # wait 5s, then 10s
                print(f"  ↻ Retry {attempt+1}/3 after {wait}s... ({e})")
                time.sleep(wait)
            else:
                raise


def normalize_bool(val) -> bool:
    """Convert CSV TRUE/FALSE string or Python bool to bool."""
    if isinstance(val, bool):
        return val
    return str(val).strip().upper() in ("TRUE", "1", "YES")


def load_dataset(path: str, max_rows: int) -> list[dict]:
    """Load CSV dataset, return list of dicts."""
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
            if len(rows) >= max_rows:
                break
    return rows


# ── Main evaluation ───────────────────────────────────────────────────────────
def run_evaluation(max_rows: int):
    print(f"\n🛡️  FraudShield India — Evaluation")
    print(f"📂  Dataset: {DATASET_PATH}")
    print(f"🌐  API:     {API_URL}")
    print(f"📊  Max rows: {max_rows}")
    print("-" * 55)

    rows = load_dataset(DATASET_PATH, max_rows)
    print(f"✅  Loaded {len(rows)} messages from dataset\n")

    results = []
    correct = 0
    category_correct = 0
    total = 0
    errors = 0

    # Per-category tracking
    cat_stats = {}  # { category: {tp, fp, fn, tn} }

    for i, row in enumerate(rows):
        msg = row.get("message", "").strip()
        true_label = normalize_bool(row.get("is_scam", "FALSE"))
        true_cat = row.get("scam_category", "unknown").strip()

        if not msg:
            continue

        print(f"[{i+1:02d}/{len(rows)}] Testing: {msg[:60]}...")

        try:
            result = classify(msg)
            pred_label = result.get("is_scam", False)
            pred_cat = result.get("category", "unknown")
            confidence = result.get("confidence", 0.0)

            is_correct = pred_label == true_label
            is_cat_correct = pred_cat == true_cat and is_correct

            if is_correct:
                correct += 1
            if is_cat_correct:
                category_correct += 1
            total += 1

            # Per-category stats
            for cat in [true_cat, pred_cat]:
                if cat not in cat_stats:
                    cat_stats[cat] = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}

            if true_label and pred_label:
                cat_stats[true_cat]["tp"] += 1
            elif not true_label and not pred_label:
                cat_stats.setdefault("legitimate", {"tp":0,"fp":0,"fn":0,"tn":0})["tn"] += 1
            elif not true_label and pred_label:
                cat_stats[pred_cat]["fp"] += 1
            elif true_label and not pred_label:
                cat_stats[true_cat]["fn"] += 1

            results.append({
                "message": msg[:80],
                "true_is_scam": true_label,
                "true_category": true_cat,
                "pred_is_scam": pred_label,
                "pred_category": pred_cat,
                "confidence": confidence,
                "correct": is_correct,
                "category_correct": is_cat_correct,
            })

            status = "✅" if is_correct else "❌"
            print(f"  {status} True: {true_label} ({true_cat}) | Pred: {pred_label} ({pred_cat}) | Conf: {confidence:.0%}")

        except Exception as e:
            errors += 1
            print(f"  ⚠️  Error: {e}")
            results.append({
                "message": msg[:80],
                "true_is_scam": true_label,
                "true_category": true_cat,
                "pred_is_scam": None,
                "pred_category": None,
                "confidence": None,
                "correct": False,
                "category_correct": False,
                "error": str(e),
            })

        if i < len(rows) - 1:
            time.sleep(REQUEST_DELAY)

    # ── Compute metrics ───────────────────────────────────────────────────────
    accuracy = correct / total if total > 0 else 0
    cat_accuracy = category_correct / total if total > 0 else 0
    error_rate = errors / len(rows) if rows else 0

    # Precision / Recall / F1 for scam detection (binary)
    tp = sum(1 for r in results if r.get("true_is_scam") and r.get("pred_is_scam"))
    fp = sum(1 for r in results if not r.get("true_is_scam") and r.get("pred_is_scam"))
    fn = sum(1 for r in results if r.get("true_is_scam") and r.get("pred_is_scam") == False)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print("\n" + "=" * 55)
    print(f"📊 RESULTS")
    print(f"   Total evaluated : {total}")
    print(f"   Accuracy        : {accuracy:.1%}")
    print(f"   Category Acc.   : {cat_accuracy:.1%}")
    print(f"   Precision       : {precision:.1%}")
    print(f"   Recall          : {recall:.1%}")
    print(f"   F1 Score        : {f1:.1%}")
    print(f"   Errors          : {errors}")
    print("=" * 55)

    # ── Write metrics.md ─────────────────────────────────────────────────────
    write_metrics_md(results, total, accuracy, cat_accuracy,
                     precision, recall, f1, errors, cat_stats, max_rows)
    print(f"\n✅  Metrics saved to: {METRICS_PATH}")


def write_metrics_md(results, total, accuracy, cat_accuracy,
                     precision, recall, f1, errors, cat_stats, max_rows):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# FraudShield India — Evaluation Metrics",
        "",
        f"> Generated: {now} | Dataset: `data/scam_messages.csv` | Model: Azure OpenAI o4-mini",
        "",
        "## Overall Performance",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Messages Evaluated | {total} |",
        f"| Scam Detection Accuracy | **{accuracy:.1%}** |",
        f"| Category Classification Accuracy | **{cat_accuracy:.1%}** |",
        f"| Precision | {precision:.1%} |",
        f"| Recall | {recall:.1%} |",
        f"| F1 Score | **{f1:.1%}** |",
        f"| API Errors | {errors} |",
        f"| Languages Tested | Hindi, Hinglish, English |",
        f"| Model | Azure OpenAI o4-mini (Korea Central) |",
        "",
        "## Per-Category Breakdown",
        "",
        "| Category | TP | FP | FN | Precision |",
        "|----------|----|----|-----|-----------|",
    ]

    for cat, s in sorted(cat_stats.items()):
        tp = s.get("tp", 0)
        fp = s.get("fp", 0)
        fn = s.get("fn", 0)
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        lines.append(f"| {cat} | {tp} | {fp} | {fn} | {prec:.0%} |")

    lines += [
        "",
        "## Individual Results",
        "",
        "| # | Message (truncated) | True Label | Predicted | Confidence | ✓ |",
        "|---|---------------------|------------|-----------|------------|---|",
    ]

    for i, r in enumerate(results, 1):
        msg = r["message"].replace("|", "\\|")[:60]
        true_l = "SCAM" if r["true_is_scam"] else "legit"
        pred_l = "SCAM" if r.get("pred_is_scam") else ("legit" if r.get("pred_is_scam") is not None else "ERROR")
        pred_cat = r.get("pred_category") or "—"
        conf = f"{r['confidence']:.0%}" if r.get("confidence") is not None else "—"
        ok = "✅" if r.get("correct") else "❌"
        lines.append(f"| {i} | {msg} | {true_l} | {pred_cat} | {conf} | {ok} |")

    lines += [
        "",
        "## Notes",
        "",
        f"- Evaluation run on {max_rows} messages due to API rate limits",
        "- Azure OpenAI o4-mini used for all classifications",
        "- Supports Hindi, Hinglish, and English messages",
        "- Report scams: **1930** | cybercrime.gov.in",
    ]

    os.makedirs(os.path.dirname(METRICS_PATH), exist_ok=True)
    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FraudShield India Evaluator")
    parser.add_argument("--max", type=int, default=10,
                        help="Max messages to evaluate (default: 10)")
    args = parser.parse_args()
    run_evaluation(args.max)
