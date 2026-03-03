import os
from azure.ai.textanalytics import TextAnalyticsClient
from azure.core.credentials import AzureKeyCredential

_client = None


def _get_language_client():
    """Return a cached TextAnalyticsClient; returns None if credentials are not configured."""
    global _client
    if _client is None:
        endpoint = os.getenv("LANGUAGE_ENDPOINT")
        key = os.getenv("LANGUAGE_KEY")
        if not endpoint or not key:
            return None
        _client = TextAnalyticsClient(endpoint=endpoint, credential=AzureKeyCredential(key))
    return _client

def analyze_message(message):
    """Run all three Azure AI Language analyses on a message."""
    result = {}
    client = _get_language_client()
    if client is None:
        return result

    # 1. Language Detection
    try:
        lang_result = client.detect_language(documents=[{"id": "1", "text": message}])
        detected = lang_result[0]
        if not detected.is_error:
            result["detected_language"] = detected.primary_language.name
            result["language_code"] = detected.primary_language.iso6391_name
            result["language_confidence"] = detected.primary_language.confidence_score
    except Exception as e:
        result["detected_language"] = "unknown"
        result["language_code"] = "un"
        result["language_confidence"] = 0.0

    # 2. PII Detection
    try:
        pii_result = client.recognize_pii_entities(documents=[{"id": "1", "text": message}])
        pii = pii_result[0]
        if not pii.is_error:
            entities = []
            for entity in pii.entities:
                entities.append({
                    "text": entity.text,
                    "category": entity.category,
                    "confidence": entity.confidence_score
                })
            result["pii_entities"] = entities
            result["redacted_text"] = pii.redacted_text

            # Extract specific evidence
            result["extracted_evidence"] = {
                "phone_numbers": [e["text"] for e in entities if e["category"] == "PhoneNumber"],
                "urls": [e["text"] for e in entities if e["category"] == "URL"],
                "persons": [e["text"] for e in entities if e["category"] == "Person"],
                "organizations": [e["text"] for e in entities if e["category"] == "Organization"],
            }
    except Exception as e:
        result["pii_entities"] = []
        result["extracted_evidence"] = {}

    # 3. Sentiment Analysis
    try:
        sent_result = client.analyze_sentiment(documents=[{"id": "1", "text": message}])
        sentiment = sent_result[0]
        if not sentiment.is_error:
            result["sentiment"] = sentiment.sentiment
            result["sentiment_scores"] = {
                "positive": sentiment.confidence_scores.positive,
                "neutral": sentiment.confidence_scores.neutral,
                "negative": sentiment.confidence_scores.negative
            }
    except Exception as e:
        result["sentiment"] = "unknown"
        result["sentiment_scores"] = {}

    return result
