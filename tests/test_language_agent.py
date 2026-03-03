"""Tests for the Azure AI Language Agent integration."""

import json
import os
import pytest
from unittest.mock import patch, MagicMock

# Ensure Azure OpenAI env vars are set so the module can be imported
os.environ.setdefault("AZURE_OPENAI_ENDPOINT", "https://test.openai.azure.com/")
os.environ.setdefault("AZURE_OPENAI_KEY", "test-key")

import function_app
from agents import language_agent


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_request(body: dict, method: str = "POST") -> MagicMock:
    """Create a mock Azure Functions HttpRequest."""
    req = MagicMock()
    req.method = method
    req.get_json.return_value = body
    return req


def _mock_language_result():
    """Return a realistic mock language analysis result."""
    return {
        "detected_language": "Hindi",
        "language_code": "hi",
        "language_confidence": 0.98,
        "pii_entities": [
            {"text": "+919876543210", "category": "PhoneNumber", "confidence": 0.95},
            {"text": "CBI officer", "category": "Person", "confidence": 0.80},
            {"text": "CBI", "category": "Organization", "confidence": 0.90},
        ],
        "redacted_text": "*** here. Transfer Rs.50,000 to avoid arrest. Call ***",
        "extracted_evidence": {
            "phone_numbers": ["+919876543210"],
            "urls": [],
            "persons": ["CBI officer"],
            "organizations": ["CBI"],
        },
        "sentiment": "negative",
        "sentiment_scores": {"positive": 0.02, "neutral": 0.08, "negative": 0.90},
    }


# ── Tests for analyze_message ────────────────────────────────────────────────

class TestAnalyzeMessage:
    def test_returns_empty_dict_when_no_credentials(self):
        """When LANGUAGE_ENDPOINT/LANGUAGE_KEY are not set, returns empty dict."""
        with patch.object(language_agent, "_get_language_client", return_value=None):
            result = language_agent.analyze_message("Test message")
        assert result == {}

    def test_language_detection_success(self):
        mock_client = MagicMock()
        lang_doc = MagicMock()
        lang_doc.is_error = False
        lang_doc.primary_language.name = "Hindi"
        lang_doc.primary_language.iso6391_name = "hi"
        lang_doc.primary_language.confidence_score = 0.98
        mock_client.detect_language.return_value = [lang_doc]

        pii_doc = MagicMock()
        pii_doc.is_error = False
        pii_doc.entities = []
        pii_doc.redacted_text = "Test"
        mock_client.recognize_pii_entities.return_value = [pii_doc]

        sent_doc = MagicMock()
        sent_doc.is_error = False
        sent_doc.sentiment = "neutral"
        sent_doc.confidence_scores.positive = 0.1
        sent_doc.confidence_scores.neutral = 0.8
        sent_doc.confidence_scores.negative = 0.1
        mock_client.analyze_sentiment.return_value = [sent_doc]

        with patch.object(language_agent, "_get_language_client", return_value=mock_client):
            result = language_agent.analyze_message("Test message")

        assert result["detected_language"] == "Hindi"
        assert result["language_code"] == "hi"
        assert result["language_confidence"] == 0.98

    def test_pii_extraction(self):
        mock_client = MagicMock()

        lang_doc = MagicMock()
        lang_doc.is_error = False
        lang_doc.primary_language.name = "English"
        lang_doc.primary_language.iso6391_name = "en"
        lang_doc.primary_language.confidence_score = 0.99
        mock_client.detect_language.return_value = [lang_doc]

        phone_entity = MagicMock()
        phone_entity.text = "+919876543210"
        phone_entity.category = "PhoneNumber"
        phone_entity.confidence_score = 0.95

        org_entity = MagicMock()
        org_entity.text = "CBI"
        org_entity.category = "Organization"
        org_entity.confidence_score = 0.90

        pii_doc = MagicMock()
        pii_doc.is_error = False
        pii_doc.entities = [phone_entity, org_entity]
        pii_doc.redacted_text = "*** here. Call ***"
        mock_client.recognize_pii_entities.return_value = [pii_doc]

        sent_doc = MagicMock()
        sent_doc.is_error = False
        sent_doc.sentiment = "negative"
        sent_doc.confidence_scores.positive = 0.02
        sent_doc.confidence_scores.neutral = 0.08
        sent_doc.confidence_scores.negative = 0.90
        mock_client.analyze_sentiment.return_value = [sent_doc]

        with patch.object(language_agent, "_get_language_client", return_value=mock_client):
            result = language_agent.analyze_message("CBI officer here. Call +919876543210")

        assert "+919876543210" in result["extracted_evidence"]["phone_numbers"]
        assert "CBI" in result["extracted_evidence"]["organizations"]
        assert len(result["pii_entities"]) == 2

    def test_sentiment_analysis(self):
        mock_client = MagicMock()

        lang_doc = MagicMock()
        lang_doc.is_error = False
        lang_doc.primary_language.name = "English"
        lang_doc.primary_language.iso6391_name = "en"
        lang_doc.primary_language.confidence_score = 0.99
        mock_client.detect_language.return_value = [lang_doc]

        pii_doc = MagicMock()
        pii_doc.is_error = False
        pii_doc.entities = []
        pii_doc.redacted_text = "Test"
        mock_client.recognize_pii_entities.return_value = [pii_doc]

        sent_doc = MagicMock()
        sent_doc.is_error = False
        sent_doc.sentiment = "negative"
        sent_doc.confidence_scores.positive = 0.02
        sent_doc.confidence_scores.neutral = 0.08
        sent_doc.confidence_scores.negative = 0.90
        mock_client.analyze_sentiment.return_value = [sent_doc]

        with patch.object(language_agent, "_get_language_client", return_value=mock_client):
            result = language_agent.analyze_message("Urgent! Transfer money now!")

        assert result["sentiment"] == "negative"
        assert result["sentiment_scores"]["negative"] == 0.90

    def test_language_detection_error_handled(self):
        mock_client = MagicMock()
        mock_client.detect_language.side_effect = Exception("Service unavailable")

        pii_doc = MagicMock()
        pii_doc.is_error = False
        pii_doc.entities = []
        pii_doc.redacted_text = "Test"
        mock_client.recognize_pii_entities.return_value = [pii_doc]

        sent_doc = MagicMock()
        sent_doc.is_error = False
        sent_doc.sentiment = "neutral"
        sent_doc.confidence_scores.positive = 0.3
        sent_doc.confidence_scores.neutral = 0.5
        sent_doc.confidence_scores.negative = 0.2
        mock_client.analyze_sentiment.return_value = [sent_doc]

        with patch.object(language_agent, "_get_language_client", return_value=mock_client):
            result = language_agent.analyze_message("Test")

        assert result["detected_language"] == "unknown"
        assert result["language_code"] == "un"
        assert result["sentiment"] == "neutral"

    def test_pii_error_handled(self):
        mock_client = MagicMock()

        lang_doc = MagicMock()
        lang_doc.is_error = False
        lang_doc.primary_language.name = "English"
        lang_doc.primary_language.iso6391_name = "en"
        lang_doc.primary_language.confidence_score = 0.99
        mock_client.detect_language.return_value = [lang_doc]

        mock_client.recognize_pii_entities.side_effect = Exception("PII service down")

        sent_doc = MagicMock()
        sent_doc.is_error = False
        sent_doc.sentiment = "neutral"
        sent_doc.confidence_scores.positive = 0.3
        sent_doc.confidence_scores.neutral = 0.5
        sent_doc.confidence_scores.negative = 0.2
        mock_client.analyze_sentiment.return_value = [sent_doc]

        with patch.object(language_agent, "_get_language_client", return_value=mock_client):
            result = language_agent.analyze_message("Test")

        assert result["pii_entities"] == []
        assert result["extracted_evidence"] == {}
        assert result["detected_language"] == "English"

    def test_sentiment_error_handled(self):
        mock_client = MagicMock()

        lang_doc = MagicMock()
        lang_doc.is_error = False
        lang_doc.primary_language.name = "English"
        lang_doc.primary_language.iso6391_name = "en"
        lang_doc.primary_language.confidence_score = 0.99
        mock_client.detect_language.return_value = [lang_doc]

        pii_doc = MagicMock()
        pii_doc.is_error = False
        pii_doc.entities = []
        pii_doc.redacted_text = "Test"
        mock_client.recognize_pii_entities.return_value = [pii_doc]

        mock_client.analyze_sentiment.side_effect = Exception("Sentiment service down")

        with patch.object(language_agent, "_get_language_client", return_value=mock_client):
            result = language_agent.analyze_message("Test")

        assert result["sentiment"] == "unknown"
        assert result["sentiment_scores"] == {}
        assert result["detected_language"] == "English"


# ── Tests for /api/analyze endpoint ──────────────────────────────────────────

class TestAnalyzeEndpoint:
    def test_analyze_returns_language_data(self):
        mock_result = _mock_language_result()
        with patch.object(function_app, "analyze_message", return_value=mock_result):
            req = _make_request({"message": "CBI officer here"})
            resp = function_app.analyze(req)

        body = json.loads(resp.get_body())
        assert resp.status_code == 200
        assert body["detected_language"] == "Hindi"
        assert body["sentiment"] == "negative"
        assert "+919876543210" in body["extracted_evidence"]["phone_numbers"]

    def test_analyze_empty_message_returns_400(self):
        req = _make_request({"message": ""})
        resp = function_app.analyze(req)
        assert resp.status_code == 400

    def test_analyze_invalid_json_returns_400(self):
        req = MagicMock()
        req.method = "POST"
        req.get_json.side_effect = ValueError("bad json")
        resp = function_app.analyze(req)
        assert resp.status_code == 400

    def test_analyze_service_failure_returns_500(self):
        with patch.object(function_app, "analyze_message", side_effect=Exception("Service down")):
            req = _make_request({"message": "Test message"})
            resp = function_app.analyze(req)
        assert resp.status_code == 500


# ── Tests for /api/classify with language analysis ───────────────────────────

class TestClassifyWithLanguageAnalysis:
    def _detection_result(self):
        return {
            "is_scam": True,
            "category": "digital_arrest",
            "confidence": 0.95,
            "risk_level": "high",
            "explanation_en": "Test explanation",
            "explanation_hi": "टेस्ट",
            "red_flags": ["flag1"],
            "message": "CBI officer here",
            "source": "sms",
            "sender": "+919876500001",
        }

    def test_classify_includes_language_data(self):
        detection = self._detection_result()
        lang_result = _mock_language_result()
        complaint = {
            "portal": "cybercrime.gov.in",
            "helpline": "1930",
            "complaint_draft_en": "Test",
            "complaint_draft_hi": "टेस्ट",
            "evidence_to_collect": [],
            "immediate_steps": [],
        }

        with patch.object(function_app, "classify_message", return_value=detection), \
             patch.object(function_app, "analyze_message", return_value=lang_result), \
             patch.object(function_app, "generate_response_complaint", return_value=complaint):
            req = _make_request({"message": "CBI officer here", "source": "sms", "sender": "+919876500001"})
            resp = function_app.classify(req)

        body = json.loads(resp.get_body())
        assert resp.status_code == 200
        assert body["detected_language"] == "Hindi"
        assert body["sentiment"] == "negative"
        assert "extracted_evidence" in body
        assert "pii_entities" in body
        assert "complaint_form" in body

    def test_classify_works_when_language_analysis_fails(self):
        detection = self._detection_result()
        complaint = {
            "portal": "cybercrime.gov.in",
            "helpline": "1930",
            "complaint_draft_en": "Test",
            "complaint_draft_hi": "टेस्ट",
            "evidence_to_collect": [],
            "immediate_steps": [],
        }

        with patch.object(function_app, "classify_message", return_value=detection), \
             patch.object(function_app, "analyze_message", side_effect=Exception("Language service down")), \
             patch.object(function_app, "generate_response_complaint", return_value=complaint):
            req = _make_request({"message": "CBI officer here", "source": "sms", "sender": "+919876500001"})
            resp = function_app.classify(req)

        body = json.loads(resp.get_body())
        assert resp.status_code == 200
        assert body["is_scam"] is True
        assert "detected_language" not in body

    def test_classify_works_when_language_returns_empty(self):
        detection = self._detection_result()
        complaint = {
            "portal": "cybercrime.gov.in",
            "helpline": "1930",
            "complaint_draft_en": "Test",
            "complaint_draft_hi": "टेस्ट",
            "evidence_to_collect": [],
            "immediate_steps": [],
        }

        with patch.object(function_app, "classify_message", return_value=detection), \
             patch.object(function_app, "analyze_message", return_value={}), \
             patch.object(function_app, "generate_response_complaint", return_value=complaint):
            req = _make_request({"message": "CBI officer here", "source": "sms", "sender": "+919876500001"})
            resp = function_app.classify(req)

        body = json.loads(resp.get_body())
        assert resp.status_code == 200
        assert body["is_scam"] is True
        assert "detected_language" not in body
