"""Tests for the Response Agent integration in function_app.py."""

import json
import os
import pytest
from unittest.mock import patch, MagicMock

# Ensure Azure OpenAI env vars are set so the module can be imported
os.environ.setdefault("AZURE_OPENAI_ENDPOINT", "https://test.openai.azure.com/")
os.environ.setdefault("AZURE_OPENAI_KEY", "test-key")

import function_app


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_request(body: dict, method: str = "POST") -> MagicMock:
    """Create a mock Azure Functions HttpRequest."""
    req = MagicMock()
    req.method = method
    req.get_json.return_value = body
    return req


def _mock_openai_response(content: str) -> MagicMock:
    """Create a mock OpenAI ChatCompletion response."""
    msg = MagicMock()
    msg.content = content
    choice = MagicMock()
    choice.message = msg
    resp = MagicMock()
    resp.choices = [choice]
    return resp


# ── Tests for _get_fallback_complaint_form ───────────────────────────────────

class TestFallbackComplaintForm:
    def test_returns_required_keys(self):
        result = function_app._get_fallback_complaint_form("digital_arrest", "+919876500001")
        assert result["portal"] == "cybercrime.gov.in"
        assert result["helpline"] == "1930"
        assert "complaint_category" in result
        assert "complaint_draft_en" in result
        assert "complaint_draft_hi" in result
        assert "evidence_to_collect" in result
        assert "immediate_steps" in result

    def test_includes_sender_in_drafts(self):
        sender = "+919876500001"
        result = function_app._get_fallback_complaint_form("kyc_freeze", sender)
        assert sender in result["complaint_draft_en"]
        assert sender in result["complaint_draft_hi"]

    def test_includes_category_in_drafts(self):
        result = function_app._get_fallback_complaint_form("fake_cashback", "unknown")
        assert "fake cashback" in result["complaint_draft_en"]


# ── Tests for generate_response_complaint ────────────────────────────────────

class TestGenerateResponseComplaint:
    def test_parses_valid_json_response(self):
        complaint_json = json.dumps({
            "complaint_category": "Online Financial Fraud > Impersonation of Government Official",
            "complaint_draft_en": "I received a fraudulent message from +919876500001.",
            "complaint_draft_hi": "मुझे +919876500001 से एक फर्जी संदेश प्राप्त हुआ।",
            "evidence_to_collect": ["Screenshot of the message"],
            "immediate_steps": ["Do NOT transfer any money", "Block the sender"],
            "portal": "cybercrime.gov.in",
            "helpline": "1930",
        })
        mock_resp = _mock_openai_response(complaint_json)

        with patch.object(function_app, "_get_client") as mock_client:
            mock_client.return_value.chat.completions.create.return_value = mock_resp
            result = function_app.generate_response_complaint(
                "digital_arrest", "CBI officer here", "+919876500001", ["CBI claim"]
            )

        assert result["portal"] == "cybercrime.gov.in"
        assert result["helpline"] == "1930"
        assert "complaint_draft_en" in result

    def test_strips_markdown_backticks(self):
        complaint_json = json.dumps({
            "complaint_category": "Test",
            "complaint_draft_en": "Test",
            "complaint_draft_hi": "Test",
            "evidence_to_collect": [],
            "immediate_steps": [],
            "portal": "cybercrime.gov.in",
            "helpline": "1930",
        })
        wrapped = f"```json\n{complaint_json}\n```"
        mock_resp = _mock_openai_response(wrapped)

        with patch.object(function_app, "_get_client") as mock_client:
            mock_client.return_value.chat.completions.create.return_value = mock_resp
            result = function_app.generate_response_complaint(
                "fake_cashback", "msg", "sender", []
            )

        assert result["portal"] == "cybercrime.gov.in"

    def test_raises_on_invalid_json(self):
        mock_resp = _mock_openai_response("this is not json")

        with patch.object(function_app, "_get_client") as mock_client:
            mock_client.return_value.chat.completions.create.return_value = mock_resp
            with pytest.raises(json.JSONDecodeError):
                function_app.generate_response_complaint(
                    "phishing_link", "click here", "sender", []
                )


# ── Tests for /api/classify with Response Agent ──────────────────────────────

class TestClassifyWithResponseAgent:
    def _detection_result(self, is_scam=True, confidence=0.95, category="digital_arrest"):
        return {
            "is_scam": is_scam,
            "category": category,
            "confidence": confidence,
            "risk_level": "high",
            "explanation_en": "Test explanation",
            "explanation_hi": "टेस्ट",
            "red_flags": ["flag1", "flag2"],
            "message": "test message",
            "source": "sms",
            "sender": "+919876500001",
        }

    def test_scam_with_high_confidence_includes_complaint_form(self):
        detection = self._detection_result(is_scam=True, confidence=0.95)
        complaint = {
            "complaint_category": "Online Financial Fraud > Impersonation",
            "complaint_draft_en": "Complaint text",
            "complaint_draft_hi": "शिकायत",
            "evidence_to_collect": ["Screenshot"],
            "immediate_steps": ["Block sender"],
            "portal": "cybercrime.gov.in",
            "helpline": "1930",
        }

        with patch.object(function_app, "classify_message", return_value=detection), \
             patch.object(function_app, "generate_response_complaint", return_value=complaint):
            req = _make_request({"message": "CBI officer here", "source": "sms", "sender": "+919876500001"})
            resp = function_app.classify(req)

        body = json.loads(resp.get_body())
        assert body["is_scam"] is True
        assert "complaint_form" in body
        assert body["complaint_form"]["portal"] == "cybercrime.gov.in"
        assert body["complaint_form"]["complaint_draft_en"] == "Complaint text"

    def test_scam_with_low_confidence_no_complaint_form(self):
        detection = self._detection_result(is_scam=True, confidence=0.5)

        with patch.object(function_app, "classify_message", return_value=detection):
            req = _make_request({"message": "some message", "source": "sms", "sender": "unknown"})
            resp = function_app.classify(req)

        body = json.loads(resp.get_body())
        assert "complaint_form" not in body

    def test_legitimate_message_no_complaint_form(self):
        detection = self._detection_result(is_scam=False, confidence=0.9, category="legitimate")

        with patch.object(function_app, "classify_message", return_value=detection):
            req = _make_request({"message": "Hello friend", "source": "sms", "sender": "unknown"})
            resp = function_app.classify(req)

        body = json.loads(resp.get_body())
        assert "complaint_form" not in body

    def test_response_agent_failure_uses_fallback(self):
        detection = self._detection_result(is_scam=True, confidence=0.95)

        with patch.object(function_app, "classify_message", return_value=detection), \
             patch.object(function_app, "generate_response_complaint", side_effect=Exception("API error")):
            req = _make_request({"message": "CBI officer", "source": "sms", "sender": "+919876500001"})
            resp = function_app.classify(req)

        body = json.loads(resp.get_body())
        assert resp.status_code == 200
        assert "complaint_form" in body
        assert body["complaint_form"]["portal"] == "cybercrime.gov.in"
        assert body["complaint_form"]["helpline"] == "1930"

    def test_classify_still_returns_200_when_response_agent_fails(self):
        detection = self._detection_result(is_scam=True, confidence=0.95)

        with patch.object(function_app, "classify_message", return_value=detection), \
             patch.object(function_app, "generate_response_complaint", side_effect=RuntimeError("timeout")):
            req = _make_request({"message": "Arrest warrant", "source": "sms", "sender": "+91000"})
            resp = function_app.classify(req)

        assert resp.status_code == 200


# ── Tests for existing endpoints (not broken) ───────────────────────────────

class TestExistingEndpoints:
    def test_health_endpoint(self):
        req = MagicMock()
        resp = function_app.health(req)
        body = json.loads(resp.get_body())
        assert body["status"] == "ok"
        assert body["service"] == "FraudShield India"

    def test_classify_options_returns_204(self):
        req = _make_request({}, method="OPTIONS")
        resp = function_app.classify(req)
        assert resp.status_code == 204

    def test_classify_empty_message_returns_400(self):
        req = _make_request({"message": ""})
        resp = function_app.classify(req)
        assert resp.status_code == 400

    def test_classify_invalid_json_returns_400(self):
        req = MagicMock()
        req.method = "POST"
        req.get_json.side_effect = ValueError("bad json")
        resp = function_app.classify(req)
        assert resp.status_code == 400
