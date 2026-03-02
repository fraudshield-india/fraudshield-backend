"""
FraudShield India — Event Hub Publisher
Publishes fraud classification events to Azure Event Hub.
"""
import json
import logging
import os
from dotenv import load_dotenv

load_dotenv()

try:
    from azure.eventhub import EventHubProducerClient, EventData
except ImportError:
    raise ImportError("Run: pip install azure-eventhub")

logger = logging.getLogger(__name__)


def get_producer() -> EventHubProducerClient:
    """Create and return an Event Hub producer client."""
    connection_str = os.environ.get("EVENT_HUB_CONNECTION", "")
    eventhub_name = os.environ.get("EVENT_HUB_NAME", "fraud-events")
    if not connection_str:
        raise RuntimeError("EVENT_HUB_CONNECTION is not set.")
    return EventHubProducerClient.from_connection_string(
        connection_str, eventhub_name=eventhub_name
    )


def publish_fraud_event(event: dict) -> None:
    """Publish a single fraud classification event to Event Hub.

    Args:
        event: dict with at minimum keys: message, source, sender,
               is_scam, category, confidence, risk_level.
    """
    producer = get_producer()
    try:
        with producer:
            batch = producer.create_batch()
            batch.add(EventData(json.dumps(event, ensure_ascii=False)))
            producer.send_batch(batch)
            logger.info(
                "Published fraud event: category=%s confidence=%.2f",
                event.get("category"),
                event.get("confidence", 0),
            )
    except Exception as exc:
        logger.error("Failed to publish fraud event: %s", exc)
        raise


if __name__ == "__main__":
    # Quick smoke-test
    sample = {
        "message": "Google Pay se Rs.1500 cashback mila hai. Approve karein.",
        "source": "test",
        "sender": "unknown",
        "is_scam": True,
        "category": "fake_cashback",
        "confidence": 0.97,
        "risk_level": "high",
        "explanation_en": "Fake cashback lure asking to approve collect request.",
        "explanation_hi": "Yeh ek nakli cashback scam hai.",
    }
    publish_fraud_event(sample)
    print("Event published successfully.")
