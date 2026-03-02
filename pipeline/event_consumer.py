"""
FraudShield India — Event Hub Consumer
Reads fraud classification events from Azure Event Hub and writes
results to Cosmos DB Gremlin graph.
"""
import json
import logging
import os
import time
from dotenv import load_dotenv

load_dotenv()

try:
    from azure.eventhub import EventHubConsumerClient
except ImportError:
    raise ImportError("Run: pip install azure-eventhub")

try:
    from gremlin_python.driver import client as gremlin_client, serializer
except ImportError:
    raise ImportError("Run: pip install gremlinpython")

logger = logging.getLogger(__name__)


def _get_gremlin_client():
    """Return a connected Gremlin client for Cosmos DB."""
    endpoint = os.environ.get("COSMOS_DB_ENDPOINT", "").replace("https://", "").rstrip("/").replace(":443", "")
    key = os.environ.get("COSMOS_DB_KEY", "")
    if not endpoint or not key:
        raise RuntimeError("COSMOS_DB_ENDPOINT and COSMOS_DB_KEY must be set.")
    return gremlin_client.Client(
        f"wss://{endpoint}:443/",
        "g",
        username="/dbs/FraudShieldDB/colls/ScamNetwork",
        password=key,
        message_serializer=serializer.GraphSONSerializersV2d0(),
    )


def _write_to_graph(gremlin, event: dict) -> None:
    """Upsert a fraud event vertex into the Cosmos DB Gremlin graph."""
    q = (
        "g.V().has('FraudEvent', 'event_id', event_id)"
        ".fold()"
        ".coalesce("
        "  unfold(),"
        "  addV('FraudEvent').property('event_id', event_id)"
        ")"
        ".property('category', category)"
        ".property('confidence', confidence)"
        ".property('risk_level', risk_level)"
        ".property('source', source)"
        ".property('sender', sender)"
        ".property('pk', category)"
    )
    bindings = {
        "event_id": event.get("event_id", f"evt_{int(time.time())}"),
        "category": event.get("category", "unknown"),
        "confidence": float(event.get("confidence", 0)),
        "risk_level": event.get("risk_level", "low"),
        "source": event.get("source", "unknown"),
        "sender": event.get("sender", "unknown"),
    }
    try:
        gremlin.submitAsync(q, bindings=bindings).result()
        logger.info("Written event %s to graph.", bindings["event_id"])
    except Exception as exc:
        logger.error("Failed to write event to graph: %s", exc)


def on_event(partition_context, event):
    """Callback invoked for each received Event Hub event."""
    try:
        body = json.loads(event.body_as_str())
        logger.info(
            "Received event: category=%s confidence=%.2f",
            body.get("category"),
            body.get("confidence", 0),
        )
        gremlin = _get_gremlin_client()
        try:
            _write_to_graph(gremlin, body)
        finally:
            gremlin.close()
        partition_context.update_checkpoint(event)
    except Exception as exc:
        logger.error("Error processing event: %s", exc)


def start_consumer() -> None:
    """Start the Event Hub consumer and process events indefinitely."""
    connection_str = os.environ.get("EVENT_HUB_CONNECTION", "")
    eventhub_name = os.environ.get("EVENT_HUB_NAME", "fraud-events")
    consumer_group = os.environ.get("EVENT_HUB_CONSUMER_GROUP", "$Default")

    if not connection_str:
        raise RuntimeError("EVENT_HUB_CONNECTION is not set.")

    consumer = EventHubConsumerClient.from_connection_string(
        connection_str,
        consumer_group=consumer_group,
        eventhub_name=eventhub_name,
    )
    logger.info("Starting Event Hub consumer for '%s'...", eventhub_name)
    with consumer:
        consumer.receive(on_event=on_event, starting_position="-1")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    start_consumer()
