import nest_asyncio

nest_asyncio.apply()

"""
FraudShield India — Cosmos DB Gremlin Seed Script
Seeds scam UPI IDs, phone numbers, and their connections into the graph.

Usage:
  pip install gremlinpython nest_asyncio
  python agents/investigation/seed_graph.py

Env vars needed:
  COSMOS_DB_ENDPOINT=https://fraudshield-cosmosdb.documents.azure.com:443/
  COSMOS_DB_KEY=your_primary_key
"""

import logging
import os
import sys
import time
import traceback
from concurrent.futures import TimeoutError as FutureTimeoutError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

try:
    from gremlin_python.driver import client, serializer
except ImportError:
    log.error("Run: pip install gremlinpython")
    sys.exit(1)


QUERY_TIMEOUT = 30  # seconds — per-query timeout to prevent hanging
BATCH_SIZE = 5      # concurrent queries to submit at once


def _build_client(endpoint: str, key: str):
    """Create and return a connected Gremlin client with timeout configuration."""
    log.info("🔌 Connecting to Gremlin endpoint host: %s", endpoint)
    t0 = time.time()
    try:
        gremlin_client = client.Client(
            f"wss://{endpoint}:443/",
            "g",
            username="/dbs/FraudShieldDB/colls/ScamNetwork",
            password=key,
            message_serializer=serializer.GraphSONSerializersV2d0(),
            read_timeout=QUERY_TIMEOUT,
            write_timeout=QUERY_TIMEOUT,
        )
        # Lightweight connectivity probe so the workflow fails fast if unreachable
        probe_future = gremlin_client.submitAsync("g.V().limit(1)")
        probe = probe_future.result(timeout=QUERY_TIMEOUT)
        _ = probe.all().result()
    except FutureTimeoutError:
        log.error("⏱️  Connectivity probe timed out after %ds", QUERY_TIMEOUT)
        raise
    except Exception as e:
        log.error("❌ Could not connect to Cosmos DB Gremlin endpoint.")
        log.error("   Host: %s", endpoint)
        log.error("   Error: %s", e)
        log.error(
            "   Tip: Verify COSMOS_DB_ENDPOINT, COSMOS_DB_KEY and that the Gremlin "
            "firewall allows GitHub Actions IPs."
        )
        raise

    log.info("✅ Gremlin client ready in %.1fs", time.time() - t0)
    return gremlin_client


def run(gremlin_client, query: str, bindings: dict | None = None):
    """Execute a single Gremlin query and return results."""
    try:
        future = gremlin_client.submitAsync(query, bindings=bindings)
        return future.result(timeout=QUERY_TIMEOUT)
    except FutureTimeoutError:
        log.error("⏱️  Query timed out after %ds: %.100s", QUERY_TIMEOUT, query)
        return None
    except Exception:
        log.error("⚠️  Query failed: %.100s\n%s", query, traceback.format_exc())
        return None


def run_batch(gremlin_client, queries):
    """
    Submit queries in concurrent batches for higher throughput.
    Each batch of BATCH_SIZE queries is submitted concurrently; results are
    collected before the next batch is dispatched (avoids rate-limit bursts).
    """
    results = []
    for chunk_start in range(0, len(queries), BATCH_SIZE):
        chunk = queries[chunk_start : chunk_start + BATCH_SIZE]
        log.debug("  Submitting batch %d–%d", chunk_start + 1, chunk_start + len(chunk))
        futures = [gremlin_client.submitAsync(q, bindings=b) for q, b in chunk]
        for i, fut in enumerate(futures):
            idx = chunk_start + i
            try:
                results.append(fut.result(timeout=QUERY_TIMEOUT))
            except FutureTimeoutError:
                log.error("⏱️  Batch item %d timed out", idx)
                results.append(None)
            except Exception:
                log.error("⚠️  Batch item %d failed:\n%s", idx, traceback.format_exc())
                results.append(None)
    return results


def drop_all(gremlin_client):
    """Clear all existing vertices for a clean seed."""
    if os.environ.get("ENV", "").lower() == "production":
        log.error("❌ Refusing to drop graph in production. Unset ENV=production to proceed.")
        sys.exit(1)
    if sys.stdin.isatty():
        try:
            confirm = input("⚠️  This will wipe ALL graph data. Type 'yes' to confirm: ")
        except EOFError:
            log.info("Aborted (non-interactive mode).")
            sys.exit(0)
        if confirm.strip().lower() != "yes":
            log.info("Aborted.")
            sys.exit(0)
    else:
        log.info("🤖 Non-interactive mode — skipping drop confirmation.")
    log.info("🗑️  Clearing existing graph data...")
    t0 = time.time()
    run(gremlin_client, "g.V().drop()")
    log.info("   Cleared in %.1fs", time.time() - t0)


# ── Scam UPI IDs ──────────────────────────────────────────────────────────────
# Format: (id, vpa, category, report_count, status, state, victims_est)
SCAM_UPIS = [
    ("upi1",  "taskpay.earn@ybl",         "job_scam",          27, "active",   "Maharashtra",    450),
    ("upi2",  "kbcprize2024@paytm",      "lottery_scam",      23, "active",   "Uttar Pradesh",  380),
    ("upi3",  "sbikyc.update@ybl",       "kyc_freeze",         8, "blocked",  "Rajasthan",      120),
    ("upi4",  "cashback.official@okaxis","fake_cashback",     31, "active",   "Delhi",          520),
    ("upi5",  "cbi.penalty@upi",         "digital_arrest",    12, "active",   "Tamil Nadu",     200),
    ("upi6",  "echallane.pay@ybl",       "govt_impersonation", 6, "active",   "Karnataka",       90),
    ("upi7",  "refund.process@paytm",    "fake_cashback",     19, "active",   "Gujarat",        310),
    ("upi8",  "youtube.task@ybl",        "job_scam",          27, "active",   "West Bengal",    440),
    ("upi9",  "jiodraw@paytm",           "lottery_scam",      15, "active",   "Bihar",          250),
    ("upi10", "loanfast@ybl",            "job_scam",           9, "active",   "Telangana",      150),
    ("upi11", "goldscheme@ybl",          "fake_cashback",     11, "active",   "Madhya Pradesh", 180),
    ("upi12", "customsduty@ybl",         "govt_impersonation",14, "active",   "Punjab",         230),
    ("upi13", "doubleincome@ybl",        "fake_cashback",     21, "active",   "Haryana",        350),
    ("upi14", "dream11winner@ybl",       "lottery_scam",      17, "active",   "Andhra Pradesh", 280),
    ("upi15", "meta-jobs@ybl",           "job_scam",           7, "active",   "Kerala",         110),
    ("upi16", "cybercell@ybl",           "digital_arrest",    18, "active",   "Delhi",          300),
    ("upi17", "flipkart-prize@okaxis",   "lottery_scam",      13, "active",   "Maharashtra",    210),
    ("upi18", "taxsettlement@ybl",       "govt_impersonation",10, "active",   "Uttar Pradesh",  165),
    ("upi19", "bgv-check@ybl",           "job_scam",           5, "active",   "Karnataka",       80),
    ("upi20", "bescom-urgent@ybl",       "govt_impersonation", 8, "active",   "Karnataka",      130),
]


# ── Phone numbers ─────────────────────────────────────────────────────────────
# Format: (id, number, state, operator)
SCAM_PHONES = [
    ("ph1",  "+91-9876500001", "Rajasthan",      "Jio"),
    ("ph2",  "+91-9876500002", "Uttar Pradesh",  "Airtel"),
    ("ph3",  "+91-9876500003", "Maharashtra",    "Jio"),
    ("ph4",  "+91-9876500004", "Delhi",          "BSNL"),
    ("ph5",  "+91-9876500005", "Tamil Nadu",     "Vi"),
    ("ph6",  "+91-9330284713", "West Bengal",    "Airtel"),
    ("ph7",  "+91-9223011112", "West Bengal",    "Jio"),
    ("ph8",  "+91-9876500008", "Gujarat",        "Airtel"),
    ("ph9",  "+91-9876500009", "Bihar",          "Jio"),
    ("ph10", "+91-9876500010", "Haryana",        "Vi"),
]


# ── UPI → Phone links (same scammer controls multiple accounts) ───────────────
# Format: (phone_id, upi_id, relationship)
LINKS = [
    ("ph1",  "upi1",  "OPERATED_BY"),
    ("ph1",  "upi8",  "OPERATED_BY"),
    ("ph2",  "upi2",  "OPERATED_BY"),
    ("ph2",  "upi9",  "OPERATED_BY"),
    ("ph3",  "upi4",  "OPERATED_BY"),
    ("ph3",  "upi7",  "OPERATED_BY"),
    ("ph3",  "upi13", "OPERATED_BY"),
    ("ph4",  "upi5",  "OPERATED_BY"),
    ("ph4",  "upi16", "OPERATED_BY"),
    ("ph5",  "upi3",  "OPERATED_BY"),
    ("ph6",  "upi6",  "OPERATED_BY"),
    ("ph7",  "upi12", "OPERATED_BY"),
    ("ph8",  "upi11", "OPERATED_BY"),
    ("ph9",  "upi17", "OPERATED_BY"),
    ("ph10", "upi10", "OPERATED_BY"),
    ("ph10", "upi15", "OPERATED_BY"),
    ("ph10", "upi19", "OPERATED_BY"),
]


def seed_upis(gremlin_client):
    log.info("📌 Seeding %d scam UPI vertices...", len(SCAM_UPIS))
    t0 = time.time()
    queries = []
    for uid, vpa, cat, count, status, state, victims in SCAM_UPIS:
        q = (
            "g.addV('UpiId')"
            ".property('id', vid)"
            ".property('vpa', vpa)"
            ".property('category', cat)"
            ".property('report_count', report_count)"
            ".property('status', status)"
            ".property('state', state)"
            ".property('estimated_victims', estimated_victims)"
            ".property('pk', cat)"
        )
        bindings = {
            "vid": uid,
            "vpa": vpa,
            "cat": cat,
            "report_count": count,
            "status": status,
            "state": state,
            "estimated_victims": victims,
        }
        queries.append((q, bindings))
    run_batch(gremlin_client, queries)
    log.info("   ✅ %d UPI vertices seeded in %.1fs", len(SCAM_UPIS), time.time() - t0)


def seed_phones(gremlin_client):
    log.info("📱 Seeding %d phone vertices...", len(SCAM_PHONES))
    t0 = time.time()
    queries = []
    for pid, number, state, operator in SCAM_PHONES:
        q = (
            "g.addV('Phone')"
            ".property('id', pid)"
            ".property('number', number)"
            ".property('state', state)"
            ".property('operator', operator)"
            ".property('pk', 'phone')"
        )
        bindings = {"pid": pid, "number": number, "state": state, "operator": operator}
        queries.append((q, bindings))
    run_batch(gremlin_client, queries)
    log.info("   ✅ %d phone vertices seeded in %.1fs", len(SCAM_PHONES), time.time() - t0)


def seed_links(gremlin_client):
    log.info("🔗 Creating %d edges (phone → UPI)...", len(LINKS))
    t0 = time.time()
    queries = []
    for pid, uid, rel in LINKS:
        q = "g.V(pid).addE(rel).to(g.V(uid))"
        bindings = {"pid": pid, "uid": uid, "rel": rel}
        queries.append((q, bindings))
    run_batch(gremlin_client, queries)
    log.info("   ✅ %d edges created in %.1fs", len(LINKS), time.time() - t0)


def print_stats(gremlin_client):
    log.info("📊 Graph Statistics:")
    t0 = time.time()
    v_count = run(gremlin_client, "g.V().count()")
    e_count = run(gremlin_client, "g.E().count()")
    log.info("   Vertices: %s", v_count)
    log.info("   Edges:    %s", e_count)
    rings = run(
        gremlin_client,
        "g.V().hasLabel('Phone').where(out('OPERATED_BY').count().is(gte(2))).values('number')",
    )
    log.info("🔍 Scam rings (phones controlling 2+ UPI IDs): %s", rings)
    log.info("   Stats fetched in %.1fs", time.time() - t0)


def main():
    log.info("🕸️  FraudShield India — Seeding Scam Network Graph")
    log.info("=" * 55)
    script_start = time.time()

    cosmos_endpoint = os.environ.get("COSMOS_DB_ENDPOINT", "")
    cosmos_key = os.environ.get("COSMOS_DB_KEY", "")

    log.info("ENDPOINT present: %s", bool(cosmos_endpoint))
    log.info("KEY present: %s", bool(cosmos_key))
    if cosmos_endpoint:
        log.info("ENDPOINT prefix: %s...", cosmos_endpoint[:30])

    if not cosmos_endpoint or not cosmos_key:
        log.error(
            "Available COSMOS env vars: %s",
            [k for k in os.environ if "COSMOS" in k.upper()],
        )
        log.error(
            "❌ COSMOS_DB_ENDPOINT or COSMOS_DB_KEY not set. Configure them in "
            "GitHub Actions secrets or your environment."
        )
        sys.exit(1)

    # Normalise endpoint: strip protocol (https/http/wss), optional :443 or :443/ and trailing slash
    cosmos_endpoint = (
        cosmos_endpoint.replace("https://", "")
        .replace("http://", "")
        .replace("wss://", "")
    )
    cosmos_endpoint = cosmos_endpoint.replace(":443/", "").replace(":443", "").rstrip("/")

    gremlin_client = None
    try:
        gremlin_client = _build_client(cosmos_endpoint, cosmos_key)

        t0 = time.time()
        drop_all(gremlin_client)
        log.info("drop_all completed in %.1fs", time.time() - t0)

        t0 = time.time()
        seed_upis(gremlin_client)
        log.info("seed_upis completed in %.1fs", time.time() - t0)

        t0 = time.time()
        seed_phones(gremlin_client)
        log.info("seed_phones completed in %.1fs", time.time() - t0)

        t0 = time.time()
        seed_links(gremlin_client)
        log.info("seed_links completed in %.1fs", time.time() - t0)

        print_stats(gremlin_client)

        log.info("✅ Graph seeded successfully in %.1fs total", time.time() - script_start)
        log.info("   View at: portal.azure.com → fraudshield-cosmosdb → Data Explorer")

    except Exception:
        log.error("❌ Seed failed:\n%s", traceback.format_exc())
        sys.exit(1)
    finally:
        if gremlin_client is not None:
            log.info("Closing Gremlin client...")
            gremlin_client.close()
            log.info("Client closed.")


if __name__ == "__main__":
    main()

