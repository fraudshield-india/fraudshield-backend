# Apply nest_asyncio patch to prevent event loop conflicts with gremlinpython on Python 3.11+
import nest_asyncio
nest_asyncio.apply()

"""
FraudShield India — Cosmos DB Gremlin Seed Script
Seeds scam UPI IDs, phone numbers, and their connections into the graph.

Usage:
  pip install gremlinpython python-dotenv
  python agents/investigation/seed_graph.py

Env vars needed:
  COSMOS_DB_ENDPOINT=https://fraudshield-graphdb.documents.azure.com:443/
  COSMOS_DB_KEY=your_primary_key
"""

import os
import sys
import time
from dotenv import load_dotenv

load_dotenv()

# ── Connect to Cosmos DB Gremlin ──────────────────────────────────────────────
try:
    from gremlin_python.driver import client, serializer
except ImportError:
    print("Run: pip install gremlinpython")
    exit(1)

# Debug: print what we're getting
COSMOS_ENDPOINT = os.environ.get("COSMOS_DB_ENDPOINT", "")
COSMOS_KEY = os.environ.get("COSMOS_DB_KEY", "")

print(f"ENDPOINT present: {bool(COSMOS_ENDPOINT)}")
print(f"KEY present: {bool(COSMOS_KEY)}")
print(f"ENDPOINT value: '{COSMOS_ENDPOINT[:30]}...' " if COSMOS_ENDPOINT else "ENDPOINT: EMPTY")

if not COSMOS_ENDPOINT or not COSMOS_KEY:
    print("Available env vars:", [k for k in os.environ.keys() if 'COSMOS' in k.upper()])
    print("❌ Set COSMOS_DB_ENDPOINT and COSMOS_DB_KEY in your .env file")
    exit(1)

COSMOS_ENDPOINT = COSMOS_ENDPOINT.replace("https://", "").replace("http://", "").rstrip("/").removesuffix(":443")
print(f"🔌 Connecting to: {COSMOS_ENDPOINT}")

gremlin = client.Client(
    f"wss://{COSMOS_ENDPOINT}:443/",
    "g",
    username="/dbs/FraudShieldDB/colls/ScamNetwork",
    password=COSMOS_KEY,
    message_serializer=serializer.GraphSONSerializersV2d0(),
)

def run(query: str, bindings: dict = None):
    """Execute a Gremlin query and return results."""
    try:
        result = gremlin.submitAsync(query, bindings=bindings).result()
        return result
    except Exception as e:
        print(f"  ⚠️  Query error: {e}")
        return None

def drop_all():
    """Clear all existing vertices for a clean seed."""
    if os.environ.get("ENV", "").lower() == "production":
        print("❌ Refusing to drop graph in production environment. Unset ENV=production to proceed.")
        exit(1)
    if sys.stdin.isatty():
        try:
            confirm = input("⚠️  This will wipe ALL graph data. Type 'yes' to confirm: ")
        except EOFError:
            print("Aborted (non-interactive mode).")
            exit(0)
        if confirm.strip().lower() != "yes":
            print("Aborted.")
            exit(0)
    else:
        print("🤖 Non-interactive mode detected — skipping confirmation prompt.")
    print("🗑️  Clearing existing graph data...")
    run("g.V().drop()")
    time.sleep(2)

# ── Scam UPI IDs ──────────────────────────────────────────────────────────────
# Format: (id, vpa, category, report_count, status, state, victims_est)
SCAM_UPIS = [
    ("upi1",  "taskpay.earn@ybl",         "job_scam",          27, "active",   "Maharashtra",    450),
    ("upi2",  "kbcprize2024@paytm",        "lottery_scam",      23, "active",   "Uttar Pradesh",  380),
    ("upi3",  "sbikyc.update@ybl",         "kyc_freeze",         8, "blocked",  "Rajasthan",      120),
    ("upi4",  "cashback.official@okaxis",  "fake_cashback",     31, "active",   "Delhi",          520),
    ("upi5",  "cbi.penalty@upi",           "digital_arrest",    12, "active",   "Tamil Nadu",     200),
    ("upi6",  "echallane.pay@ybl",         "govt_impersonation", 6, "active",   "Karnataka",       90),
    ("upi7",  "refund.process@paytm",      "fake_cashback",     19, "active",   "Gujarat",        310),
    ("upi8",  "youtube.task@ybl",          "job_scam",          27, "active",   "West Bengal",    440),
    ("upi9",  "jiodraw@paytm",             "lottery_scam",      15, "active",   "Bihar",          250),
    ("upi10", "loanfast@ybl",              "job_scam",           9, "active",   "Telangana",      150),
    ("upi11", "goldscheme@ybl",            "fake_cashback",     11, "active",   "Madhya Pradesh", 180),
    ("upi12", "customsduty@ybl",           "govt_impersonation",14, "active",   "Punjab",         230),
    ("upi13", "doubleincome@ybl",          "fake_cashback",     21, "active",   "Haryana",        350),
    ("upi14", "dream11winner@ybl",         "lottery_scam",      17, "active",   "Andhra Pradesh", 280),
    ("upi15", "meta-jobs@ybl",             "job_scam",           7, "active",   "Kerala",         110),
    ("upi16", "cybercell@ybl",             "digital_arrest",    18, "active",   "Delhi",          300),
    ("upi17", "flipkart-prize@okaxis",     "lottery_scam",      13, "active",   "Maharashtra",    210),
    ("upi18", "taxsettlement@ybl",         "govt_impersonation",10, "active",   "Uttar Pradesh",  165),
    ("upi19", "bgv-check@ybl",             "job_scam",           5, "active",   "Karnataka",       80),
    ("upi20", "bescom-urgent@ybl",         "govt_impersonation", 8, "active",   "Karnataka",      130),
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
    ("ph1",  "upi8",  "OPERATED_BY"),   # Same phone → 2 UPIs = linked scammer
    ("ph2",  "upi2",  "OPERATED_BY"),
    ("ph2",  "upi9",  "OPERATED_BY"),   # Same phone → 2 UPIs
    ("ph3",  "upi4",  "OPERATED_BY"),
    ("ph3",  "upi7",  "OPERATED_BY"),   # Same phone → 2 UPIs
    ("ph3",  "upi13", "OPERATED_BY"),   # Same phone → 3 UPIs = scam ring!
    ("ph4",  "upi5",  "OPERATED_BY"),
    ("ph4",  "upi16", "OPERATED_BY"),   # Digital arrest ring
    ("ph5",  "upi3",  "OPERATED_BY"),
    ("ph6",  "upi6",  "OPERATED_BY"),
    ("ph7",  "upi12", "OPERATED_BY"),
    ("ph8",  "upi11", "OPERATED_BY"),
    ("ph9",  "upi17", "OPERATED_BY"),
    ("ph10", "upi10", "OPERATED_BY"),
    ("ph10", "upi15", "OPERATED_BY"),
    ("ph10", "upi19", "OPERATED_BY"),   # Job scam ring — same phone 3 UPIs
]

# ── Seed UPI vertices ─────────────────────────────────────────────────────────

def seed_upis():
    print(f"\n📌 Seeding {len(SCAM_UPIS)} scam UPI IDs...")
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
            "vid": uid, "vpa": vpa, "cat": cat,
            "report_count": count, "status": status, "state": state,
            "estimated_victims": victims,
        }
        run(q, bindings)
        print(f"  ✅ {vpa} ({cat}) — {state}")
        time.sleep(0.5)


def seed_phones():
    print(f"\n📱 Seeding {len(SCAM_PHONES)} scam phone numbers...")
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
        run(q, bindings)
        print(f"  ✅ {number} ({state}, {operator})")
        time.sleep(0.5)


def seed_links():
    print(f"\n🔗 Creating {len(LINKS)} edges (phone → UPI links)...")
    for pid, uid, rel in LINKS:
        q = "g.V(pid).addE(rel).to(g.V(uid))"
        bindings = {"pid": pid, "uid": uid, "rel": rel}
        run(q, bindings)
        print(f"  ✅ {pid} → {uid}")
        time.sleep(0.5)


def print_stats():
    print("\n📊 Graph Statistics:")
    v_count = gremlin.submitAsync("g.V().count()").result()
    e_count = gremlin.submitAsync("g.E().count()").result()
    print(f"  Vertices: {v_count}")
    print(f"  Edges:    {e_count}")

    print("\n🔍 Scam rings (phones controlling 2+ UPI IDs):")
    rings = gremlin.submitAsync(
        "g.V().hasLabel('Phone').where(out('OPERATED_BY').count().is(gte(2)))"
        ".values('number')"
    ).result()
    print(f"  {rings}")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("🕸️  FraudShield India — Seeding Scam Network Graph")
    print("=" * 55)

    drop_all()
    seed_upis()
    seed_phones()
    seed_links()
    print_stats()

    gremlin.close()
    print("\n✅ Graph seeded successfully!")
    print("   View at: portal.azure.com → fraudshield-graphdb → Data Explorer")
