"""
FraudShield India — Investigation Agent
Queries the Cosmos DB Gremlin graph to find scam rings and related
entities for a given UPI ID or phone number.
"""
import os
from dotenv import load_dotenv

load_dotenv()

try:
    from gremlin_python.driver import client, serializer
except ImportError:
    raise ImportError("Run: pip install gremlinpython")


def _get_gremlin_client():
    """Return a connected Gremlin client for Cosmos DB."""
    endpoint = os.environ.get("COSMOS_DB_ENDPOINT", "").replace("https://", "").rstrip("/").replace(":443", "")
    key = os.environ.get("COSMOS_DB_KEY", "")
    if not endpoint or not key:
        raise RuntimeError("COSMOS_DB_ENDPOINT and COSMOS_DB_KEY must be set.")
    return client.Client(
        f"wss://{endpoint}:443/",
        "g",
        username="/dbs/FraudShieldDB/colls/ScamNetwork",
        password=key,
        message_serializer=serializer.GraphSONSerializersV2d0(),
    )


def investigate_upi(vpa: str) -> dict:
    """Look up a UPI VPA in the graph and return its scam details plus related phone numbers.

    Args:
        vpa: UPI Virtual Payment Address, e.g. "taskpay.earn@ybl"

    Returns:
        dict with keys: found (bool), upi_data (dict), related_phones (list)
    """
    gremlin = _get_gremlin_client()
    try:
        # Find the UPI vertex
        upi_result = gremlin.submitAsync(
            "g.V().hasLabel('UpiId').has('vpa', vpa).valueMap(true)",
            bindings={"vpa": vpa},
        ).result()

        if not upi_result:
            return {"found": False, "upi_data": {}, "related_phones": []}

        upi_data = dict(upi_result[0])

        # Find phones that operate this UPI (incoming OPERATED_BY edges)
        phones_result = gremlin.submitAsync(
            "g.V().hasLabel('UpiId').has('vpa', vpa)"
            ".in('OPERATED_BY').valueMap(true)",
            bindings={"vpa": vpa},
        ).result()

        related_phones = [dict(p) for p in phones_result]
        return {"found": True, "upi_data": upi_data, "related_phones": related_phones}
    finally:
        gremlin.close()


def investigate_phone(number: str) -> dict:
    """Look up a phone number in the graph and return related UPI IDs.

    Args:
        number: Phone number, e.g. "+91-9876500001"

    Returns:
        dict with keys: found (bool), phone_data (dict), operated_upis (list),
        is_ring (bool — True if phone controls 2+ UPI IDs)
    """
    gremlin = _get_gremlin_client()
    try:
        phone_result = gremlin.submitAsync(
            "g.V().hasLabel('Phone').has('number', number).valueMap(true)",
            bindings={"number": number},
        ).result()

        if not phone_result:
            return {"found": False, "phone_data": {}, "operated_upis": [], "is_ring": False}

        phone_data = dict(phone_result[0])

        upis_result = gremlin.submitAsync(
            "g.V().hasLabel('Phone').has('number', number)"
            ".out('OPERATED_BY').valueMap(true)",
            bindings={"number": number},
        ).result()

        operated_upis = [dict(u) for u in upis_result]
        return {
            "found": True,
            "phone_data": phone_data,
            "operated_upis": operated_upis,
            "is_ring": len(operated_upis) >= 2,
        }
    finally:
        gremlin.close()


def find_scam_rings() -> list:
    """Return phone numbers that control 2 or more UPI IDs (scam rings).

    Returns:
        list of phone number strings
    """
    gremlin = _get_gremlin_client()
    try:
        result = gremlin.submitAsync(
            "g.V().hasLabel('Phone').where(out('OPERATED_BY').count().is(gte(2)))"
            ".values('number')"
        ).result()
        return list(result)
    finally:
        gremlin.close()


if __name__ == "__main__":
    print("FraudShield — Investigation Agent")
    print("=" * 40)

    rings = find_scam_rings()
    print(f"Detected {len(rings)} scam ring(s):")
    for r in rings:
        print(f"  {r}")
        details = investigate_phone(r)
        for u in details.get("operated_upis", []):
            vpa = u.get("vpa", ["?"])[0] if isinstance(u.get("vpa"), list) else u.get("vpa", "?")
            print(f"    -> {vpa}")
