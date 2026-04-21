from __future__ import annotations

from datetime import datetime, timezone

from motor.motor_asyncio import AsyncIOMotorDatabase
from app.utils.host_classification import classify_host_type

# TODO: host_classification is duplicated between backend and worker.
# Consolidate into a shared package in a future mono-repo migration.

SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    None: 0,
}


def _severity_key(value: str | None) -> int:
    return SEVERITY_RANK.get(value, 0)


def _host_normalized_from_doc(document: dict) -> str | None:
    """Extract host_normalized from a v2 UDM document or fall back to v1 flat field."""
    target = document.get("target") or {}
    return target.get("host_normalized") or document.get("host") or None


async def recalculate_asset(db: AsyncIOMotorDatabase, host_normalized: str) -> None:
    """Recalculate asset stats from all open vulnerabilities for the given host.

    Works with both v2 UDM documents (``target.host_normalized``) and legacy v1
    documents (flat ``host`` field) so that migration can be done incrementally.
    """
    # Query both v2 and v1 documents for this host
    query = {
        "$or": [
            {"target.host_normalized": host_normalized},
            {"host": host_normalized},
        ],
        "status": "Open",
    }
    vulnerabilities = await db.vulnerabilities.find(query).to_list(length=None)

    if vulnerabilities:
        highest_severity = max(
            (document.get("override_severity") or document.get("severity") for document in vulnerabilities),
            key=_severity_key,
        )

        # Collect IP addresses from v2 target.ip or v1 ip field
        ip_addresses = sorted({
            (document.get("target") or {}).get("ip") or document.get("ip")
            for document in vulnerabilities
            if (document.get("target") or {}).get("ip") or document.get("ip")
        })

        last_seen_values = [document.get("last_seen") for document in vulnerabilities if document.get("last_seen")]
        last_seen = max(last_seen_values) if last_seen_values else datetime.now(timezone.utc)

        await db.assets.update_one(
            {"host_normalized": host_normalized},
            {
                "$set": {
                    "host_normalized": host_normalized,
                    "highest_severity": highest_severity,
                    "ip_addresses": ip_addresses,
                    "last_seen": last_seen,
                    "vulnerability_count": len(vulnerabilities),
                    "type": classify_host_type(host_normalized),
                },
                "$setOnInsert": {
                    "first_seen": last_seen,
                },
            },
            upsert=True,
        )
        return

    existing_asset = await db.assets.find_one({"host_normalized": host_normalized})
    if existing_asset:
        await db.assets.update_one(
            {"host_normalized": host_normalized},
            {
                "$set": {
                    "highest_severity": None,
                    "vulnerability_count": 0,
                }
            },
        )


async def ensure_asset_inventory(db: AsyncIOMotorDatabase) -> None:
    assets_count = await db.assets.count_documents({})
    missing_shape = await db.assets.find_one(
        {
            "$or": [
                {"vulnerability_count": {"$exists": False}},
            ]
        }
    )

    if assets_count > 0 and not missing_shape:
        return

    # Collect all distinct host_normalized values from v2 documents
    hosts_v2 = await db.vulnerabilities.distinct(
        "target.host_normalized",
        {"target.host_normalized": {"$exists": True, "$ne": None}},
    )
    # Also collect v1 flat hosts for backward compatibility
    hosts_v1 = await db.vulnerabilities.distinct(
        "host",
        {"host": {"$exists": True, "$ne": None}, "target": {"$exists": False}},
    )
    all_hosts = sorted({h for h in hosts_v2 + hosts_v1 if h})
    for host in all_hosts:
        await recalculate_asset(db, host)
