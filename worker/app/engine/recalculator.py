"""
Asset stats recalculation using a MongoDB aggregation pipeline.

After bulk_write completes for a batch, call recalculate_assets() with the set of
host_normalized keys that were touched.  The pipeline recomputes:
  - highest_severity   (from all Open findings for that host)
  - vulnerability_count
  - open_finding_types (distinct list)
  - services           (from port_metadata)

This replaces the old Python-side read-then-write loop.
"""
from __future__ import annotations

import logging

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.udm.enums import SEVERITY_RANK, SeverityLevel

logger = logging.getLogger("ingestion-worker.recalculator")


async def recalculate_assets(
    db: AsyncIOMotorDatabase,
    touched_hosts: set[str],
) -> None:
    """Recompute stats for every asset in `touched_hosts` using an aggregation pipeline."""
    if not touched_hosts:
        return

    # Aggregate open findings grouped by host_normalized
    pipeline = [
        {
            "$match": {
                "target.host_normalized": {"$in": list(touched_hosts)},
                "status": "Open",
            }
        },
        {
            "$group": {
                "_id":              "$target.host_normalized",
                "max_rank":         {"$max": "$_severity_rank"},
                "vuln_count":       {"$sum": 1},
                "finding_types":    {"$addToSet": "$finding_type"},
                "max_severity":     {
                    "$max": {
                        "$cond": {
                            "if":   {"$gt": ["$_severity_rank", 0]},
                            "then": "$severity",
                            "else": "unknown",
                        }
                    }
                },
            }
        },
    ]

    results = await db.vulnerabilities.aggregate(pipeline).to_list(length=None)
    stats_by_host: dict[str, dict] = {r["_id"]: r for r in results}

    for host in touched_hosts:
        stats = stats_by_host.get(host)

        if stats:
            # Determine highest_severity from the max rank
            rank = stats.get("max_rank", 0)
            highest = _rank_to_severity(rank)
            await db.assets.update_one(
                {"host_normalized": host},
                {
                    "$set": {
                        "highest_severity":   highest,
                        "vulnerability_count": stats["vuln_count"],
                        "open_finding_types": sorted(stats["finding_types"]),
                    }
                },
            )
            # Also update services array from port_metadata (if asset exists)
            await _refresh_services(db, host)
        else:
            # No open findings for this host
            await db.assets.update_one(
                {"host_normalized": host},
                {
                    "$set": {
                        "highest_severity":   None,
                        "vulnerability_count": 0,
                        "open_finding_types": [],
                    }
                },
            )


async def _refresh_services(db: AsyncIOMotorDatabase, host_normalized: str) -> None:
    """Rebuild the flat `services` array from port_metadata (open ports only)."""
    asset = await db.assets.find_one(
        {"host_normalized": host_normalized},
        {"port_metadata": 1},
    )
    if not asset:
        return
    port_meta = asset.get("port_metadata") or {}
    services = sorted({
        v.get("service", "")
        for v in port_meta.values()
        if v.get("status") == "open" and v.get("service")
    })
    await db.assets.update_one(
        {"host_normalized": host_normalized},
        {"$set": {"services": services}},
    )


def _rank_to_severity(rank: int) -> str:
    """Convert a _severity_rank integer back to its SeverityLevel string."""
    for sev, r in SEVERITY_RANK.items():
        if r == rank:
            return sev.value
    return SeverityLevel.UNKNOWN.value
