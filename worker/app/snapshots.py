from datetime import datetime, timedelta, timezone

from app.db import get_database

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SNAPSHOT_STATE_ID = "state"


async def _build_stats_snapshot(db) -> dict:
    pipeline = [
        {"$match": {"status": "Open"}},
        {
            "$addFields": {
                "effective_severity": {"$toLower": {"$ifNull": ["$override_severity", "$severity"]}},
            }
        },
        {"$match": {"effective_severity": {"$in": SEVERITIES}}},
        {"$group": {"_id": "$effective_severity", "count": {"$sum": 1}}},
    ]
    results = await db.vulnerabilities.aggregate(pipeline).to_list(length=None)
    open_severity_distribution = {severity: 0 for severity in SEVERITIES}
    for document in results:
        severity = str(document.get("_id", "")).lower()
        if severity in open_severity_distribution:
            open_severity_distribution[severity] = int(document.get("count", 0) or 0)

    return {
        "assets": await db.assets.count_documents({}),
        "open_vulnerabilities": sum(open_severity_distribution.values()),
        "critical_vulnerabilities": open_severity_distribution["critical"],
        "high_vulnerabilities": open_severity_distribution["high"],
        "medium_vulnerabilities": open_severity_distribution["medium"],
        "low_vulnerabilities": open_severity_distribution["low"],
        "info_vulnerabilities": open_severity_distribution["info"],
        "open_severity_distribution": open_severity_distribution,
    }


async def _build_trend_snapshot(db, days: int) -> dict:
    now = datetime.now(timezone.utc)
    start_date = (now - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)

    pipeline = [
        {"$match": {"first_seen": {"$gte": start_date}}},
        {
            "$addFields": {
                "effective_severity": {"$toLower": {"$ifNull": ["$override_severity", "$severity"]}},
            }
        },
        {"$match": {"effective_severity": {"$in": SEVERITIES}}},
        {
            "$project": {
                "date": {
                    "$dateToString": {
                        "format": "%Y-%m-%d",
                        "date": "$first_seen",
                    }
                },
                "severity": "$effective_severity",
            }
        },
        {
            "$group": {
                "_id": {"date": "$date", "severity": "$severity"},
                "count": {"$sum": 1},
            }
        },
    ]
    results = await db.vulnerabilities.aggregate(pipeline).to_list(length=None)

    labels = [(start_date + timedelta(days=index)).strftime("%Y-%m-%d") for index in range(days)]
    grouped = {label: {severity: 0 for severity in SEVERITIES} for label in labels}

    for document in results:
        label = document["_id"]["date"]
        severity = document["_id"]["severity"]
        if label in grouped and severity in grouped[label]:
            grouped[label][severity] = document["count"]

    return {
        "days": days,
        "labels": labels,
        "series": {severity: [grouped[label][severity] for label in labels] for severity in SEVERITIES},
    }


async def _build_tech_stack_snapshot(db, limit: int = 40) -> list[dict]:
    pipeline = [
        {
            "$addFields": {
                "effective_severity": {"$toLower": {"$ifNull": ["$override_severity", "$severity"]}},
            }
        },
        {
            "$match": {
                "effective_severity": "info",
                "host": {"$exists": True, "$ne": None},
                "name": {"$exists": True, "$ne": None},
                "status": "Open",
            }
        },
        {"$group": {"_id": "$name", "hosts": {"$addToSet": "$host"}}},
        {"$project": {"_id": 0, "name": "$_id", "host_count": {"$size": "$hosts"}}},
        {"$sort": {"host_count": -1, "name": 1}},
        {"$limit": limit},
    ]
    return await db.vulnerabilities.aggregate(pipeline).to_list(length=limit)


async def recompute_dashboard_snapshots(days_options: tuple[int, ...] = (7, 30), tech_limit: int = 40) -> None:
    db = get_database()
    generated_at = datetime.now(timezone.utc)

    stats_payload = await _build_stats_snapshot(db)
    await db.dashboard_snapshots.update_one(
        {"_id": "stats"},
        {"$set": {"payload": stats_payload, "generated_at": generated_at}},
        upsert=True,
    )

    for days in days_options:
        trend_payload = await _build_trend_snapshot(db, days)
        await db.dashboard_snapshots.update_one(
            {"_id": f"trend_{days}"},
            {"$set": {"payload": trend_payload, "generated_at": generated_at}},
            upsert=True,
        )

    tech_payload = await _build_tech_stack_snapshot(db, tech_limit)
    await db.dashboard_snapshots.update_one(
        {"_id": "tech_stack"},
        {"$set": {"payload": tech_payload, "generated_at": generated_at}},
        upsert=True,
    )
    await db.dashboard_snapshot_state.update_one(
        {"_id": SNAPSHOT_STATE_ID},
        {
            "$set": {
                "dirty": False,
                "last_refreshed_at": generated_at,
            },
            "$setOnInsert": {"created_at": generated_at},
        },
        upsert=True,
    )
