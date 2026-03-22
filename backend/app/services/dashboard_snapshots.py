from datetime import datetime, timedelta, timezone

SEVERITIES = ["critical", "high", "medium", "low", "info"]


def _coerce_utc(value):
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    return None


async def get_snapshot_payload(db, key: str, max_age_seconds: int):
    document = await db.dashboard_snapshots.find_one({"_id": key})
    if not document:
        return None

    generated_at = _coerce_utc(document.get("generated_at"))
    if not generated_at:
        return None

    age_seconds = (datetime.now(timezone.utc) - generated_at).total_seconds()
    if age_seconds > max(1, max_age_seconds):
        return None

    return {
        "payload": document.get("payload"),
        "generated_at": generated_at,
    }


async def build_live_stats(db):
    open_severity_distribution = {
        severity: await db.vulnerabilities.count_documents({"status": "Open", "severity": severity})
        for severity in SEVERITIES
    }
    return {
        "assets": await db.assets.count_documents({}),
        "open_vulnerabilities": await db.vulnerabilities.count_documents({"status": "Open"}),
        "critical_vulnerabilities": open_severity_distribution["critical"],
        "high_vulnerabilities": open_severity_distribution["high"],
        "medium_vulnerabilities": open_severity_distribution["medium"],
        "low_vulnerabilities": open_severity_distribution["low"],
        "info_vulnerabilities": open_severity_distribution["info"],
        "open_severity_distribution": open_severity_distribution,
    }


async def build_live_trend(db, days: int):
    now = datetime.now(timezone.utc)
    start_date = (now - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)

    pipeline = [
        {"$match": {"first_seen": {"$gte": start_date}, "severity": {"$in": SEVERITIES}}},
        {
            "$project": {
                "date": {
                    "$dateToString": {
                        "format": "%Y-%m-%d",
                        "date": "$first_seen",
                    }
                },
                "severity": "$severity",
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

    date_labels = [(start_date + timedelta(days=index)).strftime("%Y-%m-%d") for index in range(days)]
    grouped = {
        date_label: {severity: 0 for severity in SEVERITIES}
        for date_label in date_labels
    }

    for document in results:
        date_label = document["_id"]["date"]
        severity = document["_id"]["severity"]
        if date_label in grouped and severity in grouped[date_label]:
            grouped[date_label][severity] = document["count"]

    return {
        "days": days,
        "labels": date_labels,
        "series": {severity: [grouped[label][severity] for label in date_labels] for severity in SEVERITIES},
    }


async def build_live_tech_stack(db, limit: int = 40):
    pipeline = [
        {
            "$match": {
                "severity": "info",
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
