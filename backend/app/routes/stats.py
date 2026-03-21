from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query

from app.core.rbac import require_role
from app.db.mongo import get_database
from app.schemas.auth import CurrentUser

router = APIRouter()
SEVERITIES = ["critical", "high", "medium", "low", "info"]


@router.get("/stats")
async def get_stats(_: CurrentUser = Depends(require_role("admin", "viewer"))):
    db = get_database()
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


@router.get("/stats/trend")
async def get_attack_surface_trend(
    days: int = Query(default=7, ge=7, le=30),
    _: CurrentUser = Depends(require_role("admin", "viewer")),
):
    db = get_database()
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
                "_id": {
                    "date": "$date",
                    "severity": "$severity",
                },
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
        "series": {
            severity: [grouped[label][severity] for label in date_labels]
            for severity in SEVERITIES
        },
    }


@router.get("/stats/tech-stack")
async def get_exposed_tech_stack(_: CurrentUser = Depends(require_role("admin", "viewer"))):
    db = get_database()
    pipeline = [
        {
            "$match": {
                "severity": "info",
                "host": {"$exists": True, "$ne": None},
                "name": {"$exists": True, "$ne": None},
            }
        },
        {
            "$group": {
                "_id": "$name",
                "hosts": {"$addToSet": "$host"},
            }
        },
        {
            "$project": {
                "_id": 0,
                "name": "$_id",
                "host_count": {"$size": "$hosts"},
            }
        },
        {"$sort": {"host_count": -1, "name": 1}},
        {"$limit": 40},
    ]

    return await db.vulnerabilities.aggregate(pipeline).to_list(length=40)
