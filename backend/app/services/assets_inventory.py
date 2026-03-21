from datetime import datetime, timezone

from motor.motor_asyncio import AsyncIOMotorDatabase
from app.utils.host_classification import classify_host_type

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


def _sort_ports(values: list[str]) -> list[str]:
    unique_values = {str(value) for value in values if value}
    return sorted(unique_values, key=lambda value: (not value.isdigit(), int(value) if value.isdigit() else value))


async def recalculate_asset(db: AsyncIOMotorDatabase, host: str) -> None:
    vulnerabilities = await db.vulnerabilities.find({"host": host, "status": "Open"}).to_list(length=None)
    if vulnerabilities:
        highest_severity = max(
            [document.get("override_severity") or document.get("severity") for document in vulnerabilities],
            key=_severity_key,
        )
        ip_addresses = sorted({document.get("ip") for document in vulnerabilities if document.get("ip")})
        open_ports = _sort_ports([str(document.get("port")) for document in vulnerabilities if document.get("port")])
        services = sorted(
            {
                document.get("scheme") or document.get("type")
                for document in vulnerabilities
                if document.get("scheme") or document.get("type")
            }
        )
        template_ids = sorted(
            {document.get("template-id") for document in vulnerabilities if document.get("template-id")}
        )
        last_seen_values = [document.get("last_seen") for document in vulnerabilities if document.get("last_seen")]
        last_seen = max(last_seen_values) if last_seen_values else datetime.now(timezone.utc)
        await db.assets.update_one(
            {"host": host},
            {
                "$set": {
                    "host": host,
                    "highest_severity": highest_severity,
                    "ip_addresses": ip_addresses,
                    "open_ports": open_ports,
                    "services": services,
                    "template_ids": template_ids,
                    "last_seen": last_seen,
                    "vulnerability_count": len(vulnerabilities),
                    "type": classify_host_type(host),
                },
                "$setOnInsert": {
                    "first_seen": last_seen,
                },
            },
            upsert=True,
        )
        return

    existing_asset = await db.assets.find_one({"host": host})
    if existing_asset:
        await db.assets.update_one(
            {"host": host},
            {
                "$set": {
                    "highest_severity": None,
                    "vulnerability_count": 0,
                    "open_ports": [],
                    "services": [],
                    "template_ids": [],
                }
            },
        )


async def ensure_asset_inventory(db: AsyncIOMotorDatabase) -> None:
    assets_count = await db.assets.count_documents({})
    missing_shape = await db.assets.find_one(
        {
            "$or": [
                {"open_ports": {"$exists": False}},
                {"services": {"$exists": False}},
                {"template_ids": {"$exists": False}},
                {"vulnerability_count": {"$exists": False}},
            ]
        }
    )

    if assets_count > 0 and not missing_shape:
        return

    hosts = await db.vulnerabilities.distinct("host", {"host": {"$exists": True, "$ne": None}})
    for host in hosts:
        await recalculate_asset(db, host)
