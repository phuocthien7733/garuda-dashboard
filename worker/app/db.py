from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING, DESCENDING

from app.config import get_settings

settings = get_settings()
client = AsyncIOMotorClient(settings.resolved_mongo_uri)
database = client[settings.mongo_db_name]


def get_database():
    return database


async def ensure_indexes() -> None:
    retention_seconds = max(1, int(settings.vulnerability_archive_retention_days)) * 24 * 60 * 60
    await database.vulnerabilities.create_index([("fingerprint", ASCENDING)], unique=True)
    await database.vulnerabilities.create_index([("_severity_rank", ASCENDING)])  # internal MAX field
    await database.vulnerabilities.create_index([("target.host_normalized", ASCENDING), ("status", ASCENDING)])
    await database.vulnerabilities.create_index([("status", ASCENDING), ("severity", ASCENDING), ("last_seen", DESCENDING)])
    await database.vulnerabilities.create_index([("host", ASCENDING), ("status", ASCENDING), ("last_seen", DESCENDING)])
    await database.vulnerabilities.create_index([("asset_id", ASCENDING), ("status", ASCENDING), ("severity", ASCENDING), ("last_seen", DESCENDING)])
    await database.vulnerabilities.create_index([("first_seen", DESCENDING)])
    await database.vulnerabilities.create_index([("last_seen", DESCENDING)])
    await database.vulnerabilities.create_index([("template_id", ASCENDING)])
    await database.vulnerabilities.create_index([("scanner", ASCENDING), ("status", ASCENDING), ("last_seen", DESCENDING)])
    await database.vulnerabilities.create_index([("host_normalized", ASCENDING), ("last_seen", DESCENDING)])

    # ── Assets: migrate old non-sparse unique index on 'host' if it exists ────
    # v2 assets use host_normalized as the unique key; the old v1 'host' unique
    # non-sparse index blocks all v2 inserts because null counts as a unique value.
    try:
        index_info = await database.assets.index_information()
        old_host_idx = index_info.get("host_1", {})
        if old_host_idx.get("unique") and not old_host_idx.get("sparse"):
            await database.assets.drop_index("host_1")
    except Exception:
        pass  # index may not exist or already correct — safe to ignore

    # Keep a non-unique sparse index on 'host' for backward-compat queries on v1 docs
    await database.assets.create_index([("host", ASCENDING)], sparse=True)
    # Primary dedup key for v2 assets
    await database.assets.create_index([("host_normalized", ASCENDING)], unique=True, sparse=True)
    await database.assets.create_index([("highest_severity", ASCENDING), ("vulnerability_count", DESCENDING), ("last_seen", DESCENDING)])
    await database.assets.create_index([("last_seen", DESCENDING)])
    await database.assets.create_index([("type", ASCENDING), ("highest_severity", ASCENDING)])
    await database.vulnerabilities_archive.create_index([("fingerprint", ASCENDING)], unique=True)
    await database.vulnerabilities_archive.create_index([("status", ASCENDING), ("severity", ASCENDING), ("last_seen", DESCENDING)])
    archive_index_info = await database.vulnerabilities_archive.index_information()
    ttl_index_name = "archived_at_ttl"
    existing_ttl = archive_index_info.get(ttl_index_name)
    if existing_ttl and existing_ttl.get("expireAfterSeconds") != retention_seconds:
        await database.vulnerabilities_archive.drop_index(ttl_index_name)
        existing_ttl = None
    if not existing_ttl:
        await database.vulnerabilities_archive.create_index(
            [("archived_at", ASCENDING)],
            name=ttl_index_name,
            expireAfterSeconds=retention_seconds,
        )
    await database.vulnerabilities_archive.create_index([("host", ASCENDING), ("last_seen", DESCENDING)])
    await database.dashboard_snapshots.create_index([("generated_at", DESCENDING)])


def close_database() -> None:
    client.close()
