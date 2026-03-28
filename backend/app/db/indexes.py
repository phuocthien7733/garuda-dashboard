from pymongo import ASCENDING, DESCENDING

from app.core.config import get_settings
from app.db.mongo import get_database


async def ensure_indexes() -> None:
    db = get_database()
    settings = get_settings()
    retention_seconds = max(1, int(settings.vulnerability_archive_retention_days)) * 24 * 60 * 60
    await db.vulnerabilities.create_index([("fingerprint", ASCENDING)], unique=True)
    await db.vulnerabilities.create_index([("status", ASCENDING), ("severity", ASCENDING), ("last_seen", DESCENDING)])
    await db.vulnerabilities.create_index([("status", ASCENDING), ("last_seen", DESCENDING)])
    await db.vulnerabilities.create_index([("host", ASCENDING), ("status", ASCENDING), ("last_seen", DESCENDING)])
    await db.vulnerabilities.create_index([("asset_id", ASCENDING), ("status", ASCENDING), ("severity", ASCENDING), ("last_seen", DESCENDING)])
    await db.vulnerabilities.create_index([("first_seen", DESCENDING)])
    await db.vulnerabilities.create_index([("last_seen", DESCENDING)])
    await db.vulnerabilities.create_index([("template_id", ASCENDING)])
    await db.vulnerabilities.create_index([("scanner", ASCENDING), ("status", ASCENDING), ("last_seen", DESCENDING)])
    await db.vulnerabilities.create_index([("host_normalized", ASCENDING), ("last_seen", DESCENDING)])
    await db.vulnerabilities.create_index([("asset_id", ASCENDING)])
    await db.assets.create_index([("host", ASCENDING)], unique=True)
    await db.assets.create_index([("highest_severity", ASCENDING), ("vulnerability_count", DESCENDING), ("last_seen", DESCENDING)])
    await db.assets.create_index([("last_seen", DESCENDING)])
    await db.assets.create_index([("type", ASCENDING), ("highest_severity", ASCENDING)])
    await db.vulnerabilities_archive.create_index([("fingerprint", ASCENDING)], unique=True)
    await db.vulnerabilities_archive.create_index([("status", ASCENDING), ("severity", ASCENDING), ("last_seen", DESCENDING)])
    await db.vulnerabilities_archive.create_index([("host", ASCENDING), ("last_seen", DESCENDING)])
    archive_index_info = await db.vulnerabilities_archive.index_information()
    ttl_index_name = "archived_at_ttl"
    existing_ttl = archive_index_info.get(ttl_index_name)
    if existing_ttl and existing_ttl.get("expireAfterSeconds") != retention_seconds:
        await db.vulnerabilities_archive.drop_index(ttl_index_name)
        existing_ttl = None
    if not existing_ttl:
        await db.vulnerabilities_archive.create_index(
            [("archived_at", ASCENDING)],
            name=ttl_index_name,
            expireAfterSeconds=retention_seconds,
        )
    await db.dashboard_snapshots.create_index([("generated_at", DESCENDING)])
    await db.users.create_index([("username", ASCENDING)], unique=True)
    await db.users.create_index([("email", ASCENDING)], unique=True, sparse=True)
    await db.mfa_challenges.create_index([("challenge_id", ASCENDING)], unique=True)
    await db.mfa_challenges.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)
    await db.auth_rate_limits.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)
    await db.revoked_tokens.create_index([("token_id", ASCENDING)], unique=True)
    await db.revoked_tokens.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)
