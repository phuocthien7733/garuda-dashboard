from datetime import datetime, timedelta, timezone

from pymongo import ASCENDING, UpdateOne

from app.db import get_database


async def archive_stale_vulnerabilities(archive_after_days: int, batch_size: int = 1000) -> int:
    db = get_database()
    cutoff_time = datetime.now(timezone.utc) - timedelta(days=max(1, archive_after_days))
    total_archived = 0

    while True:
        documents = await db.vulnerabilities.find(
            {
                "status": {"$ne": "Open"},
                "last_seen": {"$lt": cutoff_time},
            }
        ).sort("last_seen", ASCENDING).limit(batch_size).to_list(length=batch_size)

        if not documents:
            break

        archive_time = datetime.now(timezone.utc)
        archive_writes: list[UpdateOne] = []
        source_ids: list = []

        for document in documents:
            source_id = document.get("_id")
            if source_id is None:
                continue

            normalized = dict(document)
            normalized.pop("_id", None)
            normalized["archived_at"] = archive_time
            normalized["archived_reason"] = f"non-open-{archive_after_days}d"

            fingerprint = normalized.get("fingerprint")
            if not fingerprint:
                continue

            archive_writes.append(
                UpdateOne(
                    {"fingerprint": fingerprint},
                    {"$set": normalized},
                    upsert=True,
                )
            )
            source_ids.append(source_id)

        if not source_ids:
            break

        if archive_writes:
            await db.vulnerabilities_archive.bulk_write(archive_writes, ordered=False)
        await db.vulnerabilities.delete_many({"_id": {"$in": source_ids}})
        total_archived += len(source_ids)

    return total_archived
