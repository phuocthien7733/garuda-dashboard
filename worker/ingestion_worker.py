import asyncio
import logging
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers.polling import PollingObserver

from app.config import get_settings
from app.archive import archive_stale_vulnerabilities, purge_expired_archived_vulnerabilities
from app.db import close_database, ensure_indexes, get_database
from app.engine.processor import ProcessingSummary, process_file as engine_process_file
from app.adapters.registry import has_adapter
from app.snapshots import recompute_dashboard_snapshots

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("ingestion-worker")

settings = get_settings()
incoming_dir = Path(settings.incoming_dir)
archive_dir = Path(settings.archive_dir)
quarantine_dir = Path(settings.quarantine_dir)
processing_files: set[Path] = set()
queued_files: set[Path] = set()
failed_attempts: dict[Path, int] = {}
file_queue: asyncio.Queue[Path] = asyncio.Queue()
event_loop: asyncio.AbstractEventLoop | None = None


def _wait_until_file_ready(file_path: Path, retries: int = 10, delay_seconds: float = 0.5) -> bool:
    previous_size = -1
    for _ in range(retries):
        if not file_path.exists():
            return False
        current_size = file_path.stat().st_size
        if current_size > 0 and current_size == previous_size:
            return True
        previous_size = current_size
        time.sleep(delay_seconds)
    return file_path.exists() and file_path.stat().st_size > 0


def _schedule_file_processing(file_path: Path) -> None:
    global event_loop
    if event_loop is None or event_loop.is_closed():
        logger.error("Cannot schedule %s because the event loop is not available", file_path.name)
        return
    asyncio.run_coroutine_threadsafe(enqueue_file(file_path), event_loop)


class IncomingFileHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory or not event.src_path.endswith(".json"):
            return
        _schedule_file_processing(Path(event.src_path))

    def on_moved(self, event):
        if event.is_directory or not event.dest_path.endswith(".json"):
            return
        _schedule_file_processing(Path(event.dest_path))


async def enqueue_file(file_path: Path) -> None:
    normalized = file_path.resolve()
    if normalized in queued_files:
        return
    queued_files.add(normalized)
    await file_queue.put(normalized)


async def handle_file(file_path: Path) -> bool:
    if file_path in processing_files:
        return False
    if not file_path.exists():
        return False

    processing_files.add(file_path)
    try:
        if not _wait_until_file_ready(file_path):
            logger.warning("Skipping %s because the file was not ready in time", file_path.name)
            return False

        # Derive scanner name from the immediate sub-folder under incoming/
        relative_path = file_path.relative_to(incoming_dir)
        if len(relative_path.parts) < 2:
            logger.error("File %s is not inside a scanner folder — skipping", file_path.name)
            return False
        scanner_name = relative_path.parts[0]

        logger.info("Processing %s via engine (scanner=%s)", file_path.relative_to(incoming_dir), scanner_name)

        summary = await engine_process_file(
            file_path=file_path,
            scanner_name=scanner_name,
            archive_root=archive_dir,
            quarantine_root=quarantine_dir,
        )

        failed_attempts.pop(file_path, None)

        if summary.quarantined:
            logger.warning(
                "Quarantined %s | reason=%s",
                file_path.name,
                ", ".join(summary.errors),
            )
            return False

        logger.info(
            "Processed %s | processed=%s inserted=%s updated=%s assets=%s",
            file_path.name,
            summary.processed,
            summary.inserted,
            summary.updated,
            summary.assets_updated,
        )
        return summary.processed > 0
    except Exception as exc:
        # engine_process_file() handles its own errors internally;
        # this block only fires for unexpected bugs (e.g. scanner_name derivation).
        attempts = failed_attempts.get(file_path, 0) + 1
        failed_attempts[file_path] = attempts

        if attempts >= settings.ingest_max_retries:
            logger.error(
                "Unexpected error processing %s after %s attempts — giving up: %s",
                file_path.name, attempts, exc,
            )
            failed_attempts.pop(file_path, None)
        else:
            logger.exception(
                "Unexpected error processing %s (attempt %s/%s). Will retry.",
                file_path.name,
                attempts,
                settings.ingest_max_retries,
            )
        return False
    finally:
        processing_files.discard(file_path)


async def process_existing_files() -> None:
    for file_path in sorted(incoming_dir.rglob("*.json")):
        await enqueue_file(file_path)


async def queue_consumer(name: str, snapshot_dirty_ref: dict[str, bool]) -> None:
    while True:
        file_path = await file_queue.get()
        try:
            changed = await handle_file(file_path)
            if changed:
                snapshot_dirty_ref["dirty"] = True
        finally:
            queued_files.discard(file_path)
            file_queue.task_done()


async def main_async() -> None:
    incoming_dir.mkdir(parents=True, exist_ok=True)
    archive_dir.mkdir(parents=True, exist_ok=True)
    quarantine_dir.mkdir(parents=True, exist_ok=True)

    # Create sub-folders for every known adapter
    from app.adapters.registry import list_adapters
    for scanner_name in list_adapters():
        (incoming_dir / scanner_name).mkdir(parents=True, exist_ok=True)
        (archive_dir / scanner_name).mkdir(parents=True, exist_ok=True)
        (quarantine_dir / scanner_name).mkdir(parents=True, exist_ok=True)

    logger.info(
        "Worker bootstrap ready | incoming=%s archive=%s quarantine=%s",
        incoming_dir,
        archive_dir,
        quarantine_dir,
    )
    await ensure_indexes()
    await process_existing_files()
    last_archive_sweep = 0.0
    last_snapshot_refresh = 0.0
    last_snapshot_state_check = 0.0
    snapshot_state = {"dirty": True}
    db = get_database()

    observer = PollingObserver(timeout=1)
    observer.schedule(IncomingFileHandler(), str(incoming_dir), recursive=True)
    observer.start()
    logger.info("Watching %s for new JSON files", incoming_dir)
    concurrency = max(1, int(settings.ingest_concurrency))
    consumers = [
        asyncio.create_task(queue_consumer(f"consumer-{index + 1}", snapshot_state))
        for index in range(concurrency)
    ]

    try:
        while True:
            await process_existing_files()
            now_monotonic = time.monotonic()
            if not snapshot_state["dirty"] and now_monotonic - last_snapshot_state_check >= 5:
                try:
                    state_document = await db.dashboard_snapshot_state.find_one({"_id": "state"}, {"dirty": 1})
                    if state_document and state_document.get("dirty"):
                        snapshot_state["dirty"] = True
                except Exception:
                    logger.exception("Snapshot dirty-state check failed")
                finally:
                    last_snapshot_state_check = now_monotonic

            if (
                now_monotonic - last_archive_sweep
                >= settings.vulnerability_archive_sweep_interval_seconds
            ):
                try:
                    archived_count = await archive_stale_vulnerabilities(
                        settings.vulnerability_archive_after_days
                    )
                    if archived_count:
                        logger.info(
                            "Archived %s stale non-open vulnerabilities (>%s days)",
                            archived_count,
                            settings.vulnerability_archive_after_days,
                        )
                        snapshot_state["dirty"] = True
                    purged_count = await purge_expired_archived_vulnerabilities(
                        settings.vulnerability_archive_retention_days
                    )
                    if purged_count:
                        logger.info(
                            "Purged %s archived vulnerabilities older than %s days",
                            purged_count,
                            settings.vulnerability_archive_retention_days,
                        )
                except Exception:
                    logger.exception("Archive sweep failed")
                finally:
                    last_archive_sweep = now_monotonic

            if (
                snapshot_state["dirty"]
                and now_monotonic - last_snapshot_refresh >= settings.snapshot_refresh_interval_seconds
            ):
                try:
                    await recompute_dashboard_snapshots()
                    logger.info("Dashboard snapshots refreshed")
                    snapshot_state["dirty"] = False
                except Exception:
                    logger.exception("Snapshot refresh failed")
                finally:
                    last_snapshot_refresh = now_monotonic
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    finally:
        for consumer in consumers:
            consumer.cancel()
        await asyncio.gather(*consumers, return_exceptions=True)
        observer.stop()
        observer.join()
        close_database()


def main() -> None:
    global event_loop
    event_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(event_loop)
    try:
        event_loop.run_until_complete(main_async())
    finally:
        event_loop.close()


if __name__ == "__main__":
    main()
