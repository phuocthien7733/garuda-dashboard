import asyncio
import logging
import shutil
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers.polling import PollingObserver

from app.config import get_settings
from app.db import close_database, ensure_indexes
from app.scanners import get_scanner_folders, get_scanner_for_file

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("ingestion-worker")

settings = get_settings()
incoming_dir = Path(settings.incoming_dir)
archive_dir = Path(settings.archive_dir)
processing_files: set[Path] = set()
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


def _build_archive_path(file_path: Path) -> Path:
    relative_path = file_path.relative_to(incoming_dir)
    candidate = archive_dir / relative_path
    candidate.parent.mkdir(parents=True, exist_ok=True)
    if not candidate.exists():
        return candidate

    timestamp = int(time.time())
    return candidate.with_name(f"{candidate.stem}_{timestamp}{candidate.suffix}")


def _schedule_file_processing(file_path: Path) -> None:
    global event_loop
    if event_loop is None or event_loop.is_closed():
        logger.error("Cannot schedule %s because the event loop is not available", file_path.name)
        return
    asyncio.run_coroutine_threadsafe(handle_file(file_path), event_loop)


class IncomingFileHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory or not event.src_path.endswith(".json"):
            return
        _schedule_file_processing(Path(event.src_path))

    def on_moved(self, event):
        if event.is_directory or not event.dest_path.endswith(".json"):
            return
        _schedule_file_processing(Path(event.dest_path))


async def handle_file(file_path: Path) -> None:
    if file_path in processing_files or not file_path.exists():
        return

    processing_files.add(file_path)
    try:
        if not _wait_until_file_ready(file_path):
            logger.warning("Skipping %s because the file was not ready in time", file_path.name)
            return

        scanner = get_scanner_for_file(file_path, incoming_dir)
        logger.info(
            "Processing %s via %s as %s",
            file_path.relative_to(incoming_dir),
            scanner.name,
            scanner.detect_input_format(file_path),
        )
        summary = await scanner.process_file(file_path)
        target_path = _build_archive_path(file_path)
        shutil.move(str(file_path), target_path)
        logger.info(
            "Archived %s to %s | processed=%s inserted=%s updated=%s skipped=%s resolved=%s assets=%s",
            file_path.relative_to(incoming_dir),
            target_path.relative_to(archive_dir),
            summary.processed,
            summary.inserted,
            summary.updated,
            summary.skipped,
            summary.resolved,
            summary.assets_updated,
        )
    except Exception:
        logger.exception("Failed processing %s", file_path.name)
    finally:
        processing_files.discard(file_path)


async def process_existing_files() -> None:
    for file_path in sorted(incoming_dir.rglob("*.json")):
        await handle_file(file_path)


async def main_async() -> None:
    incoming_dir.mkdir(parents=True, exist_ok=True)
    archive_dir.mkdir(parents=True, exist_ok=True)
    for scanner_folder in get_scanner_folders():
        (incoming_dir / scanner_folder).mkdir(parents=True, exist_ok=True)
        (archive_dir / scanner_folder).mkdir(parents=True, exist_ok=True)
    logger.info("Worker bootstrap ready | incoming=%s archive=%s", incoming_dir, archive_dir)
    await ensure_indexes()
    await process_existing_files()

    observer = PollingObserver(timeout=1)
    observer.schedule(IncomingFileHandler(), str(incoming_dir), recursive=True)
    observer.start()
    logger.info("Watching %s for new JSON files in scanner folders: %s", incoming_dir, ", ".join(get_scanner_folders()))

    try:
        while True:
            await process_existing_files()
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    finally:
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
