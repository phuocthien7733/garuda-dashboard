from pathlib import Path

from app.scanners.base import ScannerAdapter
from app.scanners.nuclei.adapter import nuclei_scanner

SCANNERS: tuple[ScannerAdapter, ...] = (nuclei_scanner,)
SCANNERS_BY_FOLDER: dict[str, ScannerAdapter] = {scanner.incoming_folder: scanner for scanner in SCANNERS}


def get_scanner_folders() -> tuple[str, ...]:
    return tuple(SCANNERS_BY_FOLDER.keys())


def get_scanner_for_file(file_path: Path, incoming_root: Path) -> ScannerAdapter:
    relative_path = file_path.relative_to(incoming_root)
    path_parts = relative_path.parts
    if len(path_parts) < 2:
        raise ValueError(
            f"{file_path.name} must be placed inside a scanner folder under {incoming_root.name}/<scanner>/"
        )

    scanner_folder = path_parts[0]
    scanner = SCANNERS_BY_FOLDER.get(scanner_folder)
    if scanner is None:
        raise ValueError(f"No scanner adapter registered for incoming folder '{scanner_folder}'")

    if not scanner.supports(file_path):
        raise ValueError(f"{file_path.name} is not a supported file for scanner '{scanner_folder}'")

    return scanner
