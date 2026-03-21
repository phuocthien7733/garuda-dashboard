from dataclasses import dataclass
from pathlib import Path

from app.scanners.nuclei.models import ProcessingSummary
from app.scanners.nuclei.parser import detect_input_format
from app.scanners.nuclei.processor import process_file


@dataclass(frozen=True)
class NucleiScannerAdapter:
    name: str = "nuclei"
    incoming_folder: str = "nuclei"

    def supports(self, file_path: Path) -> bool:
        return file_path.suffix.lower() == ".json"

    def detect_input_format(self, file_path: Path) -> str:
        return detect_input_format(file_path)

    async def process_file(self, file_path: Path) -> ProcessingSummary:
        return await process_file(file_path)


nuclei_scanner = NucleiScannerAdapter()
