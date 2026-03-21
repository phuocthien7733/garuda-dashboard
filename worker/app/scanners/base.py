from pathlib import Path
from typing import Any, Protocol


class ScannerAdapter(Protocol):
    name: str
    incoming_folder: str

    def supports(self, file_path: Path) -> bool:
        ...

    def detect_input_format(self, file_path: Path) -> str:
        ...

    async def process_file(self, file_path: Path) -> Any:
        ...
