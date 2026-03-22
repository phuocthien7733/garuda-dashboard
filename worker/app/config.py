from functools import lru_cache
from urllib.parse import quote_plus

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    mongo_uri: str = "mongodb://localhost:27017/easm_db"
    mongo_db_name: str = "easm_db"
    mongo_host: str = "localhost"
    mongo_port: int = 27017
    mongo_username: str = ""
    mongo_password: str = ""
    mongo_auth_source: str = "easm_db"
    incoming_dir: str = "/app/data/incoming"
    archive_dir: str = "/app/data/archive"
    vulnerability_archive_after_days: int = 30
    vulnerability_archive_retention_days: int = 730
    vulnerability_archive_sweep_interval_seconds: int = 3600
    ingest_concurrency: int = 2
    snapshot_refresh_interval_seconds: int = 30

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def resolved_mongo_uri(self) -> str:
        if self.mongo_username and self.mongo_password:
            username = quote_plus(self.mongo_username)
            password = quote_plus(self.mongo_password)
            return (
                f"mongodb://{username}:{password}@{self.mongo_host}:{self.mongo_port}/"
                f"{self.mongo_db_name}?authSource={self.mongo_auth_source}"
            )

        return self.mongo_uri


@lru_cache
def get_settings() -> Settings:
    return Settings()
