from functools import lru_cache
import json
from urllib.parse import quote_plus

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "EASM Dashboard API"
    mongo_uri: str = "mongodb://localhost:27017/easm_db"
    mongo_db_name: str = "easm_db"
    mongo_host: str = "localhost"
    mongo_port: int = 27017
    mongo_username: str = ""
    mongo_password: str = ""
    mongo_auth_source: str = "easm_db"
    jwt_secret: str = "change-me"
    jwt_algorithm: str = "HS256"
    jwt_expiration_hours: int = 18
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from_email: str = ""
    smtp_from_name: str = "Test And Watch Security"
    smtp_use_tls: bool = True
    mfa_code_expiration_minutes: int = 10
    mfa_code_length: int = 6
    cors_origins: str = ""
    dashboard_snapshot_max_age_seconds: int = 180

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def parsed_cors_origins(self) -> list[str]:
        if not self.cors_origins.strip():
            return [
                "http://localhost:5173",
                "http://127.0.0.1:5173",
                "http://localhost:4173",
                "http://127.0.0.1:4173",
            ]

        raw_value = self.cors_origins.strip()

        try:
            parsed = json.loads(raw_value)
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        except json.JSONDecodeError:
            pass

        return [item.strip() for item in raw_value.split(",") if item.strip()]

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
