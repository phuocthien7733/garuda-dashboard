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
    mfa_verify_max_attempts: int = 5
    mfa_resend_cooldown_seconds: int = 60
    auth_login_rate_limit_per_ip: int = 20
    auth_login_rate_limit_per_username: int = 10
    auth_login_rate_limit_window_seconds: int = 300
    auth_mfa_verify_rate_limit_per_ip: int = 20
    auth_mfa_verify_rate_limit_window_seconds: int = 300
    auth_mfa_resend_rate_limit_per_ip: int = 10
    auth_mfa_resend_rate_limit_window_seconds: int = 300
    search_query_max_length: int = 120
    cors_origins: str = ""
    dashboard_snapshot_max_age_seconds: int = 60
    vulnerability_archive_retention_days: int = 730
    geoip_city_db_path: str = "/app/data/geoip/GeoLite2-City.mmdb"
    geoip_asn_db_path: str = "/app/data/geoip/GeoLite2-ASN.mmdb"

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
