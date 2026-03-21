from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "EASM Dashboard API"
    mongo_uri: str = "mongodb://localhost:27017/easm_db"
    mongo_db_name: str = "easm_db"
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

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
