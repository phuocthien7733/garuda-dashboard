from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.core.config import get_settings

settings = get_settings()
client = AsyncIOMotorClient(settings.resolved_mongo_uri)
database = client[settings.mongo_db_name]


def get_database() -> AsyncIOMotorDatabase:
    return database


def close_mongo_client() -> None:
    client.close()
