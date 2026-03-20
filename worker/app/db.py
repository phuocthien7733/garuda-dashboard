from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING

from app.config import get_settings

settings = get_settings()
client = AsyncIOMotorClient(settings.mongo_uri)
database = client[settings.mongo_db_name]


def get_database():
    return database


async def ensure_indexes() -> None:
    await database.vulnerabilities.create_index([("fingerprint", ASCENDING)], unique=True)
    await database.vulnerabilities.create_index([("host", ASCENDING)])
    await database.vulnerabilities.create_index([("severity", ASCENDING), ("status", ASCENDING)])
    await database.vulnerabilities.create_index([("last_seen", ASCENDING)])
    await database.assets.create_index([("host", ASCENDING)], unique=True)


def close_database() -> None:
    client.close()
