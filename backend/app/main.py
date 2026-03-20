from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.db.indexes import ensure_indexes
from app.db.mongo import close_mongo_client
from app.routes import assets, auth, graph, stats, users, vulns

ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
]


@asynccontextmanager
async def lifespan(_: FastAPI):
    await ensure_indexes()
    yield
    close_mongo_client()


app = FastAPI(
    title="EASM Dashboard API",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(stats.router, prefix="/api", tags=["stats"])
app.include_router(vulns.router, prefix="/api", tags=["vulns"])
app.include_router(assets.router, prefix="/api", tags=["assets"])
app.include_router(graph.router, prefix="/api", tags=["graph"])
app.include_router(users.router, prefix="/api", tags=["users"])


@app.get("/health", tags=["health"])
async def healthcheck():
    return {"status": "ok"}
