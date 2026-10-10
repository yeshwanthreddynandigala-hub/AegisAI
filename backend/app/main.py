"""
FastAPI Application Entry Point.
Assembles routers, configures CORS, initializes SQLite DB, and seeds demo data.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.core.config import settings
from app.core.database import init_db, SessionLocal
from app.evaluation.benchmark_runner import _ensure_benchmark_agents
from app.api.agents import router as agents_router
from app.api.events import router as events_router
from app.api.incidents import router as incidents_router
from app.api.simulations import router as simulations_router
from app.api.evaluation import router as evaluation_router
from app.api.threat_intel import router as threat_intel_router
from app.api.overview import router as overview_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize database and baseline agents
    init_db()
    db = SessionLocal()
    try:
        _ensure_benchmark_agents(db)
    finally:
        db.close()
    yield
    # Shutdown

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Research prototype for AI agent behavior security, zero-trust gateway mediation, and threat investigation.",
    lifespan=lifespan
)

# Enable CORS for local Vite development frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers under /api/v1 prefix
app.include_router(overview_router, prefix="/api/v1")
app.include_router(agents_router, prefix="/api/v1")
app.include_router(events_router, prefix="/api/v1")
app.include_router(incidents_router, prefix="/api/v1")
app.include_router(simulations_router, prefix="/api/v1")
app.include_router(evaluation_router, prefix="/api/v1")
app.include_router(threat_intel_router, prefix="/api/v1")

@app.get("/api/v1/health")
def health_check():
    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "database": settings.database_url.split("///")[-1]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
