"""FastAPI routes."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import analysis, evaluation, health, registry, runs

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(analysis.router)
api_router.include_router(runs.router)
api_router.include_router(registry.router)
api_router.include_router(evaluation.router)
