"""Main FastAPI application entry point."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import api_router
from app.core.config import get_settings
from app.core.database import create_all, session_factory
from app.core.logging import configure_logging, get_logger, new_request_id, request_id_ctx
from app.repositories.seeds import seed_evidence

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ANN202
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_format)
    if settings.demo_seed_database:
        create_all()
        with session_factory()() as session:
            seed_evidence(session)
    logger.info("warden_started", extra={"version": settings.app_version})
    yield
    logger.info("warden_stopped")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Warden — Compliance CI Gate",
        description=(
            "Compliance intelligence layer for CI/CD: infrastructure change analysis, "
            "control mapping, evidence impact and targeted verification. "
            "Deterministic decisions; LLM never overrides"
        ),
        version=settings.app_version,
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def attach_request_id(request, call_next):  # noqa: ANN001, ANN202
        token = request_id_ctx.set(new_request_id())
        try:
            return await call_next(request)
        finally:
            request_id_ctx.reset(token)

    app.include_router(api_router, prefix="/api/v1")
    return app


app = create_app()
