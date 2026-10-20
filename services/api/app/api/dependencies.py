"""FastAPI dependency providers (singleton registries + pipeline)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from sqlalchemy.orm import Session

from app.analysis.pipeline import AnalysisPipeline
from app.core.config import get_settings
from app.core.database import session_factory
from app.domain.registry import ControlRegistry, EvidenceRegistry


def _workspace_root() -> Path:
    return Path(__file__).resolve().parents[4]


@lru_cache(maxsize=1)
def get_control_registry() -> ControlRegistry:
    settings = get_settings()
    base = Path(settings.frameworks_dir) if Path(settings.frameworks_dir).is_absolute() else _workspace_root() / settings.frameworks_dir
    return ControlRegistry(base)


@lru_cache(maxsize=1)
def get_evidence_registry() -> EvidenceRegistry:
    settings = get_settings()
    base = Path(settings.frameworks_dir) if Path(settings.frameworks_dir).is_absolute() else _workspace_root() / settings.frameworks_dir
    return EvidenceRegistry(base)


@lru_cache(maxsize=1)
def get_pipelines() -> dict:
    """Singleton pipeline bundle: `deterministic` always available; `llm` when enabled."""
    settings = get_settings()
    pipeline = AnalysisPipeline(get_control_registry(), get_evidence_registry())
    bundle = {"deterministic": pipeline, "llm": None}
    if settings.llm_enabled:
        from app.adapters.llm.explainer import LlmExplainer

        bundle["llm"] = LlmExplainer.from_settings(settings)
    return bundle


def get_session_db() -> Session:
    """Fresh session per request; closed on teardown."""
    factory = session_factory()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
