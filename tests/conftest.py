"""Shared pytest configuration: isolated database + singleton registries."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

WORKSPACE = Path(__file__).resolve().parents[1]
API_DIR = WORKSPACE / "services" / "api"

_TEST_DB = WORKSPACE / ".tmp-test-warden.db"
os.environ["WARDEN_DB_OVERRIDE"] = f"sqlite:///{_TEST_DB.as_posix()}"
os.environ.setdefault("WARDEN_LOG_FORMAT", "text")
os.environ.setdefault("WARDEN_DEMO_SEED_DATABASE", "true")

sys.path.insert(0, str(API_DIR))  # noqa: E402


@pytest.fixture(scope="session")
def frameworks_dir() -> Path:
    return WORKSPACE / "frameworks"


@pytest.fixture(scope="session")
def control_registry(frameworks_dir: Path):
    from app.domain.registry import ControlRegistry

    return ControlRegistry(frameworks_dir)


@pytest.fixture(scope="session")
def evidence_registry(frameworks_dir: Path):
    from app.domain.registry import EvidenceRegistry

    return EvidenceRegistry(frameworks_dir)


@pytest.fixture()
def pipeline(control_registry, evidence_registry):
    from app.analysis.pipeline import AnalysisPipeline

    return AnalysisPipeline(control_registry, evidence_registry)


@pytest.fixture()
def client():
    from app.main import create_app
    from fastapi.testclient import TestClient

    app = create_app()
    with TestClient(app) as test_client:
        yield test_client

    from app.core.database import get_engine

    get_engine().dispose()
    if _TEST_DB.exists():
        try:
            _TEST_DB.unlink()
        except OSError:
            pass


@pytest.fixture(scope="session", autouse=True)
def cleanup_test_db():
    yield
    if _TEST_DB.exists():
        try:
            _TEST_DB.unlink()
        except OSError:
            pass
