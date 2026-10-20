"""Database engine/session setup (SQLite-first, Postgres optional)."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings

_engine: Engine | None = None
_SessionLocal = sessionmaker(autocommit=False, autoflush=False)


def _resolve_sqlite_url(raw: str) -> str:
    """Turn `sqlite:///./warden.db` into a stable absolute path under the workspace."""
    if not raw.startswith("sqlite:///./"):
        return raw
    base = Path(__file__).resolve().parents[4]
    filename = raw[len("sqlite:///./"):].lstrip("/")
    path = (base / filename).resolve()
    return f"sqlite:///{path.as_posix()}"


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    global _engine
    if _engine is None:
        settings = get_settings()
        url = _resolve_sqlite_url(settings.sqlalchemy_database_url)
        if os.environ.get("WARDEN_DB_OVERRIDE"):
            url = os.environ["WARDEN_DB_OVERRIDE"]
        created: Engine = create_engine(url, pool_pre_ping=True, future=True)

        @event.listens_for(created, "connect")
        def _pragmas(dbapi_connection, _record) -> None:  # noqa: ANN001, ANN202
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

        _engine = created
        _SessionLocal.configure(bind=_engine)
    return _engine


def get_session() -> Session:
    return _SessionLocal()


def session_factory() -> sessionmaker:
    get_engine()
    return _SessionLocal


def create_all() -> None:
    from app.models.orm import Base

    Base.metadata.create_all(get_engine())
