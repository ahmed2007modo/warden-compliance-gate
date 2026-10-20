"""Analysis-run and audit-event repositories (thin SQLAlchemy wrappers)."""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import session_factory
from app.models.orm import AnalysisRunRow, AuditEventRow, PullRequestRow, RepositoryRow


class RunRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def save(
        self,
        run_id: str,
        decision: str,
        decision_reason: str,
        rules_version: str,
        report: dict,
        repository: str,
        pr_number: int | None,
        scenario: str = "",
    ) -> int:
        repo = self._get_or_create_repository(repository)
        pr: PullRequestRow | None = None
        if pr_number is not None:
            pr = PullRequestRow(
                repository_id=repo.id,
                pr_number=pr_number,
                base_ref=report.get("base_ref", ""),
                head_ref=report.get("head_ref", ""),
                title="",
            )
            self._session.add(pr)
            self._session.flush()
        row = AnalysisRunRow(
            run_id=run_id,
            pull_request_id=pr.id if pr else None,
            scenario=scenario,
            decision=decision,
            decision_reason=decision_reason,
            rules_version=rules_version,
            report_json=report,
        )
        self._session.add(row)
        self._session.commit()
        return row.id

    def list_runs(self, limit: int = 50) -> Sequence[AnalysisRunRow]:
        stmt = select(AnalysisRunRow).order_by(AnalysisRunRow.created_at.desc()).limit(limit)
        return self._session.scalars(stmt).all()

    def get_by_id(self, analyze_id: int) -> AnalysisRunRow | None:
        return self._session.get(AnalysisRunRow, analyze_id)

    def get_by_run_id(self, run_id: str) -> AnalysisRunRow | None:
        stmt = select(AnalysisRunRow).where(AnalysisRunRow.run_id == run_id)
        return self._session.scalars(stmt).first()

    def _get_or_create_repository(self, name: str) -> RepositoryRow:
        stmt = select(RepositoryRow).where(RepositoryRow.name == name)
        repo = self._session.scalars(stmt).first()
        if repo is None:
            repo = RepositoryRow(name=name)
            self._session.add(repo)
            self._session.flush()
        return repo


class AuditRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def record(self, run_id: str, step_index: int, actor: str, event_type: str,
               payload: dict | None = None) -> None:
        self._session.add(
            AuditEventRow(
                run_id=run_id,
                step_index=step_index,
                actor=actor,
                event_type=event_type,
                payload=payload or {},
            )
        )
        self._session.commit()

    def for_run(self, run_id: str) -> list[AuditEventRow]:
        stmt = (
            select(AuditEventRow)
            .where(AuditEventRow.run_id == run_id)
            .order_by(AuditEventRow.step_index)
        )
        return list(self._session.scalars(stmt).all())


def get_default_session():
    return session_factory()()
