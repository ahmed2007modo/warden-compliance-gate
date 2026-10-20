"""Read-only access to persisted runs."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.dependencies import get_session_db
from app.domain.api_schemas import RunContent, RunListItem
from app.repositories.runs import RunRepository

router = APIRouter(tags=["runs"])


@router.get("/runs", response_model=list[RunListItem])
def list_runs(session: Session = Depends(get_session_db), limit: int = 50) -> list[RunListItem]:
    repo = RunRepository(session)
    rows = repo.list_runs(limit=limit)
    return [
        RunListItem(
            analyze_id=row.id,
            run_id=row.run_id,
            created_at=row.created_at,
            decision=row.decision,
            scenario=row.scenario,
            finding_count=len(row.report_json.get("findings", [])),
        )
        for row in rows
    ]


@router.get("/runs/{run_id}", response_model=RunContent)
def get_run(run_id: str, session: Session = Depends(get_session_db)) -> RunContent:
    repo = RunRepository(session)
    row = repo.get_by_run_id(run_id)
    if row is None:
        row = repo.get_by_id(int(run_id)) if run_id.isdigit() else None
    if row is None:
        raise HTTPException(status_code=404, detail="run not found")
    return RunContent(
        analyze_id=row.id,
        run_id=row.run_id,
        created_at=row.created_at,
        pr_number=row.report_json.get("pr_number"),
        scenario=row.scenario or None,
        report=row.report_json,
    )
