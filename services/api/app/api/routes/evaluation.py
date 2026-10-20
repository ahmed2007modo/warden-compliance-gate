"""Evaluation benchmark endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.dependencies import get_pipelines
from app.core.database import session_factory
from app.core.logging import get_logger
from app.domain.api_schemas import BenchmarkResultOut, BenchmarkScenarioRow
from app.evaluation.benchmark import BenchmarkRunner
from app.repositories.runs import AuditRepository, RunRepository

logger = get_logger(__name__)
router = APIRouter(tags=["evaluation"])


@router.post("/evaluation/run", response_model=BenchmarkResultOut)
def run_benchmark(pipelines: dict = Depends(get_pipelines)) -> BenchmarkResultOut:
    runner = BenchmarkRunner(pipelines["deterministic"])
    result = runner.run()
    with session_factory()() as session:
        repo = RunRepository(session)
        run_id = result["run_id"]
        repo.save(
            run_id=run_id,
            decision="INFO",
            decision_reason=f"benchmark: {result['correct']}/{result['total']} scenarios matched",
            rules_version="benchmark/1",
            report=result,
            repository="benchmark",
            pr_number=None,
            scenario="benchmark",
        )
        AuditRepository(session).record(
            run_id, 1, "analysis_pipeline", "benchmark_completed",
            {"accuracy": result["accuracy"]},
        )
    return BenchmarkResultOut(
        run_id=result["run_id"],
        total=result["total"],
        correct=result["correct"],
        accuracy=result["accuracy"],
        false_positive_rate=result["false_positive_rate"],
        missed_violation_rate=result["missed_violation_rate"],
        evidence_reference_validity=result["evidence_reference_validity"],
        deterministic_reproducible=result["deterministic_reproducible"],
        llm_absent_stable=result["llm_absent_stable"],
        duration_ms=result["duration_ms"],
        scenarios=[BenchmarkScenarioRow(**row) for row in result["scenarios"]],
    )
