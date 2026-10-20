"""Core analysis endpoint: ingest inline trees (and later a real GitHub PR)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.adapters.terraform.diff import ValidationError, build_pr_context_from_trees
from app.analysis.pipeline import AnalysisPipeline
from app.api.dependencies import (
    get_pipelines,  # noqa: TID252
)
from app.core.database import session_factory
from app.core.logging import get_logger
from app.domain.api_schemas import (
    AnalyzeInlineRequest,
    AnalyzeResponse,
    FindingOut,
    GraphEdgeOut,
    GraphNodeOut,
    ImpactGraphOut,
    PolicyDecisionOut,
    VerificationTaskOut,
)
from app.repositories.runs import AuditRepository

logger = get_logger(__name__)
router = APIRouter(tags=["analysis"])


def _finding_to_out(finding: dict) -> FindingOut:
    return FindingOut(
        finding_id=finding["finding_id"],
        rule_id=finding["rule_id"],
        title=finding["title"],
        description=finding["description"],
        severity=finding["severity"],
        status=finding["status"],
        confidence=finding["confidence"],
        source_file=finding["source_file"],
        line=finding["line"],
        evidence_refs=finding["evidence_refs"],
        controls_covered=finding["controls_covered"],
        resource_address=finding["resource_address"],
        scanner=finding["scanner"],
        recommendation=finding["recommendation"],
        explanation=finding.get("explanation"),
    )


def _response_from_report(report: dict, run_id: str, analyze_id: int) -> AnalyzeResponse:
    graph = report["graph"]
    return AnalyzeResponse(
        run_id=run_id,
        analyze_id=analyze_id,
        decision=report["decision"]["outcome"],
        reason=report["decision"]["reason"],
        findings=[_finding_to_out(f) for f in report["findings"]],
        policy_decision=PolicyDecisionOut(
            decision=report["decision"]["outcome"],
            reason=report["decision"]["reason"],
            rule_id=report["decision"]["rule_id"],
            requires_human_review=report["decision"]["requires_human_review"],
        ),
        required_checks=[
            task["task_id"] for task in report["verification_tasks"] if task["blocking"]
        ],
        verification_tasks=[
            VerificationTaskOut(
                task_id=t["task_id"],
                kind=t["kind"],
                title=t["title"],
                reason=t["reason"],
                control_id=t["control_id"],
                evidence_ids=t["evidence_ids"],
                blocking=t["blocking"],
            )
            for t in report["verification_tasks"]
        ],
        impacted_evidence=report["summary"]["impacted_evidence"],
        affected_controls=report["summary"]["affected_controls"],
        graph=ImpactGraphOut(
            nodes=[GraphNodeOut(**node) for node in graph["nodes"]],
            edges=[GraphEdgeOut(**edge) for edge in graph["edges"]],
            affected_controls=report["summary"]["affected_controls"],
            verification_tasks=[],
        ),
        parse_issues=report["summary"]["parse_issues"],
        unsupported_resource_types=report["summary"].get("unsupported_resource_types", []),
        ai_warning=report["ai_warning"],
        report_rules_version=report["rules_version"],
    )


def _persist_analysis(
    result,
    scenario: str,
    repository: str,
    pr_number: int,
) -> int:
    analyze_id = _save_run(result.report, scenario, repository, pr_number)
    with session_factory()() as session:
        audit = AuditRepository(session)
        audit.record(result.run_id, 1, "analysis_pipeline", "pipeline_started",
                     {"scenario": scenario})
        audit.record(result.run_id, 2, "rule_engine", "findings_emitted",
                     {"count": len(result.findings)})
        audit.record(result.run_id, 3, "analysis_pipeline", "decision_reached",
                     {"decision": result.policy_decision.decision.value})
        audit.record(result.run_id, 4, "analysis_pipeline", "report_persisted",
                     {"analyze_id": analyze_id})
    return analyze_id


def _save_run(report: dict, scenario: str, repository: str, pr_number: int) -> int:
    from app.repositories.runs import RunRepository

    with session_factory()() as session:
        repo = RunRepository(session)
        return repo.save(
            run_id=report["run_id"],
            decision=report["decision"]["outcome"],
            decision_reason=report["decision"]["reason"],
            rules_version=report["rules_version"],
            report=report,
            repository=repository,
            pr_number=pr_number,
            scenario=scenario,
        )


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze_inline(
    request: AnalyzeInlineRequest,
    pipelines: dict = Depends(get_pipelines),
) -> AnalyzeResponse:
    if not request.head_tree:
        raise HTTPException(status_code=422, detail="head_tree is required")
    repository_name = request.scenario_name or "inline"
    if not request.base_tree:
        logger.warning("analyze_inline with empty base_tree: treated as repository bootstrap",
                       extra={"files": len(request.head_tree)})
    try:
        base_map = {item.path: item.content for item in request.base_tree}
        head_map = {item.path: item.content for item in request.head_tree}
        context = build_pr_context_from_trees(
            repository=repository_name,
            pr_number=1,
            base_ref="base",
            head_ref="head",
            base_tree=base_map,
            head_tree=head_map,
            pr_description="",
        )
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    pipeline: AnalysisPipeline = pipelines["deterministic"]
    try:
        result = pipeline.run(context)
    except Exception as exc:  # noqa: BLE001
        logger.exception("pipeline failure")
        raise HTTPException(status_code=500, detail=f"pipeline failure: {exc}") from exc

    scenario = request.scenario_name
    repository = scenario if scenario else "inline"
    analyze_id = _persist_analysis(result, scenario, repository, context.pr_number)
    response = _response_from_report(result.report, result.run_id, analyze_id)
    return response


@router.post("/analyze-pr", response_model=AnalyzeResponse)
def analyze_pr(payload: dict, pipelines: dict = Depends(get_pipelines)) -> AnalyzeResponse:
    """Placeholder for the Phase-4 GitHub integration (see docs/architecture.md §4)."""
    raise HTTPException(status_code=501, detail="GitHub PR integration lands in Phase 4")
