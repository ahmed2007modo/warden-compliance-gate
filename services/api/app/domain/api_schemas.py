"""FastAPI request/response schemas (Pydantic)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class InlineFile(BaseModel):
    path: str = Field(min_length=1, max_length=512)
    content: str = Field(max_length=1_000_000)

    @field_validator("path")
    @classmethod
    def clean_path(cls, value: str) -> str:
        cleaned = value.replace("\\", "/")
        parts = [segment for segment in cleaned.split("/") if segment not in ("", ".")]
        if any(segment == ".." for segment in parts):
            raise ValueError("path traversal is not allowed")
        return "/".join(parts)


class AnalyzeInlineRequest(BaseModel):
    scenario_name: str = Field(default="")
    base_tree: list[InlineFile] = Field(default_factory=list, max_length=200)
    head_tree: list[InlineFile] = Field(default_factory=list, max_length=200)


class AnalyzePrRequest(BaseModel):
    repository_url: str = Field(min_length=8, max_length=512)
    pr_number: int = Field(ge=1)
    github_token: str = Field(default="", max_length=4096)


class ControlOut(BaseModel):
    model_config = {"protected_namespaces": ()}

    control_id: str
    shared_id: str
    framework_id: str
    title: str
    requirement_text: str
    domain: str
    evidence_expected: list[str]


class EvidenceOut(BaseModel):
    evidence_id: str
    control_id: str
    source: str
    content_hash: str
    freshness_status: str
    age_days: int
    evidence_type: str
    resource_refs: list[str]


class VerificationTaskOut(BaseModel):
    task_id: str
    kind: str
    title: str
    reason: str
    control_id: str
    evidence_ids: list[str]
    blocking: bool


class FindingOut(BaseModel):
    finding_id: str
    rule_id: str
    title: str
    description: str
    severity: str
    status: str
    confidence: str
    source_file: str
    line: int | None
    evidence_refs: list[str]
    controls_covered: list[str]
    resource_address: str
    scanner: str
    recommendation: str
    explanation: str | None = None


class GraphEdgeOut(BaseModel):
    source: str
    target: str
    kind: str
    reason: str
    rule_id: str | None = None


class GraphNodeOut(BaseModel):
    node_id: str
    node_type: str
    label: str


class ImpactGraphOut(BaseModel):
    nodes: list[GraphNodeOut]
    edges: list[GraphEdgeOut]
    affected_controls: list[str]
    verification_tasks: list[VerificationTaskOut]


class PolicyDecisionOut(BaseModel):
    decision: Literal["PASS", "FAIL", "REVIEW_REQUIRED", "ERROR"]
    reason: str
    rule_id: str | None = None
    requires_human_review: bool


class AnalyzeResponse(BaseModel):
    run_id: str
    analyze_id: int
    decision: str
    reason: str
    findings: list[FindingOut]
    policy_decision: PolicyDecisionOut
    required_checks: list[str]
    verification_tasks: list[VerificationTaskOut]
    impacted_evidence: list[str]
    affected_controls: list[str]
    graph: ImpactGraphOut | None = None
    parse_issues: list[str] = Field(default_factory=list)
    unsupported_resource_types: list[str] = Field(default_factory=list)
    ai_warning: str | None = None
    report_rules_version: str


class RunContent(BaseModel):
    analyze_id: int
    run_id: str
    created_at: datetime
    repository_url: str | None = None
    pr_number: int | None = None
    scenario: str | None = None
    report: dict[str, Any]


class RunListItem(BaseModel):
    analyze_id: int
    run_id: str
    created_at: datetime
    decision: str
    scenario: str | None = None
    finding_count: int


class BenchmarkScenarioRow(BaseModel):
    scenario_id: str
    tier: str
    expected_outcome: str
    actual_outcome: str
    expected_finding_rules: list[str]
    actual_finding_rules: list[str]
    missed_rules: list[str]
    unexpected_rules: list[str]
    impacted_evidence: list[str]
    matched: bool


class BenchmarkResultOut(BaseModel):
    run_id: str
    total: int
    correct: int
    accuracy: float
    false_positive_rate: float
    missed_violation_rate: float
    evidence_reference_validity: float
    deterministic_reproducible: bool
    llm_absent_stable: bool
    duration_ms: int
    scenarios: list[BenchmarkScenarioRow]
