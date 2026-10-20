"""Shared pure-domain types for Warden.

These dataclasses are the contract between layers. No I/O, no ORM, no external libs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

Severity = str  # "critical" | "high" | "medium" | "low" | "info"
FindingStatus = str  # "confirmed" | "potential_risk" | "unknown_evidence"
Confidence = str  # "high" | "medium" | "low"


class Decision(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    ERROR = "ERROR"


class SeverityLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class Hunk:
    """A unified-diff hunk scoped to one file."""

    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: tuple[str, ...] = ()


@dataclass(frozen=True)
class ChangedFile:
    """One changed file in a pull request, validated and parsed."""

    path: str
    old_path: str
    change_type: str  # added | modified | deleted | renamed
    old_lines: tuple[str, ...] = ()
    new_lines: tuple[str, ...] = ()
    hunks: tuple[Hunk, ...] = ()

    def is_terraform(self) -> bool:
        return self.path.endswith(".tf") or self.path.endswith(".tfvars")


@dataclass(frozen=True)
class ResourceAddress:
    """Terraform resource address like `aws_s3_bucket.logs`."""

    resource_type: str
    resource_name: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.resource_type}.{self.resource_name}"


@dataclass(frozen=True)
class ResourceSnapshot:
    """Flat view of one Terraform resource block in a file."""

    address: ResourceAddress
    file_path: str
    attributes: dict[str, Any]
    mode: str = "managed"  # managed | data
    module: str = ""


@dataclass(frozen=True)
class AttributeChange:
    """One attribute-level delta inside a resource block."""

    resource: ResourceAddress
    attribute: str | None
    before: Any
    after: Any
    change_type: str  # attribute_changed | attribute_removed | attribute_added | block_removed | block_added | resource_added | resource_deleted
    file_path: str
    line_no: int | None = None


@dataclass(frozen=True)
class Change:
    """A single semantic infrastructure change extracted from a diff."""

    change_id: str
    kind: str
    attribute_changes: tuple[AttributeChange, ...] = ()
    summary: str = ""


@dataclass(frozen=True)
class Control:
    """A shared control from the single 'map once' control set."""

    control_id: str
    title: str
    objective: str
    requirement_summary: str
    framework_refs: tuple[str, ...] = ()
    evidence_expected: tuple[str, ...] = ()


@dataclass(frozen=True)
class ControlMapping:
    """A control's mapping inside one framework (reference + posture)."""

    framework_id: str
    control_ref: str
    requirement_text: str
    control_id: str


@dataclass(frozen=True)
class Evidence:
    """A single piece of collected evidence with full provenance."""

    evidence_id: str
    control_id: str
    source: str
    source_location: str
    collected_at: datetime
    resource_refs: tuple[str, ...]
    content_hash: str
    evidence_type: str
    age_days: int
    freshness_status: str  # fresh | stale | conflicting | missing
    provenance: str = ""
    verification_status: str = "verified"


@dataclass
class SecurityFinding:
    """One deterministic finding produced by a rule or scanner adapter."""

    finding_id: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    status: FindingStatus
    confidence: Confidence
    source_file: str
    line: int | None
    evidence_refs: tuple[str, ...] = ()
    controls_covered: tuple[str, ...] = ()
    resource_address: str = ""
    scanner: str = "warden-native"
    category: str = "infrastructure"
    recommendation: str = ""
    url: str = ""
    fingerprint: str = ""

    def fingerprint_key(self) -> str:
        return self.fingerprint or f"{self.rule_id}:{self.source_file}:{self.line}"


@dataclass(frozen=True)
class RuleSpec:
    """A native deterministic rule definition."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    blocking: bool
    attribute_path: str
    controls: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    requires_llm: bool = False


@dataclass(frozen=True)
class VerificationTask:
    """Targeted post-change verification work item."""

    task_id: str
    kind: str  # evidence_revalidation | control_validation | alarm_coverage | manual_review
    title: str
    reason: str
    control_id: str
    evidence_ids: tuple[str, ...] = ()
    run_refs: tuple[str, ...] = ()
    blocking: bool = False


@dataclass(frozen=True)
class DependencyEdge:
    """One edge of the compliance impact graph, with a traversal reason."""

    source: str
    target: str
    kind: str  # change_implies_finding | finding_maps_control | control_requires_evidence | evidence_needs_verification
    reason: str
    rule_id: str | None = None


@dataclass
class ImpactAssessment:
    """Graph traversal answer: which controls/evidence/tasks are affected."""

    change_id: str
    affected_controls: tuple[str, ...] = ()
    impacted_evidence: tuple[str, ...] = ()
    verification_tasks: tuple[VerificationTask, ...] = ()
    traversal_reasons: tuple[DependencyEdge, ...] = ()
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyDecisionRecord:
    """Final gate output for one run."""

    decision: Decision
    reason: str
    rule_id: str | None = None
    concerned_finding_ids: tuple[str, ...] = ()
    requires_human_review: bool = False


@dataclass
class AuditEvent:
    """One recorded analysis action for the audit trail."""

    event_id: str
    run_id: str
    step_index: int
    actor: str  # system | analysis_pipeline | rule_engine | llm
    event_type: str
    payload: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class PullRequestContext:
    """Input bundle to run one analysis."""

    repository: str
    pr_number: int
    base_ref: str
    head_ref: str
    changed_files: list[ChangedFile]
    pr_title: str = ""
    pr_description: str = ""
    repo_comments: tuple[str, ...] = ()
