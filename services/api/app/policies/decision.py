"""Deterministic policy engine: PASS / FAIL / REVIEW_REQUIRED / ERROR.

The engine is a pure function of findings + verification tasks + control expectations. The LLM
has no code path here (ADR 0004).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from app.domain.types import Decision, FindingStatus, PolicyDecisionRecord, SecurityFinding

BLOCKING_STATUSES: frozenset[FindingStatus] = frozenset({"confirmed", "potential_risk"})

SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


@dataclass(frozen=True)
class PolicyBinding:
    """Which native rules block the pipeline (mirrors policies/default.yaml)."""

    rule_id: str
    blocking: bool
    wait_days: int = 0


@dataclass(frozen=True)
class PolicyConfig:
    bindings: tuple[PolicyBinding, ...]
    required_scanners: tuple[str, ...] = ("warden-native",)
    max_review_age_days: int = 0


def default_policy_config() -> PolicyConfig:
    from app.policies.rules import RULES

    bindings = tuple(
        PolicyBinding(rule_id=rule.rule_id, blocking=rule.blocking) for rule in RULES
    )
    return PolicyConfig(bindings=bindings)


def decide(
    findings: Iterable[SecurityFinding],
    *,
    policy: PolicyConfig | None = None,
    parse_issues: Iterable[str] = (),
    scanner_status: dict[str, str] | None = None,
    unsupported_constructs: Iterable[str] = (),
) -> PolicyDecisionRecord:
    """Compose a four-outcome deterministic decision."""
    policy = policy or default_policy_config()
    bindings = {b.rule_id: b for b in policy.bindings}
    findings = sorted(
        findings,
        key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.finding_id),
    )

    blocking_failures: list[SecurityFinding] = []
    for finding in findings:
        if finding.status not in BLOCKING_STATUSES:
            continue
        binding = bindings.get(finding.rule_id)
        blocking = binding.blocking if binding else False
        if blocking:
            blocking_failures.append(finding)

    if blocking_failures:
        top = blocking_failures[0]
        return PolicyDecisionRecord(
            decision=Decision.FAIL,
            reason=(
                f"{len(blocking_failures)} blocking finding(s); highest severity "
                f"'{top.severity}' from rule {top.rule_id} in {top.source_file}"
                + (f":{top.line}" if top.line is not None else "")
            ),
            rule_id=top.rule_id,
            concerned_finding_ids=tuple(f.finding_id for f in blocking_failures),
            requires_human_review=top.status == "potential_risk",
        )

    unknown = [f for f in findings if f.status == "unknown_evidence"]
    if unknown:
        return PolicyDecisionRecord(
            decision=Decision.REVIEW_REQUIRED,
            reason=(
                f"{len(unknown)} finding(s) could not be verified with available evidence; "
                f"(flags: {', '.join(sorted({f.rule_id for f in unknown}))})"
            ),
            rule_id=unknown[0].rule_id,
            concerned_finding_ids=tuple(f.finding_id for f in unknown),
            requires_human_review=True,
        )

    if findings:
        # Non-blocking findings still require a human to accept or reject the change.
        top = findings[0]
        return PolicyDecisionRecord(
            decision=Decision.REVIEW_REQUIRED,
            reason=(
                f"{len(findings)} non-blocking finding(s) need human review "
                f"(highest severity '{top.severity}' from rule {top.rule_id})"
            ),
            rule_id=top.rule_id,
            concerned_finding_ids=tuple(f.finding_id for f in findings),
            requires_human_review=True,
        )

    missing_scanners = _missing_required(policy.required_scanners, scanner_status) if scanner_status else []
    issues = list(parse_issues) + list(unsupported_constructs)
    if missing_scanners or issues:
        detail = []
        if missing_scanners:
            detail.append(f"required scanner(s) unavailable: {', '.join(missing_scanners)}")
        if issues:
            detail.append(f"{len(issues)} parse/coverage issue(s)")
        return PolicyDecisionRecord(
            decision=Decision.REVIEW_REQUIRED,
            reason="; ".join(detail),
            requires_human_review=True,
        )

    return PolicyDecisionRecord(
        decision=Decision.PASS,
        reason="No blocking findings, no unknown-evidence checks, all required scanners available.",
    )


def _missing_required(required: tuple[str, ...], status: dict[str, str]) -> list[str]:
    return [name for name in required if status.get(name, "unavailable") != "available"]
