"""Unit tests for the deterministic policy decision engine."""

from __future__ import annotations

from app.domain.types import Decision, SecurityFinding
from app.policies.decision import decide, default_policy_config


def _finding(
    rule_id: str = "wrd-log-001",
    severity: str = "critical",
    status: str = "confirmed",
    finding_id: str = "f1",
) -> SecurityFinding:
    return SecurityFinding(
        finding_id=finding_id,
        rule_id=rule_id,
        title="t",
        description="d",
        severity=severity,
        status=status,
        confidence="high",
        source_file="main.tf",
        line=1,
    )


class TestDecide:
    def test_pass_with_no_findings(self) -> None:
        result = decide([])
        assert result.decision == Decision.PASS
        assert not result.requires_human_review

    def test_fail_on_blocking_critical(self) -> None:
        result = decide([_finding()])
        assert result.decision == Decision.FAIL
        assert result.rule_id == "wrd-log-001"
        assert result.reason  # human-readable rationale present

    def test_review_on_non_blocking_finding(self) -> None:
        result = decide([_finding(rule_id="wrd-alm-001", severity="medium", status="confirmed")])
        assert result.decision == Decision.REVIEW_REQUIRED
        assert result.requires_human_review

    def test_review_on_unknown_evidence(self) -> None:
        result = decide([
            _finding(rule_id="wrd-log-001", status="unknown_evidence", severity="critical"),
        ])
        assert result.decision == Decision.REVIEW_REQUIRED

    def test_blocking_takes_priority_over_review(self) -> None:
        blocking = _finding(finding_id="blocking")
        review = _finding(rule_id="wrd-alm-001", severity="medium", status="confirmed",
                          finding_id="review")
        result = decide([review, blocking])
        assert result.decision == Decision.FAIL
        assert "blocking" in result.concerned_finding_ids

    def test_fail_when_required_scanner_missing(self) -> None:
        result = decide(
            [],
            policy=default_policy_config(),
            scanner_status={"warden-native": "unavailable"},
        )
        assert result.decision == Decision.REVIEW_REQUIRED
        assert "warden-native" in result.reason

    def test_review_when_unsupported_constructs(self) -> None:
        result = decide([], unsupported_constructs=["aws_docdb_cluster"])
        assert result.decision == Decision.REVIEW_REQUIRED
        assert result.requires_human_review

    def test_findings_sorted_by_severity(self) -> None:
        low = _finding(rule_id="wrd-alm-001", severity="low", status="confirmed", finding_id="low")
        high = _finding(severity="high", finding_id="high")
        result = decide([low, high])
        assert result.rule_id == high.rule_id
