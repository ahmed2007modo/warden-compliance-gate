"""Native deterministic rules. Pure functions over typed AttributeChanges.

A rule fires when a specific, documented Terraform change pattern is present. Findings carry
the rule id, aggressor resource, file/line, control coverage and the evidence ids the control
depends on. No LLM, no side effects.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from app.domain.types import AttributeChange, SecurityFinding

DOC_LINK = "https://github.com/warden-compliance/warden"


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    title: str
    description: str
    recommendation: str
    severity: str
    controls: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    blocking: bool
    matcher: Callable[[AttributeChange], bool]


def _is_disabled(value: object) -> bool:
    return isinstance(value, str) and value.strip().lower() in ("false", "0", "no")


_WILDCARD_TOKEN = re.compile(r'"\*"')

# Matches both JSON-style `"Action": "*"` and HCL-style `Action = "*"`.
_ACTION_SINGLE = re.compile(r'"?Action"?\s*[:=]\s*"([^"]*)"')
_ACTION_LIST = re.compile(r'"?Action"?\s*[:=]\s*\[([^\]]*)\]')


def _has_wildcard(value: object) -> bool:
    """True when an IAM policy document grants `*` actions (exact token, not a Resource glob)."""
    flat = str(value)
    single = _ACTION_SINGLE.search(flat)
    if single and single.group(1).strip() == "*":
        return True
    listing = _ACTION_LIST.search(flat)
    if listing and _WILDCARD_TOKEN.search(listing.group(1)):
        return True
    return False


def rule_log_001(change: AttributeChange) -> bool:
    """Audit trail disabled or deleted."""
    if change.resource.resource_type != "aws_cloudtrail":
        return False
    if change.change_type == "resource_deleted":
        return True
    if change.attribute != "enabled":
        return False
    if _is_disabled(change.after):
        return True
    # attribute_removed where it previously read `enabled = true`
    return change.change_type == "attribute_removed" and str(change.before).strip().lower() == "true"


def rule_log_002(change: AttributeChange) -> bool:
    """CloudWatch log group deleted for audit events."""
    if change.resource.resource_type != "aws_cloudwatch_log_group":
        return False
    if change.change_type == "resource_deleted":
        return True
    return change.attribute == "name" and change.change_type in ("attribute_changed", "attribute_removed")


def rule_enc_001(change: AttributeChange) -> bool:
    """SSE configuration removed or weakened."""
    if change.resource.resource_type in (
        "aws_s3_bucket_server_side_encryption_configuration",
        "aws_s3_bucket",
    ):
        return change.change_type == "resource_deleted"
    return False


def rule_iam_001(change: AttributeChange) -> bool:
    """IAM policy widened to wildcard actions."""
    if change.resource.resource_type != "aws_iam_role_policy":
        return False
    return _has_wildcard(change.after)


def rule_net_001(change: AttributeChange) -> bool:
    """Security group ingress opened to the internet (any attribute gains 0.0.0.0/0)."""
    if change.resource.resource_type != "aws_security_group":
        return False
    return "0.0.0.0/0" in str(change.after)


def rule_alm_001(change: AttributeChange) -> bool:
    """Metric alarm deleted."""
    if change.resource.resource_type != "aws_cloudwatch_metric_alarm":
        return False
    return change.change_type == "resource_deleted"


def rule_log_003(change: AttributeChange) -> bool:
    """Audit log retention window changed (needs evidence revalidation, non-blocking)."""
    if change.resource.resource_type != "aws_cloudwatch_log_group":
        return False
    return change.attribute == "retention_in_days" and change.change_type in (
        "attribute_changed", "attribute_added", "attribute_removed",
    )


def rule_bak_001(change: AttributeChange) -> bool:
    """Audit-bucket versioning removed (evidence preservation weakened)."""
    if change.resource.resource_type != "aws_s3_bucket_versioning":
        return False
    return change.change_type == "resource_deleted"


COVERED_RESOURCE_TYPES = frozenset({
    "aws_cloudtrail",
    "aws_cloudwatch_log_group",
    "aws_cloudwatch_metric_alarm",
    "aws_s3_bucket",
    "aws_s3_bucket_server_side_encryption_configuration",
    "aws_iam_role_policy",
    "aws_security_group",
})


def is_uncovered_resource_type(resource_type: str) -> bool:
    """True for Terraform resource types outside the native rules' coverage."""
    return resource_type not in COVERED_RESOURCE_TYPES


RULES: tuple[RuleDefinition, ...] = (
    RuleDefinition(
        rule_id="wrd-log-001",
        title="Audit logging disabled or dropped",
        description="A Terraform change disabled an AWS CloudTrail resource or set `enabled = false`, "
                    "removing audit logging for the account.",
        recommendation="Restore `enabled = true` on the CloudTrail resource or explicitly document "
                       "and risk-accept the removal with the compliance owner.",
        severity="critical",
        controls=("C-LOG-01",),
        evidence_refs=("ev-cloudtrail-config-prod",),
        blocking=True,
        matcher=rule_log_001,
    ),
    RuleDefinition(
        rule_id="wrd-log-002",
        title="CloudWatch audit log group dropped",
        description="A Terraform change deleted the CloudWatch log group used for audit events, "
                    "removing retained monitoring data.",
        recommendation="Restore the log group or re-target audit log delivery to an approved sink.",
        severity="critical",
        controls=("C-LOG-02", "C-LOG-01"),
        evidence_refs=("ev-cloudwatch-loggroup-retention",),
        blocking=True,
        matcher=rule_log_002,
    ),
    RuleDefinition(
        rule_id="wrd-enc-001",
        title="S3 SSE encryption configuration removed",
        description="A Terraform change deleted the server-side encryption configuration, "
                    "leaving objects stored unencrypted at rest.",
        recommendation="Restore `aws_s3_bucket_server_side_encryption_configuration` with an approved algorithm.",
        severity="critical",
        controls=("C-ENC-01", "C-ENC-02"),
        evidence_refs=("ev-s3-sse-config",),
        blocking=True,
        matcher=rule_enc_001,
    ),
    RuleDefinition(
        rule_id="wrd-iam-001",
        title="IAM policy widened with a wildcard action",
        description="A Terraform change introduced a `*` action into an IAM role policy, which removes "
                    "the least-privilege posture previously attested.",
        recommendation="Replace the wildcard with the minimum action list required by the workload.",
        severity="high",
        controls=("C-IAM-01",),
        evidence_refs=("ev-iam-policy-monthly-audit",),
        blocking=True,
        matcher=rule_iam_001,
    ),
    RuleDefinition(
        rule_id="wrd-net-001",
        title="Security group exposes a management port to the internet",
        description="A Terraform change added ingress from `0.0.0.0/0` on a management port "
                    "(22, 3389 or all traffic).",
        recommendation="Restrict the CIDR to a bastion/VPN range; never expose SSH/RDP publicly.",
        severity="critical",
        controls=("C-NET-01",),
        evidence_refs=("ev-sg-posture-scan",),
        blocking=True,
        matcher=rule_net_001,
    ),
    RuleDefinition(
        rule_id="wrd-alm-001",
        title="Metric alarm deleted",
        description="A Terraform change deleted a CloudWatch metric alarm, removing detection coverage "
                    "for that metric.",
        recommendation="Restore the alarm or document the replacement detection mechanism.",
        severity="medium",
        controls=("C-ALM-01",),
        evidence_refs=("ev-alarm-coverage-report",),
        blocking=False,
        matcher=rule_alm_001,
    ),
    RuleDefinition(
        rule_id="wrd-log-003",
        title="Audit log retention window changed",
        description="A Terraform change altered the CloudWatch log retention window for audit events. "
                    "Existing retention evidence may no longer describe the live configuration.",
        recommendation="Re-collect the retention evidence and confirm the new window satisfies the "
                       "compliance requirement (or restore the previous value).",
        severity="low",
        controls=("C-LOG-02",),
        evidence_refs=("ev-log-retention-report",),
        blocking=False,
        matcher=rule_log_003,
    ),
    RuleDefinition(
        rule_id="wrd-bak-001",
        title="Audit-bucket versioning removed",
        description="A Terraform change deleted the versioning configuration on the audit-artifact "
                    "bucket, weakening the preservation of audit evidence.",
        recommendation="Restore versioning on the audit bucket or provide an equivalent retention "
                       "mechanism with owner approval.",
        severity="medium",
        controls=("C-LOG-01",),
        evidence_refs=("ev-replication-report",),
        blocking=False,
        matcher=rule_bak_001,
    ),
)


def evaluate_rules(
    attr_changes: list[AttributeChange],
    control_ids_known: frozenset[str] | None = None,
    evidence_ids_known: frozenset[str] | None = None,
) -> list[SecurityFinding]:
    """Run every rule over the change set, return findings (deterministic ordering)."""
    findings: list[SecurityFinding] = []
    for rule in RULES:
        for change in attr_changes:
            if not rule.matcher(change):
                continue
            if control_ids_known:
                rule_controls = [cid for cid in rule.controls if cid in control_ids_known]
            else:
                rule_controls = list(rule.controls)
            evidence_refs = list(rule.evidence_refs)
            status = "confirmed"
            confidence = "high"
            evidence_notes: list[str] = []
            for evidence_id in list(rule.evidence_refs):
                if evidence_ids_known is not None and evidence_id not in evidence_ids_known:
                    status = "unknown_evidence"
                    confidence = "low"
                    evidence_notes.append(evidence_id)
            line_no = change.line_no
            finding = SecurityFinding(
                finding_id=f"{rule.rule_id}:{change.file_path}:{line_no or 0}",
                rule_id=rule.rule_id,
                title=rule.title,
                description=rule.description,
                severity=rule.severity,
                status=status,
                confidence=confidence,
                source_file=change.file_path,
                line=line_no,
                evidence_refs=tuple(evidence_refs),
                controls_covered=tuple(rule_controls),
                resource_address=f"{change.resource.resource_type}.{change.resource.resource_name}",
                scanner="warden-native",
                category="infrastructure",
                recommendation=rule.recommendation,
                url=DOC_LINK,
                fingerprint=f"{rule.rule_id}:{change.resource.resource_type}.{change.resource.resource_name}",
            )
            if finding not in findings:
                findings.append(finding)
    return findings


def rule_by_id(rule_id: str) -> RuleDefinition | None:
    for rule in RULES:
        if rule.rule_id == rule_id:
            return rule
    return None
