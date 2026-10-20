"""Unit tests for the deterministic native rules on synthetic AttributeChanges."""

from __future__ import annotations

from app.domain.types import AttributeChange, ResourceAddress
from app.policies.rules import (
    RULES,
    evaluate_rules,
    is_uncovered_resource_type,
    rule_by_id,
)

ADDR = ResourceAddress(resource_type="aws_cloudtrail", resource_name="audit_trail")


def _change(
    rtype: str = "aws_cloudtrail",
    rname: str = "audit_trail",
    attribute: str | None = "enabled",
    before: object = "true",
    after: object = "false",
    change_type: str = "attribute_changed",
    file_path: str = "infra/main.tf",
    line_no: int | None = 12,
) -> AttributeChange:
    from app.domain.types import AttributeChange, ResourceAddress

    return AttributeChange(
        resource=ResourceAddress(resource_type=rtype, resource_name=rname),
        attribute=attribute,
        before=before,
        after=after,
        change_type=change_type,
        file_path=file_path,
        line_no=line_no,
    )


class TestRuleLog001:
    def test_fires_on_disabled(self) -> None:
        findings = evaluate_rules([_change()])
        assert [f.rule_id for f in findings] == ["wrd-log-001"]
        finding = findings[0]
        assert finding.severity == "critical"
        assert finding.status == "confirmed"
        assert finding.controls_covered == ("C-LOG-01",)
        assert finding.source_file == "infra/main.tf"
        assert finding.line == 12

    def test_fires_on_resource_deleted(self) -> None:
        findings = evaluate_rules([_change(attribute=None, before={"keys": []}, after=None,
                                           change_type="resource_deleted")])
        assert len(findings) == 1

    def test_no_fire_when_enabled_unchanged(self) -> None:
        findings = evaluate_rules([_change(after="true")])
        assert findings == []

    def test_no_fire_on_other_attribute(self) -> None:
        findings = evaluate_rules([_change(attribute="name", before="a", after="b")])
        assert findings == []


class TestRuleIam001:
    def test_fires_on_json_wildcard(self) -> None:
        change = _change(
            rtype="aws_iam_role_policy", rname="app_runtime",
            attribute="policy", before='Action = ["s3:List"]', after='Action = "*"',
        )
        findings = evaluate_rules([change])
        assert [f.rule_id for f in findings] == ["wrd-iam-001"]

    def test_fires_on_hcl_wildcard(self) -> None:
        change = _change(
            rtype="aws_iam_role_policy", rname="app_runtime",
            attribute="policy",
            before='policy = jsonencode({\n  Action = ["s3:GetObject"]\n})',
            after='policy = jsonencode({\n  Action "*" = true\n})',
        )
        # HCL unquoted: `Action   = "*"` — must still match
        change = _change(
            rtype="aws_iam_role_policy", rname="app_runtime", attribute="policy",
            before="policy = jsonencode({\n  Action = [\"s3:GetObject\"]\n})",
            after="policy = jsonencode({\n  Action   = \"*\"\n})",
        )
        findings = evaluate_rules([change])
        assert [f.rule_id for f in findings] == ["wrd-iam-001"]

    def test_no_fire_on_resource_wildcard_only(self) -> None:
        change = _change(
            rtype="aws_iam_role_policy", rname="app_runtime", attribute="policy",
            before="policy = jsonencode({\n  Action = [\"s3:GetObject\"]\n  Resource = \"*\"\n})",
            after="policy = jsonencode({\n  Action = [\"s3:GetObject\"]\n  Resource = \"*\"\n})",
        )
        findings = evaluate_rules([change])
        assert findings == []


class TestRuleNet001:
    def test_fires_on_open_ingress(self) -> None:
        change = _change(
            rtype="aws_security_group", rname="bastion", attribute="ingress",
            before="ingress {\n  cidr_blocks = [\"10.0.0.0/8\"]\n}",
            after="ingress {\n  cidr_blocks = [\"0.0.0.0/0\"]\n}",
        )
        findings = evaluate_rules([change])
        assert [f.rule_id for f in findings] == ["wrd-net-001"]

    def test_no_fire_on_private_cidr(self) -> None:
        before = "ingress {\n  cidr_blocks = [\"0.0.0.0/0\"]\n}"
        change = _change(
            rtype="aws_security_group", rname="bastion", attribute="ingress",
            before=before, after="ingress {\n  cidr_blocks = [\"10.0.0.0/8\"]\n}",
        )
        findings = evaluate_rules([change])
        assert findings == []


class TestRuleEnc001:
    def test_fires_on_sse_removed(self) -> None:
        change = _change(
            rtype="aws_s3_bucket_server_side_encryption_configuration", rname="audit",
            attribute=None, before={"keys": []}, after=None, change_type="resource_deleted",
        )
        findings = evaluate_rules([change])
        assert [f.rule_id for f in findings] == ["wrd-enc-001"]


class TestCoverage:
    def test_all_rule_ids_unique(self) -> None:
        ids = [rule.rule_id for rule in RULES]
        assert len(ids) == len(set(ids))

    def test_uncovered_type(self) -> None:
        assert is_uncovered_resource_type("aws_docdb_cluster")
        assert not is_uncovered_resource_type("aws_cloudtrail")

    def test_rule_by_id_lookup(self) -> None:
        assert rule_by_id("wrd-log-001") is not None
        assert rule_by_id("missing") is None


class TestEvidenceGapMarking:
    def test_unknown_evidence_status_when_registry_lacks_evidence(self) -> None:
        findings = evaluate_rules(
            [_change()], evidence_ids_known=frozenset()  # registry empty
        )
        assert findings[0].status == "unknown_evidence"
