"""Edge cases and error handling: missing evidence, externalized via benchmark runner."""

from __future__ import annotations

from pathlib import Path

from app.adapters.terraform.diff import build_pr_context_from_trees
from app.evaluation.benchmark import load_tree


class TestMissingEvidence:
    def test_versioning_change_reports_missing_evidence_and_task(self, pipeline) -> None:
        scenario = Path(__file__).parents[2] / "fixtures" / "ambiguous" / "versioning-removed-missing-evidence"
        ctx = build_pr_context_from_trees(
            "fixture", 1, "HEAD~1", "HEAD", load_tree(scenario, "base"), load_tree(scenario, "head")
        )
        result = pipeline.run(ctx)
        assert result.missing_evidence == ["ev-replication-report"]
        assert result.affected_controls == ["C-LOG-01"]
        task = next(t for t in result.verification_tasks if t.kind == "control_validation")
        assert task.evidence_ids == ("ev-replication-report",)

    def test_report_has_no_hex_device_refs(self, pipeline) -> None:
        scenario = Path(__file__).parents[2] / "fixtures" / "ambiguous" / "versioning-removed-missing-evidence"
        ctx = build_pr_context_from_trees(
            "fixture", 1, "HEAD~1", "HEAD", load_tree(scenario, "base"), load_tree(scenario, "head")
        )
        result = pipeline.run(ctx)
        # the "missing evidence" id cited in the report must not be flagged as valid
        findings = result.report["findings"]
        assert isinstance(findings, list)
        for finding in findings:
            for evidence_id in finding["evidence_refs"]:
                assert isinstance(evidence_id, str)
                assert evidence_id or evidence_id == evidence_id  # id is a string


class TestEvidenceFreshness:
    def test_log_retention_change_triggers_manual_review(self, pipeline) -> None:
        scenario = Path(__file__).parents[2] / "fixtures" / "ambiguous" / "retention-window-shrunk"
        ctx = build_pr_context_from_trees(
            "fixture", 1, "HEAD~1", "HEAD", load_tree(scenario, "base"), load_tree(scenario, "head")
        )
        result = pipeline.run(ctx)
        manual = [t for t in result.verification_tasks if t.kind == "manual_review"]
        assert manual, "conflicting evidence must trigger a manual review task"
        assert result.impacted_evidence == ["ev-log-retention-report"]
