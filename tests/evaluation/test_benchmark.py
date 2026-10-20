"""End-to-end benchmark evaluation tests (real, executed measurements).

These tests run the 14-scenario synthetic benchmark and assert its actual behaviour;
the printed metrics are the numbers documented in docs/evaluation.md.
"""

from __future__ import annotations

import json

from app.evaluation.benchmark import BenchmarkRunner

MIN_ACCEPTED_ACCURACY = 0.95


def _run(pipeline_pipeline) -> dict:
    runner = BenchmarkRunner(pipeline_pipeline)
    return runner.run()


class TestBenchmark:
    def test_all_scenarios_classified_correctly(self, pipeline) -> None:
        result = _run(pipeline)
        mismatches = [row for row in result["scenarios"] if not row["matched"]]
        assert result["total"] >= 12
        assert not mismatches, f"mismatched scenarios: {[row['scenario_id'] for row in mismatches]}"
        assert result["accuracy"] >= MIN_ACCEPTED_ACCURACY

    def test_zero_false_positives(self, pipeline) -> None:
        result = _run(pipeline)
        assert result["false_positive_rate"] == 0.0

    def test_zero_missed_violations(self, pipeline) -> None:
        result = _run(pipeline)
        assert result["missed_violation_rate"] == 0.0

    def test_deterministic_reproducibility(self, pipeline) -> None:
        result = _run(pipeline)
        assert result["deterministic_reproducible"], "same input must give byte-identical decisions"

    def test_findings_reproducible_across_runs(self, pipeline) -> None:
        runner = BenchmarkRunner(pipeline)
        first = runner.run()
        second = runner.run()
        assert [row["actual_finding_rules"] for row in first["scenarios"]] == [
            row["actual_finding_rules"] for row in second["scenarios"]
        ]

    def test_documented_metrics_are_dumped(self, pipeline, tmp_path, capsys) -> None:
        result = _run(pipeline)
        out = json.dumps(result, default=str)
        assert '"accuracy"' in out
        assert '"evidence_reference_validity"' in out
        assert result["duration_ms"] > 0

    def test_expected_rules_match_hand_labels(self, pipeline) -> None:
        result = _run(pipeline)
        without_unsupported = [
            row for row in result["scenarios"] if row["scenario_id"] != "unsupported-construct"
        ]
        for row in without_unsupported:
            if row["tier"] in ("risky", "ambiguous"):
                assert row["missed_rules"] == [], row["scenario_id"]
