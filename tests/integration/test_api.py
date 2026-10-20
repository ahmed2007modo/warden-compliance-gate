"""Integration tests against the FastAPI application."""

from __future__ import annotations

from pathlib import Path

from app.evaluation.benchmark import load_tree
from fastapi.testclient import TestClient

WORKSPACE = Path(__file__).resolve().parents[2]


def _inline_payload(scenario: str, tier_dir: str) -> dict:
    scenario_dir = WORKSPACE / "fixtures" / tier_dir / scenario
    payload = {
        "scenario_name": f"fixtures/{tier_dir}/{scenario}",
        "base_tree": [
            {"path": path, "content": content}
            for path, content in load_tree(scenario_dir, "base").items()
        ],
        "head_tree": [
            {"path": path, "content": content}
            for path, content in load_tree(scenario_dir, "head").items()
        ],
    }
    return payload


class TestApi:
    def test_health(self, client: TestClient) -> None:
        response = client.get("/api/v1/healthz")
        assert response.status_code == 200

    def test_analyze_risky_pr_fails(self, client: TestClient) -> None:
        response = client.post("/api/v1/analyze", json=_inline_payload("audit-trail-disabled", "risky"))
        assert response.status_code == 200
        body = response.json()
        assert body["decision"] == "FAIL"
        assert body["run_id"]
        assert any(f["rule_id"] == "wrd-log-001" for f in body["findings"])
        assert body["policy_decision"]["requires_human_review"] is False
        assert body["report_rules_version"].startswith("warden-native-rules")

    def test_analyze_safe_pr_passes(self, client: TestClient) -> None:
        response = client.post("/api/v1/analyze", json=_inline_payload("docs-only", "safe"))
        body = response.json()
        assert body["decision"] == "PASS"
        assert body["findings"] == []

    def test_analyze_unsupported_construct_requires_review(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/analyze", json=_inline_payload("unsupported-construct", "ambiguous")
        )
        body = response.json()
        assert body["decision"] == "REVIEW_REQUIRED"
        assert "aws_docdb_cluster" in set(body["unsupported_resource_types"])

    def test_path_traversal_rejected(self, client: TestClient) -> None:
        payload = _inline_payload("docs-only", "safe")
        payload["head_tree"].append({"path": "../../etc/passwd.tf", "content": "x=1\n"})
        response = client.post("/api/v1/analyze", json=payload)
        assert response.status_code == 422

    def test_run_is_persisted_and_fetchable(self, client: TestClient) -> None:
        analyzed = client.post("/api/v1/analyze", json=_inline_payload("audit-trail-disabled", "risky"))
        run_id = analyzed.json()["run_id"]
        fetched = client.get(f"/api/v1/runs/{run_id}")
        assert fetched.status_code == 200
        assert fetched.json()["run_id"] == run_id
        assert fetched.json()["report"]["decision"]["outcome"] == "FAIL"

    def test_run_not_found(self, client: TestClient) -> None:
        response = client.get("/api/v1/runs/does-not-exist")
        assert response.status_code == 404

    def test_runs_list_reports(self, client: TestClient) -> None:
        client.post("/api/v1/analyze", json=_inline_payload("audit-trail-disabled", "risky"))
        response = client.get("/api/v1/runs")
        assert response.status_code == 200
        runs = response.json()
        assert runs, "at least one persisted run expected"

    def test_audit_events_are_recorded(self, client: TestClient) -> None:
        from app.core.database import session_factory
        from app.models.orm import AuditEventRow
        from sqlalchemy import select

        analyzed = client.post("/api/v1/analyze", json=_inline_payload("iam-policy-widened", "risky"))
        run_id = analyzed.json()["run_id"]
        with session_factory()() as session:
            events = session.scalars(
                select(AuditEventRow).where(AuditEventRow.run_id == run_id)
                .order_by(AuditEventRow.step_index)
            ).all()
            assert [e.event_type for e in events] == [
                "pipeline_started",
                "findings_emitted",
                "decision_reached",
                "report_persisted",
            ]

    def test_evidence_registry_endpoint(self, client: TestClient) -> None:
        response = client.get("/api/v1/evidence")
        assert response.status_code == 200
        evidence_ids = {row["evidence_id"] for row in response.json()}
        assert "ev-cloudtrail-config-prod" in evidence_ids
        assert "ev-log-retention-report" in evidence_ids

    def test_controls_endpoint_shared_mapping(self, client: TestClient) -> None:
        response = client.get("/api/v1/controls")
        assert response.status_code == 200
        mappings = response.json()
        assert len(mappings) >= 15
        log01 = [row for row in mappings if row["control_id"] == "C-LOG-01"]
        framework_ids = {row["framework_id"] for row in log01}
        assert "iso-27001-2022" in framework_ids
        for framework_id in ("soc2", "nis2", "cra"):
            assert any(row["framework_id"] == framework_id
                       for row in mappings), f"{framework_id} not represented"
