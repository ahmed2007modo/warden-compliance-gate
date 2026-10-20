"""Unit tests for the compliance dependency graph (cycles, duplicates, missing nodes)."""

from __future__ import annotations

from app.domain.types import (
    AttributeChange,
    DependencyEdge,
    Evidence,
    ResourceAddress,
    SecurityFinding,
)
from app.graph.impact import ImpactAnalyzer


def _evidence(evidence_id: str = "ev-a", control_id: str = "C-X") -> Evidence:
    from datetime import datetime

    return Evidence(
        evidence_id=evidence_id,
        control_id=control_id,
        source="test",
        source_location="s3://bucket/x",
        collected_at=datetime(2026, 1, 1, tzinfo=None),
        resource_refs=("res.x",),
        content_hash="sha256:abc",
        evidence_type="type",
        age_days=5,
        freshness_status="fresh",
    )


def _finding(finding_id: str = "f1", controls: tuple[str, ...] = ("C-X",),
             evidence_refs: tuple[str, ...] = ("ev-a",), address: str = "aws_x.res") -> SecurityFinding:
    return SecurityFinding(
        finding_id=finding_id,
        rule_id="r1",
        title="t",
        description="d",
        severity="critical",
        status="confirmed",
        confidence="high",
        source_file="main.tf",
        line=1,
        controls_covered=controls,
        evidence_refs=evidence_refs,
        resource_address=address,
    )


def _change(address: ResourceAddress | None = None) -> AttributeChange:
    return AttributeChange(
        resource=address or ResourceAddress("aws_x", "res"),
        attribute="enabled",
        before="true",
        after="false",
        change_type="attribute_changed",
        file_path="main.tf",
        line_no=2,
    )


class TestGraphBasics:
    def test_change_links_to_finding(self) -> None:
        analyzer = ImpactAnalyzer([_change()], [_finding()], {})
        kinds = {
            (src, tgt, attrs["kind"]) for src, tgt, attrs in analyzer.graph.edges()
        }
        assert any(kind == "change_implies_finding" for _s, _t, kind in kinds)

    def test_impact_lists_controls_and_evidence(self) -> None:
        analyzer = ImpactAnalyzer([_change()], [_finding()], {"ev-a": _evidence()})
        result = analyzer.analyse()
        assert result["affected_controls"] == ["C-X"]
        assert result["impacted_evidence"] == ["ev-a"]
        assert len(result["verification_tasks"]) == 1

    def test_missing_evidence_produces_collection_task(self) -> None:
        analyzer = ImpactAnalyzer([_change()], [_finding(evidence_refs=("ev-missing",))], {})
        result = analyzer.analyse()
        assert result["missing_evidence"] == ["ev-missing"]
        task = result["verification_tasks"][0]
        assert task.kind == "control_validation"

    def test_stale_evidence_requires_manual_review(self) -> None:
        stale = _evidence()
        fresh = Evidence(**{**stale.__dict__, "freshness_status": "conflicting", "age_days": 400})
        analyzer = ImpactAnalyzer([_change()], [_finding()], {"ev-a": fresh})
        result = analyzer.analyse()
        assert result["verification_tasks"][0].kind == "manual_review"


class TestGraphRobustness:
    def test_cycle_tolerated(self) -> None:
        analyzer = ImpactAnalyzer([_change()], [_finding()], {})
        analyzer.graph.add_edge(DependencyEdge(
            source="finding:f1", target="change:aws_x.res:enabled",
            kind="guarded_loop", reason="synthetic cycle",
        ))
        result = analyzer.analyse()
        assert result["affected_controls"] == ["C-X"]

    def test_duplicate_edges_dedupe_with_reasons(self) -> None:
        analyzer = ImpactAnalyzer([_change()], [_finding()], {})
        analyzer.graph.add_edge(DependencyEdge(
            source="finding:f1", target="control:C-X",
            kind="finding_maps_control", reason="first",
        ))
        before = len(analyzer.graph.edges())
        analyzer.graph.add_edge(DependencyEdge(
            source="finding:f1", target="control:C-X",
            kind="finding_maps_control", reason="second traverse with distinct provenance",
        ))
        assert len(analyzer.graph.edges()) == before

    def test_unrelated_change_produces_no_impact(self) -> None:
        analyzer = ImpactAnalyzer([], [], {})
        empty = analyzer.analyse()
        assert empty["affected_controls"] == []
        assert empty["impacted_evidence"] == []

    def test_dangling_finding_ref_tolerated(self) -> None:
        analyzer = ImpactAnalyzer([_change()], [_finding()], {})
        dangling = analyzer.graph.reachable("finding:does-not-exist", ("finding_maps_control",))
        assert dangling == set()
