"""Analysis pipeline: diff → changes → native rules → impact graph → decision → report."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from app.adapters.terraform.changes import extract_resource_changes
from app.domain.registry import ControlRegistry, EvidenceRegistry
from app.domain.types import (
    AttributeChange,
    PullRequestContext,
    SecurityFinding,
)
from app.graph.impact import ImpactAnalyzer
from app.policies.decision import PolicyDecisionRecord, decide, default_policy_config
from app.policies.rules import RULES, RuleDefinition, evaluate_rules, is_uncovered_resource_type

REPORT_RULES_VERSION = "warden-native-rules/1.2.0"


@dataclass
class AnalysisResult:
    run_id: str
    context: PullRequestContext
    findings: list[SecurityFinding]
    unsupported_resource_types: list[str]
    parse_issues: list[str]
    policy_decision: PolicyDecisionRecord
    affected_controls: list[str]
    impacted_evidence: list[str]
    missing_evidence: list[str]
    verification_tasks: list[dict[str, Any]]
    traversal_reasons: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    report: dict[str, Any] = field(default_factory=dict)


class AnalysisPipeline:
    """Orchestrates the deterministic half of Warden. No LLM dependency."""

    def __init__(
        self,
        control_registry: ControlRegistry,
        evidence_registry: EvidenceRegistry,
    ) -> None:
        self.controls = control_registry
        self.evidence = evidence_registry
        self._rule_map: dict[str, RuleDefinition] = {rule.rule_id: rule for rule in RULES}

    def run(self, context: PullRequestContext) -> AnalysisResult:
        attr_changes: list[AttributeChange] = []
        parse_issues: list[str] = []
        for changed in context.changed_files:
            if not (changed.path.endswith(".tf") or changed.path.endswith(".tfvars")):
                continue
            try:
                attr_changes.extend(extract_resource_changes(changed))
            except Exception as exc:  # noqa: BLE001 - parser failures degrade, never crash
                parse_issues.append(f"{changed.path}: {type(exc).__name__}: {exc}")

        uncovered = sorted(
            {f"{c.resource.resource_type}" for c in attr_changes
             if is_uncovered_resource_type(c.resource.resource_type)}
        )

        findings = evaluate_rules(
            attr_changes,
            control_ids_known=frozenset(self.controls.controls),
            evidence_ids_known=frozenset(self.evidence.evidence),
        )

        analyzer = ImpactAnalyzer(attr_changes, findings, dict(self.evidence.evidence))
        impact = analyzer.analyse()

        policy_decision = decide(
            findings,
            policy=default_policy_config(),
            unsupported_constructs=uncovered,
        )

        graph_payload = self._graph_payload(analyzer)

        run_id = uuid.uuid4().hex
        report = self._report(
            run_id=run_id,
            context=context,
            attr_changes=attr_changes,
            findings=findings,
            policy=policy_decision,
            affected_controls=impact["affected_controls"],
            impacted_evidence=impact["impacted_evidence"],
            missing_evidence=impact["missing_evidence"],
            tasks=impact["verification_tasks"],
            reasons=impact["traversal_reasons"],
            uncovered=uncovered,
            parse_issues=parse_issues,
            graph=graph_payload,
        )

        return AnalysisResult(
            run_id=run_id,
            context=context,
            findings=findings,
            unsupported_resource_types=uncovered,
            parse_issues=parse_issues,
            policy_decision=policy_decision,
            affected_controls=impact["affected_controls"],
            impacted_evidence=impact["impacted_evidence"],
            missing_evidence=impact["missing_evidence"],
            verification_tasks=impact["verification_tasks"],
            traversal_reasons=impact["traversal_reasons"],
            edges=graph_payload["edges"],
            report=report,
        )

    def _graph_payload(self, analyzer: ImpactAnalyzer) -> dict[str, Any]:
        nodes = []
        for node_id, attrs in analyzer.graph.nodes().items():
            node_type, _ = node_id.split(":", 1)
            nodes.append(
                {"node_id": node_id, "node_type": attrs.get("node_type", node_type),
                 "label": attrs.get("label", node_id)}
            )
        edges = []
        for source, target, attrs in analyzer.graph.edges():
            edges.append(
                {
                    "source": source,
                    "target": target,
                    "kind": attrs.get("kind", ""),
                    "reason": attrs.get("reason", ""),
                    "rule_id": attrs.get("rule_id") or None,
                }
            )
        return {"nodes": nodes, "edges": edges}

    def _report(self, **kwargs: Any) -> dict[str, Any]:
        run_id: str = kwargs["run_id"]
        context: PullRequestContext = kwargs["context"]
        policy: PolicyDecisionRecord = kwargs["policy"]
        graph: dict[str, Any] = kwargs["graph"]
        affected, impacted, missing = (
            kwargs["affected_controls"], kwargs["impacted_evidence"], kwargs["missing_evidence"],
        )
        raw_tasks: list[dict[str, Any]] = kwargs["tasks"]
        tasks = [
            {
                "task_id": task.task_id,
                "kind": task.kind,
                "title": task.title,
                "reason": task.reason,
                "control_id": task.control_id,
                "evidence_ids": list(task.evidence_ids),
                "run_refs": list(task.run_refs),
                "blocking": task.blocking,
            }
            for task in raw_tasks
        ]

        findings_payload = []
        for finding in kwargs["findings"]:
            refs = self.controls.refs_for_control(finding.controls_covered[0]) if finding.controls_covered else []
            framework_refs = [
                {"framework_id": fw, "ref": ref} for fw, ref in refs
            ]
            findings_payload.append(
                {
                    "finding_id": finding.finding_id,
                    "rule_id": finding.rule_id,
                    "title": finding.title,
                    "description": finding.description,
                    "severity": finding.severity,
                    "status": finding.status,
                    "confidence": finding.confidence,
                    "source_file": finding.source_file,
                    "line": finding.line,
                    "resource_address": finding.resource_address,
                    "controls_covered": list(finding.controls_covered),
                    "framework_refs": framework_refs,
                    "evidence_refs": list(finding.evidence_refs),
                    "scanner": finding.scanner,
                    "recommendation": finding.recommendation,
                    "url": finding.url,
                }
            )

        diff_digest = hashlib.sha256(
            json.dumps(
                [f.path for f in context.changed_files] + [f.path for f in context.changed_files],
            ).encode()
        ).hexdigest()[:12]

        report: dict[str, Any] = {
            "run_id": run_id,
            "repository": context.repository,
            "pr_number": context.pr_number,
            "base_ref": context.base_ref,
            "head_ref": context.head_ref,
            "changeset_digest": diff_digest,
            "rules_version": REPORT_RULES_VERSION,
            "decision": {
                "outcome": policy.decision.value,
                "reason": policy.reason,
                "rule_id": policy.rule_id,
                "requires_human_review": policy.requires_human_review,
                "concerned_finding_ids": list(policy.concerned_finding_ids),
            },
            "summary": {
                "findings": len(findings_payload),
                "critical": sum(1 for f in findings_payload if f["severity"] == "critical"),
                "high": sum(1 for f in findings_payload if f["severity"] == "high"),
                "verification_tasks": len(tasks),
                "affected_controls": affected,
                "impacted_evidence": impacted,
                "missing_evidence": missing,
                "unsupported_resource_types": kwargs["uncovered"],
                "parse_issues": kwargs["parse_issues"],
            },
            "findings": findings_payload,
            "verification_tasks": tasks,
            "graph": graph,
            "mode": "deterministic",
            "llm_used": False,
            "ai_warning": (
                "This report was produced without any language model input. "
                "Findings are code-derived; verification tasks are recommendations, not verdicts."
            ),
        }
        return report
