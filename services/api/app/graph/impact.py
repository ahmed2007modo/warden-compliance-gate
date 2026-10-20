"""Compliance dependency graph and change-impact traversal.

Structure:
    Change ─▶ Finding ─▶ Control ─▶ Evidence ─▶ VerificationTask

Every edge carries a reason string citing the rule id + diff evidence, so any impact verdict
can be reproduced and audited. Traversal is bounded (visited set + depth cap) and tolerant of
cycles, duplicate edges and dangling references.
"""

from __future__ import annotations

import networkx as nx

from app.domain.types import (
    AttributeChange,
    DependencyEdge,
    Evidence,
    SecurityFinding,
    VerificationTask,
)


class ImpactGraph:
    """Typed wrapper over a networkx DiGraph with reason-annotated edges."""

    def __init__(self) -> None:
        self._g = nx.DiGraph()

    def add_node(self, node_id: str, node_type: str, label: str) -> None:
        if not self._g.has_node(node_id):
            self._g.add_node(node_id, node_type=node_type, label=label)

    def add_edge(self, edge: DependencyEdge) -> None:
        if self._g.has_edge(edge.source, edge.target):
            existing = self._g[edge.source][edge.target]
            reasons = set(existing.get("reasons", []))
            reasons.add(edge.reason)
            existing["reasons"] = sorted(reasons)
            if edge.rule_id and not existing.get("rule_id"):
                existing["rule_id"] = edge.rule_id
            return
        self._g.add_edge(
            edge.source, edge.target,
            kind=edge.kind,
            reason=edge.reason,
            rule_id=edge.rule_id or "",
        )

    def has_node(self, node_id: str) -> bool:
        return self._g.has_node(node_id)

    def nodes(self) -> dict[str, dict]:
        return dict(self._g.nodes(data=True))

    def edges(self) -> list[tuple[str, str, dict]]:
        return list(self._g.edges(data=True))

    def out_from(self, node_id: str) -> list[str]:
        if not self._g.has_node(node_id):
            return []
        return list(self._g.successors(node_id))

    def edges_from(self, node_id: str, kind: str) -> list[tuple[str, str, dict]]:
        return [
            (source, target, attrs)
            for source, target, attrs in self._g.out_edges(node_id, data=True)
            if attrs.get("kind") == kind
        ]

    def reachable(self, start: str, follow_kinds: tuple[str, ...], max_depth: int = 6) -> set[str]:
        """Bounded traversal following only edges of the given kinds (cycle-safe)."""
        if not self._g.has_node(start):
            return set()
        seen: set[str] = set()
        frontier: list[str] = [start]
        for _ in range(max_depth):
            nxt: list[str] = []
            for node_id in frontier:
                if node_id in seen:
                    continue
                seen.add(node_id)
                for succ in self._g.successors(node_id):
                    attr = self._g[node_id][succ]
                    if attr.get("kind") in follow_kinds:
                        nxt.append(succ)
            if not nxt:
                break
            frontier = nxt
        seen.discard(start)
        return seen


CHANGE_KIND = "change_implies_finding"
CONTROL_KIND = "finding_maps_control"
EVIDENCE_KIND = "control_requires_evidence"
TASK_KIND = "evidence_needs_verification"


class ImpactAnalyzer:
    """Builds the graph from one analysis result and traverses it for impact."""

    def __init__(
        self,
        attr_changes: list[AttributeChange],
        findings: list[SecurityFinding],
        evidence_registry: dict[str, Evidence],
    ) -> None:
        self.changes = attr_changes
        self.findings = findings
        self.evidence = evidence_registry
        self.graph = self._build()

    def _build(self) -> ImpactGraph:
        graph = ImpactGraph()
        for change in self.changes:
            addr = f"{change.resource.resource_type}.{change.resource.resource_name}"
            change_node = f"change:{addr}:{change.attribute or change.change_type}"
            graph.add_node(change_node, "change", f"{change.change_type} {addr}")
        for finding in self.findings:
            graph.add_node(f"finding:{finding.finding_id}", "finding", finding.title)

            for control_id in finding.controls_covered:
                control_node = f"control:{control_id}"
                graph.add_node(control_node, "control", control_id)
                graph.add_edge(
                    DependencyEdge(
                        source=f"finding:{finding.finding_id}",
                        target=control_node,
                        kind=CONTROL_KIND,
                        reason=f"rule {finding.rule_id} maps to control {control_id}",
                        rule_id=finding.rule_id,
                    )
                )
                for evidence_id in finding.evidence_refs:
                    ev_node = f"evidence:{evidence_id}"
                    if evidence_id in self.evidence:
                        item = self.evidence[evidence_id]
                        graph.add_node(ev_node, "evidence", item.evidence_id)
                        graph.add_edge(
                            DependencyEdge(
                                source=control_node,
                                target=ev_node,
                                kind=EVIDENCE_KIND,
                                reason=f"control {control_id} is supported by evidence {evidence_id}",
                                rule_id=finding.rule_id,
                            )
                        )
                    else:
                        graph.add_node(ev_node, "evidence_missing", evidence_id)
                        graph.add_edge(
                            DependencyEdge(
                                source=control_node,
                                target=ev_node,
                                kind=EVIDENCE_KIND,
                                reason=(
                                    f"control {control_id} expects evidence {evidence_id} "
                                    f"but it is not present in the evidence registry"
                                ),
                                rule_id=finding.rule_id,
                            )
                        )
        self._link_changes_to_findings(graph)
        return graph

    def _link_changes_to_findings(self, graph: ImpactGraph) -> None:
        for finding in self.findings:
            addr = finding.resource_address
            for change in self.changes:
                change_addr = f"{change.resource.resource_type}.{change.resource.resource_name}"
                if change_addr != addr:
                    continue
                attr_token = change.attribute if change.attribute else change.change_type
                change_node = f"change:{change_addr}:{attr_token}"
                reason = (
                    f"finding {finding.rule_id} is triggered by this change to "
                    f"{change_addr} ({attr_token})"
                )
                graph.add_edge(
                    DependencyEdge(
                        source=change_node,
                        target=f"finding:{finding.finding_id}",
                        kind=CHANGE_KIND,
                        reason=reason,
                        rule_id=finding.rule_id,
                    )
                )

    def analyse(self) -> dict[str, object]:
        """Traverse from change nodes → findings → controls → evidence, plan tasks."""
        affected_controls: set[str] = set()
        impacted_evidence: set[str] = set()
        missing_evidence: set[str] = set()
        tasks: list[VerificationTask] = []
        reasons: list[DependencyEdge] = []

        for finding in self.findings:
            finding_node = f"finding:{finding.finding_id}"
            for control_node in self.graph.reachable(finding_node, (CONTROL_KIND,)):
                control_id = control_node.split(":", 1)[1]
                affected_controls.add(control_id)
                for _src, target, attrs in self.graph.edges_from(control_node, EVIDENCE_KIND):
                    ev_id = target.split(":", 1)[1]
                    reasons.append(
                        DependencyEdge(
                            source=control_node,
                            target=target,
                            kind=EVIDENCE_KIND,
                            reason=str(attrs.get("reason", "")),
                            rule_id=attrs.get("rule_id") or None,
                        )
                    )
                    impacted_evidence.add(ev_id)
                    node_type = "evidence"
                    if self.graph.has_node(target):
                        node_type = str(self.graph.nodes()[target].get("node_type", "evidence"))
                    if node_type == "evidence_missing":
                        missing_evidence.add(ev_id)
                    tasks.append(self._task_for(control_id, ev_id, node_type, finding.finding_id))

        seen: set[str] = set()
        unique_tasks: list[VerificationTask] = []
        for task in tasks:
            if task.task_id in seen:
                continue
            seen.add(task.task_id)
            unique_tasks.append(task)

        return {
            "affected_controls": sorted(affected_controls),
            "impacted_evidence": sorted(impacted_evidence),
            "missing_evidence": sorted(missing_evidence),
            "verification_tasks": unique_tasks,
            "traversal_reasons": reasons,
        }

    def _task_for(
        self, control_id: str, evidence_id: str, node_type: str, finding_id: str
    ) -> VerificationTask:
        if node_type == "evidence_missing":
            return VerificationTask(
                task_id=f"collect:{control_id}:{evidence_id}",
                kind="control_validation",
                title=f"Collect missing evidence for control {control_id}",
                reason=(
                    f"Control {control_id} supports finding {finding_id} but evidence "
                    f"{evidence_id} does not exist in the registry; collect a current sample."
                ),
                control_id=control_id,
                evidence_ids=(evidence_id,),
                run_refs=(finding_id,),
                blocking=False,
            )
        item = self.evidence.get(evidence_id)
        if item is not None and item.freshness_status in ("stale", "conflicting"):
            kind = "manual_review"
            title = f"Resolve conflicting evidence for control {control_id}"
            reason = (
                f"Evidence {evidence_id} is currently marked {item.freshness_status}; "
                f"a linked change was detected and needs human verification."
            )
            blocking = True
        else:
            kind = "evidence_revalidation"
            title = f"Re-validate evidence {evidence_id} for control {control_id}"
            reason = (
                f"The infrastructure change behind finding {finding_id} may invalidate "
                f"evidence {evidence_id} collected {item.age_days} days ago; re-collect and compare."
            )
            blocking = False
        return VerificationTask(
            task_id=f"revalidate:{control_id}:{evidence_id}",
            kind=kind,
            title=title,
            reason=reason,
            control_id=control_id,
            evidence_ids=(evidence_id,),
            run_refs=(finding_id,),
            blocking=blocking,
        )
