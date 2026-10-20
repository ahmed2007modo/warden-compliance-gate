# ADR 0003 — Evidence is a first-class registry keyed by *versioned* source

Status: Accepted · 2026-10-19

## Context

The central prototype hypothesis is change-impact analysis: a Terraform change should say which
*evidence* items (audit logs, encryption attestations, screenshots) must be re-validated. Naive
treatments either (a) treat old timestamps as "stale" and invalidate everything, or (b) ignore
evidence entirely.

## Decision

Each `Evidence` record carries: `id`, `source` (system + location), `collected_at`,
`resource_refs`, `content_hash`, `freshness_policy` (per evidence *type*, e.g. "collected
within 90 days"), `verification_status` (`current | stale | conflicting | missing`), and
`provenance` (who collected it, how).

**Freshness alone never invalidates.** Invalidation is always the result of a *dependency
rule*: a control declares, per rule, which evidence ids and which resource-change patterns
break it (e.g. `aws_cloudtrail.enabled: true→false` invalidates `ev-aws-cloudtrail-sample`).
Rules live in `policies/impact_rules.yaml` so they are auditable.

## Consequences

- Change→evidence impact is explainable: every invalidation cites the rule id and the exact
  attribute change.
- Graph traversal is bounded and testable (cycle, duplicate edges, missing nodes).
- Contradictory *evidence state* results in `REVIEW_REQUIRED`, not silent PASS.
