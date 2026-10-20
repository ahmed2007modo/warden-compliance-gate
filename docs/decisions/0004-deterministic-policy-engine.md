# ADR 0004 — Deterministic policy engine decides; optional LLM only explains

Status: Accepted · 2026-10-19

## Context

A compliance gate must be reproducible, auditable and independent of any vendor LLM. Using a
model to decide PASS/FAIL would also inherit prompt-injection risk from repo content
(ADR 0005 in the threat model).

## Decision

`policies/DecisionEngine` is pure Python with four outcomes: `PASS`, `FAIL`,
`REVIEW_REQUIRED`, `ERROR`. It consumes structured findings, a policy binding file
(`policies/default.yaml`) that declares which findings block, and produces a typed
`PolicyDecision` plus a human-readable rationale. It never calls the network.

An **optional** `llm` adapter may attach:
- `explanation` string, `remediation_draft`, `missing_info`
and is strictly forbidden from setting the outcome. Adapter output is Pydantic-validated
against a fixed schema; any invalid or missing response leaves the decision untouched and
records an `AuditEvent(llm_explanation_failed)`.

## Consequences

- Same diff → same decision, byte-identical JSON, with no LLM configured.
- All "the model said so" paths become *additions* to, not mutations of, deterministic truth.
- Prompt-injection content in the diff cannot flip the outcome — there is no code path from
  model output to `outcome`.
