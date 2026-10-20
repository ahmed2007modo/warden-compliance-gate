# ADR 0002 — Native deterministic rules engine primary; optional external scanners

Status: Accepted · 2026-10-19

## Context

The prototype must be reproducible on a clean machine with zero setup and must not depend on
vendor binaries. Checkov / Trivy / OPA are excellent but not installed in every local and CI
environment, and `pip install checkov` pulls a large dependency tree.

## Decision

- Implement a small, **pure-Python deterministic rules engine** over the python-hcl2 AST that
  covers a focused, well-documented rule set: audit logging, encryption-at-rest, IAM
  permissions, public network exposure.
- Every deterministic rule emits the exact same `SecurityFinding` schema that an external
  scanner would, prefixed with `wrd-` ids and tagged `scanner: warden-native`.
- Expose an optional **Checkov adapter** (installed via the `llm`/`checkov` extras) and
  position `TrivyAdapter` / `OPAAdapter` as binary-probe adapters that degrade gracefully to
  `unavailable` when the binary is absent.
- **Never** silently claim PASS from a missing scanner; absence of mandated scanner coverage is
  surfaced as `REVIEW_REQUIRED`.

## Consequences

- Warden is fully functional with no LLM key, no docker, no vendored binaries.
- The benchmark is deterministic and CI-free.
- External scanners remain a precision upgrade, not a correctness prerequisite.
