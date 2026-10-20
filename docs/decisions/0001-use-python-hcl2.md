# ADR 0001 — Terraform parsing strategy (line-oriented extractor; `python-hcl2` pinned but dormant)

Status: Amended · 2026-10-19

## Context

Warden must map a Terraform diff to resource-level semantic changes (blocks, attributes,
nested blocks). Writing a tokeniser by hand is a trap: HCL has interpolation, heredocs,
for-expressions, providers with quirky syntax, and .tfvars.

## Decision

`python-hcl2` is pinned in `pyproject.toml` (>=4.3,<6.0) but the pipeline currently does **not**
call it. In practice the prototype ships a deliberately conservative **line-oriented extractor**
(`adapters/terraform/hcl_parser.py`) that:

- matches `resource`/`data` headers and tracks brace depth to collect attribute lines,
- records original line numbers (used for evidence citation in the PR report),
- treats anything it cannot statically resolve (heredocs spanning many lines, `dynamic`
  blocks, `count`-style conditionals) as **unsupported constructs**, which surface as
  `REVIEW_REQUIRED`, never as PASS.

## Why the deviation

- The scanner's needs are narrow: attribute values, block presence/absence. The extractor
  covers exactly that envelope and fails closed outside it.
- Diffs are compared per-file between the base and head trees; line-anchored extraction
  keeps finding provenance (file:line) exact for evidence mapping.
- True fully-general HCL parsing (interpolations, for-expressions) is deferred; when a
  construct is out of envelope the run degrades to REVIEW_REQUIRED rather than guessing.

## Consequences

- Budget 0&nbsp;↔ phase 2: if richer HCL (modules, expressions) is needed, wire `python-hcl2`
  behind `adapters/terraform/hcl_parser.py` and extend the unsupported-construct list rather
  than widening the line-oriented heuristics.
- Warden never claims *complete* HCL coverage — unsupported constructs surface as
  `REVIEW_REQUIRED` with reason `unsupported_construct`.
- Benchmark scenario `unsupported-construct` (aws_docdb_cluster) exercises exactly this path.
