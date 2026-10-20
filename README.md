# Warden — Compliance CI Gate

Warden is a compliance intelligence layer for CI/CD. It parses Terraform pull-request
diffs, maps infrastructure changes to compliance controls, assesses evidence impact via a
dependency graph, and emits **deterministic** PASS / FAIL / REVIEW_REQUIRED / ERROR decisions
with an auditable JSON report.

Design invariant: **an LLM can never override the verdict.** All classification is done by
deterministic, hand-auditable native rules (`wrd-*`); the optional LLM adapter can only add
explanatory prose, in a separate non-authoritative field.

## Repository layout

```
services/api/        FastAPI app: adapters → rules → graph → policy → API (SQLAlchemy + SQLite)
frameworks/          Shared controls + framework mappings (ISO-27001-2022, SOC2, NIS2, CRA) + evidence seed
fixtures/            14 deterministic benchmark PR scenarios (safe / risky / ambiguous)
scripts/             make_fixtures.py (fixture generator), run_benchmark.py (evaluation CLI)
docs/                product-research, architecture, threat-model, evaluation + ADRs (decisions/)
tests/               unit / integration / security / evaluation pytest suites (84 tests)
.github/workflows/   CI (ruff + pytest)
reports/             evaluation-latest.json (regenerated per benchmark run; git-ignored)
```

## Quickstart

```bash
python -m venv .venv
.venv\Scripts\pip install -e services/api[dev]     # Linux/macOS: .venv/bin/pip ...

# run the API (dev)
.venv\Scripts\uvicorn app.main:app --app-dir services/api --reload

# run the full test suite
.venv\Scripts\pytest

# run the evaluation benchmark and save the report
.venv\Scripts\python scripts/run_benchmark.py --save
```

`GET /api/v1/healthz`, `GET /docs` (OpenAPI UI) once the server is up. The API seeds the
SQLite database with the evidence registry on startup in dev mode.

## Endpoints (v1)

| Method | Path | Purpose |
|--------|------|---------|
| GET  | `/api/v1/healthz` | liveness |
| POST | `/api/v1/analyze` | analyze inline base/head trees; persists a run |
| POST | `/api/v1/analyze-pr` | GitHub PR ingestion (Phase 4, currently 501) |
| GET  | `/api/v1/runs` / `/api/v1/runs/{run_id}` | audit-accessible history of runs |
| GET  | `/api/v1/controls` | control mappings across frameworks |
| GET  | `/api/v1/evidence` | evidence registry snapshot |
| POST | `/api/v1/evaluate` | re-run the benchmark in-process |

## Decision semantics

| Outcome | Trigger |
|---------|---------|
| `FAIL` | any confirmed finding on a blocking rule at critical/high severity |
| `REVIEW_REQUIRED` | non-blocking findings, evidence that cannot be validated (missing/conflicting), unsupported Terraform constructs, required scanner unavailable |
| `PASS` | no findings and no open questions |
| `ERROR` | pipeline failure (parse crash, registry fault) — never silently degraded |

Every run emits: findings (with controls + evidence refs), verification tasks
(re-collect / manual review), the bilingual dependency graph (change → finding → control →
evidence), and an `{outcome, reason, rule_id, requires_human_review}` decision object.

## Evaluation

Latest executed run: 14/14 scenarios correct, accuracy 1.0, false-positive rate 0.0,
missed-violation rate 0.0, evidence-reference validity 0.9 (one reference is *deliberately*
absent from the seed registry to exercise the missing-evidence path), reproducible: true.
Reproduce with `python scripts/run_benchmark.py --save`; details and hand labels live in
`docs/evaluation.md`.

## Security posture

- Path traversal rejected in every tree path (no `..`, no absolute/backslash escapes).
- Diff/tree size caps; `read-only` ingestion; no subprocess calls to `terraform`.
- Prompt-injection comments in `.tf` files are inert (see `tests/security`).
- Optional LLM calls decompose severity, redact `AKIA…`/bearer tokens first, and are
  validated against fabricated file references before being attached to a report;
  failure is non-authoritative by construction.

See `docs/threat-model.md` and `docs/architecture.md` for the full walk-through.
