# Warden — System Architecture

Compliance CI Gate: an evidence-backed compliance intelligence layer for CI/CD,
implemented as a **modular monolith** with explicit, typed module boundaries.

## 1. Data flow

```
        ┌──────────────────────────────────────────────────────────┐
        │                    GitHub Pull Request                   │
        └──────────────────────────────┬───────────────────────────┘
                                       │  (REST trigger or webhook)
                                       ▼
        ┌──────────────────────────────────────────────────────────┐
        │ 1. Diff adapter      git unified diff → per-file hunks   │
        │ 2. Terraform adapter python-hcl2 AST → resource changes  │
        │ 3. Scanner adapters   native rules + optional Checkov/   │
        │                       Trivy/OPA behind one interface     │
        │ 4. Findings           normalised, deduplicated           │
        │ 5. Control mapping    finding → controls (many→many)     │
        │ 6. Evidence impact    dependency graph traversal         │
        │ 7. Verification planner targeted tasks                   │
        │ 8. Policy engine      PASS / FAIL / REVIEW_REQUIRED /    │
        │                       ERROR (deterministic)              │
        │ 9. Report             evidence-backed JSON               │
        │10. Surface            GitHub Checks / PR comment         │
        │   (optional 11)       AI explanation, never override    │
        └──────────────────────────────────────────────────────────┘
```

## 2. Module map

| `app/` module | Responsibility | Public type(s) |
|---|---|---|
| `api/` | FastAPI routes, request/response schemas only | `analyze`, `runs`, `controls`, `evidence`, `evaluation`, `healthz` |
| `core/` | Settings, structured logging, shared errors | `Settings`, `get_logger` |
| `domain/` | Pure dataclasses shared by every layer (no I/O) | `Change`, `SecurityFinding`, `Control`, `Evidence`, `PolicyDecision`, … |
| `models/` | SQLAlchemy 2.x ORM persisted rows | `RepositoryRow`, `PullRequestRow`, `RunRow`, `AuditEventRow`, … |
| `repositories/` | SQLAlchemy persistence for runs, evidence, findings | `RunRepository`, `AuditRepository` |
| `adapters/` | Border translation | `github/`, `terraform/diff_parser` + `hcl_parser`, `scanners/` (`native`, `checkov`, `trivy`, `opa`), `llm/` |
| `analysis/` | Pipeline orchestration over the above | `AnalysisPipeline`, `AnalysisResult` |
| `graph/` | NetworkX dependency graph + impact traversal | `DependencyGraph`, `ImpactAnalysis` |
| `policies/` | Deterministic rule engine + 4-outcome decision model | `PolicyEngine`, `RuleSpec` |
| `evaluation/` | Benchmark runner, scenario fixtures, scoring | `BenchmarkRunner`, `Scenario` |
| `services/` | Cross-cutting: registry loading, report rendering | `ControlRegistry`, `EvidenceRegistry`, `ReportBuilder` |

**Rule:** layers may depend only *downward* (api → services/analysis → adapters/graph/policies →
domain → core). Enforced by `tests/unit/architecture_test.py` import-direction checks.

## 3. Request → run lifecycle

1. `POST /v1/analyze` with a repo URL + PR number (+ optional base/head SHAs).
   Cells run as: **fetch diff** → **parse** → **rules** → **graph** → **policy** → **persist**.
2. Every step emits `AuditEvent` rows with monotonic `step_index`; report JSON is a pure function
   of `(repo, base, head, registry versions)` → re-running the same inputs yields the same JSON.
3. Persisted run has a stable `run_id`; `GET /v1/runs/{run_id}` re-reads without re-analyzing.

## 4. Key decisions captured elsewhere

| Topic | Decision |
|---|---|
| Storage | SQLite by default; Postgres optional via `psycopg`/compose (SQLite-first per user decision) |
| HCL parsing | `python-hcl2` (no custom parser) — see ADR 0001 |
| Scanners | Native rule engine primary; Checkov/Trivy/OPA optional — see ADR 0002 |
| Graph | NetworkX `DiGraph` — sufficient for real IP-time traversal; no Graph DB |
| LLM | Optional, provider-agnostic OpenAI-compatible, **never authoritative** |

## 5. Failure and degradation

- HCL parse error → `ParseIssue` finding, **WARN**, pipeline continues with non-Terraform files.
- Scanner unavailable → findings absent marked `scanner=unavailable`; policy engine treats
  *required-but-missing* scanner coverage as `REVIEW_REQUIRED` (never silently PASS).
- LLM unavailable / invalid schema / injection attempt → explanation field set to `None`,
  decision still emitted from deterministic path. Dependability is never borrowed from the model.

## 6. Reproducibility

Deterministic components (diff parse, rules, graph, policy) are pure functions of inputs +
registry versions; no wall-clock, no entropy in decision logic. Runtime timestamps are recorded
on the *run row*, never inside the decision content. Resume from any `run_id`.

## 7. Extensibility

Adding a control: `frameworks/controls.yaml` + `policies/rules/*.yaml`; adding a scanner: subclass
`adapters/scanners/base.py:ScannerAdapter` and register in `ScannersService`; new framework:
`frameworks/<name>.yaml` referencing existing control ids only (no per-framework duplicate rules).
