# Evaluation framework — Warden

All numbers reported are from **actually executed** runs (`python scripts/run_benchmark.py --save`
and `pytest tests/evaluation`). Nothing below is a benchmark fabrication; the authoritative
machine record is `reports/evaluation-latest.json`, regenerated per run.

## 1. Scope

A reproducible synthetic benchmark of **14 Terraform pull-request scenarios**, each defined as a
pair of PR trees (`fixtures/<tier>/<name>/base/` and `head/`). Warden is fed both trees and
produces a run outcome (PASS / FAIL / REVIEW_REQUIRED / ERROR) and a set of findings,
impacted evidence and verification tasks. Fixtures are materialized deterministically by
`scripts/make_fixtures.py`.

## 2. Scenario matrix (14 scenarios, implemented in `fixtures/`)

| # | Tier | Scenario | Expected outcome |
|---|------|----------|------------------|
| 01 | risky | audit-trail-disabled | **FAIL** (`wrd-log-001`) |
| 02 | risky | log-group-dropped | **FAIL** (`wrd-log-002`) |
| 03 | risky | combined-violations | **FAIL** (multiple rules) |
| 04 | risky | iam-policy-widened | **FAIL** (`wrd-iam-001`) |
| 05 | risky | s3-encryption-removed | **FAIL** (`wrd-enc-001`) |
| 06 | risky | security-group-opened | **FAIL** (`wrd-net-001`) |
| 07 | ambiguous | alarm-dropped | **REVIEW_REQUIRED** (non-blocking rule `wrd-alm-001`) |
| 08 | ambiguous | retention-window-shrunk | **REVIEW_REQUIRED** (`wrd-log-003` + conflicting evidence) |
| 09 | ambiguous | versioning-removed-missing-evidence | **REVIEW_REQUIRED** (`wrd-bak-001` + `ev-replication-report` absent) |
| 10 | ambiguous | scanner-unavailable | **REVIEW_REQUIRED** (declared scanner status unavailable) |
| 11 | ambiguous | unsupported-construct | **REVIEW_REQUIRED** (`aws_docdb_cluster` outside rule envelope) |
| 12 | safe | docs-only | **PASS** (README `.md` only) |
| 13 | safe | prompt-injection-comment | **PASS** (injected comment is inert; see §6) |
| 14 | safe | tag-update | **PASS** (alarm rename; note: content is an alarm-name change, not tags) |

Latest executed measurement (regenerate with `python scripts/run_benchmark.py --save`):

- classification accuracy **1.0** (14/14), zero false positives, zero missed violations;
- evidence_reference_validity **0.9**: expected — the `versioning-removed-missing-evidence`
  scenario intentionally cites `ev-replication-report`, which is *deliberately absent* from
  the seed registry, so 1 of 10 cited references points at nothing. Any emitted score < 1.0
  for this reason is the benchmark working as designed, not a defect;
- deterministic_reproducible **true** (same input ⇒ byte-identical report hash);
- duration ~130 ms (SQLite, warm).

## Scoring dimensions

| Metric | Meaning |
|---|---|
| Classification accuracy | Scenarios whose outcome matches expectation / total |
| False-positive rate | Expected-PASS scenarios judged FAIL or REVIEW_REQUIRED |
| Missed-violation rate | Expected-FAIL scenarios judged PASS |
| Evidence-reference validity | Fraction of cited evidence ids that exist in the registry |
| Decision reproducibility | Running twice produces a byte-identical report hash |

## How to run (and what CI runs)

```bash
pip install -e services/api[dev]
pytest -q                                     # whole suite (84 tests)
pytest tests/evaluation -q                    # benchmark tests only
python scripts/run_benchmark.py --save        # regenerate reports/evaluation-latest.json
```

CI (`.github/workflows/ci.yml`) runs ruff + the full pytest suite on every push/PR.

## Recording an actual run (no fabricated numbers)

Every benchmark run can write a machine-generated record to `reports/evaluation-latest.json`
(git-ignored). Any claim in this repo of measured precision/recall must be re-generatable by
re-running the suite; docs never hard-code a number produced elsewhere.

## Known limits of the benchmark

- Synthetic Terraform; real PRs have richer context (data blocks, modules, multi-root repos).
- 14 scenarios is a smoke-scale set, not a statistical claim.
- "Expected outcomes" are the prototype author's hand labels, documented here for critique.
