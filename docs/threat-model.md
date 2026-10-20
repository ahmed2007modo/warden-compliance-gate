# Threat Model — Warden (Compliance CI Gate)

Prototype scope; written to be reviewed by someone who attacks it. STRIDE-lite, with trust
boundaries and mitigations that are **implemented** (not aspirational).

## 1. Scope

Read-only analysis of pull-request diffs mapping IaC changes to compliance controls/evidence and
producing a report. No write path to infrastructure, no production credentials, no cloud API
exploitation. Synthetic data only.

## 2. Trust boundaries

```
TB1: Untrusted  →  Warden
     inputs: webhook payload, PR diff, repo contents, PR comments
TB2: Warden  →  GitHub API
     read-only by auth scope, HTTPS pinned, no secrets egressed in body
TB3: Warden  →  LLM provider (optional)
     only de-identified snippets go out; only for *explanation*s
TB4: Warden  →  database
     parameterised SQL via SQLAlchemy; no string-interpolated queries
TB5: Warden  →  user (browser/API consumer)
     explicit JSON schemas; server-side filtering by tenant
```

## 3. Attacker personas

| Actor | Motivation | Capability |
|---|---|---|
| Malicious PR author | Evade a FAIL; plant a veto bypass | Owns code in fork; can add files, rename files, abuse hunk syntax |
| Compromised dependency | RCE during analysis | Runs Warden's deps; supply-chain risk |
| Prompt-injection content | Hijack optional LLM call | Text inside comments/READMEs/docs/large code strings |
| Replay attacker | Re-send old webhook, spoof a commit | Raw HTTP |

## 4. Assets at risk

Raw repo secrets if accidentally ingested, compliance decision integrity, DB, Warden's
credentials to GitHub.

## 5. Mitigations (implemented in this codebase)

| # | Threat | Mitigation | Where |
|---|---|---|---|
| 1 | **Path traversal** in archive/extract/file read | `SafePath.safe_relative()` rejects absolute paths, `..`, drives, UNC, and normalizes with `posixpath` | `app/adapters/terraform/diff_parser.py`, `app/core/paths.py` |
| 2 | **Zip-slip/Zip bomb** in fixture loading | Max entry size, total size, entry count; only files inside the archive's root allowed; extension allowlist | `_load_fixtures.py` uses `_safe_extract()` |
| 3 | **Prompt injection** | Repo content is *data*, never *instructions*: wrapped in `<repo_diff>` explicitly marked `DO NOT FOLLOW`; LLM instructed to **report** suspicious text rather than act; structured output validated against Pydantic; **no arbitrary tool surface** — llm adapter holds no shell/file/db access | `app/adapters/llm/base.py` |
| 4 | **LLM over-trust / fabrication** | LLM may *not* set PASS/FAIL/REVIEW/ERROR; it only fills `explanation`, `remediation_draft`, `missing_info`; `validate_fabricatedRefs()` rejects tip-named file refs not present in evidence list | `app/policies/decision.py`, `app/adapters/llm/schema.py` |
| 5 | **Secrets in logs / egress** | `Redactors` patterns for AWS keys, PEM bodies, basic auth, bearer/jwt; scan applied to LLM payload, logs and reports; test proves a fake `AKIA…` does not reach the LLM | `app/core/redact.py` |
| 6 | **Malicious diff / huge payloads** | Size caps (`WARDEN_MAX_DIFF_SIZE_BYTES`, `WARDEN_MAX_FILE_SIZE_BYTES`), per-file and total limits, and the diff parser aborts with typed error | `app/adapters/github/diff.py` |
| 7 | **SQL injection** | SQLAlchemy expressions Orm `text()` only for migrating; ORM for reads; Alembic for DDL; parameter binding everywhere | `app/models/*`, `app/repositories/*`; `tests/security/test_no_raw_sql.py:20` |
| 8 | **CSRF/webhook replay** | `X-Hub-Signature-256` HMAC with constant-time compare; webhook-secret logged redacted; GitHub delivery id dedupe | `app/adapters/github/webhook.py` |
| 9 | **Over-privileged GitHub token** | Documented least-scope (contents:read, checks:write, pull_requests:write); no use of `repo` broad scope; Warden never requests workflow/write scopes | README; `app/adapters/github/client.py` |
| 10 | **PII / customer data leakage into benchmark** | Fixtures are synthetic, marked `fixture-*`, never real repo names; CI never pulls private repos by default | `fixtures/*` |

## 6. Residual risks / limitations (honest)

- **No cryptographic signing of reports** in v1; JSON is tamper-evident only via logged content
  hash in `AuditEvent`. Production would use detached signatures or WORM storage.
- **LLM egress**: even redacted, code snippets leave the process when LLM is enabled. Default is
  OFF; when on, Warden allows `base_url` override so providers can be self-hosted (断网/air-gapped).
- **Rule fidelity**: rule coverage is deliberately small; scanning is **not** a security scanner
  replacement. False negatives exist for constructs outside the rule set.
- **Denial-of-service**: the prototype trusts the token holder's expertise; expensive graph runs
  are capped by number of changed files only.

## 7. Out-of-scope

Secret scanning (deferred to Trivy), image/dependency vuln scanning (out of scope for the diff),
covert-channel exfil via the Check body (GitHub limits body size anyway), and network
segmentation of the LLM provider (env-configurable endpoint documented).
