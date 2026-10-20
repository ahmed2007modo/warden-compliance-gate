# Product Research — Compliance CI Gate ("Warden")

Independent prototype exploring a **compliance intelligence layer for CI/CD** inspired by the
product domain of agentic GRC (specifically the public positioning of GetTeddy, whose pages were
used as **domain references only** — no branding, text or visual identity copied).

> **Sourcing note.** Only publicly accessible pages were used (getteddy.ai `/how-it-works`,
> `/security`, `/careers`, `/careers-working-student-software-engineering-ai` — all four loaded
> successfully on 2026-10-19). Public website content does not establish GetTeddy's complete
> internal capabilities; nothing below claims a GetTeddy feature is missing. This project is an
> **independently developed prototype exploring a potential product opportunity**, not a clone.

---

## 1. Domain takeaway from the reference pages

Concepts lifted from the reference material that shape Warden's product framing:

| Reference-page concept | How Warden translates it |
|---|---|
| "Map once, comply everywhere" — one company model, obligations mapped onto **one shared control set** | A single **control registry** many frameworks (SOC 2 / ISO 27001 / NIS2 / CRA) point at, so one IaC finding explains impact across every framework it maps to |
| Continuous **evidence** collection; "evidence counts for every framework it supports" | An **evidence registry with provenance** (source location, hash, freshness, verification status) that can be *invalidated by code change*, not only by time |
| **Agents draft, people decide** — human approval on every decision | Deterministic policy engine decides; LLM only explains/summarises and can never override a PASS/FAIL/REVIEW_REQUIRED/ERROR verdict |
| Read-only by default; read-only service accounts | Warden only reads git diffs and repo state; writes nothing to production |
| Complete activity log ready "to show your auditor" | **AuditEvent** per run; reproducible-by-id runs that can be re-executed byte-for-byte |
| Evidence Agent / Gap Audit Agent split of agent duties | Optional AI helper performs only **explanation, summarisation, remediation drafting** inside a schema — never evidence creation or decisions |
| "Answer from your live program" | Findings reference actual file/line, not generic advice |
| Questionnaire/audit → also a **Trusted Data** posture | Prompt-injection defence: repo contents are untrusted data |

---

## 2. Product vision

Traditional CI states whether code *builds* and *passes tests*. Warden adds a fourth question:

> **"Which compliance obligations, evidence and controls could this change affect — and what
> verification is needed before deployment?"**

Core scenario: a PR modifies Terraform — disabling audit logging, widening IAM, weakening
encryption. Warden parses the diff, maps changed resources to controls, walks a dependency graph
to find affected evidence, plans targeted verification, and emits an evidence-backed report as a
GitHub Check / PR comment, non-blocking (report) or blocking (enforce).

It explicitly does **not** claim: a green check == regulatory compliance. Findings are labelled
`confirmed`, `potential_risk`, `unknown_evidence`, or `pass`.

---

## 3. Competitive analysis (researched, not assumed)

| Tool | Core strength | Where the change-impact gap remains | Warden posture |
|---|---|---|---|
| **Checkov** (Prisma Cloud) | Broad, mature IaC misconfig checks (Terraform/CFN/K8s) w/ framework tags | Static single-snapshot scanner: latest file states; no cross-change evidence impact, no registry of *which* evidence a change invalidates, no graph traceability | **Optional scanner adapter** — normalised as *native findings*; Warden adds evidence/verification layer |
| **Trivy IaC** | Fast multi-format IaC/secret scan | Same snapshot-scanning scope; no CI:CD *compliance* context | Optional external adapter (binary probe) |
| **OPA / Conftest** | General-purpose Rego policy over any structured input | You own the parsing, input shaping, control mapping and evidence chaining | Optional external adapter; blocked-rule semantics mirrored inside Warden when OPA absent |
| **Semgrep** | Fast rule SAST for application code | Not design/infra compliance nor evidence lineage | Not targeted for v1 |
| **GitHub native** (code scanning, Dependabot, Checks API) | Tree-wide scanning surfaces in PRs | No compliance-model mapping; any *revalidation* or control linkage is bespoke | Warden consumes the **Checks API** as its only outbound surface |
| **GRC platforms** (Vanta, Drata, GetTeddy) | Continuous, post-change monitoring of live systems → control mapping, evidence, human approval | Comparatively weaker at *PR-time, diff-level* change-impact analysis on the IaC artifact itself; those systems generally key off **live cloud state** (AWS APIs, MDM, HRIS), not the diff | **Adjacent** — complements rather than competes head-on |

### The integration gap (hypothesis)

Mature scanners answer **"what's misconfigured now"**. GRC platforms answer **"what's compliant over time"**.
Few, if any of these tools, answer *at the pull-request level*:

```
diff → resource → finding → control → evidence affected → verification needed
```

with **deterministic reproducibility** and **human approval** — the cross-layer integration this
prototype hypothesises is a real product opportunity.

---

## 4. Innovation hypothesis (falsifiable)

> A pull-request-time system can connect *infrastructure changes → controls → evidence →
> targeted verification* with high precision and reproducibility, and measurably reduce the
> set of evidence items a human must re-review after any given change.

Falsifier: benchmark shows evidence-impact precision/recall materially below that of naive
"re-review everything" (precision 1.0, recall 1.0) at the same or better human cost. Measured in
`evaluation.md`.

---

## 5. Non-goals / honesty commitments

- No claim that PASS = compliant. A PASS means: *every check Warden implements, ran and passed.*
- No crawler hallucination: all docs are written from actually-read pages; full GetTeddy
  capabilities are **not knowable** from public pages and are never assumed.
- No custom HCL parser: `python-hcl2` is used.
- No real customer secrets; fixtures are synthetic.
- No Kubernetes/Kafka/Redis: monolith + NetworkX graph, honestly kept simple.

---

## 6. Method of record

The full benchmark palette (12 scenarios), scoring and reproducibility protocol is documented in
`docs/evaluation.md` and implemented in `tests/evaluation/`.
