# Common Evidence and Policy Decision Schema

The initial implementation is in
`policies/security-gates/decision.rego`, with unit tests in
`policies/security-gates/decision_test.rego`. Run the policy tests from the
repository root with:

```bash
conftest verify --policy policies/security-gates --strict --no-color
```

The first tool adapter is
`scripts/normalize-gitleaks.py`. It converts a Gitleaks JSON report into the
evidence document consumed by the decision layer. Gitleaks exit code `0`
(clean) and exit code `1` (findings present) are successful scan completions;
other exit codes produce incomplete evidence and fail the required gate closed.

The decision runner is `scripts/run-security-decision.py`. It accepts one or
more normalised evidence documents, evaluates them through the Rego policy
using Conftest, writes a `decision/v1` record, and returns exit code `1` for
`BLOCK` and `0` for `PASS` or `WARN`:

Use `--gate-id` to declare which required gate the evidence represents. This
keeps the runner generic across Gitleaks, Semgrep, and later scanners.

```bash
python3 scripts/run-security-decision.py \
  --evidence artifacts/f01/evidence.json \
  --output artifacts/f01/decision.json \
  --fixture-id F01 \
  --commit-id "$COMMIT_ID" \
  --pipeline proposed \
  --stage source \
  --run-id local-f01
```

## Purpose

Security tools produce different report formats and severity vocabularies. The
framework therefore converts each tool result into a common evidence record
before OPA/Rego evaluates the gate decision.

The schema separates:

1. raw scanner output, retained unchanged as an artifact;
2. normalised finding evidence, consumed by policy;
3. the final decision record, consumed by deployment and metrics collection.

The schema is versioned independently from scanner versions and policy
versions.

## Evidence lifecycle

```text
Raw scanner report
        |
        v
Tool adapter and normaliser
        |
        v
Evidence document
        |
        v
OPA/Rego decision
        |
        v
Decision record + deployment outcome
```

An adapter must not silently discard an unrecognised finding. It must either
normalise the finding with `normalization_status: "partial"` and a reason, or
fail the required gate as `BLOCK` because evidence is incomplete.

## Normalised finding schema

The following fields are required unless marked optional:

| Field | Type | Requirement |
|---|---|---|
| `schema_version` | string | Must be `evidence/v1` |
| `finding_id` | string | Stable identifier from the source tool |
| `fingerprint` | string | Stable hash for deduplication |
| `tool` | string | `gitleaks`, `semgrep`, `dependency-check`, `trivy`, or `zap` |
| `tool_version` | string | Exact scanner version |
| `category` | string | `secret`, `source`, `dependency`, `container`, or `runtime` |
| `severity` | string | Normalised to `low`, `medium`, `high`, or `critical` |
| `confidence` | string | `low`, `medium`, `high`, or `unknown` |
| `message` | string | Actionable description |
| `requirement_ids` | array | NIST SSDF/OWASP ASVS identifiers |
| `asset` | object | Location or package/image/endpoint affected |
| `status` | string | `confirmed`, `suspected`, `suppressed`, or `invalid` |
| `normalization_status` | string | `complete` or `partial` |
| `observed_at` | string | UTC timestamp |

Optional fields include `cve`, `cwe`, `package`, `installed_version`,
`fixed_version`, `image_digest`, `url`, `line_start`, `line_end`, and
`raw_artifact`.

### Example normalised finding

```json
{
  "schema_version": "evidence/v1",
  "finding_id": "semgrep:javascript.lang.security.detect-eval",
  "fingerprint": "sha256:example-fingerprint",
  "tool": "semgrep",
  "tool_version": "1.XX.X",
  "category": "source",
  "severity": "high",
  "confidence": "high",
  "message": "User-controlled input reaches eval().",
  "requirement_ids": ["SSDF-PW.5", "SSDF-PW.7", "ASVS-V5"],
  "asset": {
    "path": "src/example.js",
    "line_start": 42,
    "line_end": 42
  },
  "status": "confirmed",
  "normalization_status": "complete",
  "observed_at": "2026-10-28T00:00:00Z",
  "cwe": "CWE-95",
  "raw_artifact": "artifacts/semgrep.json"
}
```

## Evidence document schema

Each gate emits one evidence document:

```json
{
  "schema_version": "evidence-document/v1",
  "run": {
    "run_id": "local-or-github-run-id",
    "fixture_id": "F01",
    "commit_id": "immutable-commit-sha",
    "pipeline": "baseline",
    "stage": "source",
    "workflow_started_at": "2026-10-28T00:00:00Z"
  },
  "gate": {
    "gate_id": "secret-detection",
    "required": true,
    "completed": true,
    "tool_exit_code": 1,
    "tool_version": "8.X.X"
  },
  "findings": [],
  "normalization": {
    "status": "complete",
    "adapter_version": "0.1.0",
    "raw_artifacts": ["artifacts/gitleaks.json"]
  }
}
```

The `findings` array may be empty only when a required scanner completed
successfully and found no issues. A missing document, failed scanner, invalid
JSON, or incomplete normalisation is not equivalent to an empty finding list.

## Decision input schema

OPA receives a decision request containing all evidence available at the
decision point:

```json
{
  "schema_version": "decision-input/v1",
  "policy_version": "0.1.0",
  "run": {
    "run_id": "local-or-github-run-id",
    "fixture_id": "F01",
    "commit_id": "immutable-commit-sha",
    "pipeline": "proposed",
    "stage": "source"
  },
  "requirements": {
    "asvs_version": "4.0.3",
    "ssdf_profile": "selected-ci-cd-requirements"
  },
  "thresholds": {
    "blocking_severities": ["medium", "high", "critical"],
    "warning_severities": ["low"],
    "required_gates": ["secret-detection"]
  },
  "evidence_documents": []
}
```

The workflow must pass thresholds and required-gate configuration explicitly
so that a decision can be reproduced from its archived input. Rego must not
depend on hidden environment variables or mutable external state.

## Decision output schema

OPA returns a decision document:

```json
{
  "schema_version": "decision/v1",
  "policy_version": "0.1.0",
  "run": {
    "run_id": "local-or-github-run-id",
    "fixture_id": "F01",
    "commit_id": "immutable-commit-sha",
    "pipeline": "proposed",
    "stage": "source"
  },
  "decision": "BLOCK",
  "deployment_allowed": false,
  "reasons": [
    {
      "gate_id": "secret-detection",
      "finding_id": "gitleaks:fixture-secret",
      "severity": "high",
      "requirement_ids": ["SSDF-PW.5", "ASVS-V6"],
      "message": "Confirmed secret exposure requires blocking."
    }
  ],
  "completed_gates": ["secret-detection"],
  "missing_required_gates": [],
  "generated_at": "2026-10-28T00:00:01Z"
}
```

## Decision rules

The initial deterministic rules are:

1. Any confirmed, normalised finding with severity `medium`, `high`, or
   `critical` produces `BLOCK`.
2. A confirmed, normalised `low` finding produces `WARN` if no blocking
   finding exists.
3. No findings from all completed required gates produces `PASS`.
4. A required gate that failed, timed out, emitted invalid output, or did not
   produce an evidence document produces `BLOCK`.
5. A finding with `status: "invalid"` cannot produce `PASS` and causes
   `BLOCK` when it is from a required gate.
6. `BLOCK` takes precedence over `WARN`, and `WARN` takes precedence over
   `PASS`.
7. Suppressed findings require a recorded suppression reason, approver or
   policy reference, and expiry; otherwise they are treated as unsafely
   suppressed and produce `BLOCK`.
8. Tool exit code alone must not determine vulnerability severity. The
   normalised evidence and gate completion status are evaluated separately.

## Missing-evidence handling

The framework fails closed for required security gates. The following
conditions produce `BLOCK`:

- scanner process failure;
- timeout;
- malformed or missing report;
- unsupported severity or category;
- missing requirement mapping;
- incomplete normalisation;
- missing raw artifact reference;
- policy input not matching the declared schema version.

The decision must identify the missing or invalid evidence in
`missing_required_gates` or `reasons`. This makes an infrastructure failure
distinguishable from a genuine vulnerability while preventing an accidental
fail-open deployment.

## Severity normalisation

Adapters must map source-tool values to the common vocabulary:

| Common severity | Examples of source values |
|---|---|
| `critical` | Critical, 9.0–10.0 CVSS, ZAP High with confirmed critical policy mapping |
| `high` | High, 7.0–8.9 CVSS, ZAP High |
| `medium` | Medium, 4.0–6.9 CVSS, ZAP Medium |
| `low` | Low, 0.1–3.9 CVSS, ZAP Low |

Tool-specific mappings must be documented in the adapter and tested with
representative fixtures. Ambiguous values map to `unknown` and cannot satisfy
a required gate.

## Traceability requirements

Every blocking or warning decision must be traceable through:

```text
decision
  -> finding_id and fingerprint
  -> raw_artifact
  -> source tool and version
  -> requirement_ids
  -> policy_version and thresholds
  -> commit_id and fixture_id
```

This chain is required for RQ1 and prevents a result from being reported as a
generic scanner count without explaining the security requirement or gate
action that produced it.

## Unit-test cases for the policy layer

Before scanner integration, the Rego policy must be tested with synthetic
normalised evidence for:

1. no findings → `PASS`;
2. low finding → `WARN`;
3. medium finding → `BLOCK`;
4. high finding → `BLOCK`;
5. critical finding → `BLOCK`;
6. multiple findings → highest applicable decision;
7. failed required gate with no findings → `BLOCK`;
8. malformed or incomplete evidence → `BLOCK`;
9. suppressed finding without valid metadata → `BLOCK`;
10. valid suppression with expiry and reference → no block from that finding;
11. evidence from an unknown tool or category → `BLOCK`;
12. clean control across all required gates → `PASS`.

These tests establish the decision semantics before real scanner output is
introduced.
