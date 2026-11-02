# Comparative workflow execution

The repository provides three GitHub Actions workflows:

- `security-gates-tests.yml` validates the Python adapters and Rego policy.
- `security-gate-proposed.yml` evaluates normalized evidence with
  `pipeline: proposed`.
- `security-gate-baseline.yml` evaluates the same evidence with
  `pipeline: baseline`.
- `source-security-gates.yml` executes Gitleaks or Semgrep for F01/F02 and
  their clean controls, then normalizes and evaluates the result.

The baseline and proposed workflows deliberately accept an evidence path
rather than silently running different scanner configurations. This makes the
comparison auditable: the same fixture commit and normalized evidence can be
passed to both workflows, while the pipeline label and stage represent the
experimental condition.

## Running a workflow

1. Push the fixture commit and its normalized evidence to the repository, or
   make the evidence available in the checked-out commit.
2. Open **Actions** and select either the baseline or proposed workflow.
3. Select **Run workflow**.
4. Provide the fixture ID, evidence path, stage, and gate ID.
5. Download the uploaded decision artifact after completion.

Examples:

| Fixture | Evidence path | Stage | Gate |
|---|---|---|---|
| F01 | `artifacts/f01/evidence.json` | `source` | `secret-detection` |
| F02 | `artifacts/f02/evidence.json` | `source` | `source-analysis` |
| F03 | `artifacts/f03/evidence.json` | `dependencies` | `dependency-analysis` |
| F04 | `artifacts/f04/evidence.json` | `container` | `container-analysis` |
| F05 | `artifacts/f05/evidence.json` | `runtime` | `runtime-analysis` |

The workflows fail when the decision is `BLOCK`, remain successful for
`PASS`/`WARN`, and always upload the normalized evidence and decision output.
The source workflow also uploads the scanner's raw report. Dependency-Check,
Trivy, and ZAP remain separate until their tool-specific cache, image, service,
and credential requirements are configured for GitHub-hosted runners.

For a valid comparative run, use the same commit and evidence path for both
workflow conditions, then record:

- first detection stage;
- decision and deployment outcome;
- workflow duration;
- uploaded evidence and raw-artifact references.
