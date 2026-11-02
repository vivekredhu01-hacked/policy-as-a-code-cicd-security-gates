# Controlled Vulnerability Fixtures and Ground Truth

## Purpose

This catalogue defines the controlled commits used by the comparative
experiment. Each fixture has one primary vulnerability class, a known
ground-truth label, an expected first-detection stage, and an expected
deployment outcome. The same commit must be executed by both the baseline and
the proposed pipeline.

The fixture catalogue is defined before scanner implementation to prevent the
tools from defining the research outcome after the fact.

Secret scanning must distinguish current fixture contents from repository
history. F01 and F06 are directory-based controls, so the experiment invokes
Gitleaks with `--no-git` to scan checked-out files only. A history scan would
rediscover the F01 secret while evaluating F06 and invalidate the clean-control
comparison.

## Pipeline stages

The proposed pipeline uses these logical stages:

1. `source` — checkout, secret detection, and source-code analysis
2. `dependencies` — dependency resolution and software composition analysis
3. `build` — application build and container image creation
4. `container` — image and container configuration scanning
5. `runtime` — application startup and dynamic web testing
6. `deploy` — deployment decision and controlled target

The baseline performs the same build, test, and deployment flow but runs its
security checks only at the late security stage immediately before deployment.
The exact workflow timestamps and commands must be recorded for both paths.

## Ground-truth schema

Every fixture must have a machine-readable record with these fields:

| Field | Description |
|---|---|
| `fixture_id` | Stable identifier, for example `F01` |
| `commit_id` | Immutable Git commit used in the experiment |
| `vulnerability_class` | Secret, source, dependency, container, or runtime |
| `description` | Human-readable vulnerability description |
| `ground_truth` | Whether the vulnerability is intentionally present |
| `affected_asset` | File, package, image, endpoint, or configuration |
| `expected_tool` | Tool expected to provide supporting evidence |
| `requirement_ids` | NIST SSDF and ASVS mapping identifiers |
| `minimum_severity` | Severity at which the gate must block |
| `expected_first_stage` | Earliest proposed-pipeline stage expected to detect it |
| `baseline_expected_detection` | Expected baseline detection stage |
| `expected_decision` | `PASS`, `WARN`, or `BLOCK` |
| `deployment_expected` | Whether deployment should be allowed |
| `false_positive_control` | Clean control paired with the fixture |

## Initial fixture catalogue

The first test payloads are implemented under
`fixtures/controlled-app/`. Commit IDs remain unassigned until the fixture is
committed and selected for a comparative run. Placeholder commit IDs must not
be used as experimental evidence.

| ID | Vulnerability class | Controlled change | Expected tool | Requirement alignment | First proposed stage | Baseline stage | Decision |
|---|---|---|---|---|---|---|---|
| F01 | Exposed secret | Add a clearly synthetic but detector-compatible API token to a tracked source/configuration file | Gitleaks | SSDF PW.5; ASVS V6 | `source` | `late-security` | `BLOCK` |
| F02 | Source vulnerability | Add a deliberately unsafe source-code pattern with a stable Semgrep rule match | Semgrep | SSDF PW.5/PW.7; ASVS V5 | `source` | `late-security` | `BLOCK` |
| F03 | Vulnerable dependency | Pin an intentionally vulnerable direct dependency and lockfile version | OWASP Dependency-Check | SSDF PS.3; ASVS V1/V14 | `dependencies` | `late-security` | `BLOCK` |
| F04 | Container vulnerability | Build from a deliberately vulnerable, version-pinned base image or introduce an insecure image configuration | Trivy | SSDF PW.6; ASVS V14 | `container` | `late-security` | `BLOCK` |
| F05 | Runtime web vulnerability | Add a controlled vulnerable endpoint or test fixture detectable by ZAP | OWASP ZAP | SSDF RV.1; ASVS V4/V5 | `runtime` | `late-security` | `BLOCK` |
| F06 | Clean control | Secure counterpart with no intentional finding and equivalent build/deploy path | All applicable tools | All selected requirements | No finding | No finding | `PASS` |
| F07 | Low-severity control | Add a documented low-severity condition that is detectable but below the blocking threshold | Relevant scanner | Selected requirement | Relevant stage | `late-security` | `WARN` |
| F08 | Scanner failure control | Make required evidence unavailable or malformed without changing application code | Policy decision layer | SSDF PO.3/PW.1; ASVS V14 | Relevant stage | `late-security` | `BLOCK` |

F07 is included only if a stable, reproducible low-severity fixture can be
created without introducing an uncontrolled vulnerability. If not, the
`WARN` branch will be tested with a synthetic normalised finding in policy
unit tests and excluded from deployment-prevention metrics.

F08 tests fail-closed evidence handling rather than vulnerability detection.
It must be reported separately from the vulnerability detection-rate metric.

## Required controls

Each vulnerability fixture must be paired with controls:

- **Clean control:** same application and workflow with the vulnerable change
  removed.
- **Tool-specific negative control:** a similar safe pattern that should not
  trigger the selected scanner.
- **Reproducibility control:** the commit must build and run without relying on
  network state that can change during the experiment, except for explicitly
  pinned dependency or vulnerability databases.

Clean controls are necessary for false-positive measurement. They must not be
counted as vulnerabilities avoided or as vulnerabilities detected.

## Ground-truth acceptance criteria

A fixture is accepted into the experiment only when:

1. the vulnerability is intentionally introduced and documented;
2. the affected asset and expected tool are unambiguous;
3. the relevant tool can produce a stable finding under pinned versions;
4. the expected stage is earlier than or equal to the baseline stage;
5. the clean control does not trigger a blocking finding;
6. the commit can be rebuilt from a clean checkout;
7. the expected outcome is recorded before comparative execution.

If a tool fails to detect a fixture, the result must be recorded as a false
negative or tool limitation. The fixture must not be silently replaced after
the experiment begins.

## Experimental result record

Each pipeline execution should append one record with this shape:

```json
{
  "fixture_id": "F01",
  "commit_id": "REPLACE_WITH_COMMIT",
  "pipeline": "baseline",
  "run_id": "REPLACE_WITH_RUN_ID",
  "first_detection_stage": "late-security",
  "first_detection_timestamp": "REPLACE_WITH_TIMESTAMP",
  "decision": "BLOCK",
  "deployment_attempted": true,
  "deployment_succeeded": false,
  "findings": [],
  "workflow_duration_ms": 0,
  "policy_version": "0.1.0"
}
```

The `findings` array must contain normalised evidence records, not only raw
tool output. Raw reports should be retained as artifacts and linked by
filename or artifact identifier.

## Metric derivation

For a set of ground-truth vulnerability fixtures:

- **Detection rate** = fixtures with a correct supporting finding / vulnerable
  fixtures executed.
- **First-detection stage** = earliest stage with a correct supporting finding.
- **Time-to-security-feedback** = first actionable finding timestamp minus the
  workflow start timestamp.
- **Vulnerable deployments prevented** = vulnerable deployment attempts that
  terminate with `BLOCK` before successful deployment.
- **False-positive rate** = clean-control executions with an incorrect
  blocking finding / clean-control executions.
- **Added pipeline time** = proposed workflow duration minus baseline workflow
  duration for matched fixture and run conditions.

Detection and prevention metrics must be reported separately. A tool finding
does not count as a prevented deployment unless the policy decision actually
blocks the deployment.

## Execution order

1. Create a minimal application and clean control.
2. Add one fixture at a time in separate commits.
3. Pin tool versions and scanner databases where supported.
4. Verify each fixture and its clean control manually once.
5. Record the ground-truth manifest before pipeline comparison.
6. Run matched baseline and proposed executions.
7. Preserve workflow logs, raw scanner reports, normalised evidence, policy
   decisions, deployment outcomes, and timing data.
