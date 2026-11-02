# Controlled experiment fixtures

The fixture catalogue and acceptance criteria are documented in
[`../docs/controlled-fixtures.md`](../docs/controlled-fixtures.md).

The first implemented fixture is F01, an exposed synthetic secret, paired with
the clean F06 control. Ground truth is recorded in
[`ground-truth.yaml`](ground-truth.yaml) before scanner integration.

F01 is intentionally a test-only value. It is not a real credential and must
not be replaced with one.

## F01 scanner path

After installing a pinned Gitleaks release, run it against one fixture
checkout and retain its raw report:

```bash
mkdir -p artifacts/f01
gitleaks detect \
  --source fixtures/controlled-app/F01-secret \
  --no-git \
  --redact \
  --report-format json \
  --report-path artifacts/f01/gitleaks.json
gitleaks_exit=$?
```

Gitleaks returns `1` when findings are present. Preserve that exit code and
normalise the report:

```bash
python3 scripts/normalize-gitleaks.py \
  --report artifacts/f01/gitleaks.json \
  --output artifacts/f01/evidence.json \
  --fixture-id F01 \
  --commit-id REPLACE_WITH_COMMIT \
  --pipeline proposed \
  --stage source \
  --run-id local-f01 \
  --tool-version REPLACE_WITH_GITLEAKS_VERSION \
  --exit-code "$gitleaks_exit" \
  --raw-artifact artifacts/f01/gitleaks.json
```

Run the same commands against `fixtures/controlled-app/clean`, using fixture
ID `F06`, and write the report to `artifacts/f06/gitleaks.json`. Include
`--no-git --redact` there as well. The expected policy outcomes are F01
`BLOCK` and F06 `PASS`.

Evaluate the normalised evidence through the central decision layer:

```bash
COMMIT_ID="$(git rev-parse HEAD)"

python3 scripts/run-security-decision.py \
  --evidence artifacts/f01/evidence.json \
  --output artifacts/f01/decision.json \
  --fixture-id F01 \
  --commit-id "$COMMIT_ID" \
  --pipeline proposed \
  --stage source \
  --gate-id secret-detection \
  --run-id local-f01
```

The F01 command returns exit code `1` and writes `decision: "BLOCK"`.
Repeat with the F06 evidence and paths to verify a `PASS` decision and exit
code `0`.

## F02 source-analysis path

F02 uses a controlled JavaScript `eval(...)` pattern and a Semgrep rule in
`fixtures/controlled-app/F02-source/semgrep.yml`. The clean counterpart is
`fixtures/controlled-app/F02-clean`.

After installing a pinned Semgrep release, scan F02:

```bash
mkdir -p artifacts/f02
set +e
semgrep scan \
  --config fixtures/controlled-app/F02-source/semgrep.yml \
  --error \
  --json \
  --output artifacts/f02/semgrep.json \
  fixtures/controlled-app/F02-source
semgrep_exit=$?
set -e

python3 scripts/normalize-semgrep.py \
  --report artifacts/f02/semgrep.json \
  --output artifacts/f02/evidence.json \
  --fixture-id F02 \
  --commit-id "$COMMIT_ID" \
  --pipeline proposed \
  --stage source \
  --run-id local-f02 \
  --tool-version "$(semgrep --version)" \
  --exit-code "$semgrep_exit" \
  --raw-artifact artifacts/f02/semgrep.json
```

Run the same command, including `--error`, against
`fixtures/controlled-app/F02-clean`, using
fixture ID `F02-clean` and an `artifacts/f02-clean/` output directory. The
expected decisions are F02 `BLOCK` and F02-clean `PASS`.

## F03 dependency-analysis path

F03 pins vulnerable lodash `4.17.19` in
`fixtures/controlled-app/F03-dependency/package-lock.json`. The clean
counterpart pins patched lodash `4.18.0`. Run OWASP Dependency-Check against each
fixture and retain its JSON report:

Dependency-Check 13.0.0 may fail while updating the NVD database when an empty
API key is passed. Upgrade first with `brew upgrade dependency-check`. If the
installed version still requires a key, obtain one from the NVD developer
portal and export it only in the current terminal session. Never commit or
paste the key into repository files.

```bash
brew upgrade dependency-check
dependency-check --version
mkdir -p artifacts/f03
set +e
dependency-check \
  --project policy-reuse-evaluation-f03 \
  --scan fixtures/controlled-app/F03-dependency \
  --format JSON \
  --data artifacts/dependency-check-data \
  --out artifacts/f03
dependency_check_exit=$?
set -e
```

Continue only if `artifacts/f03/dependency-check-report.json` exists and the
scan completed. An NVD update failure is incomplete evidence and must not be
normalised as a vulnerability result.

If the command reports that an NVD API key is required, set a real key locally
and rerun the same command with this additional option:

```bash
export NVD_API_KEY='your-key'
```

```text
--nvdApiKey "$NVD_API_KEY"
```

Normalise the report and evaluate it with the dependency gate:

```bash
python3 scripts/normalize-dependency-check.py \
  --report artifacts/f03/dependency-check-report.json \
  --output artifacts/f03/evidence.json \
  --fixture-id F03 \
  --commit-id "$COMMIT_ID" \
  --pipeline proposed \
  --stage dependencies \
  --run-id local-f03 \
  --tool-version "REPLACE_WITH_DEPENDENCY_CHECK_VERSION" \
  --exit-code "$dependency_check_exit" \
  --raw-artifact artifacts/f03/dependency-check-report.json

set +e
python3 scripts/run-security-decision.py \
  --evidence artifacts/f03/evidence.json \
  --output artifacts/f03/decision.json \
  --fixture-id F03 \
  --commit-id "$COMMIT_ID" \
  --pipeline proposed \
  --stage dependencies \
  --gate-id dependency-analysis \
  --run-id local-f03
set -e
```

Repeat with `fixtures/controlled-app/F03-clean`, fixture ID `F03-clean`, and
an `artifacts/f03-clean/` output directory. The expected decisions are F03
`BLOCK` and F03-clean `PASS`.

## F04 container-analysis path

F04 scans an intentionally outdated Python base image with Trivy. Build the
images locally before scanning them:

```bash
docker build -t policy-gate-f04:controlled fixtures/controlled-app/F04-container
docker build -t policy-gate-f04:clean fixtures/controlled-app/F04-clean
```

Run Trivy with `--exit-code 1` so findings are represented by exit code `1`
while a completed clean scan returns `0`:

```bash
mkdir -p artifacts/f04
set +e
trivy image \
  --severity MEDIUM,HIGH,CRITICAL \
  --exit-code 1 \
  --format json \
  --output artifacts/f04/trivy.json \
  policy-gate-f04:controlled
trivy_exit=$?
set -e
```

Normalize the report and evaluate the container gate:

```bash
python3 scripts/normalize-trivy.py \
  --report artifacts/f04/trivy.json \
  --output artifacts/f04/evidence.json \
  --fixture-id F04 \
  --commit-id "$COMMIT_ID" \
  --pipeline proposed \
  --stage container \
  --run-id local-f04 \
  --tool-version "$(trivy --version | head -n 1)" \
  --exit-code "$trivy_exit" \
  --raw-artifact artifacts/f04/trivy.json

set +e
python3 scripts/run-security-decision.py \
  --evidence artifacts/f04/evidence.json \
  --output artifacts/f04/decision.json \
  --fixture-id F04 \
  --commit-id "$COMMIT_ID" \
  --pipeline proposed \
  --stage container \
  --gate-id container-analysis \
  --run-id local-f04
set -e
```

Repeat the scan and normalization with image
`policy-gate-f04:clean`, fixture ID `F04-clean`, and output directory
`artifacts/f04-clean/`. The clean control is scratch-based so it contains no
OS package database for Trivy to report. The expected decisions are F04
`BLOCK` and F04-clean `PASS`.

## F05 runtime-analysis path

F05 runs OWASP ZAP against a local test server. The vulnerable server
reflects the `q` query parameter without escaping; the clean control escapes
it. Start one server at a time:

```bash
python3 fixtures/controlled-app/F05-runtime/vulnerable/server.py
```

In a second terminal, run ZAP's baseline scan and retain the JSON report:

```bash
mkdir -p artifacts/f05
set +e
docker run --network host --rm \
  -v "$PWD/artifacts/f05:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t http://host.docker.internal:8000 \
  -J zap.json \
  -r zap.html
zap_exit=$?
set -e
```

Normalize and evaluate the runtime evidence:

```bash
python3 scripts/normalize-zap.py \
  --report artifacts/f05/zap.json \
  --output artifacts/f05/evidence.json \
  --fixture-id F05 \
  --commit-id "$COMMIT_ID" \
  --pipeline proposed \
  --stage runtime \
  --run-id local-f05 \
  --tool-version "REPLACE_WITH_ZAP_VERSION" \
  --exit-code "$zap_exit" \
  --raw-artifact artifacts/f05/zap.json

set +e
python3 scripts/run-security-decision.py \
  --evidence artifacts/f05/evidence.json \
  --output artifacts/f05/decision.json \
  --fixture-id F05 \
  --commit-id "$COMMIT_ID" \
  --pipeline proposed \
  --stage runtime \
  --gate-id runtime-analysis \
  --run-id local-f05
set -e
```

Stop the vulnerable server, start
`fixtures/controlled-app/F05-runtime/clean/server.py`, and repeat with
fixture ID `F05-clean` and `artifacts/f05-clean/`. The expected decisions are
F05 `BLOCK` and F05-clean `PASS`.

## F07 low-severity warning path

F07 uses a controlled Semgrep diagnostic-log rule whose normalized severity is
`low`. Low findings should produce `WARN` while deployment remains allowed.
Scan the fixture:

```bash
COMMIT_ID="$(git rev-parse HEAD)"
mkdir -p artifacts/f07
set +e
semgrep scan \
  --config fixtures/controlled-app/F07-low/semgrep.yml \
  --error \
  --json \
  --output artifacts/f07/semgrep.json \
  fixtures/controlled-app/F07-low
f07_semgrep_exit=$?
set -e

python3 scripts/normalize-semgrep.py \
  --report artifacts/f07/semgrep.json \
  --output artifacts/f07/evidence.json \
  --fixture-id F07 \
  --commit-id "$COMMIT_ID" \
  --pipeline proposed \
  --stage source \
  --run-id local-f07 \
  --tool-version "$(semgrep --version)" \
  --exit-code "$f07_semgrep_exit" \
  --raw-artifact artifacts/f07/semgrep.json

python3 scripts/run-security-decision.py \
  --evidence artifacts/f07/evidence.json \
  --output artifacts/f07/decision.json \
  --fixture-id F07 \
  --commit-id "$COMMIT_ID" \
  --pipeline proposed \
  --stage source \
  --gate-id source-analysis \
  --run-id local-f07
```

Repeat against `fixtures/controlled-app/F07-clean` with fixture ID
`F07-clean` and an `artifacts/f07-clean/` directory. Expected outcomes:
F07 `WARN` with deployment allowed, and F07-clean `PASS`.

## F08 fail-closed evidence path

F08 represents a required scanner that failed before producing complete
evidence. The fixture records the failure using a valid evidence document with
`completed: false`; an absent finding list must never be treated as a clean
scan.

Use the real commit ID and evaluate the fixture:

```bash
COMMIT_ID="$(git rev-parse HEAD)"
mkdir -p artifacts/f08
COMMIT_ID="$COMMIT_ID" python3 - <<'PY'
import json
from pathlib import Path

source = Path("fixtures/controlled-app/F08-failure/evidence.json")
target = Path("artifacts/f08/evidence.json")
document = json.loads(source.read_text())
document["run"]["commit_id"] = __import__("os").environ["COMMIT_ID"]
target.write_text(json.dumps(document, indent=2) + "\n")
PY
```

The decision must block:

```bash
set +e
python3 scripts/run-security-decision.py \
  --evidence artifacts/f08/evidence.json \
  --output artifacts/f08/decision.json \
  --fixture-id F08 \
  --commit-id "$COMMIT_ID" \
  --pipeline proposed \
  --stage source \
  --gate-id source-analysis \
  --run-id fixture-f08
f08_exit=$?
set -e

echo "F08 decision exit code: $f08_exit"
jq '{fixture: .run.fixture_id, decision, deployment_allowed, reasons}' \
  artifacts/f08/decision.json
```

Expected result: `BLOCK`, `deployment_allowed: false`, and a reason that the
required gate did not produce complete evidence.
