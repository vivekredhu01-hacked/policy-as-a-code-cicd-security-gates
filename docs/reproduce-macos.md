# Reproducing on macOS with VS Code

This repository was originally documented around Windows PowerShell. The
policies and Kubernetes manifests are platform-independent, so the evaluation
can be reproduced from macOS by using the included Ubuntu Dev Container.

## Prerequisites

- Docker Desktop
- Visual Studio Code
- VS Code Dev Containers extension

## CI policy validation

1. Open the repository folder in VS Code.
2. Select **Dev Containers: Reopen in Container**.
3. Wait for the container build to finish.
4. Open the integrated terminal and run:

   ```bash
   ./scripts/conftest-test.sh
   ```

The script uses Conftest 0.67.1, which bundles the OPA version used by the
replication package. It evaluates every manifest in `tests/good/` and
`tests/bad/`, checks the multi-violation case, and writes a timestamped log
under `results/logs/`.

## Admission-control validation

The admission-control experiment requires a local Kubernetes cluster. Install
`kind` and `kubectl` on the Mac or in a suitable Ubuntu environment, then
follow the Gatekeeper procedure in
[`docs/evaluation-plan.md`](evaluation-plan.md). Docker Desktop must be
running because `kind` creates the cluster using Docker.

Do not use local macOS timings as the official cross-pipeline performance
results. Use fixed tool versions on the GitHub Actions Ubuntu runner for the
reported experiment.

## Reproducibility record

For each run, record:

- host and container architecture;
- Conftest version;
- Kubernetes and Gatekeeper versions;
- Git commit;
- cluster name and Kubernetes context;
- generated log and evidence files.
