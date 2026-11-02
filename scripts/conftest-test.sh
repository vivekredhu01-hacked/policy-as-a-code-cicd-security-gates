#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY_DIR="$ROOT_DIR/policies/kubernetes"
GOOD_DIR="$ROOT_DIR/tests/good"
BAD_DIR="$ROOT_DIR/tests/bad"
RESULTS_DIR="$ROOT_DIR/results/logs"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="$RESULTS_DIR/conftest-test-$TIMESTAMP.log"

mkdir -p "$RESULTS_DIR"
exec > >(tee "$LOG_FILE") 2>&1

if ! command -v conftest >/dev/null 2>&1; then
  echo "ERROR: conftest is not installed or is not on PATH." >&2
  exit 1
fi

total=0
expected=0
unexpected=0

test_manifest() {
  local file="$1"
  local should_pass="$2"
  local label="$3"
  local status=0

  total=$((total + 1))
  printf '\n[%s] %s\n' "$label" "${file#"$ROOT_DIR"/}"

  conftest test "$file" --policy "$POLICY_DIR" --no-color || status=$?

  if [[ "$should_pass" == "true" && "$status" -eq 0 ]] ||
     [[ "$should_pass" == "false" && "$status" -ne 0 ]]; then
    echo ">> RESULT: PASS (as expected)"
    expected=$((expected + 1))
  else
    echo ">> RESULT: UNEXPECTED RESULT"
    unexpected=$((unexpected + 1))
  fi
}

echo "Conftest validation started: $TIMESTAMP"
echo "Conftest version: $(conftest --version)"

while IFS= read -r -d '' file; do
  test_manifest "$file" true GOOD
done < <(find "$GOOD_DIR" -type f -name '*.yaml' -print0 | sort -z)

while IFS= read -r -d '' file; do
  test_manifest "$file" false BAD
done < <(find "$BAD_DIR" -type f -name '*.yaml' -print0 | sort -z)

multi_file="$BAD_DIR/deployment-multi-violation.yaml"
if [[ -f "$multi_file" ]]; then
  total=$((total + 1))
  violation_count="$(
    conftest test "$multi_file" --policy "$POLICY_DIR" --no-color 2>&1 |
      grep -c 'FAIL -' || true
  )"
  echo
  echo "Multi-violation checks: $violation_count"
  if [[ "$violation_count" -ge 5 ]]; then
    echo ">> RESULT: PASS"
    expected=$((expected + 1))
  else
    echo ">> RESULT: UNEXPECTED RESULT"
    unexpected=$((unexpected + 1))
  fi
fi

echo
echo "Total tests run  : $total"
echo "Expected results : $expected"
echo "Unexpected results: $unexpected"
echo "Log saved to     : $LOG_FILE"

if [[ "$unexpected" -ne 0 ]]; then
  exit 1
fi
