#!/usr/bin/env python3
"""Evaluate evidence documents through the central OPA/Rego decision policy."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
POLICY_DIR = ROOT / "policies" / "security-gates"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", action="append", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--fixture-id", required=True)
    parser.add_argument("--commit-id", required=True)
    parser.add_argument("--pipeline", choices=("baseline", "proposed"), required=True)
    parser.add_argument("--stage", required=True)
    parser.add_argument("--gate-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--policy-version", default="0.1.0")
    return parser.parse_args()


def load_evidence(paths: list[Path]) -> list[dict[str, Any]]:
    documents = []
    for path in paths:
        document = json.loads(path.read_text(encoding="utf-8"))
        documents.append(document)
    return documents


def build_input(args: argparse.Namespace, documents: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "decision-input/v1",
        "policy_version": args.policy_version,
        "run": {
            "run_id": args.run_id,
            "fixture_id": args.fixture_id,
            "commit_id": args.commit_id,
            "pipeline": args.pipeline,
            "stage": args.stage,
        },
        "requirements": {
            "asvs_version": "4.0.3",
            "ssdf_profile": "selected-ci-cd-requirements",
        },
        "thresholds": {
            "blocking_severities": ["medium", "high", "critical"],
            "warning_severities": ["low"],
            "required_gates": [args.gate_id],
        },
        "evidence_documents": documents,
    }


def extract_decision(result: list[dict[str, Any]]) -> dict[str, Any]:
    messages = []
    evaluated = False
    for item in result:
        if not isinstance(item, dict):
            continue
        if item.get("successes", 0):
            evaluated = True
        for key in ("failures", "warnings"):
            for entry in item.get(key, []):
                message = entry.get("msg")
                if isinstance(message, str):
                    try:
                        messages.append(json.loads(message))
                    except json.JSONDecodeError:
                        raise RuntimeError("Conftest returned an invalid decision record")
    if messages:
        return messages[0]
    if not evaluated:
        raise RuntimeError("Conftest returned no successful policy evaluation")
    return {
        "schema_version": "decision/v1",
        "decision": "PASS",
        "deployment_allowed": True,
        "reasons": [],
    }


def main() -> int:
    args = parse_args()
    try:
        documents = load_evidence(args.evidence)
        decision_input = build_input(args, documents)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "decision-input.json"
            input_path.write_text(json.dumps(decision_input), encoding="utf-8")
            process = subprocess.run(
                [
                    "conftest",
                    "test",
                    "--policy",
                    str(POLICY_DIR),
                    "--namespace",
                    "main",
                    "--parser",
                    "json",
                    "--output",
                    "json",
                    "--no-color",
                    "--no-fail",
                    str(input_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            if process.returncode not in (0, 1):
                raise RuntimeError(process.stderr.strip() or process.stdout.strip())
            result = json.loads(process.stdout)
        decision = extract_decision(result)
        decision["run"] = decision.get("run", decision_input["run"])
        decision["policy_version"] = decision.get(
            "policy_version", args.policy_version
        )
        args.output.write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
        return 1 if decision.get("decision") == "BLOCK" else 0
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as error:
        print(f"ERROR: security decision failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
