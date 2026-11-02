#!/usr/bin/env python3
"""Convert a Gitleaks JSON report into the evidence-document/v1 contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--fixture-id", required=True)
    parser.add_argument("--commit-id", required=True)
    parser.add_argument("--pipeline", choices=("baseline", "proposed"), required=True)
    parser.add_argument("--stage", default="source")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--tool-version", required=True)
    parser.add_argument("--exit-code", required=True, type=int)
    parser.add_argument("--raw-artifact", required=True)
    return parser.parse_args()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def stable_fingerprint(finding: dict[str, Any]) -> str:
    source = "|".join(
        str(finding.get(key, ""))
        for key in ("RuleID", "File", "StartLine", "EndLine", "Commit")
    )
    return f"sha256:{hashlib.sha256(source.encode()).hexdigest()}"


def normalise_finding(
    finding: dict[str, Any], tool_version: str, raw_artifact: str
) -> dict[str, Any]:
    rule_id = finding.get("RuleID")
    file_path = finding.get("File")
    if not rule_id or not file_path:
        raise ValueError("Gitleaks finding must contain RuleID and File")

    return {
        "schema_version": "evidence/v1",
        "finding_id": f"gitleaks:{rule_id}",
        "fingerprint": finding.get("Fingerprint") or stable_fingerprint(finding),
        "tool": "gitleaks",
        "tool_version": tool_version,
        "category": "secret",
        "severity": "high",
        "confidence": "high",
        "message": finding.get("Description") or f"Secret matched rule {rule_id}.",
        "requirement_ids": ["SSDF-PW.5", "ASVS-V6"],
        "asset": {
            "path": file_path,
            "line_start": finding.get("StartLine"),
            "line_end": finding.get("EndLine"),
        },
        "status": "confirmed",
        "normalization_status": "complete",
        "observed_at": utc_now(),
        "raw_artifact": raw_artifact,
    }


def build_document(args: argparse.Namespace, report: Any) -> dict[str, Any]:
    if not isinstance(report, list):
        raise ValueError("Gitleaks JSON report must be an array")

    findings = [
        normalise_finding(item, args.tool_version, args.raw_artifact)
        for item in report
        if isinstance(item, dict)
    ]
    if len(findings) != len(report):
        raise ValueError("Every Gitleaks report item must be an object")

    complete = args.exit_code in (0, 1)
    return {
        "schema_version": "evidence-document/v1",
        "run": {
            "run_id": args.run_id,
            "fixture_id": args.fixture_id,
            "commit_id": args.commit_id,
            "pipeline": args.pipeline,
            "stage": args.stage,
        },
        "gate": {
            "gate_id": "secret-detection",
            "required": True,
            "completed": complete,
            "tool_exit_code": args.exit_code,
            "tool_version": args.tool_version,
        },
        "findings": findings,
        "normalization": {
            "status": "complete" if complete else "partial",
            "adapter_version": "0.1.0",
            "raw_artifacts": [args.raw_artifact],
        },
    }


def main() -> int:
    args = parse_args()
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        document = build_document(args, report)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(document, indent=2) + "\n", encoding="utf-8"
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: unable to normalise Gitleaks report: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
