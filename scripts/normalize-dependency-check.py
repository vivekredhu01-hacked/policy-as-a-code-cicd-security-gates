#!/usr/bin/env python3
"""Convert an OWASP Dependency-Check JSON report to evidence-document/v1."""

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
    parser.add_argument("--stage", default="dependencies")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--tool-version", required=True)
    parser.add_argument("--exit-code", required=True, type=int)
    parser.add_argument("--raw-artifact", required=True)
    return parser.parse_args()


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalise_severity(vulnerability: dict[str, Any]) -> str:
    severity = str(vulnerability.get("severity", "")).lower()
    if severity in {"low", "medium", "high", "critical"}:
        return severity
    score = vulnerability.get("cvssv3", {}).get("baseScore")
    if isinstance(score, (int, float)):
        if score >= 9:
            return "critical"
        if score >= 7:
            return "high"
        if score >= 4:
            return "medium"
        return "low"
    return "unknown"


def fingerprint(dependency: dict[str, Any], vulnerability: dict[str, Any]) -> str:
    key = "|".join(
        str(value)
        for value in (
            dependency.get("filePath"),
            dependency.get("fileName"),
            dependency.get("version"),
            vulnerability.get("name"),
        )
    )
    return f"sha256:{hashlib.sha256(key.encode()).hexdigest()}"


def findings(report: dict[str, Any], args: argparse.Namespace) -> list[dict[str, Any]]:
    output = []
    for dependency in report.get("dependencies", []):
        for vulnerability in dependency.get("vulnerabilities", []):
            name = vulnerability.get("name")
            if not name:
                raise ValueError("Dependency-Check vulnerability must contain name")
            output.append(
                {
                    "schema_version": "evidence/v1",
                    "finding_id": f"dependency-check:{name}",
                    "fingerprint": fingerprint(dependency, vulnerability),
                    "tool": "dependency-check",
                    "tool_version": args.tool_version,
                    "category": "dependency",
                    "severity": normalise_severity(vulnerability),
                    "confidence": "high",
                    "message": vulnerability.get("description")
                    or f"Vulnerability {name} affects {dependency.get('fileName', 'dependency')}.",
                    "requirement_ids": ["SSDF-PS.3", "ASVS-V1", "ASVS-V14"],
                    "asset": {
                        "path": dependency.get("filePath") or dependency.get("fileName"),
                        "package": dependency.get("fileName"),
                        "version": dependency.get("version"),
                    },
                    "status": "confirmed",
                    "normalization_status": "complete",
                    "observed_at": now(),
                    "raw_artifact": args.raw_artifact,
                }
            )
    return output


def main() -> int:
    args = parse_args()
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        if not isinstance(report.get("dependencies"), list):
            raise ValueError("Dependency-Check report must contain a dependencies array")
        complete = args.exit_code in (0, 1)
        document = {
            "schema_version": "evidence-document/v1",
            "run": {
                "run_id": args.run_id,
                "fixture_id": args.fixture_id,
                "commit_id": args.commit_id,
                "pipeline": args.pipeline,
                "stage": args.stage,
            },
            "gate": {
                "gate_id": "dependency-analysis",
                "required": True,
                "completed": complete,
                "tool_exit_code": args.exit_code,
                "tool_version": args.tool_version,
            },
            "findings": findings(report, args),
            "normalization": {
                "status": "complete" if complete else "partial",
                "adapter_version": "0.1.0",
                "raw_artifacts": [args.raw_artifact],
            },
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: unable to normalise Dependency-Check report: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
