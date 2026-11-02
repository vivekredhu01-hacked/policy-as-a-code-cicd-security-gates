#!/usr/bin/env python3
"""Convert a Trivy JSON report to evidence-document/v1."""

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
    parser.add_argument("--stage", default="container")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--tool-version", required=True)
    parser.add_argument("--exit-code", required=True, type=int)
    parser.add_argument("--raw-artifact", required=True)
    return parser.parse_args()


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def fingerprint(target: str, vulnerability: dict[str, Any]) -> str:
    key = "|".join(
        str(value)
        for value in (
            target,
            vulnerability.get("VulnerabilityID"),
            vulnerability.get("PkgName"),
            vulnerability.get("InstalledVersion"),
        )
    )
    return f"sha256:{hashlib.sha256(key.encode()).hexdigest()}"


def normalise(vulnerability: dict[str, Any], target: str, args: argparse.Namespace) -> dict[str, Any]:
    vulnerability_id = vulnerability.get("VulnerabilityID")
    package = vulnerability.get("PkgName")
    if not vulnerability_id or not package:
        raise ValueError("Trivy vulnerability must contain VulnerabilityID and PkgName")
    severity = str(vulnerability.get("Severity", "")).lower()
    if severity not in {"low", "medium", "high", "critical"}:
        severity = "unknown"
    return {
        "schema_version": "evidence/v1",
        "finding_id": f"trivy:{vulnerability_id}",
        "fingerprint": fingerprint(target, vulnerability),
        "tool": "trivy",
        "tool_version": args.tool_version,
        "category": "container",
        "severity": severity,
        "confidence": "high",
        "message": vulnerability.get("Title")
        or vulnerability.get("Description")
        or f"{vulnerability_id} affects {package}.",
        "requirement_ids": ["SSDF-PW.6", "ASVS-V14"],
        "asset": {
            "target": target,
            "package": package,
            "installed_version": vulnerability.get("InstalledVersion"),
            "fixed_version": vulnerability.get("FixedVersion"),
        },
        "cve": vulnerability_id,
        "status": "confirmed",
        "normalization_status": "complete",
        "observed_at": now(),
        "raw_artifact": args.raw_artifact,
    }


def main() -> int:
    args = parse_args()
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        results = report.get("Results") or []
        if not isinstance(results, list):
            raise ValueError("Trivy report must contain a Results array or null")
        output = []
        for result in results:
            target = result.get("Target")
            if not target:
                raise ValueError("Trivy result must contain Target")
            for vulnerability in result.get("Vulnerabilities") or []:
                output.append(normalise(vulnerability, target, args))
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
                "gate_id": "container-analysis",
                "required": True,
                "completed": complete,
                "tool_exit_code": args.exit_code,
                "tool_version": args.tool_version,
            },
            "findings": output,
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
        print(f"ERROR: unable to normalise Trivy report: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
