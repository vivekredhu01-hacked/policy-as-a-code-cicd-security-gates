#!/usr/bin/env python3
"""Convert an OWASP ZAP JSON report to evidence-document/v1."""

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
    parser.add_argument("--stage", default="runtime")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--tool-version", required=True)
    parser.add_argument("--exit-code", required=True, type=int)
    parser.add_argument("--raw-artifact", required=True)
    return parser.parse_args()


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def severity(alert: dict[str, Any]) -> str:
    value = str(alert.get("riskdesc", "")).split("(", 1)[0].strip().lower()
    if value == "informational":
        return "low"
    for level in ("critical", "high", "medium", "low"):
        if level in value:
            return level
    return "unknown"


def fingerprint(site: str, alert: dict[str, Any], instance: dict[str, Any]) -> str:
    key = "|".join(
        str(value)
        for value in (site, alert.get("pluginid"), instance.get("uri"))
    )
    return f"sha256:{hashlib.sha256(key.encode()).hexdigest()}"


def normalise(
    site: str, alert: dict[str, Any], instance: dict[str, Any], args: argparse.Namespace
) -> dict[str, Any]:
    plugin_id = alert.get("pluginid")
    name = alert.get("alert")
    if not plugin_id or not name:
        raise ValueError("ZAP alert must contain pluginid and alert")
    return {
        "schema_version": "evidence/v1",
        "finding_id": f"zap:{plugin_id}",
        "fingerprint": fingerprint(site, alert, instance),
        "tool": "zap",
        "tool_version": args.tool_version,
        "category": "runtime",
        "severity": severity(alert),
        "confidence": "high",
        "message": alert.get("desc") or name,
        "requirement_ids": ["SSDF-RV.1", "ASVS-V4", "ASVS-V5"],
        "asset": {
            "url": instance.get("uri") or site,
            "method": instance.get("method"),
            "parameter": instance.get("param"),
        },
        "cwe": alert.get("cweid"),
        "status": "confirmed",
        "normalization_status": "complete",
        "observed_at": now(),
        "raw_artifact": args.raw_artifact,
    }


def main() -> int:
    args = parse_args()
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        documents = []
        for site_entry in report.get("site", []):
            site = site_entry.get("@name", "")
            for alert in site_entry.get("alerts", []):
                instances = alert.get("instances") or [{}]
                documents.extend(normalise(site, alert, instance, args) for instance in instances)
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
                "gate_id": "runtime-analysis",
                "required": True,
                "completed": complete,
                "tool_exit_code": args.exit_code,
                "tool_version": args.tool_version,
            },
            "findings": documents,
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
        print(f"ERROR: unable to normalise ZAP report: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
