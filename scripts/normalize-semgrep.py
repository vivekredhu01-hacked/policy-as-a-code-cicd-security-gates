#!/usr/bin/env python3
"""Convert a Semgrep JSON report into the evidence-document/v1 contract."""

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


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def fingerprint(result: dict[str, Any]) -> str:
    key = "|".join(
        str(result.get(key, ""))
        for key in ("check_id", "path", "start", "end")
    )
    return f"sha256:{hashlib.sha256(key.encode()).hexdigest()}"


def severity(result: dict[str, Any]) -> str:
    metadata = result.get("extra", {}).get("metadata", {})
    value = str(metadata.get("severity", "high")).lower()
    return value if value in {"low", "medium", "high", "critical"} else "unknown"


def normalise(result: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    check_id = result.get("check_id")
    path = result.get("path")
    if not check_id or not path:
        raise ValueError("Semgrep result must contain check_id and path")
    extra = result.get("extra", {})
    metadata = extra.get("metadata", {})
    return {
        "schema_version": "evidence/v1",
        "finding_id": f"semgrep:{check_id}",
        "fingerprint": fingerprint(result),
        "tool": "semgrep",
        "tool_version": args.tool_version,
        "category": "source",
        "severity": severity(result),
        "confidence": "high",
        "message": extra.get("message") or f"Semgrep rule {check_id} matched.",
        "requirement_ids": metadata.get(
            "requirement_ids", ["SSDF-PW.5", "SSDF-PW.7", "ASVS-V5"]
        ),
        "asset": {
            "path": path,
            "line_start": result.get("start", {}).get("line"),
            "line_end": result.get("end", {}).get("line"),
        },
        "status": "confirmed",
        "normalization_status": "complete",
        "observed_at": now(),
        "raw_artifact": args.raw_artifact,
    }


def main() -> int:
    args = parse_args()
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        results = report.get("results")
        if not isinstance(results, list):
            raise ValueError("Semgrep report must contain a results array")
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
                "gate_id": "source-analysis",
                "required": True,
                "completed": complete,
                "tool_exit_code": args.exit_code,
                "tool_version": args.tool_version,
            },
            "findings": [normalise(item, args) for item in results],
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
        print(f"ERROR: unable to normalise Semgrep report: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
