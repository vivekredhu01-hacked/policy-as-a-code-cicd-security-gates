import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[2]
ADAPTER = ROOT / "scripts" / "normalize-semgrep.py"


class SemgrepAdapterTests(unittest.TestCase):
    def test_finding_is_normalised(self):
        report = {
            "results": [{
                "check_id": "javascript-security-test-eval",
                "path": "src/unsafe.js",
                "start": {"line": 7},
                "end": {"line": 7},
                "extra": {
                    "message": "Unsafe dynamic evaluation.",
                    "metadata": {
                        "severity": "high",
                        "requirement_ids": ["SSDF-PW.7", "ASVS-V5"],
                    },
                },
            }]
        }
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            report_path = directory / "semgrep.json"
            output_path = directory / "evidence.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable, str(ADAPTER),
                    "--report", str(report_path), "--output", str(output_path),
                    "--fixture-id", "F02", "--commit-id", "test-commit",
                    "--pipeline", "proposed", "--run-id", "test-f02",
                    "--tool-version", "1.0.0", "--exit-code", "1",
                    "--raw-artifact", "artifacts/f02/semgrep.json",
                ],
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            evidence = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["gate"]["gate_id"], "source-analysis")
            self.assertEqual(evidence["findings"][0]["severity"], "high")
            self.assertEqual(evidence["findings"][0]["requirement_ids"], ["SSDF-PW.7", "ASVS-V5"])

    def test_empty_report_is_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            report_path = directory / "semgrep.json"
            output_path = directory / "evidence.json"
            report_path.write_text('{"results": []}', encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable, str(ADAPTER),
                    "--report", str(report_path), "--output", str(output_path),
                    "--fixture-id", "F06", "--commit-id", "test-commit",
                    "--pipeline", "proposed", "--run-id", "test-f06",
                    "--tool-version", "1.0.0", "--exit-code", "0",
                    "--raw-artifact", "artifacts/f06/semgrep.json",
                ],
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            evidence = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["findings"], [])
            self.assertTrue(evidence["gate"]["completed"])


if __name__ == "__main__":
    unittest.main()
