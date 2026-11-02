import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[2]
ADAPTER = ROOT / "scripts" / "normalize-gitleaks.py"


class GitleaksAdapterTests(unittest.TestCase):
    def run_adapter(self, report, exit_code):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            report_path = directory / "gitleaks.json"
            output_path = directory / "evidence.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(ADAPTER),
                    "--report",
                    str(report_path),
                    "--output",
                    str(output_path),
                    "--fixture-id",
                    "F01",
                    "--commit-id",
                    "test-commit",
                    "--pipeline",
                    "proposed",
                    "--run-id",
                    "test-run",
                    "--tool-version",
                    "8.0.0",
                    "--exit-code",
                    str(exit_code),
                    "--raw-artifact",
                    "artifacts/gitleaks.json",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            return result, json.loads(output_path.read_text(encoding="utf-8"))

    def test_finding_is_normalised_without_secret_value(self):
        result, document = self.run_adapter(
            [
                {
                    "RuleID": "aws-access-token",
                    "Description": "AWS access token",
                    "File": "src/config.js",
                    "StartLine": 4,
                    "EndLine": 4,
                    "Secret": "must-not-be-copied",
                }
            ],
            1,
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(document["gate"]["completed"], True)
        self.assertEqual(document["findings"][0]["finding_id"], "gitleaks:aws-access-token")
        self.assertNotIn("must-not-be-copied", json.dumps(document))

    def test_clean_report_is_complete(self):
        result, document = self.run_adapter([], 0)

        self.assertEqual(result.returncode, 0)
        self.assertEqual(document["findings"], [])
        self.assertEqual(document["normalization"]["status"], "complete")

    def test_scanner_failure_is_incomplete(self):
        result, document = self.run_adapter([], 2)

        self.assertEqual(result.returncode, 0)
        self.assertEqual(document["gate"]["completed"], False)
        self.assertEqual(document["normalization"]["status"], "partial")


if __name__ == "__main__":
    unittest.main()
