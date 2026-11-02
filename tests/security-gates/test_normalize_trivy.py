import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[2]
ADAPTER = ROOT / "scripts" / "normalize-trivy.py"


class TrivyAdapterTests(unittest.TestCase):
    def run_adapter(self, report, exit_code=1):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            report_path = directory / "trivy.json"
            output_path = directory / "evidence.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable, str(ADAPTER),
                    "--report", str(report_path),
                    "--output", str(output_path),
                    "--fixture-id", "F04",
                    "--commit-id", "test-commit",
                    "--pipeline", "proposed",
                    "--stage", "container",
                    "--run-id", "test-f04",
                    "--tool-version", "0.67.0",
                    "--exit-code", str(exit_code),
                    "--raw-artifact", "artifacts/f04/trivy.json",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(output_path.read_text(encoding="utf-8"))

    def test_vulnerability_is_normalised(self):
        evidence = self.run_adapter(
            {
                "Results": [
                    {
                        "Target": "f04-container",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2024-99999",
                                "PkgName": "openssl",
                                "InstalledVersion": "1.0.0",
                                "FixedVersion": "1.0.1",
                                "Severity": "HIGH",
                                "Title": "Controlled container finding",
                            }
                        ],
                    }
                ]
            }
        )
        finding = evidence["findings"][0]
        self.assertEqual(evidence["gate"]["gate_id"], "container-analysis")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["category"], "container")
        self.assertEqual(finding["asset"]["fixed_version"], "1.0.1")

    def test_clean_report_is_complete(self):
        evidence = self.run_adapter({"Results": []}, exit_code=0)
        self.assertEqual(evidence["findings"], [])
        self.assertTrue(evidence["gate"]["completed"])

    def test_empty_trivy_report_with_null_results_is_complete(self):
        evidence = self.run_adapter({}, exit_code=0)
        self.assertEqual(evidence["findings"], [])
        self.assertTrue(evidence["gate"]["completed"])


if __name__ == "__main__":
    unittest.main()
