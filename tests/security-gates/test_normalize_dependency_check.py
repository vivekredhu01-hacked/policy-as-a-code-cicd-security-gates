import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[2]
ADAPTER = ROOT / "scripts" / "normalize-dependency-check.py"


class DependencyCheckAdapterTests(unittest.TestCase):
    def run_adapter(self, report, exit_code=1):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            report_path = directory / "dependency-check.json"
            output_path = directory / "evidence.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable, str(ADAPTER),
                    "--report", str(report_path),
                    "--output", str(output_path),
                    "--fixture-id", "F03",
                    "--commit-id", "test-commit",
                    "--pipeline", "proposed",
                    "--stage", "dependencies",
                    "--run-id", "test-f03",
                    "--tool-version", "12.1.0",
                    "--exit-code", str(exit_code),
                    "--raw-artifact", "artifacts/f03/dependency-check.json",
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
                "dependencies": [
                    {
                        "fileName": "lodash",
                        "filePath": "package-lock.json",
                        "version": "4.17.19",
                        "vulnerabilities": [
                            {
                                "name": "CVE-2021-23337",
                                "severity": "high",
                                "description": "Prototype pollution vulnerability.",
                            }
                        ],
                    }
                ]
            }
        )
        self.assertEqual(evidence["gate"]["gate_id"], "dependency-analysis")
        self.assertEqual(evidence["findings"][0]["severity"], "high")
        self.assertEqual(evidence["findings"][0]["category"], "dependency")

    def test_clean_report_is_complete(self):
        evidence = self.run_adapter({"dependencies": []}, exit_code=0)
        self.assertEqual(evidence["findings"], [])
        self.assertTrue(evidence["gate"]["completed"])


if __name__ == "__main__":
    unittest.main()
