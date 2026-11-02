import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[2]
ADAPTER = ROOT / "scripts" / "normalize-zap.py"


class ZapAdapterTests(unittest.TestCase):
    def run_adapter(self, report, exit_code=0):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            report_path = directory / "zap.json"
            output_path = directory / "evidence.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable, str(ADAPTER),
                    "--report", str(report_path), "--output", str(output_path),
                    "--fixture-id", "F05", "--commit-id", "test-commit",
                    "--pipeline", "proposed", "--stage", "runtime",
                    "--run-id", "test-f05", "--tool-version", "2.16.0",
                    "--exit-code", str(exit_code),
                    "--raw-artifact", "artifacts/f05/zap.json",
                ],
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(output_path.read_text(encoding="utf-8"))

    def test_alert_is_normalised(self):
        evidence = self.run_adapter(
            {
                "site": [
                    {
                        "@name": "http://127.0.0.1:8000",
                        "alerts": [
                            {
                                "pluginid": "40012",
                                "alert": "Cross Site Scripting",
                                "riskdesc": "High (Medium)",
                                "desc": "Reflected input was detected.",
                                "cweid": "79",
                                "instances": [
                                    {
                                        "uri": "http://127.0.0.1:8000/?q=test",
                                        "method": "GET",
                                        "param": "q",
                                    }
                                ],
                            }
                        ],
                    }
                ]
            },
            exit_code=1,
        )
        finding = evidence["findings"][0]
        self.assertEqual(evidence["gate"]["gate_id"], "runtime-analysis")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["category"], "runtime")

    def test_clean_report_is_complete(self):
        evidence = self.run_adapter({"site": []})
        self.assertEqual(evidence["findings"], [])
        self.assertTrue(evidence["gate"]["completed"])

    def test_zap_risk_uses_risk_not_confidence(self):
        evidence = self.run_adapter(
            {
                "site": [
                    {
                        "@name": "http://127.0.0.1:8000",
                        "alerts": [
                            {
                                "pluginid": "10036",
                                "alert": "Server information disclosure",
                                "riskdesc": "Low (High)",
                                "instances": [{"uri": "http://127.0.0.1:8000"}],
                            },
                            {
                                "pluginid": "10049",
                                "alert": "Cacheability",
                                "riskdesc": "Informational (Medium)",
                                "instances": [{"uri": "http://127.0.0.1:8000"}],
                            },
                        ],
                    }
                ]
            }
        )
        self.assertEqual(
            [finding["severity"] for finding in evidence["findings"]],
            ["low", "low"],
        )


if __name__ == "__main__":
    unittest.main()
