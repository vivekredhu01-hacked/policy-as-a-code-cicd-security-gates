import json
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[2]
RUNNER = ROOT / "scripts" / "run-security-decision.py"
ARTIFACTS = ROOT / "artifacts"

spec = importlib.util.spec_from_file_location("run_security_decision", RUNNER)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class SecurityDecisionRunnerTests(unittest.TestCase):
    def run_decision(self, fixture_id, expected_exit):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "decision.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--evidence",
                    str(ARTIFACTS / fixture_id.lower() / "evidence.json"),
                    "--output",
                    str(output),
                    "--fixture-id",
                    fixture_id,
                    "--commit-id",
                    "24232905172e36e7200b0654ca05723e47687ec5",
                    "--pipeline",
                    "proposed",
                    "--stage",
                    "source",
                    "--gate-id",
                    "secret-detection",
                    "--run-id",
                    f"test-{fixture_id.lower()}",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, expected_exit, result.stderr)
            return json.loads(output.read_text(encoding="utf-8"))

    def test_f01_blocks(self):
        decision = self.run_decision("F01", 1)
        self.assertEqual(decision["decision"], "BLOCK")
        self.assertFalse(decision["deployment_allowed"])

    def test_f06_passes(self):
        decision = self.run_decision("F06", 0)
        self.assertEqual(decision["decision"], "PASS")
        self.assertTrue(decision["deployment_allowed"])

    def test_empty_policy_result_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "no successful policy evaluation"):
            runner.extract_decision([])

    def test_invalid_policy_message_fails_closed(self):
        result = [{"failures": [{"msg": "not-json"}]}]
        with self.assertRaisesRegex(RuntimeError, "invalid decision record"):
            runner.extract_decision(result)


if __name__ == "__main__":
    unittest.main()
