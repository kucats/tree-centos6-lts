import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from release_readiness import evaluate


class ReleaseGateTests(unittest.TestCase):
    def test_real_repository_is_not_releasable(self):
        report = evaluate(ROOT)
        self.assertEqual(report["state"], "blocked")
        self.assertTrue(any("GPG signing" in x for x in report["blockers"]))
        self.assertTrue(any("CVE-2023-22809" in x for x in report["blockers"]))
        self.assertTrue(any("CVE-2023-28321" in x for x in report["blockers"]))
        self.assertFalse(report["errors"])

    def test_fail_closed_without_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            report = evaluate(Path(temp))
            self.assertEqual(report["state"], "blocked")
            self.assertTrue(report["errors"])

    def test_enforced_mode_exits_nonzero(self):
        p = subprocess.run(
            [sys.executable, str(ROOT / "scripts/release_readiness.py"), "--enforce"],
            capture_output=True, text=True,
        )
        self.assertEqual(p.returncode, 1)
        self.assertEqual(json.loads(p.stdout)["state"], "blocked")


if __name__ == "__main__":
    unittest.main()
