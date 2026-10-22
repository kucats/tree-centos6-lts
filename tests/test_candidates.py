import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


class CandidateConfigTests(unittest.TestCase):
    def test_every_candidate_is_complete_and_pinned(self):
        pkgs = json.loads((ROOT / "config/candidates.json").read_text())["packages"]
        for name, c in pkgs.items():
            with self.subTest(package=name):
                self.assertRegex(c["sha256"], r"^[0-9a-f]{64}$")
                self.assertTrue(c["url"].startswith("https://vault.centos.org/6.10/"))
                self.assertTrue(c["url"].endswith("/" + c["srpm"]))
                self.assertTrue(c["srpm"].startswith(name + "-") and c["srpm"].endswith(".src.rpm"))
                self.assertRegex(c["dist"], r"^\.el6(_\d+)?$")
                self.assertTrue(c["patches"])
                self.assertEqual(sorted(c["guards"]), sorted(c["patches"]))
                for cve in c["patches"]:
                    self.assertRegex(cve, CVE)
                    self.assertTrue((ROOT / "packages" / name / (cve + ".patch")).is_file())
                    self.assertTrue(c["guards"][cve].strip())
                tests = list((ROOT / "tests/integration/candidates" / name).glob("*.sh"))
                self.assertTrue(tests, "each candidate needs a before/after test")


if __name__ == "__main__":
    unittest.main()
