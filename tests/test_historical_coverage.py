"""Do not accidentally downgrade downstream vulnerability evidence to semver-only claims."""
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class HistoricalCoverageSafetyTests(unittest.TestCase):
    def test_upstream_53_openssh_exception_remains_pending(self):
        advisory = json.loads(
            (ROOT / "security/advisories/CVE-2023-38408.json").read_text()
        )
        scope = json.loads(
            (ROOT / "config/cve-scope-candidates.json").read_text()
        )
        self.assertEqual(advisory["package"], "openssh")
        self.assertEqual(advisory["status"], "pending")
        self.assertEqual(advisory["proposed_status"],
                         "requires_downstream_source_audit")
        self.assertIn("pkcs11", advisory["source_finding"].lower())
        self.assertNotIn("CVE-2023-38408",
                         [x["cve"] for x in scope["assessments"]])

    def test_2026_sudo_version_scopes_require_review(self):
        data = json.loads((ROOT / "config/cve-scope-candidates.json").read_text())
        limits = {
            "CVE-2025-32462": "1.8.8",
            "CVE-2026-96512": "1.8.20",
            "CVE-2026-82474": "1.9.8",
        }
        found = {x["cve"]: x for x in data["assessments"]}
        for cve, earliest in limits.items():
            self.assertEqual(found[cve]["introduced_version"], earliest)
            self.assertEqual(found[cve]["proposed_status"], "not_affected")
            advisory = json.loads(
                (ROOT / ("security/advisories/" + cve + ".json")).read_text()
            )
            self.assertEqual(advisory["status"], "pending")
            self.assertTrue(advisory["evidence"])

    def test_openssh_source_hash_fixed(self):
        data = json.loads((ROOT / "config/source-inventory.json").read_text())
        ssh = [x for x in data["packages"] if x["name"] == "openssh"]
        self.assertEqual(len(ssh), 1)
        self.assertEqual(ssh[0]["version"], "5.3p1")
        self.assertEqual(ssh[0]["sha256"],
                         "da18c49ea13c0f0d373f7c0159da11381989f5616856f494a92f9ec03315ef56")


if __name__ == "__main__":
    unittest.main()
