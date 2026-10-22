"""Offline contract tests for release provenance requirements."""
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FINGERPRINT = "C1DAC52D1664E8A4386DBA430946FCA2C105B9DE"


class SourceTrustTests(unittest.TestCase):
    def test_source_inventory_is_fully_pinned(self):
        data = json.loads((ROOT / "config/source-inventory.json").read_text())
        for package in data["packages"]:
            self.assertEqual(len(package["sha256"]), 64)
            self.assertTrue(package["url"].startswith((
                "https://vault.centos.org/6.10/updates/Source/SPackages/",
                "https://vault.centos.org/6.10/os/Source/SPackages/")))

    def test_fingerprint_and_air_gapped_rpmdb_required(self):
        script = (ROOT / "scripts/verify_source_signatures.sh").read_text()
        self.assertIn(FINGERPRINT, script)
        self.assertIn("--network none", script)
        self.assertIn("--read-only", script)
        self.assertIn("--dbpath /tmp/rpm-verify-db", script)
        self.assertIn("-Kv", script)
        self.assertIn("NOKEY", script)

    def test_unverified_results_cannot_be_released(self):
        path = ROOT / "security/advisories"
        for advisory in path.glob("*.json"):
            content = json.loads(advisory.read_text())
            self.assertIn(content["status"], {
                "pending", "blocked", "not_affected", "fixed", "mitigated"
            })
            if content["status"] == "fixed":
                self.assertTrue(content.get("reviewed_by"))
                self.assertTrue(content.get("tests"))


if __name__ == "__main__":
    unittest.main()
