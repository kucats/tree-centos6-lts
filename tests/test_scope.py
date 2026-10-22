import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from verify_scope import version_before, validate, assess

ROOT = Path(__file__).resolve().parents[1]


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.inv = json.loads((ROOT / "config/source-inventory.json").read_text())
        self.scopes = json.loads((ROOT / "config/cve-scope-candidates.json").read_text())

    def test_inventory_has_three_packages_five_cves(self):
        self.assertEqual(validate(self.inv, self.scopes), [])
        self.assertEqual(len(self.scopes["assessments"]), 5)

    def test_version_boundaries_fail_closed(self):
        self.assertTrue(version_before("1.8.6p3", "1.9.14"))
        self.assertTrue(version_before("7.19.7", "7.69.0"))
        self.assertTrue(version_before("5.3p1", "5.5p1"))
        self.assertFalse(version_before("7.80.0", "7.69.0"))
        with self.assertRaises(ValueError):
            version_before("1.9.14p1", "1.9.14")
        with self.assertRaises(ValueError):
            version_before("7.19.7-rhel", "7.69.0")

    def test_fail_when_package_baseline_reaches_vulnerable_version(self):
        inv = copy.deepcopy(self.inv)
        inv["packages"][1]["version"] = "7.69.1"
        errors = validate(inv, self.scopes)
        self.assertTrue(any("not older" in x for x in errors), errors)

    def test_fail_on_untrusted_url_and_bad_checksum(self):
        inv = copy.deepcopy(self.inv)
        inv["packages"][0]["url"] = "https://evil.test/rpm"
        inv["packages"][0]["sha256"] = "not-a-hash"
        errors = validate(inv, self.scopes)
        self.assertTrue(any("source URL" in x for x in errors), errors)
        self.assertTrue(any("sha256" in x for x in errors), errors)

    def test_header_guard(self):
        with tempfile.TemporaryDirectory() as temp:
            header = Path(temp) / "headers.tsv"
            header.write_text("sudo\t1.8.6p3\t29.el6_10.3\ncurl\t7.19.7\t54.el6_10\nopenssh\t5.3p1\t124.el6_10\n")
            results = assess(self.inv, self.scopes, header)
            self.assertEqual(len(results), 5)
            self.assertTrue(all(r["requires_independent_review"] for r in results))
            header.write_text("sudo\t1.9.14\t29.el6_10.3\ncurl\t7.19.7\t54.el6_10\nopenssh\t5.3p1\t124.el6_10\n")
            with self.assertRaises(ValueError):
                assess(self.inv, self.scopes, header)


if __name__ == "__main__":
    unittest.main()
