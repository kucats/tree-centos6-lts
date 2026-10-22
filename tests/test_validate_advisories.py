import hashlib
import json
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from validate_advisories import check_repository, validate_document


class ValidatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "config").mkdir()
        (self.root / "security/advisories").mkdir(parents=True)
        (self.root / "patches").mkdir()
        (self.root / "config/packages.json").write_text(
            json.dumps({"packages": [{"name": "openssl"}]}), encoding="utf-8"
        )
        self.cve = "CVE-2026-12345"
        self.base = {
            "cve": self.cve,
            "package": "openssl",
            "status": "pending",
            "evidence": ["https://example.org/advisory"],
            "rationale": "Requires source-level review",
        }

    def validate(self, doc, release=False):
        return validate_document(doc, self.cve + ".json", self.root, {"openssl"}, release)

    def test_pending_needs_rationale(self):
        self.assertEqual(self.validate(self.base), [])
        doc = {**self.base, "rationale": ""}
        self.assertIn("rationale is required", self.validate(doc))

    def test_fixed_requires_patch_evidence_and_checksum(self):
        patch = b"test patch content\n"
        (self.root / "patches/fix.patch").write_bytes(patch)
        doc = {
            **self.base,
            "status": "fixed",
            "upstream_reference": "https://example.org/commit/42",
            "reviewed_by": "reviewer-1",
            "tests": ["https://example.org/test-report"],
            "patch_path": "patches/fix.patch",
            "patch_sha256": hashlib.sha256(patch).hexdigest(),
        }
        self.assertEqual(self.validate(doc), [])
        self.assertIn("patch_sha256 mismatch", self.validate({**doc, "patch_sha256": "0" * 64}))
        self.assertTrue(self.validate({**doc, "patch_path": "patches/../../etc/passwd"}))

    def test_not_affected_requires_review(self):
        doc = {**self.base, "status": "not_affected", "reviewed_by": "reviewer-2"}
        self.assertEqual(self.validate(doc, release=True), [])
        self.assertIn("not_affected requires reviewed_by", self.validate({**doc, "reviewed_by": ""}))

    def test_release_gate_and_filename(self):
        self.assertIn("release gate rejects unresolved and mitigated advisories", self.validate(self.base, True))
        self.assertIn("filename must match cve",
                      validate_document(self.base, "wrong.json", self.root, {"openssl"}))

    def test_repository_loads_records(self):
        (self.root / "security/advisories" / (self.cve + ".json")).write_text(json.dumps(self.base))
        errors, count = check_repository(self.root)
        self.assertEqual((errors, count), ([], 1))
        errors, count = check_repository(self.root, release=True)
        self.assertEqual(count, 1)
        self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
