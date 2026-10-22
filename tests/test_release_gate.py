import hashlib
import json
import shutil
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from make_updateinfo import build
from release_gate import evaluate


class ReleaseGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for rel in ("config", "security/advisories", "packages/sudo"):
            shutil.copytree(ROOT / rel, self.root / rel)

    def manifest(self, **changes):
        path = self.root / "config/release.json"
        data = json.loads(path.read_text())
        data.update(changes)
        path.write_text(json.dumps(data))

    def mark_fixed(self, cve):
        path = self.root / "security/advisories" / (cve + ".json")
        doc = json.loads(path.read_text())
        patch = "packages/sudo/%s.patch" % cve
        doc.update(status="fixed", reviewed_by="reviewer", tests=["https://example.org/run"],
                   patch_path=patch,
                   patch_sha256=hashlib.sha256((self.root / patch).read_bytes()).hexdigest())
        path.write_text(json.dumps(doc))

    def test_real_repository_is_blocked_until_review(self):
        report = evaluate(ROOT)
        self.assertEqual(report["state"], "blocked")
        self.assertTrue(any("CVE-2021-3156" in b for b in report["blockers"]))

    def test_approved_only_with_reviews_and_pinned_key(self):
        for cve in ("CVE-2021-3156", "CVE-2023-22809"):
            self.mark_fixed(cve)
        self.assertEqual(evaluate(self.root)["state"], "blocked")
        self.manifest(signing_key_fingerprint="A" * 40)
        self.assertEqual(evaluate(self.root), {"state": "approved", "blockers": []})

    def test_wrong_patch_or_tampered_patch_blocks(self):
        for cve in ("CVE-2021-3156", "CVE-2023-22809"):
            self.mark_fixed(cve)
        self.manifest(signing_key_fingerprint="A" * 40)
        (self.root / "packages/sudo/CVE-2021-3156.patch").write_text("changed\n")
        self.assertTrue(any("patch_sha256 mismatch" in b for b in evaluate(self.root)["blockers"]))

    def test_updateinfo_lists_cves_and_packages(self):
        doc = ET.fromstring(build(ROOT))
        update = doc.find("update")
        self.assertEqual(update.get("type"), "security")
        self.assertEqual({r.get("id") for r in update.iter("reference")},
                         {"CVE-2021-3156", "CVE-2023-22809"})
        self.assertIn("sudo-1.8.6p3-29.el6_10.3.tree1.x86_64.rpm",
                      [f.text for f in update.iter("filename")])


if __name__ == "__main__":
    unittest.main()
