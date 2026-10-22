import gzip
import hashlib
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from verify_repo_preview import check


class MetadataPreviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "repodata").mkdir()
        primary = (b'<metadata xmlns="http://linux.duke.edu/metadata/common">'
                   b'<package type="rpm"><name>sudo</name></package></metadata>')
        content = gzip.compress(primary)
        (self.root / "repodata/primary.xml.gz").write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        (self.root / "repodata/repomd.xml").write_text(
            '<repomd xmlns="http://linux.duke.edu/metadata/repo">'
            '<data type="primary"><checksum type="sha256">' + digest +
            '</checksum><location href="repodata/primary.xml.gz"/>'
            '</data></repomd>', encoding="utf-8")

    def test_valid_preview(self):
        self.assertEqual(check(self.root), [])

    def test_digest_mismatch(self):
        (self.root / "repodata/primary.xml.gz").write_bytes(b"tampered")
        self.assertIn("primary metadata SHA-256 mismatch", check(self.root))

    def test_disallow_traversal(self):
        doc = self.root / "repodata/repomd.xml"
        doc.write_text(doc.read_text().replace("repodata/primary.xml.gz", "../etc/passwd"))
        self.assertIn("primary metadata path escapes repodata/ or is absent",
                      check(self.root))

    def test_disallow_wrong_package(self):
        meta = self.root / "repodata/primary.xml.gz"
        content = gzip.compress(
            b'<metadata xmlns="http://linux.duke.edu/metadata/common">'
            b'<package type="rpm"><name>curl</name></package></metadata>')
        meta.write_bytes(content)
        doc = self.root / "repodata/repomd.xml"
        digest = hashlib.sha256(content).hexdigest()
        import re
        doc.write_text(re.sub(r'[a-f0-9]{64}', digest, doc.read_text()))
        self.assertTrue(any("exactly sudo" in x for x in check(self.root)))


if __name__ == "__main__":
    unittest.main()
