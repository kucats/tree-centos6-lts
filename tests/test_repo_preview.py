import gzip
import hashlib
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from verify_repo_preview import check

SHA = lambda data: hashlib.sha256(data).hexdigest()


class MetadataPreviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "repodata").mkdir()
        self.rpmfile = self.root / "sudo-1.8.6p3-29.el6_10.3.tree1.x86_64.rpm"
        self.rpmfile.write_bytes(b"test unsigned sudo RPM payload")
        self.make_metadata()

    def make_metadata(self, *, name="sudo", rpm_digest=None, rpm_size=None,
                      location=None, rel="29.el6_10.3.tree1"):
        payload = self.rpmfile.read_bytes()
        rpm_digest = SHA(payload) if rpm_digest is None else rpm_digest
        rpm_size = len(payload) if rpm_size is None else rpm_size
        location = self.rpmfile.name if location is None else location
        primary = (
            '<metadata xmlns="http://linux.duke.edu/metadata/common" packages="1">'
            '<package type="rpm"><name>{}</name><arch>x86_64</arch>'
            '<version epoch="0" ver="1.8.6p3" rel="{}"/>'
            '<checksum type="sha256" pkgid="YES">{}</checksum>'
            '<size package="{}"/><location href="{}"/></package></metadata>'
        ).format(name, rel, rpm_digest, rpm_size, location).encode()
        zipped = gzip.compress(primary)
        meta_file = self.root / "repodata/primary.xml.gz"
        meta_file.write_bytes(zipped)
        repomd = (
            '<repomd xmlns="http://linux.duke.edu/metadata/repo">'
            '<data type="primary"><checksum type="sha256">{}</checksum>'
            '<open-checksum type="sha256">{}</open-checksum>'
            '<size>{}</size><location href="repodata/primary.xml.gz"/>'
            '</data></repomd>'
        ).format(SHA(zipped), SHA(primary), len(zipped))
        (self.root / "repodata/repomd.xml").write_text(repomd, encoding="utf-8")

    def test_valid_preview(self):
        self.assertEqual(check(self.root), [])

    def test_corrupted_metadata(self):
        (self.root / "repodata/primary.xml.gz").write_bytes(b"tampered")
        self.assertTrue(any("metadata SHA-256 mismatch" in x for x in check(self.root)))

    def test_reject_traversal(self):
        self.make_metadata(location="../outside.rpm")
        self.assertTrue(any("unsafe repository location" in x for x in check(self.root)))

    def test_reject_wrong_package(self):
        self.make_metadata(name="curl")
        self.assertTrue(any("unexpected package" in x for x in check(self.root)))

    def test_reject_wrong_release(self):
        self.make_metadata(rel="29.el6_10.3")
        self.assertTrue(check(self.root))

    def test_reject_tampered_rpm(self):
        self.rpmfile.write_bytes(b"altered RPM after metadata generation")
        self.assertTrue(any("RPM payload SHA-256 mismatch" in x for x in check(self.root)))

    def test_reject_forged_checksum(self):
        self.make_metadata(rpm_digest="0" * 64)
        self.assertTrue(any("RPM payload SHA-256 mismatch" in x for x in check(self.root)))

    def test_reject_wrong_size(self):
        self.make_metadata(rpm_size=99999)
        self.assertTrue(any("RPM payload size mismatch" in x for x in check(self.root)))

    def test_reject_unexpected_metadata_signature(self):
        (self.root / "repodata/repomd.xml.asc").write_text("fake signature")
        self.assertTrue(any("unexpectedly has" in x for x in check(self.root)))

    def test_reject_missing_rpm(self):
        self.rpmfile.unlink()
        self.assertTrue(any("referenced repository file missing" in x
                            for x in check(self.root)))


if __name__ == "__main__":
    unittest.main()
