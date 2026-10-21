import datetime as dt
import unittest
from pathlib import Path
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from nvd_triage import collect, UTC


class NvdTests(unittest.TestCase):
    def test_pagination_and_deduplication(self):
        page1 = {"totalResults": 3, "vulnerabilities": [
            {"cve": {"id": "CVE-2026-5555", "published": "2026-01-01"}},
            {"cve": {"id": "CVE-2026-4444"}},
        ]}
        page2 = {"totalResults": 3, "vulnerabilities": [
            {"cve": {"id": "CVE-2026-5555", "lastModified": "2026-02-02"}},
        ]}
        start = dt.datetime(2026, 1, 1, tzinfo=UTC)
        end = start + dt.timedelta(days=1)
        with patch("nvd_triage.fetch_page", side_effect=[page1, page2]) as fetched, \
             patch("nvd_triage.time.sleep"):
            items = collect(start, end)
        self.assertEqual(fetched.call_count, 2)
        self.assertEqual([x["cve"] for x in items], ["CVE-2026-4444", "CVE-2026-5555"])
        self.assertTrue(all(x["status"] == "untriaged" for x in items))

    def test_invalid_window(self):
        start = dt.datetime(2026, 1, 1, tzinfo=UTC)
        with self.assertRaises(ValueError):
            collect(start, start)
        with self.assertRaises(ValueError):
            collect(start, start + dt.timedelta(days=121))


if __name__ == "__main__":
    unittest.main()
