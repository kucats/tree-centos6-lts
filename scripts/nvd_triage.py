#!/usr/bin/env python3
"""Fetch recently modified NVD CVE IDs for review. Never infers CentOS applicability."""
import argparse
import datetime as dt
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UTC = dt.timezone.utc


def fetch_page(start, end, offset, page_size=2000):
    params = urllib.parse.urlencode({
        "lastModStartDate": start.isoformat(timespec="seconds"),
        "lastModEndDate": end.isoformat(timespec="seconds"),
        "startIndex": offset,
        "resultsPerPage": page_size,
    })
    headers = {"User-Agent": "tree-centos6-lts-triage/0.1"}
    if os.environ.get("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]
    req = urllib.request.Request(API + "?" + params, headers=headers)
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=40) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code not in (429, 500, 502, 503, 504) or attempt == 2:
                raise
            time.sleep(3 * (attempt + 1))
    raise RuntimeError("unreachable")


def collect(start, end):
    if end <= start or end - start > dt.timedelta(days=120):
        raise ValueError("NVD window must be positive and <= 120 days")
    results = {}
    offset = 0
    while True:
        page = fetch_page(start, end, offset)
        items = page.get("vulnerabilities", [])
        if not isinstance(items, list):
            raise ValueError("NVD response has no vulnerabilities list")
        for item in items:
            cve = item["cve"]
            cve_id = cve["id"]
            results[cve_id] = {
                "cve": cve_id,
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "source": "NVD",
                "status": "untriaged",
            }
        offset += len(items)
        total = page.get("totalResults", 0)
        if offset >= total:
            break
        if not items:
            raise ValueError("NVD returned an empty page before totalResults")
        # Without an API key, respect NVD rate limits.
        time.sleep(6 if not os.environ.get("NVD_API_KEY") else 1)
    return [results[key] for key in sorted(results)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hours", type=int, default=48)
    parser.add_argument("--output", type=Path, default=Path("dist/nvd-triage.json"))
    args = parser.parse_args()
    if not (1 <= args.hours <= 24 * 120):
        parser.error("--hours must be between 1 and 2880")
    end = dt.datetime.now(UTC)
    start = end - dt.timedelta(hours=args.hours)
    cves = collect(start, end)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({
        "generated_at": end.isoformat(),
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "warning": "Candidate CVEs only. No CentOS 6 applicability has been determined.",
        "cves": cves,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(cves)} candidate CVEs to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
