#!/usr/bin/env python3
"""Fail-closed preflight. A green build is not authorization to publish RPMs.

This tool is read-only and cannot sign, upload or release. It intentionally
does not accept self-attested CLI flags for trust/review: those need a separately
protected release system with cryptographic evidence and human approval.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE_BLOCKERS = (
    "No independently reviewed, complete CVE coverage inventory for CentOS 6",
    "No full package regression and compatibility attestation",
    "No separately controlled GPG signing of candidate binary and source RPMs",
    "No separately GPG-signed yum repomd.xml",
    "No protected and independently approved production publication workflow",
)


def evaluate(root):
    errors = []
    try:
        source = json.loads((root / "config/source-inventory.json").read_text())
        names = {x["name"] for x in source["packages"]}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return {"state": "blocked", "errors": [str(exc)], "blockers": list(BASE_BLOCKERS)}
    coverage = {name: [] for name in sorted(names)}
    for path in sorted((root / "security/advisories").glob("*.json")):
        try:
            doc = json.loads(path.read_text())
            if doc["package"] not in coverage or doc["cve"] + ".json" != path.name:
                errors.append(f"{path.name}: inconsistent or untracked package/CVE")
                continue
            coverage[doc["package"]].append({
                "cve": doc["cve"], "status": doc.get("status", "missing")
            })
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(f"{path.name}: {exc}")
    blockers = list(BASE_BLOCKERS)
    for name, items in coverage.items():
        if not items:
            blockers.append(name + ": no advisory records at all")
        for item in items:
            if item["status"] not in ("fixed", "not_affected"):
                blockers.append(name + ": " + item["cve"] + " is " + item["status"])
    return {
        "state": "blocked",
        "mode": "report_only_no_release_capability",
        "packages": coverage,
        "blockers": blockers,
        "errors": errors,
        "note": "Successful source signature checks are only input provenance, not authorization to release patched RPMs.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--enforce", action="store_true", help="return nonzero if blocked")
    args = parser.parse_args()
    result = evaluate(args.root.resolve())
    rendered = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    print(rendered)
    return int(bool(result["errors"]) or (args.enforce and result["state"] != "approved"))


if __name__ == "__main__":
    sys.exit(main())
