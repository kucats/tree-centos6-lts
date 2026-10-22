#!/usr/bin/env python3
"""Fail-closed SRPM inventory and upstream version-scope triage.

Only makes *provisional* not-affected suggestions. Never updates release
advisories or publishes packages. Binary RPM compatibility and source-level
downstream backports are separate review requirements.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
import urllib.request
from urllib.parse import urlparse

PKG_NAME = re.compile(r"^[a-z][a-z0-9+_.-]*$")
FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.-]*\.src\.rpm$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
VERSION = re.compile(r"^([0-9]+)\.([0-9]+)\.([0-9]+)(p[0-9]+)?$")


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def version_before(baseline, introduced):
    """Conservative numeric-triple ordering; same triple is inconclusive."""
    a = VERSION.fullmatch(baseline)
    b = VERSION.fullmatch(introduced)
    if a is None or b is None:
        raise ValueError("unsupported version syntax; needs manual review")
    an = tuple(map(int, a.group(1, 2, 3)))
    bn = tuple(map(int, b.group(1, 2, 3)))
    if an == bn:
        raise ValueError("versions share a numeric triple; needs manual review")
    return an < bn


def validate(inventory, scopes):
    issues = []
    if inventory.get("schema_version") != 1 or scopes.get("schema_version") != 1:
        issues.append("unsupported schema_version")
    packages = {}
    for item in inventory.get("packages", []):
        if not isinstance(item, dict):
            issues.append("invalid package entry")
            continue
        name, fn, sha, url = (item.get(k) for k in ("name", "filename", "sha256", "url"))
        if not isinstance(name, str) or not PKG_NAME.fullmatch(name):
            issues.append("invalid package name")
            continue
        if name in packages:
            issues.append("duplicate package " + name)
        packages[name] = item
        if not isinstance(fn, str) or not FILENAME.fullmatch(fn):
            issues.append("invalid SRPM filename for " + name)
        if url != "https://vault.centos.org/6.10/updates/Source/SPackages/" + str(fn):
            issues.append("unrecognized source URL for " + name)
        if not isinstance(item.get("version"), str) or not VERSION.fullmatch(item["version"]):
            issues.append("unsupported package version for " + name)
        if not isinstance(item.get("release"), str) or not item["release"]:
            issues.append("missing release for " + name)
        if sha is not None and (not isinstance(sha, str) or not SHA256.fullmatch(sha)):
            issues.append("invalid sha256 for " + name)
    if not packages:
        issues.append("empty inventory")
    seen = set()
    for item in scopes.get("assessments", []):
        if not isinstance(item, dict):
            issues.append("invalid CVE assessment")
            continue
        cve, name = item.get("cve"), item.get("package")
        if not isinstance(cve, str) or not CVE.fullmatch(cve):
            issues.append("invalid CVE")
        if cve in seen:
            issues.append("duplicate CVE " + str(cve))
        seen.add(cve)
        if name not in packages:
            issues.append("unknown package for " + str(cve))
            continue
        if item.get("proposed_status") != "not_affected":
            issues.append("only provisional not_affected scope is supported")
        try:
            if not version_before(packages[name]["version"], item["introduced_version"]):
                issues.append(str(cve) + ": baseline is not older than introduction")
        except (KeyError, ValueError, TypeError) as e:
            issues.append(str(cve) + ": " + str(e))
        references = item.get("references")
        if not isinstance(references, list) or not references or not all(
                isinstance(x, str) and x.startswith("https://") for x in references):
            issues.append(str(cve) + ": missing HTTPS upstream evidence")
    if not scopes.get("assessments"):
        issues.append("empty scope list")
    return issues


def download_sources(inventory, out, allow_unpinned=False):
    out.mkdir(parents=True, exist_ok=True)
    for item in inventory["packages"]:
        if item["sha256"] is None and not allow_unpinned:
            raise ValueError(item["name"] + ": missing pinned SRPM digest")
        target = out / item["filename"]
        fd, temp_name = tempfile.mkstemp(prefix=".download-", dir=out)
        digest = hashlib.sha256()
        total = 0
        try:
            with open(fd, "wb") as dst:
                request = urllib.request.Request(item["url"], headers={
                    "User-Agent": "tree-centos6-lts-source-audit/1.0"})
                with urllib.request.urlopen(request, timeout=90) as src:
                    if urlparse(src.url).hostname not in ("vault.centos.org",):
                        raise ValueError("SRPM download redirected to untrusted host")
                    while True:
                        chunk = src.read(128 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > 60 * 1024 * 1024:
                            raise ValueError("SRPM exceeds 60 MiB bound")
                        digest.update(chunk)
                        dst.write(chunk)
            sha = digest.hexdigest()
            if item["sha256"] is not None and sha != item["sha256"]:
                raise ValueError(item["name"] + ": SHA-256 mismatch")
            Path(temp_name).replace(target)
            print(sha + "  " + item["filename"], flush=True)
        finally:
            Path(temp_name).unlink(missing_ok=True)


def assess(inventory, scopes, headers):
    """headers is a TSV of actual rpm -qp name, version, release."""
    found = {}
    for raw in Path(headers).read_text(encoding="utf-8").splitlines():
        parts = raw.split("\t")
        if len(parts) != 3 or parts[0] in found:
            raise ValueError("unexpected or duplicate RPM header: " + raw)
        found[parts[0]] = parts[1:]
    packages = {x["name"]: x for x in inventory["packages"]}
    if set(found) != set(packages):
        raise ValueError("RPM header package inventory differs from expected inventory")
    for name, item in packages.items():
        if found[name] != [item["version"], item["release"]]:
            raise ValueError("RPM header mismatch for " + name)
    return [{
        "cve": x["cve"], "package": x["package"], "status": "candidate_not_affected",
        "installed_source_version": packages[x["package"]]["version"],
        "introduced_version": x["introduced_version"],
        "source_sha256_pinned": bool(packages[x["package"]]["sha256"]),
        "requires_independent_review": True,
        "notes": "Upstream introduction is newer than baseline; downstream code needs separate review."
    } for x in scopes["assessments"]]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("operation", choices=["validate", "fetch", "assess"])
    ap.add_argument("--inventory", type=Path, default=Path("config/source-inventory.json"))
    ap.add_argument("--scopes", type=Path, default=Path("config/cve-scope-candidates.json"))
    ap.add_argument("--out", type=Path, default=Path("dist/sources"))
    ap.add_argument("--headers", type=Path, default=Path("dist/sources/rpm-headers.tsv"))
    ap.add_argument("--allow-unpinned", action="store_true")
    args = ap.parse_args()
    inv, scopes = load(args.inventory), load(args.scopes)
    issues = validate(inv, scopes)
    if issues:
        for issue in issues:
            print("ERROR: " + issue, file=sys.stderr)
        return 1
    if args.operation == "fetch":
        download_sources(inv, args.out, args.allow_unpinned)
    elif args.operation == "assess":
        report = assess(inv, scopes, args.headers)
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "scope-report.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))
    else:
        print("Validated", len(inv["packages"]), "source packages and",
              len(scopes["assessments"]), "upstream CVE scope candidates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
