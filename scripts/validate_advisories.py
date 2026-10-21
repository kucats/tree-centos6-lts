#!/usr/bin/env python3
"""Validate security decision records, without claiming vulnerability remediation."""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

CVE_RE = re.compile(r"^CVE-(1999|20[0-9]{2})-[0-9]{4,}$")
SHA_RE = re.compile(r"^[a-f0-9]{64}$")
STATES = {"fixed", "not_affected", "mitigated", "pending", "blocked"}


def _nonempty(value):
    return isinstance(value, str) and bool(value.strip())


def _url(value):
    return _nonempty(value) and value.startswith(("https://", "http://"))


def validate_document(doc, filename, root, packages, release=False):
    """Return human-readable failures; no network requests are performed."""
    errors = []
    if not isinstance(doc, dict):
        return ["advisory must be a JSON object"]
    cve = doc.get("cve")
    if not isinstance(cve, str) or not CVE_RE.fullmatch(cve):
        errors.append("cve must be a valid CVE identifier")
    elif filename != cve + ".json":
        errors.append("filename must match cve")
    if doc.get("package") not in packages:
        errors.append("package must exist in config/packages.json")
    state = doc.get("status")
    if state not in STATES:
        errors.append("status is unknown")
    evidence = doc.get("evidence")
    if not isinstance(evidence, list) or not evidence or not all(_url(v) for v in evidence):
        errors.append("evidence must be a nonempty list of HTTP(S) URLs")
    if state in {"pending", "blocked", "not_affected", "mitigated"} and not _nonempty(doc.get("rationale")):
        errors.append("rationale is required")
    if state == "not_affected" and not _nonempty(doc.get("reviewed_by")):
        errors.append("not_affected requires reviewed_by")
    if state == "mitigated" and not _nonempty(doc.get("mitigation")):
        errors.append("mitigated requires mitigation")
    if state == "fixed":
        if not _url(doc.get("upstream_reference")):
            errors.append("fixed requires upstream_reference URL")
        if not _nonempty(doc.get("reviewed_by")):
            errors.append("fixed requires reviewed_by")
        tests = doc.get("tests")
        if not isinstance(tests, list) or not tests or not all(_url(v) for v in tests):
            errors.append("fixed requires test-evidence URLs")
        path = doc.get("patch_path")
        sha = doc.get("patch_sha256")
        if not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
            errors.append("patch_sha256 must be a lowercase SHA-256 hex digest")
        if not isinstance(path, str) or not path.startswith("patches/"):
            errors.append("patch_path must be under patches/")
        else:
            candidate = (root / path).resolve()
            patch_root = (root / "patches").resolve()
            if not candidate.is_relative_to(patch_root) or not candidate.is_file():
                errors.append("patch_path must resolve to an existing file inside patches/")
            elif isinstance(sha, str) and SHA_RE.fullmatch(sha):
                if hashlib.sha256(candidate.read_bytes()).hexdigest() != sha:
                    errors.append("patch_sha256 mismatch")
    if release and state not in {"fixed", "not_affected"}:
        errors.append("release gate rejects unresolved and mitigated advisories")
    return errors


def check_repository(root, release=False):
    errors = []
    try:
        config = json.loads((root / "config/packages.json").read_text(encoding="utf-8"))
        packages = {p["name"] for p in config["packages"]}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return [f"invalid package config: {exc}"], 0
    if not packages:
        return ["package config is empty"], 0
    count = 0
    for path in sorted((root / "security/advisories").glob("*.json")):
        count += 1
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            errors.append(f"{path.name}: invalid JSON: {exc}")
            continue
        errors.extend(f"{path.name}: {msg}" for msg in
                      validate_document(data, path.name, root, packages, release))
    if release and count == 0:
        errors.append("release gate requires at least one advisory")
    return errors, count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--release", action="store_true", help="reject unresolved decisions")
    args = parser.parse_args()
    errors, count = check_repository(args.root.resolve(), args.release)
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    print(f"Validated {count} advisory records; errors={len(errors)}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
