#!/usr/bin/env python3
"""Validate the structure and SHA-256 of an *unsigned* local yum metadata preview.

This is NOT a trust / GPG signature verifier or proof of security remediation.
"""
import argparse
import gzip
import hashlib
import pathlib
import sys
import xml.etree.ElementTree as ET

REPO_NS = "{http://linux.duke.edu/metadata/repo}"
COMMON_NS = "{http://linux.duke.edu/metadata/common}"


def check(root):
    root = pathlib.Path(root).resolve()
    errors = []
    manifest = root / "repodata/repomd.xml"
    if not manifest.is_file():
        return ["missing repodata/repomd.xml"]
    try:
        doc = ET.parse(manifest).getroot()
    except (ET.ParseError, OSError) as exc:
        return [f"invalid repomd.xml: {exc}"]
    entries = [x for x in doc.findall(REPO_NS + "data")
               if x.get("type") == "primary"]
    if len(entries) != 1:
        return ["exactly one primary metadata entry required"]
    entry = entries[0]
    checksum = entry.find(REPO_NS + "checksum")
    location = entry.find(REPO_NS + "location")
    if checksum is None or checksum.get("type") != "sha256" or not checksum.text:
        return ["SHA-256 primary metadata checksum required"]
    if location is None or not location.get("href"):
        return ["primary metadata location required"]
    href = location.get("href")
    # Relative repository URLs must not traverse out of the preview.
    resolved = (root / href).resolve()
    if (pathlib.PurePosixPath(href).is_absolute() or
            not resolved.is_relative_to(root / "repodata") or
            not resolved.is_file()):
        return ["primary metadata path escapes repodata/ or is absent"]
    data = resolved.read_bytes()
    if hashlib.sha256(data).hexdigest() != checksum.text.strip().lower():
        errors.append("primary metadata SHA-256 mismatch")
        return errors
    try:
        primary = ET.fromstring(gzip.decompress(data))
    except (OSError, ET.ParseError) as exc:
        return [f"primary metadata cannot be parsed: {exc}"]
    names = []
    for p in primary.findall(COMMON_NS + "package"):
        name = p.find(COMMON_NS + "name")
        names.append(name.text if name is not None else None)
    if names != ["sudo"]:
        errors.append(f"expected exactly sudo main RPM; got {names!r}")
    if (root / "repodata/repomd.xml.asc").exists():
        errors.append("preview unexpectedly contains metadata signature")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=pathlib.Path)
    args = parser.parse_args()
    errors = check(args.directory)
    for err in errors:
        print("FAIL:", err, file=sys.stderr)
    if errors:
        return 1
    print("PASS: internal checksum and sudo RPM metadata in UNSIGNED preview")
    return 0


if __name__ == "__main__":
    sys.exit(main())
