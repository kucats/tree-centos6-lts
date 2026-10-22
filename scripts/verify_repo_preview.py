#!/usr/bin/env python3
"""Inspect a local, unsigned yum preview; never trust or publish its contents.

Checks SHA-256 from repomd -> metadata -> RPM, package identity, size and
relative paths. This is *not* cryptographic release authentication.
"""
import argparse
import gzip
import hashlib
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

REPO_NS = "{http://linux.duke.edu/metadata/repo}"
COMMON_NS = "{http://linux.duke.edu/metadata/common}"
HEX256 = re.compile(r"^[a-f0-9]{64}$")
EXPECTED = ("sudo", "x86_64", "1.8.6p3", "29.el6_10.3.tree1")
MAX_METADATA_BYTES = 16 * 1024 * 1024


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _metadata_path(root, href, directory=None):
    if not href or not isinstance(href, str):
        raise ValueError("missing relative location href")
    parts = pathlib.PurePosixPath(href)
    if parts.is_absolute() or ".." in parts.parts or "\\" in href:
        raise ValueError("unsafe repository location")
    path = (root / href).resolve()
    parent = (root / directory).resolve() if directory else root
    if not path.is_relative_to(parent) or not path.is_file():
        raise ValueError("referenced repository file missing or escaped")
    return path


def _checksum(element):
    if element is None or element.get("type") != "sha256":
        raise ValueError("SHA-256 checksum required")
    value = (element.text or "").strip().lower()
    if not HEX256.fullmatch(value):
        raise ValueError("malformed SHA-256 checksum")
    return value


def check(root):
    root = pathlib.Path(root).resolve()
    manifest = root / "repodata/repomd.xml"
    if not manifest.is_file():
        return ["missing repodata/repomd.xml"]
    if (root / "repodata/repomd.xml.asc").exists():
        return ["unsigned preview unexpectedly has a metadata signature"]
    try:
        doc = ET.parse(manifest).getroot()
        if doc.tag != REPO_NS + "repomd":
            raise ValueError("invalid repomd namespace/root")
        entries = doc.findall(REPO_NS + "data")
        types = [entry.get("type") for entry in entries]
        if len(types) != len(set(types)) or types.count("primary") != 1:
            raise ValueError("duplicate metadata types or missing primary metadata")
        primary = None
        for entry in entries:
            loc = entry.find(REPO_NS + "location")
            href = loc.get("href") if loc is not None else None
            target = _metadata_path(root, href, "repodata")
            encoded = target.read_bytes()
            if len(encoded) > MAX_METADATA_BYTES:
                raise ValueError("metadata file exceeds size bound")
            expected = _checksum(entry.find(REPO_NS + "checksum"))
            if _sha256(encoded) != expected:
                raise ValueError("metadata SHA-256 mismatch: " + str(entry.get("type")))
            stored_size = entry.find(REPO_NS + "size")
            if stored_size is not None and int(stored_size.text or "-1") != len(encoded):
                raise ValueError("metadata size mismatch")
            if entry.get("type") == "primary":
                if not href.endswith(".xml.gz"):
                    raise ValueError("primary metadata must be .xml.gz")
                with gzip.open(target, "rb") as stream:
                    decoded = stream.read(MAX_METADATA_BYTES + 1)
                if len(decoded) > MAX_METADATA_BYTES:
                    raise ValueError("decompressed primary metadata exceeds size bound")
                rawsum = entry.find(REPO_NS + "open-checksum")
                if rawsum is not None and _sha256(decoded) != _checksum(rawsum):
                    raise ValueError("primary metadata uncompressed SHA-256 mismatch")
                primary = ET.fromstring(decoded)
        if primary is None or primary.tag != COMMON_NS + "metadata":
            raise ValueError("missing or invalid primary metadata XML")
        packages = primary.findall(COMMON_NS + "package")
        if len(packages) != 1 or primary.get("packages") not in (None, "1"):
            raise ValueError("preview must contain exactly one package")
        pkg = packages[0]
        if pkg.get("type") != "rpm":
            raise ValueError("package type must be rpm")
        def required(tag):
            value = pkg.find(COMMON_NS + tag)
            return value
        name = required("name")
        arch = required("arch")
        version = required("version")
        if (name is None or arch is None or version is None or
                (name.text, arch.text, version.get("ver"), version.get("rel")) != EXPECTED or
                version.get("epoch") not in ("0", None)):
            raise ValueError("unexpected package name, architecture or EVR")
        checksum = _checksum(required("checksum"))
        loc = required("location")
        href = loc.get("href") if loc is not None else None
        rpmfile = _metadata_path(root, href)
        expected_filename = "sudo-1.8.6p3-29.el6_10.3.tree1.x86_64.rpm"
        if href != expected_filename:
            raise ValueError("unexpected RPM filename/location")
        payload = rpmfile.read_bytes()
        if _sha256(payload) != checksum:
            raise ValueError("RPM payload SHA-256 mismatch")
        size = required("size")
        if size is None or int(size.get("package", "-1")) != len(payload):
            raise ValueError("RPM payload size mismatch")
        return []
    except (ET.ParseError, OSError, ValueError, TypeError, EOFError) as exc:
        return [str(exc)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=pathlib.Path)
    args = parser.parse_args()
    errors = check(args.directory)
    for err in errors:
        print("FAIL:", err, file=sys.stderr)
    if errors:
        return 1
    print("PASS: unsigned yum preview repomd -> primary -> sudo RPM SHA-256 and EVR")
    return 0


if __name__ == "__main__":
    sys.exit(main())
