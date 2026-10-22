#!/usr/bin/env python3
"""Write yum updateinfo.xml (security errata) for the updates in config/release.json."""
import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build(root):
    manifest = json.loads((root / "config/release.json").read_text(encoding="utf-8"))
    top = ET.Element("updates")
    for item in manifest["updates"]:
        update = ET.SubElement(top, "update", {
            "from": manifest["channel"], "status": "stable", "type": "security", "version": "1.4"})
        ET.SubElement(update, "id").text = item["id"]
        ET.SubElement(update, "title").text = item["title"]
        ET.SubElement(update, "issued", {"date": item["issued"] + " 00:00:00"})
        ET.SubElement(update, "severity").text = item["severity"]
        ET.SubElement(update, "description").text = (
            "Backported fixes for " + ", ".join(item["advisories"]) +
            " on the final CentOS 6.10 " + item["package"] + " package.")
        refs = ET.SubElement(update, "references")
        for cve in item["advisories"]:
            ET.SubElement(refs, "reference", {
                "href": "https://www.cve.org/CVERecord?id=" + cve,
                "id": cve, "type": "cve", "title": cve})
        coll = ET.SubElement(ET.SubElement(update, "pkglist"), "collection",
                             {"short": manifest["channel"]})
        ET.SubElement(coll, "name").text = manifest["channel"]
        for name in item["rpms"]:
            pkg = ET.SubElement(coll, "package", {
                "name": name, "epoch": "0", "version": item["version"],
                "release": item["release"], "arch": item["arch"]})
            ET.SubElement(pkg, "filename").text = "%s-%s-%s.%s.rpm" % (
                name, item["version"], item["release"], item["arch"])
    return ET.tostring(top, encoding="unicode")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_text('<?xml version="1.0" encoding="UTF-8"?>\n' + build(args.root) + "\n",
                           encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
