#!/usr/bin/env python3
"""Decide whether the update set in config/release.json may be signed and published.

Approval needs every listed advisory to be a reviewed `fixed` record whose patch
is the one the build applies, and a pinned signing-key fingerprint. Human
approval of the publishing job is enforced separately by the GitHub
`production` environment.
"""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from validate_advisories import validate_document

ROOT = Path(__file__).resolve().parents[1]
FPR_RE = re.compile(r"^[0-9A-F]{40}$")
ID_RE = re.compile(r"^TREE-[0-9]{4}:[0-9]{4}$")
EVR_RE = re.compile(r"^[A-Za-z0-9._+~^-]+$")


def evaluate(root):
    blockers = []
    try:
        manifest = json.loads((root / "config/release.json").read_text(encoding="utf-8"))
        packages = {p["name"] for p in
                    json.loads((root / "config/packages.json").read_text(encoding="utf-8"))["packages"]}
        updates = manifest["updates"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return {"state": "blocked", "blockers": ["invalid release manifest: %s" % exc]}
    if not FPR_RE.fullmatch(str(manifest.get("signing_key_fingerprint", ""))):
        blockers.append("signing_key_fingerprint is not a pinned 40-hex uppercase fingerprint")
    for key in ("base_url", "key_url"):
        if not str(manifest.get(key, "")).startswith("https://"):
            blockers.append(key + " must be an https:// URL")
    if not isinstance(updates, list) or not updates:
        blockers.append("release manifest lists no updates")
        updates = []
    seen = set()
    for update in updates:
        uid = update.get("id", "")
        if not ID_RE.fullmatch(uid) or uid in seen:
            blockers.append("update id missing, malformed or duplicated: %r" % uid)
        seen.add(uid)
        pkg = update.get("package")
        if pkg not in packages:
            blockers.append("%s: package %r is not tracked" % (uid, pkg))
        for field in ("version", "release", "arch"):
            if not EVR_RE.fullmatch(str(update.get(field, ""))):
                blockers.append("%s: invalid %s" % (uid, field))
        if not update.get("rpms") or pkg not in update.get("rpms", []):
            blockers.append("%s: rpms must include the main %s package" % (uid, pkg))
        if not update.get("advisories"):
            blockers.append("%s: no advisories" % uid)
        for cve in update.get("advisories", []):
            path = root / "security/advisories" / (str(cve) + ".json")
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                blockers.append("%s: %s unreadable: %s" % (uid, cve, exc))
                continue
            if doc.get("package") != pkg:
                blockers.append("%s: %s is recorded for another package" % (uid, cve))
            for err in validate_document(doc, path.name, root, packages, release=True):
                blockers.append("%s: %s: %s" % (uid, cve, err))
            if doc.get("status") == "fixed" and doc.get("patch_path") != "packages/%s/%s.patch" % (pkg, cve):
                blockers.append("%s: %s patch_path is not the patch the build applies" % (uid, cve))
    return {"state": "blocked" if blockers else "approved", "blockers": blockers}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    result = evaluate(args.root.resolve())
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["state"] == "approved" else 1


if __name__ == "__main__":
    sys.exit(main())
