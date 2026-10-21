# tree-centos6-lts

Community infrastructure for **auditable CentOS 6.10 security backports**.

**Status: bootstrap / research preview. No security-fixed RPMs are available. Do not treat this project as a substitute for vendor-supported updates.**

## Scope

- Baseline: CentOS 6.10, x86_64 first. i386 is not yet tested.
- Inventory: openssl, openssh, curl and sudo as initial candidates (not a claim that every CVE is known).
- Record *fixed*, *not_affected*, *mitigated*, *pending*, and *blocked* decisions with supporting evidence.
- Backport upstream security fixes without unnecessary package, ABI or user-visible behavior changes.
- Publish neither unsigned packages nor unreviewed security-fix claims.

## Current tooling

- Python standard-library advisory validator with unit tests.
- Read-only NVD CVE intake: JSON artifacts for human triage, **not** automatic affected-package declarations.
- GitHub Actions for lint/test and separately triggered CentOS 6 RPM toolchain smoke test.
- CentOS 6.10 yum configuration using archived Vault packages with RPM GPG verification.

Run locally with Python 3.11+:

    python3 -m unittest discover -s tests -v
    python3 scripts/validate_advisories.py

To exercise the legacy RPM toolchain on Linux with Docker:

    bash build/smoke.sh

The smoke test compiles a trivial noarch RPM only; it does **not** build, patch, or validate a vulnerable package. This container is an obsolete OS and not a trustworthy security boundary. Build it on disposable runners without privileged access or credentials.

## CVE decision contract

One JSON file per CVE in security/advisories/CVE-YYYY-NNNN.json. Required keys include cve, package, status, and evidence (nonempty array of authoritative URLs). Status-specific fields are enforced by the validator:

- fixed: upstream_reference, patch_path, patch_sha256, tests, reviewed_by
- not_affected: rationale, reviewed_by
- mitigated: rationale, mitigation
- pending / blocked: rationale

A fixed claim must include a patch under patches/ whose SHA-256 matches the advisory, tests with evidence links, and a reviewer identity. The validator checks bookkeeping and bytes, **not semantic correctness**. A passing CI check does not prove a security fix.

Before any release: establish SRPM provenance and pinned hashes, reproduce the vulnerability against the unpatched build, verify correction in the patched build, run ABI and application regression tests, get human review, and sign artifacts in a separately controlled release process.

## Trust and automation boundaries

- No write permissions or secrets in PR build jobs.
- NVD is a candidate feed, not a definitive CentOS 6 applicability database. Version-string matching is insufficient for backported distributions.
- Archived package GPG signatures validate CentOS-provided RPMs; the archive and container image remain legacy dependencies. Pin image digests and capture checksums before a production-grade build.
- Do not execute untrusted contributions on self-hosted runners or with release-signing secrets.
- Publication and updateinfo.xml are intentionally not enabled yet.

Sources: https://wiki.centos.org/Manuals%282f%29ReleaseNotes%282f%29CentOS6%282e%2910.html ; https://nvd.nist.gov/developers/vulnerabilities
