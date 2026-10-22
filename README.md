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

## First real SRPM backport experiment: sudo

CVE-2023-22809 was published after CentOS 6 reached end-of-life. A candidate patch for the old `sudo-1.8.6p3-29.el6_10.3` source RPM is stored at `packages/sudo/CVE-2023-22809.patch`. It was adapted from the upstream fix: https://github.com/sudo-project/sudo/commit/0274a4f3b403162a37a10f199c989f3727ed3ad4

The `CentOS 6 sudo CVE-2023-22809 candidate E2E` GitHub Actions workflow:

1. Downloads the actual source RPM from CentOS Vault and verifies its observed SHA-256 (`7fa30b571a1bcb5762dd8754a17001a71080475b7eb7dffc831ea1f2e6bd809d`).
2. Uses a disposable CentOS 6.10 builder to inject the patch into the original spec, applies all preexisting downstream patches, and builds candidate x86_64 RPM and source RPM with a release suffix `.tree1`.
3. Checks the candidate RPM's version ordering against the archived base package.
4. Compares exported dynamic symbols and DT_NEEDED entries of the original and candidate sudo binaries and sudoers plugin.
5. Runs a safe regression harness in a network-isolated container: the original RPM accepts an injected editor-argument separator; the patched RPM rejects it; regular editor usage still works.
6. Retains unsigned, untrusted candidate artifacts for only three days, with recorded hashes.

The first candidate build and three behavioral assertions passed in [GitHub Actions run #3](https://github.com/kucats/tree-centos6-lts/actions/runs/39702709677). Later checks (including the ABI check and SHA pin) must be independently evaluated; a previous run's success is **not** evidence for later additions.

**Limitations:** The regression harness does not attempt privilege escalation, exercise the complete upstream test suite or test every combination of sudoers policy and editor. The dynamic-symbol check is an ABI smoke test rather than comprehensive ABI verification. The RPM is unreviewed and unsigned. This advisory remains `pending` and **must not be automatically published**.

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
