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

## sudo CVE-2021-3156 (Baron Samedit): an actually affected CentOS 6 package

sudo 1.8.2 through 1.8.31p2 is affected, and CentOS 6.10's final `sudo-1.8.6p3-29.el6_10.3` predates the January 2021 fix. `packages/sudo/CVE-2021-3156.patch` backports the [upstream fixes](https://www.sudo.ws/security/advisories/unescape_overflow/) to 1.8.6p3 and is applied after the CVE-2023-22809 candidate in the same `.tree1` build:

- the front-end rejects `-s`/`-i` when invoked as `sudoedit` (`src/parse_args.c`);
- the sudoers plugin rejects shell flags in edit mode, unescapes `user_args` only in run mode, and never skips past a trailing backslash (`plugins/sudoers/sudoers.c`);
- the shell-mode command buffer is sized from each argument instead of assuming a flat `argv`.

`tests/integration/sudoedit_cve_2021_3156.sh` runs in a network-less container as an unprivileged user without any sudoers rights. It requires the original RPM to show the vulnerable signature (`sudoedit -s /` is accepted by the parser), records whether the oversized trailing-backslash input crashes it, then requires the candidate to reject `sudoedit -s`, `sudoedit -i` and the overflow input with a usage error, while `sudo -s` / `sudo -i` command output stays byte-identical. The advisory remains `pending`: no independent review, full policy regression or signing has happened.

## Second SRPM experiment: curl and backend-dependent CVE reachability

- Source: `curl-7.19.7-54.el6_10.src.rpm`, SHA-256 `02f7ca7f49b284972cad9289efdcfe232c17d31cdd812546a52fd9d429f74f90`.
- Candidate: `packages/curl/CVE-2023-28321.patch`. The historical OpenSSL hostname-checking helper accepts unsafe partial and multi-level wildcard matches before this candidate patch; both are rejected afterward in the isolated C regression.
- [Successful CI run](https://github.com/kucats/tree-centos6-lts/actions/runs/39708887176) generated curl/libcurl RPMs and a source RPM, then installed the candidate in a disposable offline CentOS 6 environment. The actual binary reported **NSS/3.44**.
- curl's upstream [CVE-2023-28321 advisory](https://curl.se/docs/CVE-2023-28321.html) states that its private vulnerable name matcher is used with OpenSSL, Schannel and Gskit, **not NSS**. Consequently the presence of affected upstream source does not establish that the **default CentOS 6 NSS build** is vulnerable. A custom build using another TLS backend needs separate analysis.
- This experiment is a useful *applicability triage* example, not a security-update release. The candidate's legacy `%check` section is short-circuited in research CI to avoid running an unbounded historical suite, and full integration/ABI tests plus independent human review have **not** passed. The CVE stays `pending` with a provisional `not_affected_on_default_nss_binary` assessment. **Do not install research RPMs in production.**

### CI evidence so far

| Experiment | Verified result | Remaining release gate |
| --- | --- | --- |
| sudo / CVE-2023-22809 | [RPM/SRPM build, exact main-RPM selection, dynamic symbols, DT_NEEDED and sudoedit regression passed](https://github.com/kucats/tree-centos6-lts/actions/runs/39708887148) | Full policy regression, independent review, supply-chain signing |
| sudo / CVE-2021-3156 | [RPM/SRPM build, ABI smoke, before/after sudoedit -s/-i regression and offline yum upgrade passed](https://github.com/kucats/tree-centos6-lts/actions/runs/39723659150) | Independent review, full policy regression, supply-chain signing |
| curl / CVE-2023-28321 | [RPM/SRPM build and source-level before/after check passed; NSS/3.44 runtime detected](https://github.com/kucats/tree-centos6-lts/actions/runs/39708887176) | Decide applicability separately for default NSS vs optional OpenSSL builds; full suite and runtime integration |

No signed yum repository, production-ready update, or comprehensive CentOS 6 CVE coverage has been established.

## October 2026 historical CVE applicability audit

The existing candidate sudo `.tree1` RPM includes pending patches for CVE-2021-3156 and CVE-2023-22809; this does **not** establish complete sudo security coverage or production readiness.

Recent sudo CVEs have upstream introduction boundaries newer than CentOS 6 sudo 1.8.6p3. All remain `pending` pending downstream source review; no version-only comparison is a final release decision:

| CVE | Upstream introduced | CentOS 6.10 provisional finding |
| --- | --- | --- |
| CVE-2025-32462 | sudo 1.8.8 | Likely not affected: 1.8.6p3 predates the host-option bug |
| CVE-2026-96512 | sudo 1.8.20 | Likely not affected: time-based policy feature was introduced later |
| CVE-2026-82474 | sudo 1.9.8 | Likely not affected: intercept policy support was introduced later |

**High priority: OpenSSH CVE-2023-38408.** Upstream's affected-version list starts at 5.5, but Red Hat explicitly states RHEL 6 is affected. Examination of the officially signed CentOS 6.10 `openssh-5.3p1-124.el6_10.src.rpm` (SHA-256 `da18c49ea13c0f0d373f7c0159da11381989f5616856f494a92f9ec03315ef56`) found Red Hat's `openssh-5.3p1-pkcs11-support.patch` declared as `Patch103`. Its contents add PKCS#11 support to ssh-agent and a helper binary. Our dedicated GitHub Actions source audit attempts RPM `%prep` to confirm the applied vendor code, not merely the patch filename. The issue remains pending; no approved OpenSSH patch has been released. Oracle Linux 6 ELS advisory [ELSA-2023-4428](https://linux.oracle.com/errata/ELSA-2023-4428.html) contains a same-line 5.3p1 security fix, first shipped as `5.3p1-124.0.1`. Its later source RPM `openssh-5.3p1-124.0.2.el6_10.src.rpm` has vendor-listed SHA-256 `baa207d586d630ebd7549e7c656b1fe3fb4c06ad10b78ae3012964e13b0d4a2d`. This is a **reference donor to investigate**, not a verified or imported patch; access rights, code differences and independent compatibility testing remain open.

Further OpenSSH advisories published in July–August 2026 have been added as **pending**, not assumed vulnerable: CVE-2026-59995 (sftp download path containment; review actual 5.3p1 sftp destination handling), CVE-2026-59999 (DisableForwarding versus PermitTunnel policy; first establish whether old sshd implements the relevant option), and CVE-2026-73282 (use-after-free in concurrent remote forwarding and multiplexing; especially audit CentOS/RHEL ControlPersist vendor patches). Reference: [OpenSSH releases](https://www.openssh.org/releasenotes.html), [NVD CVE-2026-59995](https://nvd.nist.gov/vuln/detail/CVE-2026-59995), [NVD CVE-2026-73282](https://nvd.nist.gov/vuln/detail/CVE-2026-73282).

The latest [OpenSSH 10.6 release of October 6, 2026](https://www.openssh.org/releasenotes.html#10.6p1) and [Ubuntu's October 14, 2026 advisory](https://ubuntu.com/security/notices/USN-8928-1) identify nine more issues tracked as `pending` here: CVE-2026-106552, CVE-2026-106553, CVE-2026-106555, CVE-2026-106582, CVE-2026-106583, CVE-2026-106584, CVE-2026-106585, CVE-2026-106586 and CVE-2026-106587. High-priority review themes include GSSAPI authentication state carry-over, decompression bounds, shared compression side channels and command-line username injection. Separately, CVE-2026-73281 is provisionally not affected based on Red Hat's explicit RHEL6 statement that the `session-bind@openssh.com` extension began in 8.9; the status remains pending until historic source verification. The OpenSSH `%prep` audit reports source feature presence, not complete exploitability.

For risk reduction while assessing the affected forwarded-agent scenario, disable SSH agent forwarding to untrusted destinations (`ForwardAgent no`; avoid `ssh -A`). This is not an all-purpose fix.

The CentOS Vault GPG signatures (historical RSA/SHA1) authenticate old archive artifacts, not their present-day security. Pinned SHA-256 digests and independent source review remain necessary. No signing or production yum repository is enabled.

References: [OpenSSH upstream](https://www.openssh.org/security.html), [Red Hat CVE-2023-38408](https://access.redhat.com/security/cve/cve-2023-38408), [sudo CVE-2025-32462](https://www.sudo.ws/security/advisories/host_any/), [sudo CVE-2026-96512](https://www.openwall.com/lists/oss-security/2026/09/24/4), [sudo NEWS](https://github.com/sudo-project/sudo/blob/main/NEWS).

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
