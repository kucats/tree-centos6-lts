#!/usr/bin/env bash
# Research trust gate: check pinned CentOS 6 official key AND signature on each SRPM.
# Usage: bash scripts/verify_source_signatures.sh dist/sources dist/provenance
set -euo pipefail
sources="${1:-dist/sources}"
evidence="${2:-dist/provenance}"
expected_fingerprint='C1DAC52D1664E8A4386DBA430946FCA2C105B9DE'
key_url='https://vault.centos.org/RPM-GPG-KEY-CentOS-6'
mkdir -p "$evidence"
sources=$(cd "$sources" && pwd)
evidence=$(cd "$evidence" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -m 700 "$work/gnupg"
curl --proto '=https' --tlsv1.2 --fail --silent --show-error \
    --location --retry 3 --max-time 60 "$key_url" \
    -o "$work/RPM-GPG-KEY-CentOS-6"
GNUPGHOME="$work/gnupg" gpg --batch --import "$work/RPM-GPG-KEY-CentOS-6" >/dev/null 2>&1
actual=$(GNUPGHOME="$work/gnupg" gpg --batch --with-colons --fingerprint \
    | awk -F: '$1=="fpr" {print $10}')
if [[ "$actual" != "$expected_fingerprint" ]]; then
    printf 'FAIL: signing key fingerprint mismatch: %s\n' "$actual" >&2
    exit 1
fi
printf '%s\n' "$actual" > "$evidence/CENTOS6-TRUSTED-KEY-FINGERPRINT.txt"
printf 'Verified official CentOS 6 fingerprint: %s\n' "$actual"
# The script below is fixed code in a pinned, offline CentOS 6 image. No
# signing secrets, host RPM database, network, or privileged device mounts.
docker run --rm --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 128 --memory 512m \
    --tmpfs /tmp:rw,nosuid,nodev,size=100m \
    -v "$sources:/sources:ro" \
    -v "$work/RPM-GPG-KEY-CentOS-6:/key:ro" \
    -v "$evidence:/evidence" \
    centos:6@sha256:a93df2e96e07f56ea48f215425c6f1673ab922927894595bb5c0ee4c5a955133 \
    bash -euc '
        mkdir -p /tmp/rpm-verify-db
        rpm --dbpath /tmp/rpm-verify-db --initdb
        rpm --dbpath /tmp/rpm-verify-db --import /key
        rpm --dbpath /tmp/rpm-verify-db -q gpg-pubkey --qf "%{NAME} %{VERSION}-%{RELEASE}\n"
        set -- /sources/*.src.rpm
        test -f "$1"
        for package in "$@"; do
            echo "Checking $package"
            rpm --dbpath /tmp/rpm-verify-db -Kv "$package"
        done
    ' | tee "$evidence/SRPM-SIGNATURE-CHECK.txt"
if grep -Eqi 'NOKEY|NOT OK|NOTSIGNED|BAD SIGNATURE|NOT SIGNED' \
    "$evidence/SRPM-SIGNATURE-CHECK.txt"; then
    echo 'FAIL: failed signature check, unsigned SRPM, or untrusted key' >&2
    exit 1
fi
count=$(grep -c '^Checking /sources/.*\.src\.rpm$' "$evidence/SRPM-SIGNATURE-CHECK.txt")
if [[ "$count" -lt 1 ]]; then
    echo 'FAIL: no SRPM was checked' >&2
    exit 1
fi
printf 'PASS: checked %s source RPM signature(s) against the pinned official key\n' "$count"
